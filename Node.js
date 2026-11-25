
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const db = new Database(process.env.DB_FILE || "./zann-vip.sqlite");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PAYMENT_DESTINATION =
  process.env.PAYMENT_DESTINATION || "089671458080";

if (!JWT_SECRET || JWT_SECRET.length < 32 || !ADMIN_PASSWORD) {
  throw new Error("Isi JWT_SECRET minimal 32 karakter dan ADMIN_PASSWORD di .env");
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keys_store (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL,
  duration_days INTEGER,
  status TEXT NOT NULL DEFAULT 'UNUSED',
  user_id INTEGER,
  activated_at INTEGER,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  unit_price INTEGER NOT NULL,
  total INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at INTEGER NOT NULL,
  approved_at INTEGER
);

CREATE TABLE IF NOT EXISTS participants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS game_state (
  id INTEGER PRIMARY KEY CHECK(id=1),
  running INTEGER NOT NULL DEFAULT 0,
  round_number INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS modules (
  name TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO game_state(id,running,round_number,updated_at)
VALUES(1,0,0,unixepoch());
`);

const PLANS = {
  "3hari": { label: "3 Hari", days: 3, price: 5000 },
  "7hari": { label: "7 Hari", days: 7, price: 10000 },
  "30hari": { label: "30 Hari", days: 30, price: 40000 },
  "permanen": { label: "Permanen", days: null, price: 100000 }
};

const MODULE_NAMES = [
  "timer",
  "mysteryBox",
  "manualGift",
  "leaderboard",
  "auction",
  "characters",
  "backgrounds",
  "hostSettings"
];

const adminPasswordHash = bcrypt.hashSync(ADMIN_PASSWORD, 12);

function now() {
  return Math.floor(Date.now() / 1000);
}

function makeToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  try {
    if (!token) throw new Error("No token");
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Silakan login kembali." });
  }
}

function adminOnly(req, res, next) {
  if (req.auth?.role !== "admin") {
    return res.status(403).json({ error: "Khusus admin." });
  }
  next();
}

function makeKeyCode() {
  return "ZVIP-" +
    crypto.randomBytes(4).toString("hex").toUpperCase() + "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase();
}

// Buat KEY. Tidak ada batas total KEY di database.
// Batas 10.000 hanya untuk satu permintaan agar server tidak kehabisan memori.
function issueKeys(planId, quantity) {
  const plan = PLANS[planId];
  if (!plan) throw new Error("Paket KEY tidak valid.");
  if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 10000) {
    throw new Error("Jumlah per proses harus 1 sampai 10.000. Buat batch berikutnya untuk jumlah lebih banyak.");
  }

  const insert = db.prepare(`
    INSERT INTO keys_store
    (code,plan,duration_days,status,created_at)
    VALUES(?,?,?,'UNUSED',?)
  `);

  const codes = [];
  for (let i = 0; i < quantity; i++) {
    let code;
    do {
      code = makeKeyCode();
    } while (db.prepare("SELECT id FROM keys_store WHERE code=?").get(code));

    insert.run(code, planId, plan.days, now());
    codes.push(code);
  }
  return codes;
}

function getActiveKey(userId) {
  const timestamp = now();

  db.prepare(`
    UPDATE keys_store
    SET status='EXPIRED'
    WHERE user_id=?
      AND status='ACTIVE'
      AND expires_at IS NOT NULL
      AND expires_at<=?
  `).run(userId, timestamp);

  return db.prepare(`
    SELECT * FROM keys_store
    WHERE user_id=?
      AND status='ACTIVE'
      AND (expires_at IS NULL OR expires_at>?)
    ORDER BY (expires_at IS NULL) DESC, expires_at DESC
    LIMIT 1
  `).get(userId, timestamp);
}

function premium(req, res, next) {
  if (req.auth.role === "admin") return next();

  const key = getActiveKey(req.auth.id);
  if (!key) {
    return res.status(403).json({
      error: "KEY belum aktif atau sudah kedaluwarsa. Silakan aktifkan KEY baru.",
      code: "KEY_EXPIRED"
    });
  }

  req.activeKey = key;
  next();
}

function readModule(name, fallback = {}) {
  const row = db.prepare("SELECT data FROM modules WHERE name=?").get(name);
  if (!row) return fallback;

  try {
    return JSON.parse(row.data);
  } catch {
    return fallback;
  }
}

function writeModule(name, data) {
  db.prepare(`
    INSERT INTO modules(name,data,updated_at)
    VALUES(?,?,?)
    ON CONFLICT(name) DO UPDATE SET
      data=excluded.data,
      updated_at=excluded.updated_at
  `).run(name, JSON.stringify(data), now());
}

// ---------------- HEALTH ----------------

app.get("/api/health", (req, res) => {
  res.json({ online: true, name: "ZANN ELIMINASI VIP" });
});

// ---------------- REGISTER / LOGIN ----------------

app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: "Username 3–20 karakter, huruf, angka, atau underscore."
    });
  }

  if (password.length < 8 || password.length > 100) {
    return res.status(400).json({
      error: "Password minimal 8 karakter."
    });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      "INSERT INTO users(username,password_hash) VALUES(?,?)"
    ).run(username, hash);

    res.json({
      success: true,
      userId: result.lastInsertRowid
    });
  } catch {
    res.status(409).json({ error: "Username sudah digunakan." });
  }
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (
    username === ADMIN_USERNAME &&
    await bcrypt.compare(password, adminPasswordHash)
  ) {
    return res.json({
      token: makeToken({ role: "admin", username }),
      role: "admin"
    });
  }

  const user = db.prepare(
    "SELECT * FROM users WHERE username=?"
  ).get(username);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Username atau password salah." });
  }

  res.json({
    token: makeToken({
      role: "user",
      id: user.id,
      username: user.username
    }),
    role: "user"
  });
});

// ---------------- TOKO KEY TANPA LOGIN ----------------

app.get("/api/store/plans", (req, res) => {
  res.json({
    plans: PLANS,
    destination: PAYMENT_DESTINATION
  });
});

app.post("/api/store/checkout", (req, res) => {
  const planId = String(req.body.plan || "");
  const quantity = Number(req.body.quantity);
  const plan = PLANS[planId];

  if (!plan) {
    return res.status(400).json({ error: "Paket tidak tersedia." });
  }

  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 20) {
    return res.status(400).json({ error: "Jumlah KEY 1–20 per pesanan." });
  }

  const total = plan.price * quantity;

  const result = db.prepare(`
    INSERT INTO transactions
    (plan,quantity,unit_price,total,status,created_at)
    VALUES(?,?,?,?, 'PENDING',?)
  `).run(planId, quantity, plan.price, total, now());

  res.json({
    success: true,
    transactionId: result.lastInsertRowid,
    plan: plan.label,
    quantity,
    total,
    destination: PAYMENT_DESTINATION,
    status: "PENDING",
    message: "KEY akan diterbitkan setelah pembayaran diperiksa admin."
  });
});

// ---------------- REDEEM KEY ----------------

app.post("/api/key/redeem", auth, (req, res) => {
  if (req.auth.role !== "user") {
    return res.status(403).json({ error: "Akun pengguna diperlukan." });
  }

  const code = String(req.body.code || "").trim().toUpperCase();
  const key = db.prepare(
    "SELECT * FROM keys_store WHERE code=? AND status='UNUSED'"
  ).get(code);

  if (!key) {
    return res.status(400).json({
      error: "KEY tidak ditemukan atau sudah digunakan."
    });
  }

  const activate = db.transaction(() => {
    const timestamp = now();
    const expiresAt = key.duration_days === null
      ? null
      : timestamp + key.duration_days * 86400;

    const result = db.prepare(`
      UPDATE keys_store
      SET user_id=?,status='ACTIVE',activated_at=?,expires_at=?
      WHERE id=? AND status='UNUSED'
    `).run(req.auth.id, timestamp, expiresAt, key.id);

    if (result.changes !== 1) throw new Error("KEY sudah digunakan.");

    return { expiresAt, plan: key.plan };
  });

  try {
    res.json({ success: true, ...activate() });
  } catch (err) {
    res.status(409).json({ error: err.message });
  }
});

app.get("/api/key/status", auth, (req, res) => {
  if (req.auth.role === "admin") {
    return res.json({ active: true, admin: true, permanent: true });
  }

  const key = getActiveKey(req.auth.id);
  if (!key) return res.json({ active: false });

  res.json({
    active: true,
    plan: key.plan,
    permanent: key.expires_at === null,
    expiresAt: key.expires_at ? key.expires_at * 1000 : null
  });
});

// ---------------- ADMIN: BUAT KEY TANPA BATAS TOTAL ----------------

app.post("/api/admin/keys/create", auth, adminOnly, (req, res) => {
  const planId = String(req.body.plan || "");
  const quantity = Number(req.body.quantity);

  try {
    const codes = db.transaction(() =>
      issueKeys(planId, quantity)
    )();

    res.json({
      success: true,
      quantity: codes.length,
      codes
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/admin/keys", auth, adminOnly, (req, res) => {
  const rows = db.prepare(`
    SELECT id,code,plan,duration_days,status,user_id,
           activated_at,expires_at,created_at
    FROM keys_store
    ORDER BY id DESC
    LIMIT 500
  `).all();

  res.json(rows);
});

// ---------------- ADMIN: PEMBAYARAN ----------------

app.get("/api/admin/transactions", auth, adminOnly, (req, res) => {
  res.json(db.prepare(`
    SELECT * FROM transactions
    ORDER BY id DESC
    LIMIT 200
  `).all());
});

app.post("/api/admin/transactions/:id/approve", auth, adminOnly, (req, res) => {
  const id = Number(req.params.id);

  try {
    const result = db.transaction(() => {
      const tx = db.prepare(
        "SELECT * FROM transactions WHERE id=?"
      ).get(id);

      if (!tx || tx.status !== "PENDING") {
        throw new Error("Transaksi tidak ada atau sudah diproses.");
      }

      const codes = issueKeys(tx.plan, tx.quantity);

      const updated = db.prepare(`
        UPDATE transactions
        SET status='PAID',approved_at=?
        WHERE id=? AND status='PENDING'
      `).run(now(), id);

      if (updated.changes !== 1) {
        throw new Error("Transaksi sudah diproses.");
      }

      return codes;
    })();

    res.json({
      success: true,
      message: "Pembayaran disetujui. Bagikan KEY ini kepada pembeli.",
      keys: result
    });
  } catch (err) {
    res.status(409).json({ error: err.message });
  }
});

app.post("/api/admin/transactions/:id/reject", auth, adminOnly, (req, res) => {
  const result = db.prepare(`
    UPDATE transactions SET status='REJECTED'
    WHERE id=? AND status='PENDING'
  `).run(Number(req.params.id));

  if (!result.changes) {
    return res.status(409).json({
      error: "Transaksi tidak ditemukan atau sudah diproses."
    });
  }

  res.json({ success: true });
});

// ---------------- MODE ELIMINASI ----------------

app.get("/api/game/state", auth, premium, (req, res) => {
  const game = db.prepare(
    "SELECT * FROM game_state WHERE id=1"
  ).get();

  const participants = db.prepare(
    "SELECT * FROM participants ORDER BY id ASC"
  ).all();

  res.json({
    running: !!game.running,
    round: game.round_number,
    participants,
    modules: Object.fromEntries(
      MODULE_NAMES.map(name => [name, readModule(name)])
    )
  });
});

app.post("/api/admin/game/participants", auth, adminOnly, (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 40);

  if (!name) {
    return res.status(400).json({ error: "Nama peserta wajib diisi." });
  }

  const result = db.prepare(`
    INSERT INTO participants(name,status,created_at)
    VALUES(?,'ACTIVE',?)
  `).run(name, now());

  res.json({ success: true, id: result.lastInsertRowid });
});

app.post("/api/admin/game/participants/:id/eliminate", auth, adminOnly, (req, res) => {
  const result = db.prepare(`
    UPDATE participants SET status='ELIMINATED'
    WHERE id=? AND status='ACTIVE'
  `).run(Number(req.params.id));

  if (!result.changes) {
    return res.status(404).json({ error: "Peserta aktif tidak ditemukan." });
  }

  res.json({ success: true });
});

app.post("/api/admin/game/participants/:id/restore", auth, adminOnly, (req, res) => {
  const result = db.prepare(`
    UPDATE participants SET status='ACTIVE'
    WHERE id=?
  `).run(Number(req.params.id));

  if (!result.changes) {
    return res.status(404).json({ error: "Peserta tidak ditemukan." });
  }

  res.json({ success: true });
});

app.post("/api/admin/game/start-round", auth, adminOnly, (req, res) => {
  const result = db.prepare(`
    UPDATE game_state
    SET running=1,round_number=round_number+1,updated_at=?
    WHERE id=1
  `).run(now());

  const game = db.prepare(
    "SELECT * FROM game_state WHERE id=1"
  ).get();

  res.json({ success: true, round: game.round_number });
});

app.post("/api/admin/game/stop", auth, adminOnly, (req, res) => {
  db.prepare(`
    UPDATE game_state SET running=0,updated_at=? WHERE id=1
  `).run(now());

  res.json({ success: true });
});

app.post("/api/admin/game/reset", auth, adminOnly, (req, res) => {
  const reset = db.transaction(() => {
    db.prepare("UPDATE participants SET status='ACTIVE'").run();
    db.prepare(`
      UPDATE game_state
      SET running=0,round_number=0,updated_at=?
      WHERE id=1
    `).run(now());
  });

  reset();
  res.json({ success: true });
});

// ---------------- MODUL FITUR TAMBAHAN ----------------

app.put("/api/game/module/:name", auth, premium, (req, res) => {
  const name = req.params.name;

  if (!MODULE_NAMES.includes(name)) {
    return res.status(404).json({ error: "Modul tidak ditemukan." });
  }

  const data = req.body.data;

  if (!data || typeof data !== "object" ||
      JSON.stringify(data).length > 50000) {
    return res.status(400).json({ error: "Data modul tidak valid." });
  }

  writeModule(name, data);
  res.json({ success: true });
});

// ---------------- ERROR / START ----------------

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Terjadi kesalahan server." });
});

app.listen(PORT, () => {
  console.log("ZANN ELIMINASI VIP aktif di port " + PORT);
});
