
require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");

const app = express();
const db = new Database(process.env.DB_FILE || "./zann-vip.sqlite");

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET harus diisi dengan secret panjang.");
}

app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const PLANS = {
  "3hari": { name: "3 Hari", price: 5000, days: 3 },
  "7hari": { name: "7 Hari", price: 10000, days: 7 },
  "30hari": { name: "30 Hari", price: 40000, days: 30 },
  "permanen": { name: "Permanen", price: 100000, days: null }
};

const MODULES = [
  "timer",
  "mysteryBox",
  "manualGift",
  "leaderboard",
  "auction",
  "characters",
  "backgrounds",
  "hostSettings"
];

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS keys_store (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL,
  status TEXT DEFAULT 'UNUSED',
  user_id INTEGER,
  expires_at INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  plan TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT DEFAULT 'PENDING',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS participants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  status TEXT DEFAULT 'ACTIVE',
  round INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS game_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  running INTEGER DEFAULT 0,
  round INTEGER DEFAULT 1,
  winner TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS modules (
  name TEXT PRIMARY KEY,
  data TEXT NOT NULL
);
`);

db.prepare(`
INSERT OR IGNORE INTO game_state (id, running, round, winner)
VALUES (1, 0, 1, '')
`).run();

function makeToken(payload, expiresIn = "12h") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "Silakan login." });
  }

  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Sesi tidak valid." });
  }
}

function adminOnly(req, res, next) {
  if (req.auth && req.auth.admin === true) return next();
  return res.status(403).json({ error: "Khusus admin." });
}

function premium(req, res, next) {
  if (req.auth?.admin === true) return next();

  const key = db.prepare(`
    SELECT * FROM keys_store
    WHERE user_id = ? AND status = 'ACTIVE'
    ORDER BY id DESC LIMIT 1
  `).get(req.auth?.userId);

  if (!key) {
    return res.status(403).json({ error: "KEY VIP tidak aktif." });
  }

  if (key.expires_at && Date.now() >= key.expires_at) {
    db.prepare(`
      UPDATE keys_store SET status = 'EXPIRED'
      WHERE id = ?
    `).run(key.id);

    return res.status(403).json({
      error: "Masa aktif KEY sudah habis. Silakan gunakan KEY baru."
    });
  }

  req.vipKey = key;
  next();
}

function createKey(plan) {
  const code = "ZANN-" +
    crypto.randomBytes(4).toString("hex").toUpperCase() +
    "-" +
    crypto.randomBytes(3).toString("hex").toUpperCase();

  db.prepare(`
    INSERT INTO keys_store (code, plan)
    VALUES (?, ?)
  `).run(code, plan);

  return code;
}

function createKeys(plan, count) {
  const codes = [];
  const insert = db.prepare(`
    INSERT INTO keys_store (code, plan)
    VALUES (?, ?)
  `);

  const transaction = db.transaction(() => {
    for (let i = 0; i < count; i++) {
      const code = "ZANN-" +
        crypto.randomBytes(4).toString("hex").toUpperCase() +
        "-" +
        crypto.randomBytes(3).toString("hex").toUpperCase();

      insert.run(code, plan);
      codes.push(code);
    }
  });

  transaction();
  return codes;
}

function getGameState() {
  const state = db.prepare(
    "SELECT * FROM game_state WHERE id = 1"
  ).get();

  const players = db.prepare(`
    SELECT id, name, status, round
    FROM participants ORDER BY id DESC
  `).all();

  return { ...state, participants: players };
}

/* ---------------- ADMIN LOGIN ---------------- */

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body || {};

  const expectedUser = process.env.ADMIN_USERNAME;
  const expectedPassword = process.env.ADMIN_PASSWORD;

  if (!expectedUser || !expectedPassword) {
    return res.status(500).json({ error: "Admin belum dikonfigurasi." });
  }

  const valid =
    username === expectedUser &&
    password === expectedPassword;

  if (!valid) {
    return res.status(401).json({
      error: "Username atau password admin salah."
    });
  }

  const token = makeToken({ admin: true });

  res.json({
    success: true,
    token,
    message: "Login admin berhasil."
  });
});

/* ---------------- USER ACCOUNT ---------------- */

app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: "Username harus 3-20 karakter."
    });
  }

  if (password.length < 8 || password.length > 100) {
    return res.status(400).json({
      error: "Password minimal 8 karakter."
    });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const result = db.prepare(`
      INSERT INTO users (username, password)
      VALUES (?, ?)
    `).run(username, hash);

    res.json({ success: true, userId: result.lastInsertRowid });
  } catch {
    res.status(409).json({ error: "Username sudah digunakan." });
  }
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Login gagal." });
  }

  const token = makeToken({
    userId: user.id,
    username: user.username
  });

  res.json({ success: true, token });
});

app.get("/api/me", auth, (req, res) => {
  if (req.auth.admin) {
    return res.json({ admin: true, username: process.env.ADMIN_USERNAME });
  }

  const user = db.prepare(`
    SELECT id, username FROM users WHERE id = ?
  `).get(req.auth.userId);

  res.json({ user });
});

/* ---------------- PUBLIC STORE ---------------- */

app.get("/api/store/plans", (req, res) => {
  res.json({ plans: PLANS });
});

app.post("/api/store/checkout", (req, res) => {
  const username = String(req.body.username || "").trim();
  const plan = req.body.plan;
  const quantity = Number(req.body.quantity);

  if (!username || username.length > 50) {
    return res.status(400).json({ error: "Masukkan nama pembeli." });
  }

  if (!PLANS[plan]) {
    return res.status(400).json({ error: "Paket tidak tersedia." });
  }

  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
    return res.status(400).json({ error: "Jumlah KEY 1-100." });
  }

  const amount = PLANS[plan].price * quantity;

  const result = db.prepare(`
    INSERT INTO transactions (username, plan, quantity, amount)
    VALUES (?, ?, ?, ?)
  `).run(username, plan, quantity, amount);

  res.json({
    success: true,
    transactionId: result.lastInsertRowid,
    username,
    plan: PLANS[plan].name,
    quantity,
    amount,
    destination: process.env.PAYMENT_DESTINATION,
    message: "Silakan lakukan transfer. Pesanan menunggu pemeriksaan admin."
  });
});

/* ---------------- KEY ACTIVATION ---------------- */

app.post("/api/key/redeem", auth, (req, res) => {
  if (req.auth.admin) {
    return res.status(400).json({ error: "Admin tidak perlu KEY VIP." });
  }

  const code = String(req.body.code || "").trim().toUpperCase();

  const key = db.prepare(`
    SELECT * FROM keys_store WHERE code = ?
  `).get(code);

  if (!key) {
    return res.status(404).json({ error: "KEY tidak ditemukan." });
  }

  if (key.status !== "UNUSED") {
    return res.status(409).json({ error: "KEY sudah digunakan atau tidak aktif." });
  }

  const expiresAt = key.plan === "permanen"
    ? null
    : Date.now() + PLANS[key.plan].days * 86400000;

  db.prepare(`
    UPDATE keys_store
    SET status = 'ACTIVE', user_id = ?, expires_at = ?
    WHERE id = ? AND status = 'UNUSED'
  `).run(req.auth.userId, expiresAt, key.id);

  res.json({
    success: true,
    plan: key.plan,
    expiresAt
  });
});

app.get("/api/key/status", auth, (req, res) => {
  if (req.auth.admin) {
    return res.json({ active: true, permanent: true, admin: true });
  }

  const key = db.prepare(`
    SELECT * FROM keys_store
    WHERE user_id = ? AND status = 'ACTIVE'
    ORDER BY id DESC LIMIT 1
  `).get(req.auth.userId);

  if (!key) return res.json({ active: false });

  if (key.expires_at && Date.now() >= key.expires_at) {
    db.prepare(`
      UPDATE keys_store SET status = 'EXPIRED' WHERE id = ?
    `).run(key.id);

    return res.json({ active: false, expired: true });
  }

  res.json({
    active: true,
    plan: key.plan,
    expiresAt: key.expires_at,
    permanent: key.expires_at === null
  });
});

/* ---------------- ADMIN KEY MANAGEMENT ---------------- */

app.post("/api/admin/keys/create", auth, adminOnly, (req, res) => {
  const plan = req.body.plan;
  const count = Number(req.body.count);

  if (!PLANS[plan]) {
    return res.status(400).json({ error: "Paket tidak valid." });
  }

  if (!Number.isInteger(count) || count < 1 || count > 10000) {
    return res.status(400).json({
      error: "Jumlah KEY harus 1 sampai 10000 per pembuatan."
    });
  }

  const codes = createKeys(plan, count);

  res.json({
    success: true,
    count: codes.length,
    plan,
    codes
  });
});

app.get("/api/admin/keys", auth, adminOnly, (req, res) => {
  const keys = db.prepare(`
    SELECT id, code, plan, status, user_id, expires_at, created_at
    FROM keys_store ORDER BY id DESC LIMIT 500
  `).all();

  res.json({ keys });
});

/* ---------------- ADMIN TRANSACTIONS ---------------- */

app.get("/api/admin/transactions", auth, adminOnly, (req, res) => {
  const transactions = db.prepare(`
    SELECT * FROM transactions ORDER BY id DESC LIMIT 500
  `).all();

  res.json({ transactions });
});

app.post("/api/admin/transactions/:id/approve", auth, adminOnly, (req, res) => {
  const id = Number(req.params.id);

  const transaction = db.prepare(`
    SELECT * FROM transactions WHERE id = ?
  `).get(id);

  if (!transaction || transaction.status !== "PENDING") {
    return res.status(409).json({
      error: "Transaksi tidak ditemukan atau sudah diproses."
    });
  }

  const issue = db.transaction(() => {
    const update = db.prepare(`
      UPDATE transactions SET status = 'APPROVED'
      WHERE id = ? AND status = 'PENDING'
    `).run(id);

    if (update.changes !== 1) {
      throw new Error("Transaksi sudah diproses.");
    }

    return createKeys(transaction.plan, transaction.quantity);
  });

  try {
    const codes = issue();

    res.json({
      success: true,
      transactionId: id,
      codes
    });
  } catch (error) {
    res.status(409).json({ error: error.message });
  }
});

app.post("/api/admin/transactions/:id/reject", auth, adminOnly, (req, res) => {
  const result = db.prepare(`
    UPDATE transactions SET status = 'REJECTED'
    WHERE id = ? AND status = 'PENDING'
  `).run(Number(req.params.id));

  if (!result.changes) {
    return res.status(404).json({ error: "Transaksi tidak ditemukan." });
  }

  res.json({ success: true });
});

/* ---------------- ELIMINATION GAME ---------------- */

app.get("/api/game/state", auth, premium, (req, res) => {
  res.json(getGameState());
});

app.post("/api/game/participant", auth, premium, (req, res) => {
  const name = String(req.body.name || "").trim();

  if (!name || name.length > 50) {
    return res.status(400).json({ error: "Nama peserta tidak valid." });
  }

  const state = db.prepare(
    "SELECT round FROM game_state WHERE id = 1"
  ).get();

  const result = db.prepare(`
    INSERT INTO participants (name, status, round)
    VALUES (?, 'ACTIVE', ?)
  `).run(name, state.round);

  res.json({ success: true, id: result.lastInsertRowid });
});

app.post("/api/game/eliminate/:id", auth, premium, (req, res) => {
  const result = db.prepare(`
    UPDATE participants SET status = 'ELIMINATED'
    WHERE id = ? AND status = 'ACTIVE'
  `).run(Number(req.params.id));

  if (!result.changes) {
    return res.status(404).json({ error: "Peserta tidak aktif atau tidak ditemukan." });
  }

  res.json({ success: true });
});

app.post("/api/game/restore/:id", auth, premium, (req, res) => {
  const result = db.prepare(`
    UPDATE participants SET status = 'ACTIVE'
    WHERE id = ? AND status = 'ELIMINATED'
  `).run(Number(req.params.id));

  if (!result.changes) {
    return res.status(404).json({ error: "Peserta tidak ditemukan." });
  }

  res.json({ success: true });
});

app.post("/api/game/round/start", auth, premium, (req, res) => {
  db.prepare(`
    UPDATE game_state SET running = 1 WHERE id = 1
  `).run();

  res.json({ success: true });
});

app.post("/api/game/round/next", auth, premium, (req, res) => {
  const state = db.prepare(
    "SELECT round FROM game_state WHERE id = 1"
  ).get();

  const nextRound = state.round + 1;

  db.prepare(`
    UPDATE game_state SET round = ?, running = 1 WHERE id = 1
  `).run(nextRound);

  res.json({ success: true, round: nextRound });
});

app.post("/api/game/round/stop", auth, premium, (req, res) => {
  db.prepare(`
    UPDATE game_state SET running = 0 WHERE id = 1
  `).run();

  res.json({ success: true });
});

app.post("/api/game/winner", auth, premium, (req, res) => {
  const winner = String(req.body.name || "").trim();

  if (!winner || winner.length > 50) {
    return res.status(400).json({ error: "Nama pemenang tidak valid." });
  }

  db.prepare(`
    UPDATE game_state SET winner = ?, running = 0 WHERE id = 1
  `).run(winner);

  res.json({ success: true, winner });
});

app.post("/api/game/reset", auth, premium, (req, res) => {
  const reset = db.transaction(() => {
    db.prepare("DELETE FROM participants").run();

    db.prepare(`
      UPDATE game_state
      SET running = 0, round = 1, winner = ''
      WHERE id = 1
    `).run();
  });

  reset();
  res.json({ success: true });
});

/* ---------------- GAME MODULES ---------------- */

app.get("/api/modules/:name", auth, premium, (req, res) => {
  const name = req.params.name;

  if (!MODULES.includes(name)) {
    return res.status(404).json({ error: "Modul tidak ditemukan." });
  }

  const row = db.prepare(`
    SELECT data FROM modules WHERE name = ?
  `).get(name);

  res.json({ data: row ? JSON.parse(row.data) : {} });
});

app.put("/api/modules/:name", auth, premium, (req, res) => {
  const name = req.params.name;

  if (!MODULES.includes(name)) {
    return res.status(404).json({ error: "Modul tidak ditemukan." });
  }

  const data = JSON.stringify(req.body || {});

  if (data.length > 50000) {
    return res.status(413).json({ error: "Data terlalu besar." });
  }

  db.prepare(`
    INSERT INTO modules (name, data)
    VALUES (?, ?)
    ON CONFLICT(name) DO UPDATE SET data = excluded.data
  `).run(name, data);

  res.json({ success: true });
});

/* ---------------- SERVER ---------------- */

app.get("/api/health", (req, res) => {
  res.json({ online: true, name: "ZANN ELIMINASI VIP" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log("ZANN ELIMINASI VIP berjalan di port " + PORT);
});
