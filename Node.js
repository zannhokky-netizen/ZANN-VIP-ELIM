
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ZANNGGBGT";
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const RELAY_SECRET = process.env.RELAY_SECRET || "";
const PORT = process.env.PORT || 3000;

const allowedOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error("Origin not allowed"));
  }
}));

// =============================
// DATA GAME
// =============================

const game = {
  participants: [],
  eliminated: [],
  timer: {
    duration: 0,
    startedAt: null,
    running: false
  },
  leaderboard: [],
  auction: {
    active: false,
    entries: []
  },
  mystery: {
    active: false
  },
  history: [],
  settings: {}
};

function logHistory(action, details = {}) {
  game.history.unshift({
    id: crypto.randomUUID(),
    action,
    details,
    timestamp: new Date().toISOString()
  });

  if (game.history.length > 200) game.history.pop();
}

function getTimerRemaining() {
  if (!game.timer.running || !game.timer.startedAt) {
    return game.timer.duration;
  }

  const elapsed = Math.floor((Date.now() - game.timer.startedAt) / 1000);
  return Math.max(0, game.timer.duration - elapsed);
}

// =============================
// AUTH TOKEN
// =============================

function createToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(data)
    .digest("base64url");

  return `${data}.${signature}`;
}

function verifyToken(token) {
  if (!token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [data, signature] = parts;

  const expected = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(data)
    .digest("base64url");

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString()
    );

    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function adminOnly(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : "";

  const payload = verifyToken(token);

  if (!payload || payload.admin !== true) {
    return res.status(403).json({
      error: "Admin access required"
    });
  }

  req.auth = payload;
  next();
}

// =============================
// BASIC API
// =============================

app.get("/", (req, res) => {
  res.json({
    name: "ZANN ELIMINASI VIP",
    status: "online",
    version: "1.0.0"
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    name: "ZANN ELIMINASI VIP"
  });
});

app.get("/api/game", (req, res) => {
  res.json({
    participants: game.participants,
    eliminated: game.eliminated,
    timer: {
      ...game.timer,
      remaining: getTimerRemaining()
    },
    leaderboard: game.leaderboard,
    auction: game.auction,
    mystery: game.mystery,
    settings: game.settings
  });
});

app.get("/api/history", (req, res) => {
  res.json(game.history);
});

app.get("/api/key-prices", (req, res) => {
  res.json({
    currency: "IDR",
    prices: [
      { duration: "3 days", price: 5000 },
      { duration: "7 days", price: 10000 },
      { duration: "30 days", price: 50000 },
      { duration: "permanent", price: 100000 }
    ]
  });
});

// =============================
// ADMIN LOGIN
// =============================

app.post("/api/admin/login", (req, res) => {
  const password = String(req.body.password || "");

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({
      error: "Password salah"
    });
  }

  const token = createToken({
    admin: true,
    exp: Date.now() + 60 * 60 * 1000
  });

  res.json({
    success: true,
    token,
    expiresIn: 3600
  });
});

// =============================
// PARTICIPANTS
// =============================

app.post("/api/admin/participants", adminOnly, (req, res) => {
  const username = String(req.body.username || "").trim();

  if (!username || username.length > 50) {
    return res.status(400).json({
      error: "Username tidak valid"
    });
  }

  const participant = {
    id: crypto.randomUUID(),
    username,
    score: 0,
    joinedAt: new Date().toISOString()
  };

  game.participants.push(participant);
  logHistory("participant_added", { username });

  res.json({
    success: true,
    participant
  });
});

app.post("/api/admin/eliminate", adminOnly, (req, res) => {
  const id = String(req.body.id || "");

  const index = game.participants.findIndex(p => p.id === id);

  if (index === -1) {
    return res.status(404).json({
      error: "Peserta tidak ditemukan"
    });
  }

  const participant = game.participants.splice(index, 1)[0];

  game.eliminated.push({
    ...participant,
    eliminatedAt: new Date().toISOString()
  });

  logHistory("participant_eliminated", {
    username: participant.username
  });

  res.json({
    success: true,
    participant
  });
});

app.post("/api/admin/restore", adminOnly, (req, res) => {
  const id = String(req.body.id || "");

  const index = game.eliminated.findIndex(p => p.id === id);

  if (index === -1) {
    return res.status(404).json({
      error: "Peserta tidak ditemukan"
    });
  }

  const participant = game.eliminated.splice(index, 1)[0];

  delete participant.eliminatedAt;
  game.participants.push(participant);

  logHistory("participant_restored", {
    username: participant.username
  });

  res.json({
    success: true,
    participant
  });
});

app.post("/api/admin/reset", adminOnly, (req, res) => {
  game.participants = [];
  game.eliminated = [];
  game.leaderboard = [];

  game.timer = {
    duration: 0,
    startedAt: null,
    running: false
  };

  game.auction = {
    active: false,
    entries: []
  };

  game.mystery = {
    active: false
  };

  logHistory("game_reset");

  res.json({
    success: true,
    message: "Game direset"
  });
});

// =============================
// TIMER
// =============================

app.post("/api/admin/timer", adminOnly, (req, res) => {
  const action = req.body.action;

  if (action === "start") {
    const seconds = Number(req.body.seconds);

    if (!Number.isFinite(seconds) || seconds <= 0) {
      return res.status(400).json({
        error: "Durasi harus lebih dari 0"
      });
    }

    game.timer.duration = Math.floor(seconds);
    game.timer.startedAt = Date.now();
    game.timer.running = true;
  }

  else if (action === "stop") {
    game.timer.duration = getTimerRemaining();
    game.timer.startedAt = null;
    game.timer.running = false;
  }

  else if (action === "reset") {
    game.timer.duration = Number(req.body.seconds || 0);
    game.timer.startedAt = null;
    game.timer.running = false;
  }

  else {
    return res.status(400).json({
      error: "Action timer tidak valid"
    });
  }

  logHistory("timer_" + action);

  res.json({
    success: true,
    timer: {
      ...game.timer,
      remaining: getTimerRemaining()
    }
  });
});

// =============================
// LEADERBOARD / SCORE
// =============================

app.post("/api/admin/score", adminOnly, (req, res) => {
  const id = String(req.body.id || "");
  const points = Number(req.body.points);

  if (!Number.isFinite(points)) {
    return res.status(400).json({
      error: "Skor tidak valid"
    });
  }

  const participant = game.participants.find(p => p.id === id);

  if (!participant) {
    return res.status(404).json({
      error: "Peserta tidak ditemukan"
    });
  }

  participant.score += points;

  game.leaderboard = [...game.participants]
    .sort((a, b) => b.score - a.score);

  logHistory("score_updated", {
    username: participant.username,
    points
  });

  res.json({
    success: true,
    participant,
    leaderboard: game.leaderboard
  });
});

// =============================
// AUCTION
// =============================

app.post("/api/admin/auction", adminOnly, (req, res) => {
  const action = req.body.action;

  if (action === "start") {
    game.auction.active = true;
  }

  else if (action === "stop") {
    game.auction.active = false;
  }

  else if (action === "reset") {
    game.auction.active = false;
    game.auction.entries = [];
  }

  else {
    return res.status(400).json({
      error: "Action lelang tidak valid"
    });
  }

  logHistory("auction_" + action);

  res.json({
    success: true,
    auction: game.auction
  });
});

app.post("/api/admin/auction/entry", adminOnly, (req, res) => {
  if (!game.auction.active) {
    return res.status(400).json({
      error: "Lelang belum dimulai"
    });
  }

  const username = String(req.body.username || "").trim();
  const value = Number(req.body.value);

  if (!username || !Number.isFinite(value) || value < 0) {
    return res.status(400).json({
      error: "Data entry tidak valid"
    });
  }

  const entry = {
    id: crypto.randomUUID(),
    username,
    value,
    timestamp: new Date().toISOString()
  };

  game.auction.entries.push(entry);
  logHistory("auction_entry", entry);

  res.json({
    success: true,
    entry
  });
});

// =============================
// MYSTERY BOX DEMO
// =============================

app.post("/api/admin/mystery", adminOnly, (req, res) => {
  const action = req.body.action;

  if (action === "start") {
    game.mystery.active = true;
  }

  else if (action === "stop") {
    game.mystery.active = false;
  }

  else if (action === "reset") {
    game.mystery.active = false;
  }

  else {
    return res.status(400).json({
      error: "Action mystery tidak valid"
    });
  }

  logHistory("mystery_" + action);

  res.json({
    success: true,
    mystery: game.mystery
  });
});

app.post("/api/admin/mystery/reward", adminOnly, (req, res) => {
  if (!game.mystery.active) {
    return res.status(400).json({
      error: "Mystery Box belum aktif"
    });
  }

  const id = String(req.body.id || "");
  const participant = game.participants.find(p => p.id === id);

  if (!participant) {
    return res.status(404).json({
      error: "Peserta tidak ditemukan"
    });
  }

  const rewards = [1, 2, 5, 10];
  const reward = rewards[
    crypto.randomInt(0, rewards.length)
  ];

  participant.score += reward;

  logHistory("mystery_reward", {
    username: participant.username,
    reward
  });

  res.json({
    success: true,
    username: participant.username,
    reward,
    score: participant.score
  });
});

// =============================
// RELAY EVENTS
// =============================

app.post("/api/relay/events", (req, res) => {
  if (!RELAY_SECRET) {
    return res.status(503).json({
      error: "Relay belum dikonfigurasi"
    });
  }

  const secret = req.headers["x-relay-secret"] || "";

  const a = Buffer.from(String(secret));
  const b = Buffer.from(RELAY_SECRET);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({
      error: "Relay unauthorized"
    });
  }

  const username = String(req.body.username || "").trim();
  const eventId = String(req.body.eventId || "");

  if (!username || username.length > 50) {
    return res.status(400).json({
      error: "Username tidak valid"
    });
  }

  // Hindari pemrosesan ulang event yang sama.
  if (eventId && game.history.some(h => h.details.eventId === eventId)) {
    return res.json({
      success: true,
      duplicate: true
    });
  }

  const participant = {
    id: crypto.randomUUID(),
    username,
    score: 0,
    joinedAt: new Date().toISOString()
  };

  game.participants.push(participant);

  logHistory("relay_participant_added", {
    username,
    eventId
  });

  res.json({
    success: true,
    participant
  });
});

// =============================
// ERROR HANDLER
// =============================

app.use((err, req, res, next) => {
  console.error(err.message);

  res.status(500).json({
    error: "Internal server error"
  });
});

// =============================
// START
// =============================

app.listen(PORT, () => {
  console.log("ZANN ELIMINASI VIP Backend running on port " + PORT);
});
