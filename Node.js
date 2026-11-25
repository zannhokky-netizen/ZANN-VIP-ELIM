
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");

const app = express();
app.use(express.json({limit:"1mb"}));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_THIS_ADMIN_PASSWORD";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_LONG_RANDOM_SECRET";
const PORT = process.env.PORT || 3000;
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "").split(",").map(x=>x.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin || !CORS_ORIGINS.length || CORS_ORIGINS.includes(origin)) return cb(null,true);
    return cb(new Error("Origin not allowed"));
  }
}));

const DB_FILE = process.env.DB_FILE || "./data.json";

function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE,"utf8"));
  } catch {
    return {keys:[], users:[], history:[], auction:{active:false,entries:[]}};
  }
}

let db = loadDB();

function saveDB() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db,null,2));
  fs.renameSync(tmp,DB_FILE);
}

function history(action, details={}) {
  db.history.unshift({action,details,at:new Date().toISOString()});
  db.history = db.history.slice(0,300);
}

function makeToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256",JWT_SECRET).update(data).digest("base64url");
  return data+"."+sig;
}

function verifyToken(token) {
  if (!token || typeof token!=="string") return null;
  const parts=token.split(".");
  if(parts.length!==2)return null;

  const [data,sig]=parts;
  const expected=crypto.createHmac("sha256",JWT_SECRET).update(data).digest("base64url");
  const a=Buffer.from(sig), b=Buffer.from(expected);

  if(a.length!==b.length || !crypto.timingSafeEqual(a,b))return null;

  try {
    const p=JSON.parse(Buffer.from(data,"base64url").toString());
    if(!p.exp || p.exp<Date.now())return null;
    return p;
  }catch{return null;}
}

function bearer(req) {
  const h=req.headers.authorization||"";
  return h.startsWith("Bearer ")?h.slice(7):"";
}

function adminOnly(req,res,next) {
  const p=verifyToken(bearer(req));
  if(!p||p.role!=="admin")return res.status(403).json({error:"Admin access required"});
  req.auth=p;
  next();
}

function userOnly(req,res,next) {
  const p=verifyToken(bearer(req));

  if(!p||p.role!=="user"||!p.keyId)
    return res.status(401).json({error:"KEY access required"});

  const k=db.keys.find(x=>x.id===p.keyId);

  if(!k||k.revoked||!k.redeemedAt||(!k.permanent && k.expiresAt<=Date.now()))
    return res.status(401).json({error:"KEY expired or revoked"});

  req.auth=p;
  req.key=k;
  next();
}

function newKeyString() {
  return [4,4,4,4].map(()=>crypto.randomBytes(3).toString("hex").toUpperCase()).join("-");
}

function durationFor(days) {
  return days===0?null:days*24*60*60*1000;
}

app.get("/",(req,res)=>res.json({
  name:"ZANN ELIMINASI VIP KEY SYSTEM",
  status:"online"
}));

app.get("/api/status",(req,res)=>res.json({online:true}));

// ADMIN LOGIN
app.post("/api/admin/login",(req,res)=>{
  if(String(req.body.password||"")!==ADMIN_PASSWORD)
    return res.status(401).json({error:"Password salah"});

  res.json({
    token:makeToken({role:"admin",exp:Date.now()+8*60*60*1000}),
    expiresIn:28800
  });
});

// ADMIN CREATE KEY
// durationDays: 3, 7, 30 atau 0 (permanen)
app.post("/api/admin/keys/create",adminOnly,(req,res)=>{
  const days=Number(req.body.durationDays);

  if(![3,7,30,0].includes(days))
    return res.status(400).json({error:"Pilih 3, 7, 30 hari atau 0 untuk permanen"});

  let code=newKeyString();
  while(db.keys.some(k=>k.code===code))code=newKeyString();

  const key={
    id:crypto.randomUUID(),
    code,
    durationDays:days,
    permanent:days===0,
    createdAt:Date.now(),
    redeemedAt:null,
    expiresAt:null,
    revoked:false
  };

  db.keys.push(key);
  history("key_created",{durationDays:days});
  saveDB();

  res.json({
    success:true,
    key:{
      code,
      durationDays:days,
      permanent:key.permanent
    }
  });
});

// ADMIN LIST KEYS
app.get("/api/admin/keys",adminOnly,(req,res)=>{
  res.json(db.keys.map(k=>({
    id:k.id,
    code:k.code,
    durationDays:k.durationDays,
    permanent:k.permanent,
    createdAt:k.createdAt,
    redeemedAt:k.redeemedAt,
    expiresAt:k.expiresAt,
    revoked:k.revoked
  })));
});

// ADMIN REVOKE KEY
app.post("/api/admin/keys/revoke",adminOnly,(req,res)=>{
  const k=db.keys.find(x=>x.id===req.body.id);

  if(!k)return res.status(404).json({error:"KEY tidak ditemukan"});

  k.revoked=true;
  history("key_revoked",{id:k.id});
  saveDB();

  res.json({success:true});
});

// USER REDEEM KEY
// Masa berlaku dimulai ketika KEY pertama kali digunakan.
app.post("/api/keys/redeem",(req,res)=>{
  const code=String(req.body.code||"").trim().toUpperCase();
  const k=db.keys.find(x=>x.code===code);

  if(!k)return res.status(400).json({error:"KEY tidak valid"});
  if(k.revoked)return res.status(400).json({error:"KEY telah dicabut"});
  if(k.redeemedAt)return res.status(400).json({error:"KEY sudah digunakan"});

  k.redeemedAt=Date.now();
  k.expiresAt=k.permanent?null:k.redeemedAt+durationFor(k.durationDays);

  const token=makeToken({
    role:"user",
    keyId:k.id,
    exp:k.permanent?Date.now()+30*24*60*60*1000:k.expiresAt
  });

  history("key_redeemed",{id:k.id});
  saveDB();

  res.json({
    success:true,
    token,
    permanent:k.permanent,
    expiresAt:k.expiresAt
  });
});

// VALIDATE USER SESSION
app.get("/api/user/session",userOnly,(req,res)=>{
  if(req.key.permanent){
    const token=makeToken({
      role:"user",
      keyId:req.key.id,
      exp:Date.now()+30*24*60*60*1000
    });

    return res.json({
      valid:true,
      permanent:true,
      expiresAt:null,
      token
    });
  }

  res.json({
    valid:true,
    permanent:false,
    expiresAt:req.key.expiresAt
  });
});

// PROTECTED AUCTION
app.get("/api/user/auction",userOnly,(req,res)=>{
  res.json(db.auction);
});

app.post("/api/user/auction/entry",userOnly,(req,res)=>{
  if(!db.auction.active)
    return res.status(400).json({error:"Lelang belum aktif"});

  const username=String(req.body.username||"").trim();
  const entry=String(req.body.entry||"").trim();

  if(!username||!entry||username.length>50||entry.length>100)
    return res.status(400).json({error:"Input tidak valid"});

  const item={
    id:crypto.randomUUID(),
    username,
    entry,
    at:new Date().toISOString()
  };

  db.auction.entries.push(item);
  history("auction_entry",{username});
  saveDB();

  res.json({success:true,item});
});

// ADMIN AUCTION CONTROL
app.post("/api/admin/auction",adminOnly,(req,res)=>{
  const action=req.body.action;

  if(action==="start")db.auction.active=true;
  else if(action==="stop")db.auction.active=false;
  else if(action==="reset"){
    db.auction.active=false;
    db.auction.entries=[];
  }
  else return res.status(400).json({error:"Action tidak valid"});

  history("auction_"+action);
  saveDB();

  res.json({success:true,auction:db.auction});
});

// ADMIN HISTORY
app.get("/api/admin/history",adminOnly,(req,res)=>{
  res.json(db.history);
});

app.use((err,req,res,next)=>{
  console.error(err);
  res.status(500).json({error:"Internal server error"});
});

app.listen(PORT,()=>console.log("ZANN ELIMINASI VIP backend port "+PORT));
