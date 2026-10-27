// backend/api/claim-voucher.js
// SIWS claim. The player is the wallet inside the signed message.
// Body wallet/player fields are ignored. Coordinates and the location hint
// come from locations.json after a proximity check.
const {
  loadOnchainConfig,
  buildVoucherMessageV1,
  toE6,
  resolveTtlSeconds,
  clusterSecretEnvName,
  clusterKmsEnvName,
} = require("../lib/voucherV1");

const ONCHAIN = loadOnchainConfig();

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const router = require("express").Router();
const nacl = require("tweetnacl");
const rateLimit = require("express-rate-limit");
const redis = require("../lib/redis");
const { addPublicKey } = require("../lib/keys");

const CLAIM_DOMAIN = "atomicfizzcaps.xyz";
const NONCE_TTL_SECONDS = 120;
const COOLDOWN_SECONDS = Number(process.env.CLAIM_VOUCHER_COOLDOWN_SECONDS || 60);

const ipLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { ok: false, error: "Too many claim requests — slow down, Vault Dweller" },
  standardHeaders: true,
  legacyHeaders: false,
});

function loadBs58() {
  const b = require("bs58");
  if (b && typeof b.encode === "function") return b;
  if (b && b.default && typeof b.default.encode === "function") return b.default;
  throw new Error("bs58 encode/decode missing");
}
const bs58 = loadBs58();

function buildClaimAuthMessage({ wallet, lootId, nonce, issuedAt }) {
  return [
    "Atomic Fizz Caps claim voucher",
    `Domain: ${CLAIM_DOMAIN}`,
    `Wallet: ${wallet}`,
    `Loot-Id: ${lootId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

function parseClaimAuthMessage(text) {
  if (typeof text !== "string") return null;
  const lines = text.split("\n");
  if (lines.length !== 6 || lines[0] !== "Atomic Fizz Caps claim voucher") return null;
  const field = (line, prefix) => (line.startsWith(prefix) ? line.slice(prefix.length) : null);
  const domain = field(lines[1], "Domain: ");
  const wallet = field(lines[2], "Wallet: ");
  const lootId = field(lines[3], "Loot-Id: ");
  const nonce = field(lines[4], "Nonce: ");
  const issuedRaw = field(lines[5], "Issued At: ");
  if (!domain || !wallet || !lootId || !nonce || issuedRaw == null) return null;
  if (domain !== CLAIM_DOMAIN) return null;
  if (!/^\d{1,20}$/.test(lootId)) return null;
  if (!/^[0-9a-f]{32}$/.test(nonce)) return null;
  if (!/^\d{1,12}$/.test(issuedRaw)) return null;
  return { domain, wallet, lootId, nonce, issuedAt: Number(issuedRaw) };
}

function decodePubkey(wallet) {
  try {
    const bytes = Buffer.from(bs58.decode(wallet));
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

function decodeSignature(signature) {
  if (typeof signature !== "string" || signature.length > 200) return null;
  if (/^[0-9a-fA-F]{128}$/.test(signature)) return Buffer.from(signature, "hex");
  // Base64 only when the alphabet is not plain base58. Wallet clients send base58.
  if (/[+/=]/.test(signature)) {
    const b64 = Buffer.from(signature, "base64");
    return b64.length === 64 ? b64 : null;
  }
  try {
    const raw = Buffer.from(bs58.decode(signature));
    return raw.length === 64 ? raw : null;
  } catch {
    return null;
  }
}

let LOCATIONS = [];
try {
  const file = path.join(__dirname, "..", "..", "public", "data", "locations.json");
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  LOCATIONS = (Array.isArray(raw) ? raw : []).filter(
    (loc) => loc && loc.id && Number.isFinite(Number(loc.lat)) && Number.isFinite(Number(loc.lng))
  );
} catch (err) {
  console.error("[claim-voucher] failed to load locations.json:", err && err.message);
}

function haversineMeters(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function findNearbyLocation(lat, lng) {
  let best = null;
  let bestDist = Infinity;
  for (const loc of LOCATIONS) {
    const d = haversineMeters(lat, lng, Number(loc.lat), Number(loc.lng));
    const radius = typeof loc.triggerRadius === "number" ? loc.triggerRadius : 150;
    if (d <= radius && d < bestDist) {
      best = loc;
      bestDist = d;
    }
  }
  return best;
}

function locationSnapshot(loc) {
  const hint = String(loc.name || "Wasteland").replace(/[^\w\s.,!-]/g, "").trim().slice(0, 64);
  return {
    id: String(loc.id),
    lat: Number(loc.lat),
    lng: Number(loc.lng),
    hint: hint || "Wasteland",
    rarity: String(loc.rarity || "common").toLowerCase(),
    radius: typeof loc.triggerRadius === "number" ? loc.triggerRadius : 150,
  };
}

const RARITY_CAPS = {
  common: parseInt(process.env.CAPS_COMMON || "50", 10),
  uncommon: parseInt(process.env.CAPS_UNCOMMON || "100", 10),
  rare: parseInt(process.env.CAPS_RARE || "200", 10),
  epic: parseInt(process.env.CAPS_EPIC || "500", 10),
  legendary: parseInt(process.env.CAPS_LEGENDARY || "1000", 10),
};

function nonceKey(wallet) {
  return `claim-voucher:nonce:${wallet}`;
}
function cooldownKey(wallet) {
  return `claim-voucher:cooldown:${wallet}`;
}

const SECRET_ENV = ONCHAIN ? clusterSecretEnvName(ONCHAIN.cluster) : null;
const KMS_ENV = ONCHAIN ? clusterKmsEnvName(ONCHAIN.cluster) : null;
const USE_KMS = !!(KMS_ENV && process.env[KMS_ENV]);
let SERVER_KEYPAIR = null;
let SERVER_KEY_ID = null;
let KEY_INIT_ERROR = null;

async function initServerKey() {
  if (!ONCHAIN) return;
  if (USE_KMS) return;
  const secretEnv = process.env[SECRET_ENV];
  if (!secretEnv) {
    KEY_INIT_ERROR = `${SECRET_ENV} not set`;
    return;
  }
  let secret;
  try {
    secret = Buffer.from(bs58.decode(secretEnv));
  } catch (err) {
    KEY_INIT_ERROR = `${SECRET_ENV} decode failed: ${err.message}`;
    return;
  }
  if (secret.length !== 64) {
    KEY_INIT_ERROR = `${SECRET_ENV} has invalid length (${secret.length} bytes, expected 64)`;
    return;
  }
  SERVER_KEYPAIR = nacl.sign.keyPair.fromSecretKey(secret);
  SERVER_KEY_ID = bs58.encode(Buffer.from(SERVER_KEYPAIR.publicKey));
  await addPublicKey(SERVER_KEY_ID, SERVER_KEY_ID, { notes: "claim-voucher server key" }).catch((e) => {
    KEY_INIT_ERROR = `keys.addPublicKey failed: ${e.message}`;
    SERVER_KEYPAIR = null;
  });
}

const ready = initServerKey().catch((err) => {
  KEY_INIT_ERROR = err && err.message ? err.message : String(err);
});
router.ready = ready;

router.get("/nonce", ipLimiter, async (req, res) => {
  try {
    if (!ONCHAIN) return res.status(503).json({ ok: false, error: "On-chain vouchers are disabled" });
    const latitude = Number(req.query.latitude);
    const longitude = Number(req.query.longitude);
    if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90) {
      return res.status(400).json({ ok: false, error: "invalid_latitude" });
    }
    if (!Number.isFinite(longitude) || longitude < -180 || longitude > 180) {
      return res.status(400).json({ ok: false, error: "invalid_longitude" });
    }
    const wallet = typeof req.query.wallet === "string" ? req.query.wallet : "";
    if (!decodePubkey(wallet)) {
      return res.status(400).json({ ok: false, error: "invalid_wallet" });
    }
    const nearby = findNearbyLocation(latitude, longitude);
    if (!nearby) {
      return res.status(403).json({
        ok: false,
        error: "not_near_poi",
        message: "Vault Dweller, no registered Wasteland site detected at your coordinates.",
      });
    }
    const snap = locationSnapshot(nearby);
    const nonce = crypto.randomBytes(16).toString("hex");
    const lootId = String(crypto.randomInt(1, 2 ** 48));
    const record = JSON.stringify({ nonce, lootId, ...snap });
    await redis.set(nonceKey(wallet), record, { EX: NONCE_TTL_SECONDS });
    return res.json({
      ok: true,
      nonce,
      lootId,
      domain: CLAIM_DOMAIN,
      ttl: NONCE_TTL_SECONDS,
      locationId: snap.id,
    });
  } catch (err) {
    console.error("[claim-voucher] nonce error:", err && err.message);
    return res.status(500).json({ ok: false, error: "Failed to issue nonce" });
  }
});

router.post("/", ipLimiter, async (req, res) => {
  try {
    if (!ONCHAIN) return res.status(503).json({ ok: false, error: "On-chain vouchers are disabled" });
    const body = req.body || {};
    const parsed = parseClaimAuthMessage(body.message);
    if (!parsed) return res.status(400).json({ ok: false, error: "bad_claim_message" });
    const walletBytes = decodePubkey(parsed.wallet);
    const sig = decodeSignature(body.signature);
    if (!walletBytes || !sig) return res.status(400).json({ ok: false, error: "bad_signature" });

    const now = Math.floor(Date.now() / 1000);
    if (parsed.issuedAt > now + 30 || now - parsed.issuedAt > NONCE_TTL_SECONDS) {
      return res.status(401).json({ ok: false, error: "claim_message_expired" });
    }
    const ok = nacl.sign.detached.verify(Buffer.from(body.message, "utf8"), sig, walletBytes);
    if (!ok) return res.status(401).json({ ok: false, error: "bad_signature" });

    // Wallet in the body is ignored. The signer is the wallet inside the message.
    const stored = await redis.getdel(nonceKey(parsed.wallet));
    if (!stored) return res.status(401).json({ ok: false, error: "nonce_expired" });
    let record;
    try {
      record = JSON.parse(stored);
    } catch {
      return res.status(401).json({ ok: false, error: "nonce_expired" });
    }
    if (!record || record.nonce !== parsed.nonce || String(record.lootId) !== parsed.lootId) {
      return res.status(401).json({ ok: false, error: "nonce_mismatch" });
    }

    const latitude = Number(body.latitude);
    const longitude = Number(body.longitude);
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
      return res.status(400).json({ ok: false, error: "invalid_coordinates" });
    }
    const dist = haversineMeters(latitude, longitude, record.lat, record.lng);
    if (dist > record.radius) {
      return res.status(403).json({ ok: false, error: "not_near_poi" });
    }

    const lock = await redis.set(cooldownKey(parsed.wallet), "1", { NX: true, EX: COOLDOWN_SECONDS });
    if (lock !== "OK") {
      return res.status(429).json({ ok: false, error: "claim_cooldown" });
    }

    const capsReward = RARITY_CAPS[record.rarity] || RARITY_CAPS.common;
    const voucherId = crypto.randomBytes(16).toString("hex");
    const issuedAt = now;
    let ttlSeconds;
    try {
      ttlSeconds = resolveTtlSeconds();
    } catch {
      return res.status(500).json({ ok: false, error: "Voucher TTL misconfigured" });
    }
    const expiresAt = issuedAt + ttlSeconds;
    const latE6 = toE6(record.lat);
    const lngE6 = toE6(record.lng);
    const locationHint = record.hint;
    const lootId = String(record.lootId);

    const voucher = {
      v: 2,
      voucherId,
      keyId: SERVER_KEY_ID || "kms",
      lootId,
      caps: capsReward,
      latE6,
      lngE6,
      locationHint,
      issuedAt,
      expiresAt,
      player: parsed.wallet,
    };

    const message = buildVoucherMessageV1({
      cluster: ONCHAIN.cluster,
      programId: ONCHAIN.programId,
      player: parsed.wallet,
      voucherId,
      lootId,
      latE6,
      lngE6,
      locationHint,
      issuedAt,
      expiresAt,
    });

    let signatureBytes;
    let serverPubkey = SERVER_KEY_ID;
    if (USE_KMS) {
      if (KEY_INIT_ERROR) {
        return res.status(503).json({ error: "Voucher signing service unavailable" });
      }
      const { signMessageWithKms, getPublicKeyFromKms } = require("../lib/kmsSigner");
      const { signatureBytes: sigBuf } = await signMessageWithKms(message, process.env[KMS_ENV]);
      signatureBytes = sigBuf;
      const pub = await getPublicKeyFromKms(process.env[KMS_ENV]);
      serverPubkey = pub.publicKeyBase58;
    } else {
      if (!SERVER_KEYPAIR) {
        return res.status(503).json({
          error: "Voucher signing service unavailable",
          reason: process.env.NODE_ENV === "development" ? KEY_INIT_ERROR : undefined,
        });
      }
      signatureBytes = Buffer.from(nacl.sign.detached(message, SERVER_KEYPAIR.secretKey));
    }
    if (!signatureBytes || signatureBytes.length !== 64) {
      return res.status(500).json({ error: "Failed to generate voucher" });
    }

    return res.json({
      ok: true,
      voucher,
      signature: signatureBytes.toString("base64"),
      serverPubkey,
      programId: ONCHAIN.programId,
      cluster: ONCHAIN.cluster,
    });
  } catch (err) {
    console.error("[claim-voucher] error:", err && err.message ? err.message : err);
    return res.status(500).json({ error: "Failed to generate voucher" });
  }
});

module.exports = router;
module.exports.buildClaimAuthMessage = buildClaimAuthMessage;
module.exports.CLAIM_DOMAIN = CLAIM_DOMAIN;
module.exports.NONCE_TTL_SECONDS = NONCE_TTL_SECONDS;
