// backend/lib/kmsSigner.js
const { encode: bs58encode } = require("./safe-base58");

const REGION = process.env.AWS_REGION || "us-west-2";
// On-chain vouchers require raw Ed25519. ECDSA_SHA_256 cannot be verified
// by the Solana Ed25519 precompile.
const ED25519_ALG = "ED25519_SHA_512";
const DEFAULT_SIGNING_ALG = process.env.KMS_SIGNING_ALGORITHM || ED25519_ALG;
const KMS_KEY_ID = process.env.KMS_SIGNING_KEY_ID || null;

function assertEd25519Algorithm() {
  const alg = process.env.KMS_SIGNING_ALGORITHM || ED25519_ALG;
  if (alg !== ED25519_ALG) {
    const err = new Error(
      "KMS_SIGNING_ALGORITHM must be ED25519_SHA_512 for on-chain vouchers"
    );
    err.code = "KMS_ALG";
    throw err;
  }
  return alg;
}

/** Last 32 bytes of an Ed25519 SPKI DER blob are the raw public key. */
function ed25519RawPubkeyFromSpki(der) {
  const buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  if (buf.length < 32) throw new Error("SPKI DER too short for an Ed25519 key");
  return buf.subarray(buf.length - 32);
}

if (!KMS_KEY_ID) {
  console.warn("[kmsSigner] KMS_SIGNING_KEY_ID not set. KMS signing disabled. Using local signing instead (FREE). See docs/LOCAL_SIGNING_SETUP.md");
}

let client = null;
function getClient() {
  if (client) return client;
  const { KMSClient } = require("@aws-sdk/client-kms");
  client = new KMSClient({ region: REGION, maxAttempts: 3 });
  return client;
}

async function retry(fn, attempts = 3, delayMs = 200) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, delayMs * (i + 1)));
    }
  }
  throw lastErr;
}

/**
 * signMessageWithKms
 * - messageBuffer: Buffer
 * - keyId: optional KMS key id/arn; falls back to KMS_KEY_ID
 * Returns: { keyIdUsed, signatureBase58, signatureBytes: Buffer }
 */
async function signMessageWithKms(messageBuffer, keyId = null, deps = null) {
  if (!messageBuffer || !Buffer.isBuffer(messageBuffer)) {
    throw new Error("messageBuffer must be a Buffer");
  }
  const useKey = keyId || KMS_KEY_ID;
  if (!useKey) throw new Error("No KMS key configured (KMS_SIGNING_KEY_ID missing)");

  const signingAlg = assertEd25519Algorithm();
  // MessageType RAW: do not hash the voucher before signing. The precompile
  // verifies the raw 169-byte message. Do not log message or signature bytes.
  const input = {
    KeyId: useKey,
    Message: messageBuffer,
    MessageType: "RAW",
    SigningAlgorithm: signingAlg,
  };

  const res = await retry(async () => {
    if (deps && typeof deps.send === "function") return deps.send(input);
    const { SignCommand } = require("@aws-sdk/client-kms");
    return getClient().send(new SignCommand(input));
  }, 3, deps && deps.send ? 0 : 250);
  if (!res || !res.Signature) throw new Error("KMS did not return a signature");

  const sigBytes = Buffer.from(res.Signature);
  const signatureBase58 = bs58encode(sigBytes);

  return { keyIdUsed: useKey, signatureBase58, signatureBytes: sigBytes };
}

/**
 * getPublicKeyFromKms
 * - keyId: KMS key id or ARN
 * Returns: { keyId, publicKeyBase58 (SPKI DER), algorithm }
 */
async function getPublicKeyFromKms(keyId) {
  if (!keyId) throw new Error("keyId required");
  const { GetPublicKeyCommand } = require("@aws-sdk/client-kms");
  const cmd = new GetPublicKeyCommand({ KeyId: keyId });
  const res = await retry(() => getClient().send(cmd), 3, 250);
  if (!res || !res.PublicKey) throw new Error("KMS did not return public key");
  const pubDer = Buffer.from(res.PublicKey); // SPKI DER
  const raw = ed25519RawPubkeyFromSpki(pubDer);
  const publicKeyBase58 = bs58encode(raw);
  const algorithm = res.SigningAlgorithms ? res.SigningAlgorithms.join(",") : null;
  return { keyId, publicKeyBase58, publicKeyDerBase58: bs58encode(pubDer), algorithm };
}

module.exports = {
  signMessageWithKms,
  getPublicKeyFromKms,
  assertEd25519Algorithm,
  ed25519RawPubkeyFromSpki,
  ED25519_ALG,
  DEFAULT_SIGNING_ALG,
};
