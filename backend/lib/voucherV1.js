"use strict";

/**
 * LootVoucherV1 binary message. This is the only message the on-chain
 * `claim_loot` instruction will accept. Do not use it for the off-chain
 * redeem path (that path uses the pipe format in gps.js).
 *
 * Layout is 169 bytes, little-endian. See programs/fizzcaps-onchain/src/voucher.rs.
 */

const crypto = require("crypto");

const DOMAIN = Buffer.from("FIZZCAPS:LOOT_VOUCHER:v1", "ascii"); // 24 bytes
const VOUCHER_MSG_LEN = 169;
const MAX_VOUCHER_TTL_SECONDS = 300;
const CLUSTER_TAG = { "mainnet-beta": 1, devnet: 2, localnet: 3 };

// This duplicate's declare_id is different on every cluster. The canonical
// program in ATOMIC-FIZZ-CAPS-VAULT-77-WASTELAND-GPS uses its own ids.
// Devnet and mainnet values are placeholders. Travis replaces them after
// generating deploy keypairs offline. No keypair for these ids is in the repo.
const EXPECTED_PROGRAM_ID = {
  localnet: "3mPuzEmF6YrMP3Lfn4qm9TY2tSKsanJDhsr6ZkSbSURP",
  devnet: "CRF3R219WJGS4WM41jZuER3X9rPJ3Ac6JMG38t2zzSfV",
  "mainnet-beta": "8pKQTv64QZw2F4qjpm1unPSVJj1WsYYQiTCspeS4XTFY",
};

const CLUSTER_SECRET_ENV = {
  localnet: "SERVER_SECRET_KEY_LOCALNET",
  devnet: "SERVER_SECRET_KEY_DEVNET",
  "mainnet-beta": "SERVER_SECRET_KEY_MAINNET",
};

const CLUSTER_KMS_ENV = {
  localnet: "KMS_SIGNING_KEY_ID_LOCALNET",
  devnet: "KMS_SIGNING_KEY_ID_DEVNET",
  "mainnet-beta": "KMS_SIGNING_KEY_ID_MAINNET",
};

function clusterSecretEnvName(cluster) {
  const name = CLUSTER_SECRET_ENV[cluster];
  if (!name) throw new Error("unknown cluster");
  return name;
}

function clusterKmsEnvName(cluster) {
  const name = CLUSTER_KMS_ENV[cluster];
  if (!name) throw new Error("unknown cluster");
  return name;
}

/**
 * Fail fast when the on-chain voucher env is missing or does not match
 * this program's declare_id. Set ONCHAIN_VOUCHERS=false to boot the rest
 * of the server without the voucher route.
 */
function loadOnchainConfig() {
  if (process.env.ONCHAIN_VOUCHERS === "false") return null;
  const cluster = process.env.SOLANA_CLUSTER;
  const programId = process.env.FIZZCAPS_PROGRAM_ID;
  if (!cluster || !CLUSTER_TAG[cluster]) {
    const err = new Error(
      "SOLANA_CLUSTER must be localnet, devnet, or mainnet-beta"
    );
    err.code = "ONCHAIN_CONFIG";
    throw err;
  }
  if (!programId) {
    const err = new Error("FIZZCAPS_PROGRAM_ID is required");
    err.code = "ONCHAIN_CONFIG";
    throw err;
  }
  if (programId !== EXPECTED_PROGRAM_ID[cluster]) {
    const err = new Error(
      `FIZZCAPS_PROGRAM_ID does not match the ${cluster} declare_id`
    );
    err.code = "ONCHAIN_CONFIG";
    throw err;
  }
  return { cluster, programId, clusterTag: CLUSTER_TAG[cluster] };
}

/** Degrees to microdegrees, half away from zero. */
function toE6(deg) {
  if (typeof deg !== "number" || !Number.isFinite(deg)) {
    throw new Error("degrees must be a finite number");
  }
  const scaled = deg * 1e6;
  const sign = scaled < 0 ? -1 : 1;
  return sign * Math.round(Math.abs(scaled));
}

function resolveTtlSeconds(explicit) {
  const raw =
    explicit != null
      ? explicit
      : process.env.VOUCHER_TTL_SECONDS == null || process.env.VOUCHER_TTL_SECONDS === ""
        ? MAX_VOUCHER_TTL_SECONDS
        : Number(process.env.VOUCHER_TTL_SECONDS);
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error("VOUCHER_TTL_SECONDS must be a positive number");
  }
  return Math.min(Math.floor(parsed), MAX_VOUCHER_TTL_SECONDS);
}

function w64(v, signed) {
  const b = Buffer.alloc(8);
  const n = BigInt(v);
  if (signed) b.writeBigInt64LE(n);
  else b.writeBigUInt64LE(n);
  return b;
}

function w32(v) {
  const b = Buffer.alloc(4);
  b.writeInt32LE(v);
  return b;
}

function buildVoucherMessageV1({
  cluster,
  programId,
  player,
  voucherId,
  lootId,
  latE6,
  lngE6,
  locationHint,
  issuedAt,
  expiresAt,
}) {
  const tag = CLUSTER_TAG[cluster];
  if (!tag) throw new Error("unknown cluster");
  if (typeof locationHint !== "string" || Buffer.byteLength(locationHint, "utf8") > 64) {
    throw new Error("locationHint");
  }
  const { PublicKey } = require("@solana/web3.js");
  const buf = Buffer.alloc(VOUCHER_MSG_LEN);
  let o = 0;
  const put = (b) => {
    b.copy(buf, o);
    o += b.length;
  };
  put(DOMAIN);
  put(Buffer.from([tag]));
  put(Buffer.from(new PublicKey(programId).toBytes()));
  put(Buffer.from(new PublicKey(player).toBytes()));
  const vid = Buffer.from(voucherId, "hex");
  if (vid.length !== 16) throw new Error("voucherId");
  put(vid);
  put(w64(lootId, false));
  put(w32(latE6));
  put(w32(lngE6));
  put(crypto.createHash("sha256").update(Buffer.from(locationHint, "utf8")).digest());
  put(w64(issuedAt, true));
  put(w64(expiresAt, true));
  if (o !== VOUCHER_MSG_LEN) throw new Error("layout drift");
  return buf;
}

module.exports = {
  DOMAIN,
  VOUCHER_MSG_LEN,
  MAX_VOUCHER_TTL_SECONDS,
  CLUSTER_TAG,
  EXPECTED_PROGRAM_ID,
  CLUSTER_SECRET_ENV,
  CLUSTER_KMS_ENV,
  clusterSecretEnvName,
  clusterKmsEnvName,
  loadOnchainConfig,
  toE6,
  resolveTtlSeconds,
  buildVoucherMessageV1,
};
