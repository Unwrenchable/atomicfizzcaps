"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const nacl = require("tweetnacl");
const { PublicKey, Ed25519Program } = require("@solana/web3.js");
const {
  buildVoucherMessageV1,
  toE6,
  resolveTtlSeconds,
  loadOnchainConfig,
  VOUCHER_MSG_LEN,
  MAX_VOUCHER_TTL_SECONDS,
  EXPECTED_PROGRAM_ID,
} = require("../lib/voucherV1");

const FIX = path.join(__dirname, "..", "..", "anchor-tests", "fixtures");
const golden = JSON.parse(fs.readFileSync(path.join(FIX, "voucher_v1_golden.json"), "utf8"));
const edFixture = JSON.parse(fs.readFileSync(path.join(FIX, "ed25519_ix_v1.json"), "utf8"));

function goldenInputs(overrides = {}) {
  return {
    cluster: golden.cluster,
    programId: golden.programId,
    player: golden.player,
    voucherId: golden.voucherIdHex,
    lootId: golden.lootId,
    latE6: golden.latE6,
    lngE6: golden.lngE6,
    locationHint: golden.locationHint,
    issuedAt: golden.issuedAt,
    expiresAt: golden.expiresAt,
    ...overrides,
  };
}

test("golden message matches the Rust fixture and is 169 bytes", () => {
  const msg = buildVoucherMessageV1(goldenInputs());
  assert.equal(msg.length, VOUCHER_MSG_LEN);
  assert.equal(VOUCHER_MSG_LEN, 169);
  assert.equal(msg.toString("hex"), golden.messageHex);
});

test("round trip: tweetnacl sign and verify the V1 message", () => {
  const kp = nacl.sign.keyPair();
  const player = new PublicKey(kp.publicKey).toBase58();
  const msg = buildVoucherMessageV1(goldenInputs({ player }));
  const sig = nacl.sign.detached(msg, kp.secretKey);
  assert.equal(sig.length, 64);
  assert.equal(nacl.sign.detached.verify(msg, sig, kp.publicKey), true);
  const tampered = Buffer.from(msg);
  tampered[tampered.length - 1] ^= 0xff;
  assert.equal(nacl.sign.detached.verify(tampered, sig, kp.publicKey), false);
});

test("toE6 rounds half away from zero", () => {
  assert.equal(toE6(37.77493), 37774930);
  assert.equal(toE6(-122.4194), -122419400);
  assert.equal(toE6(1.5 / 1e6), 2);
  assert.equal(toE6(-1.5 / 1e6), -2);
});

test("TTL defaults to 300s and never exceeds 300s", () => {
  const prev = process.env.VOUCHER_TTL_SECONDS;
  try {
    delete process.env.VOUCHER_TTL_SECONDS;
    assert.equal(resolveTtlSeconds(), MAX_VOUCHER_TTL_SECONDS);
    assert.equal(MAX_VOUCHER_TTL_SECONDS, 300);
    process.env.VOUCHER_TTL_SECONDS = "900";
    assert.equal(resolveTtlSeconds(), 300);
    process.env.VOUCHER_TTL_SECONDS = "60";
    assert.equal(resolveTtlSeconds(), 60);
  } finally {
    if (prev == null) delete process.env.VOUCHER_TTL_SECONDS;
    else process.env.VOUCHER_TTL_SECONDS = prev;
  }
});

test("Ed25519 web3.js layout: pubkey offset is 16, not the signature offset at byte 2", () => {
  const msg = Buffer.from(golden.messageHex, "hex");
  const ix = Ed25519Program.createInstructionWithPublicKey({
    publicKey: Buffer.alloc(32, 0xab),
    signature: Buffer.alloc(64, 0xcd),
    message: msg,
  });
  const data = Buffer.from(ix.data);
  assert.equal(data.toString("hex"), edFixture.dataHex);
  assert.equal(data.readUInt16LE(2), 48);
  assert.equal(data.readUInt16LE(6), 16);
  assert.equal(data.readUInt16LE(12), 169);
  assert.equal(data.length, 16 + 32 + 64 + 169);
});

test("expected program ids match Anchor.toml", () => {
  const anchor = fs.readFileSync(path.join(__dirname, "..", "..", "Anchor.toml"), "utf8");
  for (const [cluster, id] of Object.entries(EXPECTED_PROGRAM_ID)) {
    const section = cluster === "mainnet-beta" ? "mainnet" : cluster;
    const re = new RegExp(`\\[programs\\.${section}\\][\\s\\S]*?fizzcaps_onchain\\s*=\\s*"([^"]+)"`);
    const m = anchor.match(re);
    assert.ok(m, `missing [programs.${section}]`);
    assert.equal(m[1], id);
  }
});

test("missing SOLANA_CLUSTER or FIZZCAPS_PROGRAM_ID refuses to start", () => {
  const backend = path.join(__dirname, "..");
  const env = { PATH: process.env.PATH };
  for (const expr of [
    "require('./lib/voucherV1').loadOnchainConfig()",
    "require('./api/claim-voucher')",
  ]) {
    const r = spawnSync(process.execPath, ["-e", expr], { cwd: backend, env, encoding: "utf8" });
    assert.notEqual(r.status, 0, expr);
    assert.match(r.stderr, /SOLANA_CLUSTER/);
  }
});

test("mismatched FIZZCAPS_PROGRAM_ID refuses to start", () => {
  const prevC = process.env.SOLANA_CLUSTER;
  const prevP = process.env.FIZZCAPS_PROGRAM_ID;
  const prevO = process.env.ONCHAIN_VOUCHERS;
  try {
    delete process.env.ONCHAIN_VOUCHERS;
    process.env.SOLANA_CLUSTER = "devnet";
    process.env.FIZZCAPS_PROGRAM_ID = "11111111111111111111111111111111";
    assert.throws(() => loadOnchainConfig(), /declare_id/);
  } finally {
    if (prevC == null) delete process.env.SOLANA_CLUSTER;
    else process.env.SOLANA_CLUSTER = prevC;
    if (prevP == null) delete process.env.FIZZCAPS_PROGRAM_ID;
    else process.env.FIZZCAPS_PROGRAM_ID = prevP;
    if (prevO == null) delete process.env.ONCHAIN_VOUCHERS;
    else process.env.ONCHAIN_VOUCHERS = prevO;
  }
});

test("sha256 of the hint is what the message commits to", () => {
  const msg = buildVoucherMessageV1(goldenInputs());
  const hintHash = crypto.createHash("sha256").update(Buffer.from(golden.locationHint, "utf8")).digest();
  assert.equal(msg.subarray(121, 153).equals(hintHash), true);
});
