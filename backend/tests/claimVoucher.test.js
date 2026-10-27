"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const nacl = require("tweetnacl");
const { Keypair } = require("@solana/web3.js");
const { encode } = require("../lib/safe-base58");
const { toE6, buildVoucherMessageV1 } = require("../lib/voucherV1");

const serverKp = nacl.sign.keyPair();
process.env.SOLANA_CLUSTER = "localnet";
process.env.FIZZCAPS_PROGRAM_ID = "3mPuzEmF6YrMP3Lfn4qm9TY2tSKsanJDhsr6ZkSbSURP";
process.env.SERVER_SECRET_KEY_LOCALNET = encode(Buffer.from(serverKp.secretKey));
process.env.VOUCHER_TTL_SECONDS = "900";
process.env.CLAIM_VOUCHER_COOLDOWN_SECONDS = "60";
delete process.env.KMS_SIGNING_KEY_ID_LOCALNET;
delete process.env.ONCHAIN_VOUCHERS;
delete process.env.REDIS_URL;

const express = require("express");
const claimRouter = require("../api/claim-voucher");
const { buildClaimAuthMessage } = require("../api/claim-voucher");
const retired = require("../api/loot-voucher");

const SITE = { latitude: 16.365019, longitude: -90.892145 };

async function withServer(router, fn) {
  if (router.ready) await router.ready;
  const app = express();
  app.use(express.json());
  app.use(router);
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const port = server.address().port;
  try {
    await fn(port);
  } finally {
    if (typeof server.closeIdleConnections === "function") server.closeIdleConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

async function request(port, method, path, body) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

function signClaim(walletKp, lootId, nonce, issuedAt) {
  const wallet = encode(Buffer.from(walletKp.publicKey));
  const message = buildClaimAuthMessage({ wallet, lootId, nonce, issuedAt });
  const sig = nacl.sign.detached(Buffer.from(message, "utf8"), walletKp.secretKey);
  return { wallet, message, signature: Buffer.from(sig).toString("base64") };
}

test("retired loot-voucher route does not sign", async () => {
  await withServer(retired, async (port) => {
    const res = await request(port, "POST", "/", { player: "nope" });
    assert.equal(res.status, 410);
    assert.equal(res.json.location, "/api/claim-voucher");
  });
});

test("claim voucher is SIWS-bound, ignores body wallet, uses locations.json", async () => {
  const player = nacl.sign.keyPair();
  const imposter = Keypair.generate().publicKey.toBase58();
  await withServer(claimRouter, async (port) => {
    const qs = new URLSearchParams({
      wallet: encode(Buffer.from(player.publicKey)),
      latitude: String(SITE.latitude + 0.0004),
      longitude: String(SITE.longitude),
    });
    const nonceRes = await request(port, "GET", `/nonce?${qs}`);
    assert.equal(nonceRes.status, 200, JSON.stringify(nonceRes.json));
    const issuedAt = Math.floor(Date.now() / 1000);
    const signed = signClaim(player, nonceRes.json.lootId, nonceRes.json.nonce, issuedAt);
    const res = await request(port, "POST", "/", {
      message: signed.message,
      signature: signed.signature,
      wallet: imposter,
      player: imposter,
      locationHint: "client-supplied hint",
      latitude: SITE.latitude + 0.0004,
      longitude: SITE.longitude,
      lootId: "1",
    });
    assert.equal(res.status, 200, JSON.stringify(res.json));
    const { voucher, signature, serverPubkey, programId } = res.json;
    assert.equal(voucher.player, signed.wallet);
    assert.notEqual(voucher.player, imposter);
    assert.equal(voucher.lootId, nonceRes.json.lootId);
    assert.notEqual(voucher.lootId, "1");
    assert.equal(voucher.locationHint, "The Dimming Expanse");
    assert.equal(voucher.latE6, toE6(SITE.latitude));
    assert.equal(voucher.lngE6, toE6(SITE.longitude));
    assert.ok(voucher.expiresAt - voucher.issuedAt <= 300);
    assert.match(voucher.voucherId, /^[0-9a-f]{32}$/);
    assert.equal(programId, process.env.FIZZCAPS_PROGRAM_ID);
    assert.equal(serverPubkey, encode(Buffer.from(serverKp.publicKey)));
    const sig = Buffer.from(signature, "base64");
    const message = buildVoucherMessageV1({
      cluster: "localnet",
      programId,
      player: signed.wallet,
      voucherId: voucher.voucherId,
      lootId: voucher.lootId,
      latE6: voucher.latE6,
      lngE6: voucher.lngE6,
      locationHint: voucher.locationHint,
      issuedAt: voucher.issuedAt,
      expiresAt: voucher.expiresAt,
    });
    assert.equal(message.length, 169);
    assert.equal(nacl.sign.detached.verify(message, sig, serverKp.publicKey), true);

    const replay = await request(port, "POST", "/", {
      message: signed.message,
      signature: signed.signature,
      latitude: SITE.latitude,
      longitude: SITE.longitude,
    });
    assert.equal(replay.status, 401);

    const againNonce = await request(port, "GET", `/nonce?${qs}`);
    assert.equal(againNonce.status, 200);
    const againSigned = signClaim(
      player,
      againNonce.json.lootId,
      againNonce.json.nonce,
      issuedAt
    );
    const cooled = await request(port, "POST", "/", {
      message: againSigned.message,
      signature: againSigned.signature,
      latitude: SITE.latitude,
      longitude: SITE.longitude,
    });
    assert.equal(cooled.status, 429);
  });
});

test("far from every location is rejected", async () => {
  const player = nacl.sign.keyPair();
  await withServer(claimRouter, async (port) => {
    const qs = new URLSearchParams({
      wallet: encode(Buffer.from(player.publicKey)),
      latitude: "0",
      longitude: "0",
    });
    const res = await request(port, "GET", `/nonce?${qs}`);
    assert.equal(res.status, 403);
    assert.equal(res.json.error, "not_near_poi");
  });
});
