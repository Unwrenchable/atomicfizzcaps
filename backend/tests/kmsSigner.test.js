"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  signMessageWithKms,
  assertEd25519Algorithm,
  ed25519RawPubkeyFromSpki,
  ED25519_ALG,
} = require("../lib/kmsSigner");

test("mocked KMS client signs with ED25519_SHA_512 and RAW", async () => {
  const prev = process.env.KMS_SIGNING_ALGORITHM;
  delete process.env.KMS_SIGNING_ALGORITHM;
  const seen = [];
  try {
    const message = Buffer.from("not-logged");
    const out = await signMessageWithKms(message, "alias/fizz-devnet", {
      send: async (input) => {
        seen.push(input);
        return { Signature: Buffer.alloc(64, 4) };
      },
    });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].SigningAlgorithm, ED25519_ALG);
    assert.equal(seen[0].MessageType, "RAW");
    assert.equal(seen[0].KeyId, "alias/fizz-devnet");
    assert.equal(seen[0].Message.equals(message), true);
    assert.equal(out.signatureBytes.length, 64);
  } finally {
    if (prev == null) delete process.env.KMS_SIGNING_ALGORITHM;
    else process.env.KMS_SIGNING_ALGORITHM = prev;
  }
});

test("non-Ed25519 KMS algorithm is rejected when on-chain vouchers are enabled", () => {
  const prev = process.env.KMS_SIGNING_ALGORITHM;
  try {
    process.env.KMS_SIGNING_ALGORITHM = "ECDSA_SHA_256";
    assert.throws(() => assertEd25519Algorithm(), /ED25519_SHA_512/);
  } finally {
    if (prev == null) delete process.env.KMS_SIGNING_ALGORITHM;
    else process.env.KMS_SIGNING_ALGORITHM = prev;
  }
});

test("Ed25519 SPKI public key is the last 32 bytes", () => {
  const raw = Buffer.alloc(32, 7);
  raw[0] = 0x11;
  raw[31] = 0x22;
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const got = ed25519RawPubkeyFromSpki(der);
  assert.equal(got.length, 32);
  assert.equal(got.equals(raw), true);
});
