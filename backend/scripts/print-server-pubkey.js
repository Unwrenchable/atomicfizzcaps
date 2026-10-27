#!/usr/bin/env node
"use strict";

/**
 * Print the raw Ed25519 public key (base58) for fizz_set_server_key.
 * Usage: node backend/scripts/print-server-pubkey.js <kms-key-id-or-arn>
 *    or: KMS_SIGNING_KEY_ID=... node backend/scripts/print-server-pubkey.js
 *
 * Does not print message bytes or signatures.
 */

const { getPublicKeyFromKms } = require("../lib/kmsSigner");

const keyId = process.argv[2] || process.env.KMS_SIGNING_KEY_ID;
if (!keyId) {
  console.error("Pass a KMS key id, or set KMS_SIGNING_KEY_ID.");
  process.exit(1);
}

getPublicKeyFromKms(keyId)
  .then((res) => {
    console.log(res.publicKeyBase58);
  })
  .catch((err) => {
    console.error(err && err.message ? err.message : err);
    process.exit(1);
  });
