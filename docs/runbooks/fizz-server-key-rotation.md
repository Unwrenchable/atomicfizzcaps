# Fizz server-key rotation

`claim_loot` trusts only the Ed25519 key stored on `FizzConfig` for the cluster the binary was compiled for. It does not accept a key supplied by the transaction.

This repository's program id is `DXxzKfZh6aJCff7sEusMU1E9w4ZDwgJkYGgKStRRGRyP` on localnet, devnet, and mainnet. The canonical program lives in `Unwrenchable/ATOMIC-FIZZ-CAPS-VAULT-77-WASTELAND-GPS`. Do not deploy this copy. The steps below are the runbook for an operator who already holds the upgrade authority.

## Keys

Generate a fresh Ed25519 key per cluster. Do not reuse a key that has been in `.env`, CI logs, or a previous cluster.

- Local dev: `SERVER_SECRET_KEY_LOCALNET` (64-byte secret, base58).
- Devnet: `SERVER_SECRET_KEY_DEVNET` or `KMS_SIGNING_KEY_ID_DEVNET`.
- Mainnet: `KMS_SIGNING_KEY_ID_MAINNET`.

KMS key spec is `ECC_NIST_EDWARDS25519`, usage `SIGN_VERIFY`, algorithm `ED25519_SHA_512`, `MessageType=RAW`. Print the raw 32-byte public key:

```bash
node backend/scripts/print-server-pubkey.js "$KMS_SIGNING_KEY_ID_DEVNET"
```

`fizz_init` stores three distinct non-default keys (localnet, devnet, mainnet). The running binary reads only its own slot (`CLUSTER_TAG` 3, 2, or 1).

## Rotate

1. Pause claims: `fizz_set_paused(true)` signed by `config.authority`.
2. `fizz_set_server_key(new_pubkey)` signed by the same authority. This writes only the slot for the binary's cluster and emits `ServerKeyRotated`.
3. Deploy the backend with the matching per-cluster secret or KMS key id. `SOLANA_CLUSTER` and `FIZZCAPS_PROGRAM_ID` must match this program.
4. Issue one voucher and confirm the Ed25519 instruction sits immediately before `claim_loot`.
5. Unpause: `fizz_set_paused(false)`.

`fizz_init` itself must be signed by the program upgrade authority. The instruction reads the upgradeable loader `ProgramData` account derived from this program id and rejects any other signer.

A non-authority call to `fizz_set_server_key` or `fizz_set_paused` fails the `has_one = authority` constraint.

## Voucher rules

- Message is 169 bytes, domain `FIZZCAPS:LOOT_VOUCHER:v1`.
- Bound to the session wallet, this program id, and the compile-time cluster tag.
- TTL is at most 300 seconds. `voucher_id` is 16 bytes from `crypto.randomBytes`.
- Replay: one PDA per `voucher_id` (`voucher-claim`) and one PDA per `loot_id` (`loot-id-claim`).
