#!/bin/sh
# Metaplex token-metadata is not a solana-test-validator builtin.
# Anchor genesis and the program-test both load this exact mainnet program id.
set -eu
dest="tests/fixtures/mpl_token_metadata.so"
mkdir -p tests/fixtures target/deploy
if [ ! -f "${dest}" ]; then
  solana program dump -u https://api.mainnet-beta.solana.com \
    metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s "${dest}"
fi
cp "${dest}" target/deploy/mpl_token_metadata.so
