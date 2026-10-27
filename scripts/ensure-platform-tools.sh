#!/bin/sh
# Solana CLI 2.3.0's bundled platform-tools (v1.48 / Rust 1.84) cannot parse
# blake3's edition2024 manifest. v1.58 (Rust 1.95) can. The v1.58 tarball
# unpacks rust/ and llvm/ at the top; cargo-build-sbf looks under platform-tools/.
set -eu
VER=v1.58
ROOT="${HOME}/.cache/solana/${VER}"
RUSTC="${ROOT}/platform-tools/rust/bin/rustc"
if [ -x "${RUSTC}" ]; then
  exit 0
fi
mkdir -p "${ROOT}/platform-tools"
tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
url="https://github.com/anza-xyz/platform-tools/releases/download/${VER}/platform-tools-linux-x86_64.tar.bz2"
curl -fsSL -o "${tmp}/pt.tar.bz2" "${url}"
tar -xjf "${tmp}/pt.tar.bz2" -C "${tmp}"
if [ -d "${tmp}/rust" ] && [ -d "${tmp}/llvm" ]; then
  mv "${tmp}/rust" "${tmp}/llvm" "${ROOT}/platform-tools/"
elif [ -d "${tmp}/platform-tools/rust" ] && [ -d "${tmp}/platform-tools/llvm" ]; then
  mv "${tmp}/platform-tools/rust" "${tmp}/platform-tools/llvm" "${ROOT}/platform-tools/"
else
  echo "unexpected platform-tools layout in ${tmp}" >&2
  find "${tmp}" -maxdepth 3 -type d >&2
  exit 1
fi
test -x "${RUSTC}"
