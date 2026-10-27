#!/bin/sh
# Anchor forwards every argument after `--` to the IDL `cargo test` as well as
# to cargo-build-sbf. `--tools-version` is not a cargo flag, so the SBF
# toolchain pin lives here. Solana CLI 2.3.0 defaults to platform-tools v1.48
# (Rust 1.84), which cannot parse blake3's edition2024 manifest.
set -eu
REAL="${SOLANA_CARGO_BUILD_SBF:-${HOME}/.local/share/solana/install/active_release/bin/cargo-build-sbf}"
# `cargo build-sbf` passes the subcommand name as argv[1]. The real binary
# rejects that name once extra flags precede it.
if [ "${1:-}" = "build-sbf" ]; then
  shift
fi
export PATH="${HOME}/.cache/solana/v1.58/platform-tools/rust/bin:${PATH}"
exec "${REAL}" --tools-version v1.58 --no-rustup-override "$@"
