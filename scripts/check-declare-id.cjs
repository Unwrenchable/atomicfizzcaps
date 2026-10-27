"use strict";

/**
 * Fail if declare_id! for a cluster feature disagrees with Anchor.toml,
 * or if Cargo.toml puts localnet back in default features.
 */

const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const anchor = fs.readFileSync(path.join(root, "Anchor.toml"), "utf8");
const lib = fs.readFileSync(path.join(root, "programs", "fizzcaps-onchain", "src", "lib.rs"), "utf8");
const cargo = fs.readFileSync(path.join(root, "programs", "fizzcaps-onchain", "Cargo.toml"), "utf8");
const voucher = fs.readFileSync(path.join(root, "programs", "fizzcaps-onchain", "src", "voucher.rs"), "utf8");

function anchorId(section) {
  const re = new RegExp(`\\[programs\\.${section}\\][\\s\\S]*?fizzcaps_onchain\\s*=\\s*"([^"]+)"`);
  const m = anchor.match(re);
  if (!m) throw new Error(`missing [programs.${section}] fizzcaps_onchain id`);
  return m[1];
}

const declared = {};
const re = /declare_id!\("([^"]+)"\);\s*\/\/\s*cluster:(\w+)/g;
let match;
while ((match = re.exec(lib))) {
  declared[match[2]] = match[1];
}

const map = { localnet: "localnet", devnet: "devnet", mainnet: "mainnet" };
let failed = false;
for (const [feature, section] of Object.entries(map)) {
  const fromAnchor = anchorId(section);
  const fromCode = declared[feature];
  if (!fromCode) {
    console.error(`declare_id for cluster:${feature} not found`);
    failed = true;
    continue;
  }
  if (fromAnchor !== fromCode) {
    console.error(`MISMATCH ${section}: Anchor.toml=${fromAnchor} declare_id(${feature})=${fromCode}`);
    failed = true;
  } else {
    console.log(`ok ${section}: ${fromAnchor}`);
  }
}

const features = cargo
  .split("[features]")[1]
  .split(/\n\[/)[0]
  .split("\n")
  .filter((line) => !line.trim().startsWith("#"))
  .join("\n");
if (/default\s*=\s*\[[^\]]*localnet/.test(features)) {
  console.error('Cargo.toml must not set default = ["localnet"]');
  failed = true;
}
if (!lib.includes("compile_error!")) {
  console.error("lib.rs is missing compile_error! for the cluster feature gate");
  failed = true;
}
if (!/rd\(6\)/.test(voucher)) {
  console.error("voucher.rs pubkey offset must be read at header byte 6 (rd(6)), not the signature offset");
  failed = true;
}
if (!voucher.includes("VOUCHER_MSG_LEN")) {
  console.error("voucher.rs must enforce VOUCHER_MSG_LEN");
  failed = true;
}
const ids = Object.values(declared);
if (new Set(ids).size !== ids.length) {
  console.error(`program ids are not unique per cluster: ${ids.join(", ")}`);
  failed = true;
}

if (failed) process.exit(1);
