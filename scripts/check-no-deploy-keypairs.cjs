"use strict";

/**
 * Fail if a devnet or mainnet program keypair JSON is present in the tree.
 * The only allowed keypair file is the localnet anchor-test key.
 */

const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const allowed = "programs/fizzcaps-onchain/keys/localnet-keypair.json";
const skipDirs = new Set(["node_modules", "target", ".git", ".anchor"]);

function walk(dir, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (skipDirs.has(ent.name)) continue;
    const abs = path.join(dir, ent.name);
    if (ent.isDirectory()) walk(abs, out);
    else if (ent.isFile()) out.push(abs);
  }
}

function isKeypairArray(text) {
  if (text.length > 20000) return false;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return false;
  }
  return (
    Array.isArray(parsed) &&
    parsed.length === 64 &&
    parsed.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)
  );
}

const files = [];
walk(root, files);
let failed = false;

for (const abs of files) {
  const rel = path.relative(root, abs).split(path.sep).join("/");
  const base = path.basename(rel).toLowerCase();
  const namedDeployKey =
    base.endsWith(".json") &&
    /keypair/.test(base) &&
    (/devnet/.test(base) || /mainnet/.test(base));
  const extraKeysFile = rel.startsWith("programs/fizzcaps-onchain/keys/") && rel !== allowed;
  if (namedDeployKey || extraKeysFile) {
    console.error(`devnet/mainnet keypair JSON must not be in the repo: ${rel}`);
    failed = true;
    continue;
  }
  if (!base.endsWith(".json") || rel === allowed) continue;
  let text;
  try {
    text = fs.readFileSync(abs, "utf8");
  } catch {
    continue;
  }
  if (isKeypairArray(text)) {
    console.error(`keypair JSON must not be committed: ${rel}`);
    failed = true;
  }
}

if (failed) process.exit(1);
console.log("ok: no devnet or mainnet keypair JSON in the tree");
