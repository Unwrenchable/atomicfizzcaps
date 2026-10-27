"use strict";

// tests/security.test.js is CommonJS, but the repo package.json is
// "type": "module", so Node will not run it directly. Execute it as CJS.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const testPath = path.join(__dirname, "..", "tests", "security.test.js");
const src = fs.readFileSync(testPath, "utf8");
const sandbox = {
  require,
  module: { exports: {} },
  exports: {},
  __dirname: path.dirname(testPath),
  __filename: testPath,
  console,
  process,
  Buffer,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
};
sandbox.module.exports = sandbox.exports;
vm.runInNewContext(src, sandbox, { filename: testPath });
