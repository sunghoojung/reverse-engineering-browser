const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {deobfuscate} = require("./deobfuscator");

const source = fs.readFileSync(path.join(__dirname, "fixtures/mixed.js"), "utf8");
const result = deobfuscate(source);

assert.equal(result.schema, "ast-deobfuscation-poc-v1");
assert.match(result.code, /window\.fetch\(12, "token"\);/);
assert.doesNotMatch(result.code, /unreachable/);
assert.doesNotMatch(result.code, /const table/);
assert.doesNotMatch(result.code, /const add/);
assert(result.passes.some((pass) => pass.counts.substituteConstants > 0));
assert(result.passes.some((pass) => pass.counts.replaceStringArrayAccesses > 0));
assert(result.passes.some((pass) => pass.counts.inlinePureProxies > 0));
assert(result.passes.some((pass) => pass.counts.removeDeadBranches > 0));
console.log("AST pipeline test passed");
