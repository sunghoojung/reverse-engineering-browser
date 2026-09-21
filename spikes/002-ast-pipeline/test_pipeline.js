const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {deobfuscate, staticValue, UNKNOWN} = require("./deobfuscator");

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
assert(result.transforms.length > 0);
for (const transform of result.transforms) {
  assert(Number.isInteger(transform.originalStart));
  assert(Number.isInteger(transform.originalEnd));
  assert(transform.originalStart < transform.originalEnd);
  assert.match(source.slice(transform.originalStart, transform.originalEnd), /\S/);
}

const edgeCases = deobfuscate(`
  const missing = [, , 3];
  const infinity = 1 / 0;
  const negative = -7;
  const kind = typeof void 0;
  window.kind = kind;
  if (void 0) { window.bad = true; } else { window.ok = negative; }
`);

// Sparse arrays and non-finite arithmetic are evidence the static evaluator
// must not guess about. They remain in the output instead of being rewritten.
assert.match(edgeCases.code, /const missing = \[,, 3\];/);
assert.match(edgeCases.code, /const infinity = 1 \/ 0;/);
assert.doesNotMatch(edgeCases.code, /window\.bad/);
assert.match(edgeCases.code, /window\.ok = -7;/);
assert.match(edgeCases.code, /window\.kind = "undefined";/);
assert(edgeCases.transforms.some((transform) => transform.kind === "constant-fold"));
assert.equal(staticValue({type: "Identifier", name: "notKnown"}), UNKNOWN);
console.log("AST pipeline test passed");
