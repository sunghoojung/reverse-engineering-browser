# Historical AST pipeline experiment

This Babel prototype explores constant folding, binding substitution, string
tables, proxy functions, dead branches and member normalization. It is not a
production correctness boundary and must not be wired into Sources.

Its binding substitution, array alias handling, proxy argument effects, nested
`void` handling and declaration removal are not sufficiently conservative for
captured source. Babel positions are UTF-16 offsets, not UTF-8 bytes, and
regenerated nodes do not carry a complete original-source map. Its narrow
fixtures demonstrate ideas, not semantic equivalence for arbitrary JavaScript.

The [Rust worker](../../apps/deobfuscator-worker/README.md) owns the production
subset. See [method coverage](../../docs/product/deobfuscation-method-coverage.md)
for the article comparison, negative cases and unsupported techniques. Do not
promote this experiment's additional passes without equivalent correctness,
resource-limit and original-source mapping evidence.

To reproduce the historical experiment:

```sh
npm ci
npm test
node deobfuscator.js fixtures/mixed.js
```
