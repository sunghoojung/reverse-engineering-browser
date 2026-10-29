# Owned handler-retention ledger

These are repository-owned synthetic interpreters and binding cases, never
captured website source. `ledger.json` keeps one compact row per case: the base
and expected handler counts, a static-binding category, and a reference to the
recorded runtime observation. Runtime results remain data, including errors
when execution replaces a statically bound table.

The Rust `owned_handler_retention_ledger` test runs analysis and workspace
extraction. `node --experimental-vm-modules tools/check-dispatch-retention.mjs`
independently rebuilds and hashes the same inputs, then executes them in fresh,
bounded Node contexts. `make lint` runs that runtime check. Wasm observations
report module validation, not guest execution.

The 3,587 rows cover owned shapes, previous review inputs and 3,200 mutations.
Shared sources and runtime observations are named once. Mutation recipes use
ordered UTF-8 byte edits into a seed plus a case index; both checkers generate
mutated source at test time. Repeated bundles use text or indexed-template parts.
The large data-URI literal is generated with a fixed 32-bit LCG seed, multiplier
1664525 and increment 1013904223, indexing the base64 alphabet with its high six
bits. Its former random bytes were replaced by this reproducible synthetic
literal, with the same runtime result. Large source bodies and runtime dumps
are not committed. SHA-256 checks prevent the two generators from drifting.

Claims describe static bindings. Rows formerly withheld for global replacement,
reflection or initialization order now use the category
"static binding; runtime replacement out of scope" when those claims survive.
Their runtime observations remain separate. The same-function `this` boundary
and static single-write rules remain, as specified in the
[classification contract](../../../protocol/vm-dispatch-classification-v1.md).
Native guest capture is the authority for what actually executes.
