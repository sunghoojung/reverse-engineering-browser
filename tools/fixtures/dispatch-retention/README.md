# Owned handler-retention ledger

These are repository-owned synthetic JavaScript interpreters and adversarial
binding cases. No captured website source, vendor key or function map is used.
`ledger.json` is the judged oracle, including base emitted handler counts,
expected gated counts, the runtime invocation and observed result or error.

The Rust `owned_handler_retention_ledger` test runs the complete analysis and
workspace path. `node --experimental-vm-modules tools/check-dispatch-retention.mjs`
executes these owned inputs in fresh bounded Node contexts to verify the runtime
evidence. `make lint` runs that runtime check. A directory named `attack` does
not determine the judgment: comments, templates, labels and other positive
controls keep all handlers that unchanged recovery emits.

The 22 owned shapes retain every one of the 15 tables that base emits, including
handler-advanced PCs and block `let`/`const`. Seven shapes have no base handlers;
this post-filter cannot add recovery. The corpus ledger keeps all 24 previously
lost true claims and withholds the four one-shot/router cases. Duplicate copies
preserve the review's case counts. The `this` cases cover same-function receiver
identity, arrow preservation, function/method/class boundaries, assignment order,
multiple writes, unrelated static keys, computed keys, mutator APIs and aliases,
and destructuring targets. A runtime-correct table may still be withheld when
these conservative proof conditions are not met, such as another receiver's
write to the same property name.

The review ledger also covers all 3,443 executable inputs from the sixth review,
including its 3,200 mutation cases and its repository fixture copies, plus 42
additional global, receiver, dominance and literal controls. Each review input
has a SHA-256, a CLI handler count and a bounded runtime verdict. Wasm verdicts
explicitly report module validation, not guest execution. Repeated bundle source
is stored as deterministic text or indexed-template parts; both checkers rebuild
and hash the exact bytes. This keeps realistic 0.5-8 MiB bundles reproducible
without storing repeated source text.

Global classic-script bindings require no dynamic code evaluation or potentially
matching global writes within the artifact. This cannot establish stability
against other scripts sharing the global object. Reflective receivers and
non-fresh `this` calls have a separate refusal. Initialization must execute as an
unconditional statement in the dispatch loop's own function before the loop.
Separate declaration and unique assignment are accepted. Literal contents do not
contribute to the parser's syntactic depth guard.

The stricter dominance rule intentionally removes three claims apiece from
`attack/computed_key.js`, `attack/getter.js` and `this/arrow_preserves_this.js`.
All three still produce `[42]` at runtime, but their table initialization and
dispatch occupy different functions. Their ledger judgments record that
conservative loss. The original 22 owned shapes still retain all 45 base claims;
the five normal bundles and the data-URI bundle retain all three claims each.
