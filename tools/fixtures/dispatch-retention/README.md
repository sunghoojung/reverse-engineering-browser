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
