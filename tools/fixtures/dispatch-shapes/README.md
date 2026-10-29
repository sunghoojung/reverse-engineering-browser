# Dispatch shape fixtures

Repository-owned WebAssembly and JavaScript programs for the structural
dispatch classifier ([`vm-dispatch-classification-v1`](../../../protocol/vm-dispatch-classification-v1.md)).
They exercise generic shapes only: no third-party module, constant, function
map, or role label is used as a fixture, label, or ground truth.

| Fixture | Shape |
| --- | --- |
| `cursor-interpreter.wat` | `br_table` in a loop on `code[pc]`, `pc` advanced in the loop |
| `frame-slot-interpreter.wat` | `pc` reloaded from a linear-memory frame slot and stored back each iteration |
| `handler-table-interpreter.wat` | `call_indirect` handler table; element segments at offsets 1 and 5 |
| `multiplexer.wat` | one-shot routers on the first argument: an `i32.eq` ladder and a `br_table` |
| `ordinary-match.wat` | a 40-arm `br_table` with no loop, and a `br_table` on a loop-invariant argument |
| `switch-interpreter.js` | `switch (code[pc++])` in a loop |
| `handler-array-interpreter.js` | `handlers[code[pc++]](state)` in a loop |
| `router.js` | `if (k === C) return f(...)` ladder on an argument |
| `tokenizer.js` | `for (i) switch (s[i])` over a string |
| `rotated-interpreter.wat` | rotated loop: first opcode fetched in the preheader, next at the latch |
| `worklist-dispatch.wat` | worklist: `br_table` on `kinds[id]` with `id` from a pop call |
| `normalized-multiplexer.wat` | routers on an argument masked to a byte, or clamped by a guard |
| `match-in-loop.wat` | counting loop with a `br_table` on a struct field the loop never advances |
| `multi-site-interpreter.wat` | three sites in one function: argument mode switch, opcode, operand mode |
| `host-step.wat` | host-driven `step()`: pc reloaded and stored back once per call, no loop |
| `rotated-loop.js` | `let op = code[pc++]; while (op) { switch (op) ...; op = code[pc++]; }`: recovery follows every write of the rotated selector |
| `worklist.js` | `while (q.length) { const id = q.pop(); switch (types[id]) ... }` |
| `minified.js` | comma declarations and statement-form `do switch (...) {...} while (...)` |
| `normalized-router.js` | `k = k \| 0` then an `if (k === C)` ladder |
| `text-walk.js` | `switch (s.charCodeAt(i))` loop: a string scan, role `other` |
| `bfs-lookup.js` | `id = q[head++]; switch (types[id])`: a second-level lookup, role `other` |
| `arguments-loop.js` | `switch (arguments[i])` loop: an arguments scan, role `other` |

Short review repro programs are inlined in
`apps/origin-trace-backend/src/vm_review_inputs.rs`.

`expected.json` is the classification each site must receive. The checked-in
`.wasm` files are built from the `.wat` sources by the exactly pinned `wat`
crate (a development dependency of `apps/origin-trace-backend`). The
classifier reads only the checked-in bytes.

```sh
make dispatch-shape-check      # source/binary drift, classification, schema
make dispatch-shape-fixtures   # rebuild the .wasm files after editing a .wat
```

`make check` runs `dispatch-shape-check`, so an edited `.wat` without a rebuilt
`.wasm`, or a stale `.wasm`, fails the gate.
