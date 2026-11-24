# Block graph fixtures

One synthetic function of exception handling for the
[block graph](../../../protocol/wasm-inspection-v2.md#function-index-and-block-graph)
of `wasm-block-graph-v1`. Function 1 (`run`; function 0 is the imported
`env.step`) covers each way the graph resolves an exception locally. Tags 0
and 1 are imported, so they may be one tag; tags 2 and 3 are defined in the
module, each its own. No third-party module is used.

| Instruction | Edges from its block |
| --- | --- |
| `call 0` in the `try_table` | `call: catch 2` and `call: catch_all`: a call may raise any tag |
| `throw 2` in the `try_table` | `catch 2` only: a defined tag is no other |
| `throw 0` in a legacy `try` | `catch 1` (imported, may be tag 0) and `catch_all` |
| `rethrow 1` in a `catch` body | unresolved `rethrow`: a catch body is not covered |
| `call 0` in a `try` that ends in `delegate 0` | `call: catch_all` of the `try` around it |
| `throw 1` in a `try` that catches only tag 0 | `catch 0` and unresolved `throw: may escape` |
| `throw 3` outside any handler | unresolved `throw` |
| `throw 3` in a `try_table` with `catch_all_ref` | `catch_all_ref` |
| `throw_ref` outside any handler | unresolved `throw_ref` |

The checked-in `exceptions.wasm` is built from `exceptions.wat` by the exactly
pinned `wat` crate. `make check` runs the `wasm_graph` tests, which fail when
the `.wasm` drifted from its source or an edge above changed; rebuild it with
`make wasm-block-graph-fixtures`. The rendered UI fixture serves it as
artifact 344, beside a switch ladder (341), a 256-arm interpreter loop (342),
nested loops (343) and a 19,459-block interpreter loop (345) that
`evidence-fixture.mjs` generates.
