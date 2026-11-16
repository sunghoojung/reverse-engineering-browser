# Value-flow fixture

A repository-owned WebAssembly module for
[`wasm-value-flow-v1`](../../../protocol/wasm-value-flow-v1.md). It uses no
third-party code, constants or names.

| Function | Shape |
| --- | --- |
| 2 `mix` | parameters; a load with an address expression; a store and load at the same constant address (forwarded); a loop join of two locals; an `if`/`else` result join; an import call (`env.send`), a global, a store address and the return |
| 3 `route` | a direct caller of `mix`; its result feeds a `br_table` selector, a `call_indirect` argument and its table index |
| 4 `pick` | a store, then a call, then a load at the same address (not forwarded); a block result joined from a `br_if` value and the fallthrough |

`value-flow.wasm` is built from `value-flow.wat` by the exactly pinned `wat`
development dependency of `apps/origin-trace-backend`. The test
`wasm_value_flow::tests::checked_in_fixture_is_built_from_its_wat_source` fails
when they differ; rebuild after editing the source with:

```sh
REB_WRITE_VALUE_FLOW_FIXTURE=1 cargo test --locked \
  --manifest-path apps/origin-trace-backend/Cargo.toml \
  --lib wasm_value_flow::tests::checked_in_fixture_is_built_from_its_wat_source
```

The rendered UI fixture (`tools/origin-trace-rendered-ui/evidence-fixture.mjs`)
stores the checked-in module as artifact 440.
