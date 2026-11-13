# Module diff fixtures

Two synthetic builds of one small program for
[`wasm-module-diff-v1`](../../../protocol/wasm-module-diff-v1.md). Build B
adds an import (so every call index shifts), moves the static data, edits one
function, removes one, adds one, rewrites and renames the checksum export, and
keeps two identical stubs. No third-party module is used.

| Function in A | In B | Expected row |
| --- | --- | --- |
| 0 `env.log` | 0 | identical, `import_name` |
| none | 1 `env.now` | added |
| 1 mix | 2 | identical, `identical` |
| 2 read static data | 3 | renumbered, `normalized` |
| 3 step | 4 | changed, `call_graph` |
| 4 `run` | 5 | renumbered, `normalized` |
| 5 shift | none | removed |
| 6, 7 stubs | 6, 7 | four ambiguous rows, one per stub, in one tie by `identical` |
| 8 `checksum` | 8 `digest` | changed, `structural` |
| none | 9 square | added |

The checked-in `.wasm` files are built from the `.wat` sources by the exactly
pinned `wat` crate. `make check` runs the `wasm_diff` tests, which fail when a
`.wasm` drifted from its source or a row above changed; rebuild with
`make wasm-diff-fixtures`. The rendered UI fixture serves both modules as
artifacts 430 and 431.
