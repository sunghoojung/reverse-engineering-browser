# Wasm function names v1

Researcher names for WebAssembly functions: rename `func 1337` to
`encode_payload` once and every Wasm read, in the UI and through `reb-api mcp`,
shows it. A name is interpretation, never evidence. It sits beside the captured
identity (`func N`, the import, export and name-section names) and never
replaces, hides or edits it. The storage, editor and general bounds are the
[evidence names](../docs/product/evidence-names-v1.md) document; this contract
adds the Wasm kind, its key and the read joins.

## Key

A Wasm function name is keyed by:

- `sha256`: the module's SHA-256, 64 lowercase hex characters, as
  `inspect_wasm`, `get_artifacts` and every Wasm read report it;
- `function`: the function index in the module's **full index space**, imports
  included, as every Wasm read numbers it (0 to 4,294,967,295).

The canonical text key is `wasm-function:<sha256>:<index>`. The key names no
session, artifact ID, URL or file name, so a name follows identical module
bytes across sessions and capture origins, and other bytes under the same URL
are a different module. Every retained artifact with those bytes shows the
name. A name whose index lies outside a module's index space is kept but not
shown.

## Stored form

Names live in the evidence-names document (`Evidence names.reb-names.json`).
Version 2 of that closed document adds one member:

```json
{"document_kind": "reb-evidence-names", "contract_version": 2,
 "scope": "local-analyst-library", "requests": [], "artifacts": [],
 "vm_programs": [],
 "wasm_modules": [{"sha256": "<64 hex>",
                   "functions": [{"function": 5, "name": "encode_payload"}]}]}
```

- `wasm_modules` holds at most 64 module groups, one per SHA-256. A group has a
  nonempty `functions` list; clearing its last name removes the group.
- Each entry holds exactly `function` (an integer) and `name`. Unknown members,
  duplicate indexes in one group and duplicate groups are refused.
- Wasm names share the document's 500-name count, 80-character name rule and
  32 KiB byte bound with every other kind.
- Every number is an integer written as one. A hand-edited `1.0` or `2e0` is
  refused, by the backend's strict parser and by the UI, even where it equals
  an integer, so both sides accept exactly the same documents.
- Version 1 documents stay readable. Writers keep writing version 1 while no
  Wasm name exists and switch to version 2 for the first one, so a build that
  predates Wasm names keeps reading a library that has none.
- A malformed, unsupported or ambiguous document (more than one candidate)
  shows no names anywhere and is never overwritten or repaired.

The backend (`apps/origin-trace-backend/src/wasm_names.rs`) and the UI
(`apps/research-ui/evidence_names.js`) apply the same validation, so a
document one refuses joins no name in the other either.

## Writing

Two routes write names, both through `POST /api/local-analyst/actions`
(`analyst_action`):

- `set_wasm_function_name` with `sha256`, `function`, `name` and an optional
  `expected_name` (the name last read, or `null` for an unnamed function). The
  backend reads the library, changes only that entry and replaces one library
  generation; other names, Analyst files and folders are kept. The name is
  trimmed; an empty name clears it. When `expected_name` is present and the
  saved name differs, nothing is written and the call fails with 409. A stale
  library generation also fails with 409 and is never retried. The result is
  `wasm-function-name-result-v1`: `key`, `sha256`, `function`, `name`,
  `previous_name`, `changed`, `library_generation` and `file`. This action
  needs `--allow-effects` (level A), and the caller never reads or resends the
  other Analyst files, which the read-only levels omit.
- `replace_local_analyst_workspace` with a whole library whose names file holds
  the version 2 document, as the UI writes it. That needs the file contents,
  so an agent can use it only at Full access.

## Read joins

The loopback HTTP routes join names into every agent-facing Wasm read. Each
adds the name as a separate `analyst_name` (present only when a name exists)
and one `analyst_names` status member. No captured field changes.

| Operation | Where names appear |
| --- | --- |
| `inspect_wasm` | `analyst_name` on `function`, `import`, `declaration` and `start` rows (by `function_index`); `target_analyst_name` on `call`, `return_call` and `ref.func` rows beside their new structural `target_function_index`; the module's names in `analyst_names.functions` |
| `get_wasm_functions` | `analyst_names.functions` as `[index, name]` pairs, beside the name-section `names` |
| `get_wasm_function_graph` | `analyst_name` for the function; the module's names in `analyst_names.functions`, so a `call N` row resolves |
| `get_xrefs` | `selection.wasm_sha256` and `selection.function_index` identify the selection; rows that name a Wasm function carry `function_index` and `analyst_name`. A `call_indirect` row names a callee only when its table entry resolved in this instance; a null, out-of-bounds, foreign or unresolved entry is labeled by its resolution and carries no `function_index` |
| `get_flow_graph` | Wasm nodes carry `sha256` and `analyst_name` |
| `get_request_stack` | Wasm frames carry `module_sha256` and `analyst_name`, in the stack and every task segment |

`analyst_names` has `status` (`none`, `ready`, `malformed`, `ambiguous` or
`unavailable`), `file`, `library_generation` and `notice`. A one-module read
adds `module_sha256` and `functions`; a read that spans modules adds `joined`,
the number of items named. Only `ready` joins names.

`target_function_index` is structure, like `function_index`: a read that omits
row text (the read-only permission levels) still names a call's target.

The native `reb://app` routes and the `origin-trace-wasm` CLI do not join names;
the packaged UI reads names from its own store and renders them itself.

## Bounds

- The Analyst library file is at most 1 MiB and the names document at most
  32 KiB, so a parse is bounded. The backend keeps the parsed names behind a
  cache keyed by the library file's device, inode, size and modification time:
  an unchanged library costs one `stat` per read. Every library write renames a
  new file into place, so a new generation always has a new inode.
- A library without Wasm names leaves documents unchanged apart from the small
  status member. The flow graph, cached as bytes, is parsed only when one scan
  of its `sha256` members finds a module that has a name; otherwise it is
  extended as text. Its node and edge budgets bound that parse.
- The UI asks every 2 s whether the library changed, with its last ETag.
  `GET /api/local-analyst` answers an unchanged file with 304 from the same
  `stat` (device, inode, size, modification time) and never reads it, so a name
  an agent saves appears in an open window within one tick.
- A one-module `functions` list holds at most 500 pairs.

## Permission levels

Names are researcher-authored text of at most 80 characters, not captured
content: `analyst_name`, `target_analyst_name` and `analyst_names` are returned
at every `reb-api mcp` permission level, like identifiers. An MCP client sends
them to its model provider. Setting a name is an effect (level A). See
[SAFETY.md](../SAFETY.md).

## Helpers for other Wasm views

Views that show a Wasm function (a readable view, identification suggestions, a
module diff carrying names forward) use these instead of reading the document:

- Rust, inside the backend: `wasm_names::key(sha256, index)`, the
  `wasm_names::Cache` an `App` holds (`App::names_reader()`), then
  `Names::function(sha256, index) -> Option<&str>`,
  `Names::module(sha256)` and `Names::module_member(sha256, function_count)` for
  the `analyst_names` member. `wasm_names::append_members` adds members to a
  document built as text.
- JavaScript, in the UI: `RebEvidenceNames.wasmFunctionKey(sha256, index)`,
  `RebEvidenceNames.wasmFunctionName(sha256, index)` (a name or `null`), and
  `RebWasmFunctionNames` (`nameOf`, `nameNode` for an inert, bidi-isolated
  name span, `mark` so F2 inside an element renames its function, with an
  optional editor host and focus fallback, `beginFrom`, `subscribe` to repaint
  on a rename).

F2 resolves the function under the cursor from where focus really is.
Inspect rows take no focus, so with the Graph closed and focus on the code
view it uses the row under the caret selection, else the row last pointed at,
else the current line. With the Graph open, F2 from the code view or the body
uses the Graph's function; only a caret on a marked row of the linear listing
shown beside it names that row instead. A body row (an instruction or locals row) stands
for the function that contains it, so F2 on one renames that function. Tree
rows, tabs and the toolbar keep the file rename.

A view that carries a name to another module (a diff match) must write it under
the other module's own key; a name never follows a match implicitly.
