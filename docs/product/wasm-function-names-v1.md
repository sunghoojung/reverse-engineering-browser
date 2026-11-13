# WASM Laboratory: function names v1

A disassembler's core habit is that a rename sticks: name `func 1337`
`encode_payload` once and every view shows it. Origin Trace now does this for
captured WebAssembly.

- **Rename** a function from Sources **Inspect** (the pencil on its row), the
  **Graph** (toolbar **Rename**, or F2 on the graph or a highlighted row of the
  **Functions** list) or a **Flow** graph Wasm card (**Rename** in Details, or
  F2). F2 on a call row renames the callee. Enter saves, Escape cancels and an
  empty name clears it, as for every [evidence name](evidence-names-v1.md).
- **See** the name, in the researcher-name italic, beside the captured identity
  in the decoded listing (headers and call targets), the Graph title, the
  function list (whose filter matches names), Flow cards and Details, Traffic
  **Initiator** frames and cross-reference rows. `func N`, import, export and
  name-section names stay visible; a name never replaces them.
- **Agents** see the same names, with no UI, as `analyst_name` in
  `inspect_wasm`, `get_wasm_functions`, `get_wasm_function_graph`, `get_xrefs`,
  `get_flow_graph` and `get_request_stack`, and set or clear one with
  `analyst_action` `set_wasm_function_name` at Ask for actions.

A name is keyed by the module's SHA-256 and the function index (imports
included), so it follows identical bytes across sessions; other bytes at the
same URL are a different module. Names are interpretation, not evidence: they
live in the local Analyst names file, never change captured data, and reach a
connected agent's model provider at every permission level. The
[versioned contract](../../protocol/wasm-function-names-v1.md) owns the key,
the stored form, the read joins, bounds and the helpers other Wasm views reuse.

Not in this version: names in the command palette, local variable or global
names, and carrying names between different builds of a module (a module diff
writes them under the other module's own key).
