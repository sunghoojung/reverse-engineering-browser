# Flow graph v1

Status: implemented in the Rust backend (`apps/origin-trace-backend/src/flow_graph.rs`)
and the Flow workspace's **Graph** pane (`apps/research-ui/flow_graph.js`,
`flow_graph_layout.js`).

## Why

Each stack record answers one question: which frames were running when this
request, navigation, task or cookie write started. A researcher working
backward from a beacon wants the union: every path that reaches it, through a
same-process iframe, a posted task, a Wasm export and its JavaScript import,
or code that `eval` or `new Function` produced. `get_flow_graph` folds every
recorded stack of one session into that one graph. It is observed evidence
only: an edge exists because a recorded stack walked it.

## Inputs

`GET /api/flow-graph?session_id=` (`get_flow_graph`). `session_id` is required,
nonzero and canonical; any other parameter returns 400.

The route reads, in one forward pass over the event store, every record of that
session of these types ([native network v3](native-network-v3.md#request-initiator-stacks)):

| Type | Role |
| --- | --- |
| 34 `request_initiator_stack` | A request's stack; its sink is `METHOD host` from the parent `request_initiated` |
| 46 `navigation_initiator_stack` | A script navigation's stack; its sink is the navigation kind |
| 48 `async_task_stack` | A scheduling stack (timer, animation frame, idle callback, `postMessage`, `XMLHttpRequest.send`, `scheduler.postTask`, queued event) |
| 39 `script_cookie` | A cookie write that walked the stack (flags bits 1 and 2); its sink is the API |
| 35 `script_identity` | Script ID to realm, eval flag, start position and source digest |
| `request_initiated` | The `METHOD host` label of a request stack's sink |

Lines are selected by a byte prefilter before they are parsed. Stack, script
and module artifacts are found by SHA-256 in one artifact-manifest pass, plus
one more for task segments that name scheduling stacks no record here
describes.

## Folding

- **One decode per stack.** Records are grouped by `(process_id, digest)`. Each
  distinct stack is decoded once and weighted by how many records named it.
- **One read per source.** Every offset any frame names is gathered per script
  digest first; each retained script or module is then read once, its UTF-16
  positions resolved in one pass (as `get_request_stack` resolves them) and its
  function names read at the function start positions. One source is held at a
  time.
- **Realms.** A context is `process_id` plus the `execution_context_id` of the
  frame's `script_identity`. A same-process iframe is its own realm, so a call
  between realms is a frame boundary. A frame without an identity record goes
  to the process's unidentified realm and never claims a boundary.
- **Nodes.** A function is keyed by realm, code (the script digest, else its
  script ID) and function position (JavaScript) or index (Wasm), so the same
  code compiled twice in one realm, such as one `eval` string run twice, is one
  node. Top-level script frames are their own node. Sinks are keyed by realm and
  label.
- **Edges.** Adjacent synchronous frames give `call` edges, caller to callee,
  with up to eight distinct call sites (line and column, or Wasm module offset).
  The await chain gives `await` edges from each awaiter; a Promise combinator is
  the edge's `label`. Each task segment gives a `task` edge from the innermost
  frame of the stack that scheduled the task to the task's first frame: the
  last awaiter of the await chain, else the outermost synchronous frame, and
  for an earlier segment the outermost frame of the later one. Frameless
  microtask hops between them are listed in `via`. A stack deeper than 1,024
  frames gives one `omitted` edge across the dropped run. The innermost frame
  gets a `request`, `navigation` or `cookie_write` edge to each sink its records
  name. A stack that walks an edge more than once (a recursion, two segments
  naming one scheduling stack) counts it once: `count` sums the weights of the
  stacks that walk it and `stacks` counts them. Stacks that share an edge merge
  what they say about it: `via` is every hop any of them names, `label` every
  combinator, and `omitted` the largest dropped run.
- **Crossings.** `crosses` names `frame` (both realms known and different),
  `language` (JavaScript and Wasm) and `dynamic` (a call into eval code from
  other code).
- **Paths.** Each distinct stack lists its edges, its nodes, its weight and its
  renderer request IDs (131,072 kept in all), so the UI lights exactly the
  edges a selected stack or request walked.

Nothing is inferred. A frame whose source is missing keeps its script ID and a
`reason` (as `get_request_stack` names them), or `source_budget` and
`source_deadline` when the read budget or deadline left it unread. A stack
whose artifact is missing keeps its innermost frame, names no task entry and
is counted under `stacks.unresolved`. The chain is cut, and no edge bridges
the cut, where the first frame of a task is not known: a scheduling stack that
was not retained, a walk that stopped at 256 frames (segment flag bit 0, or an
`async_task_stack` with flag bit 0), an await chain past 32 frames (record bit
2), a chain past 32 segments (record bit 4) or a recorded cut (record bit 3), and
a frame past the node budget. The node where the chain stops carries
`chain_cut`. `entries` counts a node only when it is a known first frame.

## Answer

`schema` `flow-graph-v1`, `evidence` `observed`, and `complete`, false when the
scan stopped at its deadline or any budget or table cut something (every
`truncated` count, `stacks.over_budget`). `contexts`, `nodes`
and `edges` index each other by position. The full shape is the `FlowGraph`
schema in [openapi.json](openapi.json).

`not_shown` lists what stacks cannot contain: worker and worklet stacks (walked
on the document main thread only), `MessagePort` and worker messages,
out-of-process frames (another renderer, whose stacks appear as their own
realm with no edge to the page), and calls that never reached a recorded
request, navigation, task or cookie write.

## Bounds

| Bound | Value | When reached |
| --- | --- | --- |
| Scan deadline | 30 s | `coverage.stopped` is `deadline`, `complete` false |
| Distinct stacks | 16,384 | later stacks are counted in `stacks.over_budget` |
| Nodes, edges | 32,768, 131,072 | counted in `truncated.nodes`, `truncated.edges` |
| Path references | 1,048,576 | later paths are counted in `truncated.paths` |
| Script identities | 262,144 | counted in `truncated.identities` |
| Request labels waiting for their stack | 262,144 | the table restarts; `truncated.request_labels` |
| Source bytes read | 1 GiB | later sources are counted in `truncated.source_budget`; their frames name `source_budget` |
| Source reads after the deadline | none | counted in `truncated.source_deadline`; their frames name `source_deadline` |

Each renderer sends at most 1,024 request and 1,024 scheduling stacks per
configuration, so the stack budget holds sixteen such renderers; the node and
edge budgets hold the frames of every distinct stack of that many. The answer
is cached until the event store's last complete record or the artifact
manifest's length changes. An answer the deadline cut is not cached, so the
next request reads again.

## UI

The Flow workspace's **Graph** pane draws the answer on one canvas, read top
to bottom like a disassembler's CFG. Each realm (context) is a full-width band titled by
its script origin, realm, frame and process, and the bands are stacked in call
order: a realm that calls or posts into another sits above it, so an iframe
sits below its parent, and a call between realms runs down across the band
boundary. Inside a band, rows are call depth. A card is one function: a header
tinted by its kind with its name, the number of distinct paths through it and
its kind (`js`, `eval`, `wasm`, `chain`), then its location and one row per
edge it starts (call site, mnemonic, callee, what the edge crosses, its
count). A sink is a row of each function whose stacks reached it rather than a
card, unless no edge reaches it. Edges are coloured by kind: `call`, `await`
and `task`, a crossing (`crosses` not empty), and `request`, `navigation` and
`cookie_write`; `omitted` is dotted. Frame boundaries, task kinds, JS and Wasm
transitions and calls into eval are also written on their rows, never colour
alone. Pass-through frames inside one realm fold into a chain card. Selecting
a card lights every path through it; choosing a request lights its own paths
and the row that made it, and dims the rest. Each realm is laid out by
Triskel through `POST /api/graph-layout` when the backend serves it and
Triskel's drawing is not much wider than the layered one; the layout is
presentation only and never changes this document. See the
[Research UI README](../apps/research-ui/README.md#flow-graph).

## Validation

`cargo test --lib flow_graph` builds stores where a top page posts into a
same-process iframe whose handler calls an eval'd helper and a Wasm export
whose JavaScript import fetches, and checks the realms, crossings, call sites,
weights, paths, cache, missing bytes and malformed records, and each answer
against the `FlowGraph` schema. `tests/http.rs` checks the route's statuses.
`node tools/check-flow-graph-ui.mjs` checks the UI model, folding, layout and
panel.
