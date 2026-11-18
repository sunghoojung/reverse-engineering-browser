# Flow graph v2

Status: implemented in the Rust backend (`apps/origin-trace-backend/src/flow_graph.rs`
and `src/flow_graph/`) and the Flow workspace's **Graph** pane
(`apps/research-ui/flow_graph.js`, with `flow_graph_model.js`,
`flow_graph_layout.js` and `flow_graph_worker.js`).

Version 2 replaces version 1, which folded at most 16,384 stacks, 32,768
nodes and 131,072 edges, read one source budget and stopped at a 30-second
deadline, and listed every stack's path in the answer. Version 2 folds every
record, keeps the fold between requests, pages the graph by node and serves
paths on demand. No stored evidence names a version 1 answer, so no reader of
it remains.

## Why

Each stack record answers one question: which frames were running when this
request, navigation, task or cookie write started. A researcher working
backward from a beacon wants the union: every path that reaches it, through a
same-process iframe, a posted task, a Wasm export and its JavaScript import,
or code that `eval` or `new Function` produced. `get_flow_graph` folds every
recorded stack of one session into that one graph. It is observed evidence
only: an edge exists because a recorded stack walked it.

## Inputs

`GET /api/flow-graph?session_id=[&generation=&cursor=&limit=]`
(`get_flow_graph`) answers one page of the graph.
`GET /api/flow-graph/paths?session_id=&generation=` with one of `node`,
`request_id` and `process_id`, or `digest` (`get_flow_graph_paths`), answers
the stacks that walk a node, that one renderer request named, or that have
one digest. `session_id` is required, nonzero and canonical; any other
parameter returns 400.

The fold reads every record of that session of these types
([native network v3](native-network-v3.md#request-initiator-stacks)):

| Type | Role |
| --- | --- |
| 34 `request_initiator_stack` | A request's stack; its sink is `METHOD host` from the parent `request_initiated` |
| 46 `navigation_initiator_stack` | A script navigation's stack; its sink is the navigation kind |
| 48 `async_task_stack` | A scheduling stack (timer, animation frame, idle callback, `postMessage`, `XMLHttpRequest.send`, `scheduler.postTask`, queued event) |
| 39 `script_cookie` | A cookie write that walked the stack (flags bits 1 and 2); its sink is the API |
| 35 `script_identity` | Script ID to realm, eval flag, start position and source digest |
| `request_initiated` | The `METHOD host` label of a request stack's sink |

The event index marks these types (`reb-event-index-v1/5`, kind `flow`), so a
fold reads the session's records of them and nothing else, in store order.
A record of the session that its decoder refuses counts in
`coverage.malformed_records`; a `script_cookie` record is checked by the rules
`get_cookie_provenance` applies. A store line the event index refused (not a
record, or a duplicate) is never read by any fold; the first such line is
`coverage.index_damage`. Stack, script and module artifacts are found by
SHA-256 in the artifact lookup's digest table (`reb-artifact-lookup-v1/5`),
then read in parallel and verified against their digest.

## Folding

The fold is kept per session in memory (the four sessions asked for most
recently) and only moves forward:

- **Forward only.** A request reads the session's records appended since the
  last one. A request folds for at most 10 seconds and then answers what it
  has, with `coverage.caught_up` false; the fold keeps its place and the next
  request goes on. Nothing is cut. A client that disconnects stops the fold
  where it is, and two requests for one session share one fold.
- **One decode per stack.** Records are grouped by `(process_id, isolate,
  digest)`, the isolate being the record's
  [stack scope](native-network-v3.md#stack-scope) (version 3 request stacks,
  version 2 `async_task_stack`, version 2 and 3 `script_cookie`; earlier
  versions are the document's). Each distinct stack is decoded once, when it
  first appears, and weighted by how many records named it; a stack seen again
  adds its weight along the plan it already has. A decoded stack segment is
  kept by digest, so a segment that many stacks carry is read once.
- **Late evidence.** A stack whose script identities or stack artifacts have
  not arrived yet waits for them and is planned again when they do; what it
  added before is taken back first, so nothing is counted twice. A new
  identity for a known script ID plans the graph again from its stacks.
- **One read per source.** The offsets frames name are gathered per script
  digest; a retained script or module is read when frames ask it for offsets
  it has not resolved, its UTF-16 positions resolved in one pass (as
  `get_request_stack` resolves them) and its function names read at the
  function start positions. A source the artifact lookup did not have yet is
  asked for again when the lookup moves on.
- **Realms.** A context is `process_id`, the isolate key (`isolate_key`, null
  for the document main thread) and the `execution_context_id` of the frame's
  `script_identity`, read in that isolate: script IDs are unique only per
  isolate, so a worker's frames resolve to the worker's scripts and never to a
  page script with the same ID. A task segment a message carried resolves in
  the isolate and process its own artifact names. A same-process iframe is its
  own realm, so a call between realms is a frame boundary. A frame without an
  identity record goes to its isolate's unidentified realm and never claims a
  boundary.
- **Nodes.** A function is keyed by realm, code (the script digest, else its
  script ID) and function position (JavaScript) or index (Wasm), so the same
  code compiled twice in one realm, such as one `eval` string run twice, is one
  node. Top-level script frames are their own node. Sinks are keyed by realm and
  label. `stacks` counts the distinct stacks through a node.
- **Edges.** Adjacent synchronous frames give `call` edges, caller to callee,
  with every distinct call site (line and column, or Wasm module offset).
  The await chain gives `await` edges from each awaiter; a Promise combinator is
  the edge's `label`. Each task segment gives a `task` edge from the innermost
  frame of the stack that scheduled the task to the task's first frame: the
  last awaiter of the await chain, else the outermost synchronous frame, and
  for an earlier segment the outermost frame of the later one. A microtask
  segment that carries the stack that registered its reaction (kind 9, state
  1, recorded with promise registration stacks on) is such a segment: its
  `task` edge, task `microtask`, runs from the innermost frame of the
  registration to the reaction's first frame, its `label` is the registering
  call (`Promise.then`, `Promise.catch`, `Promise.finally` or `await`), and the
  chain goes on from the registration's outermost frame. Microtask hops that
  recorded no registration (state 6) are listed in `via` on the next task
  edge; one whose registration was not retained (state 4 or 5) cuts the
  chain. A stack deeper than 1,024 frames gives one `omitted` edge across the
  dropped run. The innermost frame gets a `request`, `navigation` or
  `cookie_write` edge to each sink its records name. A stack that walks an
  edge more than once (a recursion, two segments naming one scheduling stack)
  counts it once: `count` sums the weights of the stacks that walk it and
  `stacks` counts them. Stacks that share an edge merge what they say about
  it: `via` is every hop any of them names, `label` every combinator, and
  `omitted` the largest dropped run.
- **Crossings.** `crosses` names `frame` (both realms known and different),
  `language` (JavaScript and Wasm) and `dynamic` (a call into eval code from
  other code).
- **Requests.** Every renderer request ID a stack's records name is kept with
  the stack, so `get_flow_graph_paths` finds a request's stacks among all of
  them. A request's `METHOD host` label waits for its stack record and is let
  go once the stack joins it.

Nothing is inferred. A frame whose source is missing keeps its script ID and a
`reason` (as `get_request_stack` names them). A stack whose artifact is
missing keeps its innermost frame, names no task entry and is counted under
`stacks.unresolved`. The chain is cut, and no edge bridges the cut, where the
first frame of a task is not known: a scheduling stack that was not retained,
a walk that stopped at 256 frames (segment flag bit 0, or an
`async_task_stack` with flag bit 0), an await chain past 32 frames (record bit
2), a chain past 32 segments (record bit 4) or a recorded cut (record bit 3).
The node where the chain stops carries `chain_cut`. A segment in state 7
`no_script` (the browser, the parser or a native callback queued the task) or
state 8 `origin_rejected` ends the chain without a cut: its task's first frame
is a known entry, and the node lists the reason and task kind in
`chain_ends`. After a frameless microtask hop the frames that registered the
reaction are unknown, so that end is a cut. `entries` counts a node only when
it is a known first frame.

## Answer

`schema` `flow-graph-v2`, `evidence` `observed`. `generation` names the
graph's node and edge IDs: it changes whenever the fold changes the graph and
is never reused, even across restarts. `complete` is `coverage.caught_up` and
`coverage.artifacts_caught_up`: every record and artifact the stores held is
folded. A graph that is not complete is still growing; nothing in it is cut.
`coverage.caught_up` is exact: it is true only when the event index read the
store to its end, never when an index pass stopped at its own time slice. The
full shape is the `FlowGraph` schema in [openapi.json](openapi.json).

Only what some stack walks is written: a node or edge that every stack left
when it was planned again is not, and the IDs are dense over what is.

**Pages.** The answer is paged, so no answer has to hold a whole large
session, and a page is a run of the generation's cached encoding, so any page
size is cheap to serve:

- Every page carries the head (`coverage`, `stacks`, `not_shown`,
  `node_count`, `edge_count`), every context and `analyst_names`.
- Nodes are grouped by context, contexts in first-seen order, so a context's
  nodes are the IDs from its `first_node` on. A page holds the nodes from
  `cursor` on: at least one, and as many more as keep it within `limit` nodes
  and edges (default 65,536).
- Each edge comes on the page that holds its later end, so a client that reads
  from cursor 0 along `next_cursor` has both ends of every edge it reads.
  Edge IDs are their places in that order across the pages.
- A request without `generation` folds first and answers a page of the
  graph it folded to. A request that names a generation folds nothing and
  answers a page of that graph, so the pages of one generation stay one graph
  while the stores grow; once the graph has moved on, it answers 409 and the
  client asks again without one.

`not_shown` lists what the stack records read cannot contain, by the versions
present, as `get_request_stack` does per record. Records with the stack scope
(request stack version 3, `async_task_stack` version 2): worklet stacks, and
those of a worker past the renderer's 32 stack tables;
`ServiceWorker.postMessage`, `Client.postMessage` and `window.postMessage` to
or from another process, which carry no task origin; calls that never reached
a recorded request, navigation, task or cookie write; and frames of another
renderer process, whose stacks are their own realms, joined to this page's
only by the `MessagePort`, `BroadcastChannel` and worker message task edges a
carried segment draws. Records from earlier builds: worker and worklet stacks
(walked on the document main thread only), `MessagePort` and worker messages,
calls that never reached a recorded request, navigation, task or cookie
write, and out-of-process frames (only their own stacks appear). A store
holding both lists the earlier records' worker and message gaps as theirs.

Contexts list every script origin by function count, every frame ID with the
records whose innermost frame was in the realm (`records`), and every tab ID.
An edge with no crossing omits `crosses`, and one whose sites resolve to no
position omits `sites`.

## Paths

`get_flow_graph_paths` (`flow-graph-paths-v1`) answers the distinct stacks
that walk a node (`node`), that one renderer request's
`request_initiator_stack` record named (`process_id` and `request_id`, as its
`request_initiated` record carries them), or that have one digest (`digest`,
optionally narrowed by `process_id`). `nodes` and `edges` are every node and
edge any matching stack walks, so one answer lights them all; `paths` is one
page of the matching stacks (`cursor`, `limit`, default 64 and at most 1,024
a page) in the order the session first recorded them, each with its own nodes
and edges, its occurrences, whether its frames were retained and the number
of requests it started. Pass the generation the IDs came from: the route
never folds, and answers 409 once the graph has moved on. A session not
folded yet is folded first.

## Bounds

None of the fold's own. What remains:

| What | Why |
| --- | --- |
| A request folds for 10 seconds, then answers | An answer with progress; the fold keeps its place and cuts nothing |
| Four sessions' folds are kept | Memory; a fifth session drops the least recently asked, which is folded again from its first record when next asked |
| The stack record's own bounds (256 frames walked, 1,024 frames deep, 32 awaiters, 32 segments) | The renderer's; each is reported as a cut or an `omitted` edge |

## UI

The Flow workspace's **Graph** pane reads the pages of one generation and
draws them on one canvas, read top to bottom like a disassembler's CFG. Each
realm (context) is a band titled by its script origin, realm, frame and
process, and a realm that calls or posts into another sits above it, so an
iframe sits below its parent, and a call between realms runs down across the
band boundary. Inside a band, rows are call depth. A card is one function: a
header tinted by its kind with its name, the number of distinct stacks
through it and its kind (`js`, `eval`, `wasm`, `chain`), then its location
and one row per edge it starts (call site, mnemonic, callee, what the edge
crosses, its count). A sink is a row of each function whose stacks reached it
rather than a card, unless no edge reaches it. Edges are coloured by kind:
`call`, `await` and `task`, a crossing (`crosses` not empty), and `request`,
`navigation` and `cookie_write`; `omitted` is dotted. Frame boundaries, task
kinds, JS and Wasm transitions and calls into eval are also written on their
rows, never colour alone. Pass-through frames inside one realm fold into a
chain card. A card lists every edge it starts, a page of rows at a time.

The pane reads, models, folds and measures in a worker (the page measures
font advances and sends them, and runs the same pipeline itself where no
worker starts) and lands each page in time slices. It draws the layered
layout first, then lays out each realm the Triskel budget accepts in the
background and swaps it in, keeping the selected card where it was on
screen. Selecting a card asks `get_flow_graph_paths` for the stacks through
it and lights them; choosing a request asks for its own. Lineage (V) draws
only the lit stacks' cards, left to right. Zoomed out below 4.5%, each realm
is one block with its name and counts, and the edges between realms are
bundled. A page the backend answers with a newer generation is read from
cursor 0 again, and a refold made while it was read is applied to the new
graph. The layout is presentation only and never changes this document. See
the [Research UI README](../apps/research-ui/README.md#flow-graph).

## Validation

`cargo test --lib flow_graph` builds stores where a top page posts into a
same-process iframe whose handler calls an eval'd helper and a Wasm export
whose JavaScript import fetches, and checks the realms, crossings, call sites,
weights, paths, missing bytes and malformed records. Every test reads its
graph three nodes and edges a page and checks each page against the
`FlowGraph` schema, that each page is a run of IDs and that each edge comes
with its later end. Others check that a growing store folds forward to the
graph a fresh fold gives, that identities and artifacts that arrive late are
joined without counting twice, that a cancelled fold stays consistent, and
that a client pages one generation while the store grows and is told when it
is gone. `tests/http.rs` checks both routes' statuses. The packaged app's
rendered UI test opens the Flow workspace and checks its layout.
