# Flow graph v2: request lineage and VM evidence

Status: draft for review. No code exists for anything in this document beyond
[flow graph v1](../../protocol/flow-graph-v1.md), which it extends.

## Why

A researcher works backward from a request: what code built it, through
which frames and tasks, into which Wasm, and which VM handlers ran on the way.
The evidence for each step already exists in separate places, and no view
joins it:

| Today | What it shows | What it cannot show |
| --- | --- | --- |
| Backtraces **Steps** ([Request Origin Trace v1](request-origin-trace-v1.md)) | one request's recorded predecessors | one chain only: each step keeps one edge and drops the rest, so `issued_during_invocation` and `invocation_value_flow` never appear together |
| Backtraces **Flow graph** (v1) | every recorded stack, folded across realms, JavaScript, eval and Wasm | invocations, VM records, signals; requests are rows labelled `METHOD host` |
| VM **fingerprint evidence graph** ([anti-bot VM detection v1](anti-bot-vm-detection-v1.md)) | artifact → VM candidate → browser signals → requests, with an epistemic state per edge | it is computed in `vm.rs` and never drawn; the UI lists "correlated requests" |
| Sources and VM **Graph** (#447) | a Wasm or bytecode function's basic blocks | no runtime overlay: which `br_table` arms ran, how often, in which call |
| VM Lab **Native observations**, **Host links**, Xrefs | `br_table`, `call_indirect`, guest dispatch and host-link rows | where in the call graph each row ran, and which request it led to |

The join keys between these already exist and are exact. Nothing performs the
joins:

- **Wasm frame ↔ VM record.** A stack frame gives (process, script ID,
  function index, module offset). `script_identity` gives the SHA-256 of the
  module's wire bytes, which equals the module artifact's SHA-256. `br_table`
  (17), `call_indirect` (20), execution outcome (27) and guest records (18, 19)
  carry (process, module artifact, function index, module offset).
- **Tracked call ↔ function.** `js_invocation_start` carries (process,
  script ID, anchor offset). The anchor is V8's function start position, the
  same unit as a stack frame's function start. The join is by
  (process, script ID, position), so the UTF-8 versus UTF-16LE hash difference
  between `script_identity` and site keys never matters.
- **Tracked call ↔ Wasm and requests.** `(session, process, invocation_id)`
  is on `br_table` v2+, `call_indirect` v2+, guest invocation v4, execution
  outcomes and `js_invocation_request`. That record's `request_id` is the
  renderer request ID, the same ID flow-graph paths list.
- **Tracked call ↔ request body.** `invocation_value_flow` already matches a
  settle digest in a retained request body (correlated, exact bytes only).
- **Request ↔ signals.** The request signal profile names canvas through
  runtime categories by `parent_chain` (observed) or `same_context`
  (correlated).

## Evidence states

Every edge in every design carries one state, and the drawing never lets one
pass for another. These are the fingerprint evidence graph's four states plus
Origin Trace's time adjacency:

| State | Meaning | Drawn |
| --- | --- | --- |
| `observed` | a recorded stack frame, parent record or identity names both ends | solid |
| `correlated` | shared context or an exact digest match, not causality | dashed, labelled |
| `inferred` | bounded static analysis | dotted, labelled |
| `time_adjacent` | only order and timing | hairline, labelled, off by default |
| `unknown` | required evidence missing; the gap is the node | a cut, never an edge |

No design adds a time window, a URL match or a "last known" guess as a
relation.

## Design A: request lineage

**Idea.** Choosing a request builds its lineage: a bounded directed graph of
everything that led to it, replacing the single chain. The request is the
right edge of the drawing and its causes extend left.

```text
 click / timer / postMessage      top.test             frame.test (iframe)              request
 ───────────────────────────►  init ──postMessage──► onMessage ─► bridge ─► run (wasm) ─► POST collect
                                                                    │        │ br_table +0x2a  ×16
                                                       hsw#12 ──────┘        │ call_indirect → hash
                                                       settle ┄┄┄ value flow ┄┄┄┄┄┄┄┄┄┄┄┄► body.n
```

**Sources.**
- **Request lifecycle hops:** the origin-trace edges.
- **The stacks naming the request:** the flow-graph paths whose
  `requests` include it.
- **The tracked call that issued it:** `issued_during_invocation`.
- **That call's Wasm records:** matched by invocation ID.
- **Value flow:** into the body.
- **Signal categories:** from the signal profile.
- **VM candidates:** from the analysis graph.

**Limits.**
- Bounded to about 512 nodes per request.
- Alternatives are kept, with their states, instead of dropped.

**Strengths.**
- It answers the question a researcher asks first, directly.
- It is small, so it reads well at full size.
- It fixes the lost alternatives in Steps.

**Weaknesses.**
- It is per request: no session picture, and no way to see that two requests
  share a function.
- It repeats flow-graph folding in a second place.

## Design B: one evidence graph with layers

**Idea.** Generalize flow graph v1 into one typed, session-wide graph with
layers. Every view above becomes a projection of it:
- Steps is the request's lineage drawn as a chain.
- The VM finding graph is the Analysis layer for one artifact.
- Design A is the subgraph reachable backward from one request.

**Nodes.**
- **Realm:** drawn as a cluster.
- **Function:** `js`, `eval`, `wasm`, `chain` or top level, as in v1.
- **Request:** method, host, path, status and renderer ID, with its
  lifecycle hops collapsed into it.
- **Navigation and cookie write.**
- **Tracked call:** one admitted call of an armed function, with its settle.
- **Dispatch site:** a Wasm `br_table` or `call_indirect` site, or a JS
  dispatch site.
- **Guest handler:** an opcode, when an adapter decodes the guest.
- **Signal:** canvas, WebGL, audio, navigator, and the other categories.
- **VM candidate:** from analysis.

**Edges.**

| Edge | From → to | Source records | State |
| --- | --- | --- | --- |
| `call`, `await`, `task`, `omitted` | function → function | request, navigation, async and cookie stacks (34, 46, 48, 39) | observed |
| `request`, `navigation`, `cookie_write` | function → sink | the stack's innermost frame | observed |
| `lifecycle` | request hop → hop | origin-trace `request_initiator`, `request_lifecycle` (`artifact_request`: correlated) | observed |
| `called_as` | tracked call → function | `js_invocation_start` (process, script ID, anchor) | observed |
| `issued_during` | tracked call → request | `js_invocation_request` state 2 | observed |
| `value_flow` | tracked call → request | `invocation_value_flow` | correlated |
| `dispatch` | Wasm function → dispatch site | `br_table` 17 (selector histogram, invocation ID) | observed |
| `indirect_call` | Wasm function → Wasm function | `call_indirect` 20, resolved callee | observed |
| `direct_caller` | Wasm function → Wasm function | `br_table` v3 `direct_caller` same-instance | observed |
| `guest_dispatch` | guest invocation → guest handler | guest records 18, 19 | observed |
| `host_call` | guest handler → signal or request | VM host links | observed or correlated, as host links already state |
| `signal` | signal → request | request signal profile | observed (`parent_chain`) or correlated (`same_context`) |
| `candidate` | artifact or function → VM candidate → request | `vm.rs` finding graph | inferred, then correlated |

**Layers.**
- **Calls** is v1 and on by default. Requests, Tracked calls, VM, Signals and
  Analysis are toggles.
- Each layer has its own bounds, coverage and omissions, so turning one on can
  only add evidence and labelled gaps.
- All joins happen in the backend on exact keys. The UI never joins.

**Strengths.**
- One model, so a new record type becomes a new layer, not a new screen.
- It shows when requests share code.
- It puts VM evidence where it ran in the call graph.

**Weaknesses.**
- It is the largest build.
- A dense session needs the request filter to stay readable.

## Design C: tracked-call timeline

**Idea.** For each tracked function (any function, through **Track calls**;
`hsw` is just one), draw each call as a lane in recorded sequence order:

```text
hsw#12  ▶ start ── sync ──┐ promise job ── wasm run ▸ br_table ×9 ▸ call_indirect ×3 ── settle ✓ string 2.1 KB
                          └─ request GET /checksiteconfig (issued during)          ┄┄ value flow ┄► POST /getcaptcha
hsw#13  ▶ start ── sync ── promise job ── wasm run ▸ br_table ×7 ──────────────────────────── settle ✓
```

**Sources.**
- `js_invocation_start`, `js_invocation_settle` and `js_invocation_request`.
- The Wasm records that carry the call's invocation ID.
- The value flow into later requests.

**Ordering.**
- The axis is each renderer's sequence order, never wall-clock time.
- Two calls in one process interleave exactly as recorded.

**Strengths.**
- It is the natural view of asynchronous work and VM sampling.
- Overlapping calls stay separate, which time windows cannot do.

**Weaknesses.**
- It covers only armed functions: 8 sites, 256 calls, 64 per site.
- It depends on invocation capture, which no rebuilt Brave has run yet.
- It is not a picture of the session.

## Recommendation

Use **Design B** as the data model. Use **Design A** as what the Flow graph
shows when a request is chosen. Use **Design C** as a lens on a tracked-call
node, opened from it.

The reasoning:
- B is the only design that generalizes: each later probe becomes a layer, not
  a screen.
- A is the view researchers need most, and it falls out of B as a subgraph.
- C needs records no live build has produced yet.

**What the UI gains.**
- **Request picker.** Choosing a request switches to lineage. Its causes read
  left to right into the request card. **Lineage only** hides the rest of the
  session, and the full graph stays one toggle away.
- **Request cards.** A request becomes a card when it is the subject: method,
  host, path, status, body fields, and any value-flow edge into a field.
  Elsewhere it stays a row of the function that made it, as in v1.
- **Wasm cards.** Dispatch rows such as `br_table +0x2a · 16 samples ·
  5 selectors` and `call_indirect +0x91 → hash`, each tagged with the tracked
  call it ran in.
- **Side-by-side pane.** Selecting a function opens its body beside the graph:
  JavaScript at the line, or the Wasm function's CFG (Sources Graph) with the
  sampled `br_table` block marked and its arms shaded by count.
- **Tracked-call cards.** For example `hsw#12 · fulfilled string 2.1 KB`, with
  edges to its function, its Wasm activity and its requests.
- **Analysis layer.** It draws the fingerprint evidence graph, in dotted
  inferred and dashed correlated edges, onto the same functions and requests.

## Contract

`get_flow_graph` stays the one operation. It gains:
- `layers`, a list of layer names;
- an optional request selector (process, renderer request ID, or the four-field
  request root VM analysis already takes).

The schema becomes `flow-graph-v2`, a superset of v1. Each layer adds its
node and edge kinds, a `coverage` and `omissions` block, and its own bounds,
modelled on the VM workspace limits (4,096 rows per stream). A v1 client
asking without `layers` gets the v1 answer.

## Phases

| Phase | Scope | Can be built and checked here |
| --- | --- | --- |
| 0 | Request rows and cards name path, status and renderer ID, not only `METHOD host`. The value-flow body limit is stated two ways (16 MiB retained, as the invocation protocol and design say, and 1 MiB read by `origin_trace.rs`); settle on one. | yes |
| 1 | `flow-graph-v2` with the Requests and Tracked calls layers; request lineage replaces Steps' single chain; the side-by-side pane | yes, on synthetic stores from the existing C++ invocation encoders |
| 2 | The VM layer: `br_table`, `call_indirect`, guest and host-link joins; dispatch rows on Wasm cards; the runtime overlay on Sources Graph | yes, on the native Wasm goldens `make native-wasm-golden-check` already exports |
| 3 | Signals and Analysis layers; the fingerprint evidence graph drawn for the first time | yes |
| 4 | Live acceptance of request stacks, invocations and the VM streams on a rebuilt Brave, then the probes v1 names as not covered: the caller of `.then`, cross-process `postMessage`, workers, and a complete call-edge table | needs the Brave build machine |

## Bounds that stay

- Every native stream keeps its budget: 16 `br_table` and 16 `call_indirect`
  records per configuration, 256 tracked calls, and 1,024 stacks per
  configuration. A layer never makes a budget look larger than it was; it
  shows the stream's own gap.
- Nothing in this design changes capture, adds a probe or reads values that
  capture does not already retain. [SAFETY.md](../../SAFETY.md) applies
  unchanged.

## Open questions

1. Should Steps stay as its own view, or become the lineage drawn as a chain
   inside the Flow graph?
2. Should requests be cards everywhere once the Requests layer is on, or cards
   only for the chosen request, as above?
3. Which comes first after phase 1: the VM layer (phase 2) or Signals and
   Analysis (phase 3)?
4. Should a tracked call open the timeline (Design C) in the side pane, or as
   its own Backtraces mode?
