# Memory Origin Trace v1

## Purpose

Memory Origin Trace finds the first sampled JavaScript function boundary whose
V8 heap contains a requested value or node name. It adds a temporal dimension
to live-object and static snapshot search while remaining explicit about what
the evidence proves. The highlighted function is a bounded origin candidate,
not a claim about an exact source statement or every asynchronous transition.

## User flow

1. Open Memory and select Origin trace.
2. Enter a value or V8 node name and choose all, root-reachable, or unreachable
   reference scope.
3. Choose zero to eight steps before and zero to sixteen steps after the first
   match.
4. Arm the trace, then click the page action that creates or changes the value.
5. Inspect the chronological function-boundary rows. The first matching row is
   highlighted and can open its live source location.
6. Stop an active trace or clear a completed result explicitly.

## Sampling semantics

The bridge installs a temporary click event-listener breakpoint. At each
resulting debugger pause it captures one V8 heap snapshot, runs the native probe,
deletes the temporary file, and issues `Debugger.stepOut` to sample the next
function-return boundary. Source selection skips obvious framework and vendor
frames when a user-land frame is already present in the captured call stack.
It does not evaluate page expressions or install JavaScript wrappers.

The trace retains only the configured before window, the first matching step,
and the configured after window. It finishes when that window is complete, the
execution becomes quiet, the researcher stops it, 32 pauses are sampled, five
minutes elapse, the target disconnects, or a bounded capture fails.

## Native probe

`reb-heap-snapshot --probe` uses protocol version 1. It validates the same V8
snapshot and resource limits as full search, but stops at the first matching
node. For `all` scope it does not allocate a reachability graph or index edges.
Reachable and unreachable scopes allocate a compact one-byte reachability map
and 32-bit traversal queue, then stop at the first in-scope match. The response
reports analyzed nodes, total nodes, indexed edges, total edges, duration, the
first match, and every coverage limit.

## Debugger state contract

The debugger snapshot exposes `memory_origin_trace` protocol version 1 with:

- trace identity, target identity, query, scope, and case mode;
- lifecycle state: idle, armed, capturing, stepping, stopping, found,
  not_found, aborted, or error;
- requested before and after windows, the fixed 32-step limit, elapsed time,
  first-match step, partial status, and named limit reason;
- at most 25 retained rows, each with function location, capture size, native
  probe coverage, match state, and one bounded representative match.

The Python bridge and UI both reject malformed identifiers, counts, windows,
state combinations, out-of-order steps, mismatched match objects, oversized
captures, and invalid coverage claims before replacing the last valid state.

## Safety and privacy

- The action is explicit, target-scoped, and read-only.
- Only one trace may control the debugger at a time.
- Manual debugger and heap actions are rejected while the trace is active.
- Accessors and page expressions are not evaluated.
- Snapshot files are user-only temporary files and are deleted after every
  probe, including failure paths.
- Trace results remain ephemeral and are not written to the evidence store.
- Missing after-window steps, node, edge, or string limits remain visible as
  partial coverage rather than being treated as complete absence.
