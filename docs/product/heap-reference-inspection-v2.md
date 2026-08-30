# Heap Reference Inspection v2

## Purpose

Heap Reference Inspection explains why a matching V8 heap node remains visible,
even when it has no strong path from a V8 root. It extends snapshot search with
explicit reachability and bounded incoming-reference evidence. It does not
execute page code, invoke accessors, mutate the target, or persist captured heap
content.

## User workflow

1. Open Memory and select Heap snapshot.
2. Enter a value or V8 node name.
3. Choose all, root-reachable, or unreachable reference scope.
4. Capture and search the authorized live target.
5. Select a result to inspect its shortest strong retaining path and prioritized
   incoming references.

The result list labels every node as root-reachable or unreachable. An
unreachable result explains that no indexed non-weak root path exists, then
shows incoming internal, hidden, weak, context, shortcut, property, and element
references without promoting any one reference to a causal claim.

## Native graph semantics

The native C++20 analyzer treats snapshot node zero as the V8 root. Reachability
uses breadth-first traversal over all indexed edges except `weak`, so the stored
parent edge is also a shortest retaining path. The selected scope is applied
only after that traversal. This prevents an early result limit from hiding later
unreachable matches.

Incoming references include weak edges and are counted by a complete bounded
edge scan. At most 12 references are returned for each result. Selection is
deterministic and prioritizes `internal` and `hidden`, then `weak`, then
`context` and `shortcut`, then remaining edge types. The full incoming count and
the display-limit state remain visible.

An unreachable classification is exact only within indexed coverage. Node,
edge, and string truncation are reported separately and never hidden. An
unreachable result is not called a partial retaining path. A reachable path is
partial only when its 12-step display limit is reached.

## Version 2 response

Snapshot search protocol version 2 adds:

- `scope`, `matched_nodes`, `reachable_nodes`, and `reference_limit` at the
  response level;
- `reachable`, `incoming_reference_count`, and
  `incoming_reference_limit_reached` for every result;
- `edge_type` for every retaining-path step;
- a bounded `incoming_references` list containing source node ID, source node
  type and name, edge type, and edge name.

The debugger bridge rejects an unknown scope, noncanonical node identifiers,
inconsistent match counts, scope and reachability mismatches, oversized paths
or reference lists, incorrect limit flags, and malformed native output before
the UI replaces its last known-good state.

## Performance and privacy

The implementation uses 32-bit graph indices, one-byte result lookup entries,
and fixed 12-item top-reference heaps. Reference strings are allocated only
after a candidate survives ranking. Snapshot input remains a read-only,
sequentially advised mapping and is deleted immediately after each search.

The normal limits remain 256 MiB per snapshot, 2,000,000 nodes, 8,000,000
edges, 2,000,000 strings, 64 MiB of retained string text, 50 results, 12 path
steps, and 12 incoming references per result. No heap bytes or search results
are written to the evidence store.
