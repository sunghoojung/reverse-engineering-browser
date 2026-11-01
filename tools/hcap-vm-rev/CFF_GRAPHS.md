# CFF arm-transition graphs

Reconstructive **structural** control-flow only. Not a solver; no cipher / proof math.

Graphs are derived from existing `arm_clusters_*.json` (produced by `classify_arms_*.js`).
No new wasm lifting.

## Module

| File | Role |
|------|------|
| [`cff_graphs.js`](./cff_graphs.js) | Builds + exports graphs for workers **298, 796, 349, 667, 874, 880** |
| [`cff_graphs_fixture.js`](./cff_graphs_fixture.js) | Asserts entry states, host-gate, bulk (+ mba on decrypt) |

```js
const { GRAPHS, graph298 } = require('./cff_graphs.js');
// GRAPHS[298].entryState, .nodes, .edges, .clusterHistogram, .notables
```

Each graph:

| Field | Meaning |
|-------|---------|
| `entryState` | CFF selector seed (`local.set 3` before loop) |
| `nodes[]` | `{ state, cluster, nops, calls, nextStates[], nextState, returns }` |
| `edges[]` | `{ from, to, via }` — one per recorded transition |
| `clusterHistogram` | cluster → arm count |
| `notables` | `host_gate`, `mba`, `result_pack`, `bulk_count` / `bulk_states` / `bulk_samples` |
| `entryWalk` | linear walk from `entry_walks_*.json` when present |

### Branchy `nextStates`

Cluster summaries store a single `nextState` (last `i32.const` before `local.set 3`).
When `constsTop` contains **exactly two** in-range state ids including that `nextState`,
both are kept as an if/else fork (e.g. 796 arm 57 → `36|119` in `LIVE_CFF_298_796.md`).
Otherwise only the summarized `nextState` is recorded (avoids treating bulk/frame immediates as edges).

## Builds

| Build | Decrypt | Encrypt | Host gate | Bulk | MBA (decrypt) |
|-------|--------:|--------:|-----------|------|---------------|
| 84feb | **298** entry 21 | **796** entry 87 | `host_a_Va_gate` | `codec_bulk_via_1005` | `mba_via_710` |
| 63d9 | **349** entry 52 | **667** entry 121 | `host_a_Cc_gate` | `codec_bulk_via_937` | `mba_via_273` |
| e449 | **880** entry 70 | **874** entry 103 | `host_a_t_gate` | `codec_bulk_via_537` | `mba_via_406` |

Sources: `arm_clusters_298_796.json`, `arm_clusters_349_667.json`, `arm_clusters_874_880.json`.
Walks: `entry_walks_349_667.json`, `entry_walks_874_880.json` (298/796 walks live in LIVE docs only).

## Run

```bash
node /tmp/hcap-vm-rev/cff_graphs.js            # print per-worker counts
node /tmp/hcap-vm-rev/cff_graphs_fixture.js    # asserts
```

See also: `LIVE_CFF_298_796.md`, `LIVE_CFF_349_667.md`, `LIVE_CFF_874_880.md`, `STATUS.json`.
