/**
 * cff_graphs_fixture.js — structural asserts for arm-transition graphs.
 *
 * Checks entry states + presence of host-gate + bulk clusters per build.
 * Reconstructive only; does not execute wasm or invent cipher.
 *
 * Run: node /tmp/hcap-vm-rev/cff_graphs_fixture.js
 */
'use strict';

const assert = require('assert');
const {
  GRAPHS,
  graph298,
  graph796,
  graph349,
  graph667,
  graph874,
  graph880,
  summaryCounts,
} = require('./cff_graphs.js');

/** Expected entry states from LIVE_CFF_* / STATUS.json builds. */
const EXPECT = {
  298: {
    build: '84feb',
    role: 'decrypt',
    entryState: 21,
    hostCluster: 'host_a_Va_gate',
    bulkCluster: 'codec_bulk_via_1005',
    mbaCluster: 'mba_via_710',
  },
  796: {
    build: '84feb',
    role: 'encrypt',
    entryState: 87,
    hostCluster: 'host_a_Va_gate',
    bulkCluster: 'codec_bulk_via_1005',
    // encrypt has no mba_via_710 arm
    mbaCluster: null,
  },
  349: {
    build: '63d9',
    role: 'decrypt',
    entryState: 52,
    hostCluster: 'host_a_Cc_gate',
    bulkCluster: 'codec_bulk_via_937',
    mbaCluster: 'mba_via_273',
  },
  667: {
    build: '63d9',
    role: 'encrypt',
    entryState: 121,
    hostCluster: 'host_a_Cc_gate',
    bulkCluster: 'codec_bulk_via_937',
    mbaCluster: null,
  },
  874: {
    build: 'e449',
    role: 'encrypt',
    entryState: 103,
    hostCluster: 'host_a_t_gate',
    bulkCluster: 'codec_bulk_via_537',
    mbaCluster: null,
  },
  880: {
    build: 'e449',
    role: 'decrypt',
    entryState: 70,
    hostCluster: 'host_a_t_gate',
    bulkCluster: 'codec_bulk_via_537',
    mbaCluster: 'mba_via_406',
  },
};

assert.strictEqual(Object.keys(GRAPHS).length, 6, 'six worker graphs');
assert.strictEqual(graph298, GRAPHS[298]);
assert.strictEqual(graph796, GRAPHS[796]);
assert.strictEqual(graph349, GRAPHS[349]);
assert.strictEqual(graph667, GRAPHS[667]);
assert.strictEqual(graph874, GRAPHS[874]);
assert.strictEqual(graph880, GRAPHS[880]);

const counts = {};

for (const [idStr, exp] of Object.entries(EXPECT)) {
  const id = +idStr;
  const g = GRAPHS[id];
  assert.ok(g, `graph ${id} present`);
  assert.strictEqual(g.func, id);
  assert.strictEqual(g.build, exp.build);
  assert.strictEqual(g.role, exp.role);
  assert.strictEqual(g.entryState, exp.entryState, `${id} entryState`);
  assert.strictEqual(g.nodes.length, g.nArms, `${id} nodes === nArms`);
  assert.ok(g.nodes.length > 0, `${id} has nodes`);
  assert.ok(g.edges.length > 0, `${id} has edges`);

  const entryNode = g.nodes[g.entryState];
  assert.ok(entryNode, `${id} entry node exists`);
  assert.strictEqual(entryNode.state, g.entryState);

  // host gate
  assert.ok(g.notables.host_gate.length >= 1, `${id} has host_gate notable`);
  assert.ok(
    g.clusterHistogram[exp.hostCluster] >= 1,
    `${id} histogram has ${exp.hostCluster}`
  );
  for (const h of g.notables.host_gate) {
    assert.strictEqual(h.cluster, exp.hostCluster);
  }

  // bulk
  assert.ok(g.notables.bulk_count >= 1, `${id} has bulk clusters`);
  assert.ok(
    g.clusterHistogram[exp.bulkCluster] >= 1,
    `${id} histogram has ${exp.bulkCluster}`
  );
  assert.strictEqual(
    g.notables.bulk_count,
    g.clusterHistogram[exp.bulkCluster],
    `${id} bulk_count matches histogram`
  );

  // mba (decrypt-leaning workers)
  if (exp.mbaCluster) {
    assert.ok(g.notables.mba.length >= 1, `${id} has mba notable`);
    assert.ok(g.clusterHistogram[exp.mbaCluster] >= 1, `${id} has ${exp.mbaCluster}`);
  }

  // result pack present on every worker
  assert.ok(
    g.notables.result_pack.length >= 1,
    `${id} has result_pack_exit`
  );

  // edges reference existing nodes or are recorded targets
  for (const e of g.edges) {
    assert.ok(Number.isInteger(e.from) && Number.isInteger(e.to), `${id} edge ints`);
    assert.ok(e.from >= 0 && e.from < g.nArms, `${id} edge.from in range`);
  }

  // nextStates consistency
  for (const n of g.nodes) {
    assert.ok(Array.isArray(n.nextStates), `${id} node ${n.state} nextStates[]`);
    if (typeof n.nextState === 'number') {
      assert.ok(
        n.nextStates.includes(n.nextState),
        `${id} node ${n.state} nextStates includes nextState`
      );
    }
  }

  // entry walks attached when files exist
  if (id === 349 || id === 667 || id === 874 || id === 880) {
    assert.ok(Array.isArray(g.entryWalk) && g.entryWalk.length > 0, `${id} entryWalk`);
    assert.strictEqual(g.entryWalk[0].state, g.entryState, `${id} walk starts at entry`);
  }

  counts[id] = summaryCounts(g);
}

// Cross-build polarity sanity (decrypt vs encrypt pairs)
assert.strictEqual(graph298.role, 'decrypt');
assert.strictEqual(graph796.role, 'encrypt');
assert.strictEqual(graph349.role, 'decrypt');
assert.strictEqual(graph667.role, 'encrypt');
assert.strictEqual(graph880.role, 'decrypt');
assert.strictEqual(graph874.role, 'encrypt');

console.log('cff_graphs_fixture: ok');
console.log(JSON.stringify(counts, null, 2));
