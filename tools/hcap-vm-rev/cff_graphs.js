/**
 * cff_graphs.js — structural arm-transition graphs for live CFF workers.
 *
 * Built from arm_clusters_*.json (+ entry_walks_* when present).
 * Reconstructive control-flow only; no cipher / solver logic.
 *
 * Workers: 298, 796 (84feb) · 349, 667 (63d9) · 874, 880 (e449)
 *
 * Run fixture: node /tmp/hcap-vm-rev/cff_graphs_fixture.js
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;

const SOURCES = {
  298: { file: 'arm_clusters_298_796.json', key: 'f298', build: '84feb', role: 'decrypt' },
  796: { file: 'arm_clusters_298_796.json', key: 'f796', build: '84feb', role: 'encrypt' },
  349: { file: 'arm_clusters_349_667.json', key: 'f349', build: '63d9', role: 'decrypt' },
  667: { file: 'arm_clusters_349_667.json', key: 'f667', build: '63d9', role: 'encrypt' },
  874: { file: 'arm_clusters_874_880.json', key: 'f874', build: 'e449', role: 'encrypt' },
  880: { file: 'arm_clusters_874_880.json', key: 'f880', build: 'e449', role: 'decrypt' },
};

const ENTRY_WALKS = {
  349: 'entry_walks_349_667.json',
  667: 'entry_walks_349_667.json',
  874: 'entry_walks_874_880.json',
  880: 'entry_walks_874_880.json',
};

const HOST_GATE_RE = /^host_a_/;
const MBA_RE = /^mba_via_/;
const BULK_RE = /^codec_bulk_via_/;
const RESULT_PACK = 'result_pack_exit';

const _jsonCache = new Map();
function loadJson(name) {
  if (_jsonCache.has(name)) return _jsonCache.get(name);
  const p = path.join(ROOT, name);
  const data = JSON.parse(fs.readFileSync(p, 'utf8'));
  _jsonCache.set(name, data);
  return data;
}

/**
 * Prefer the summarized nextState. When constsTop holds exactly two in-range
 * state ids including that nextState, treat as if/else and keep both (LIVE
 * docs: e.g. 796 arm 57 → 36|119). Longer const lists are left as single-edge
 * to avoid mistaking frame/offset immediates for transitions.
 */
function nextStatesOf(summary, nArms) {
  const ns = summary.nextState;
  const fromConsts = [
    ...new Set(
      (summary.constsTop || []).filter((c) => Number.isInteger(c) && c >= 0 && c < nArms)
    ),
  ].sort((a, b) => a - b);

  if (typeof ns === 'number') {
    if (fromConsts.length === 2 && fromConsts.includes(ns)) return fromConsts;
    return [ns];
  }
  if (fromConsts.length === 2) return fromConsts;
  return [];
}

function clusterHistogram(byCluster) {
  const hist = {};
  for (const [cluster, idxs] of Object.entries(byCluster || {})) {
    hist[cluster] = idxs.length;
  }
  return hist;
}

function pickNotables(summaries) {
  const host_gate = [];
  const mba = [];
  const result_pack = [];
  const bulk = [];
  for (const s of summaries) {
    const item = {
      state: s.idx,
      cluster: s.cluster,
      nextStates: undefined, // filled by caller after nArms known
      calls: s.calls,
      nops: s.nops,
    };
    if (HOST_GATE_RE.test(s.cluster)) host_gate.push(item);
    else if (MBA_RE.test(s.cluster)) mba.push(item);
    else if (s.cluster === RESULT_PACK) result_pack.push(item);
    else if (BULK_RE.test(s.cluster)) bulk.push(item);
  }
  return { host_gate, mba, result_pack, bulk };
}

function buildGraph(funcId) {
  const meta = SOURCES[funcId];
  if (!meta) throw new Error('unknown CFF worker ' + funcId);
  const blob = loadJson(meta.file);
  const raw = blob[meta.key];
  if (!raw) throw new Error(`missing ${meta.key} in ${meta.file}`);

  const nArms = raw.nArmsParsed;
  const entryState = raw.entryState;
  const summaries = raw.summaries;

  const nodes = summaries.map((s) => {
    const nextStates = nextStatesOf(s, nArms);
    return {
      state: s.idx,
      cluster: s.cluster,
      nops: s.nops,
      calls: s.calls,
      nextStates,
      returns: !!s.returns,
      nextState: s.nextState, // raw single field from classify
    };
  });

  const edges = [];
  for (const n of nodes) {
    for (const t of n.nextStates) {
      edges.push({ from: n.state, to: t, via: n.cluster });
    }
  }

  const notables = pickNotables(summaries);
  for (const group of Object.values(notables)) {
    for (const item of group) {
      const node = nodes[item.state];
      item.nextStates = node ? node.nextStates.slice() : [];
    }
  }

  // bulk notables: keep compact index list + count (full list is large)
  const bulkStates = notables.bulk.map((b) => b.state);
  notables.bulk_count = bulkStates.length;
  notables.bulk_states = bulkStates;
  // retain a few sample bulk node records for readability
  notables.bulk_samples = notables.bulk.slice(0, 5);
  delete notables.bulk;

  let entryWalk = null;
  const walkFile = ENTRY_WALKS[funcId];
  if (walkFile && fs.existsSync(path.join(ROOT, walkFile))) {
    const walks = loadJson(walkFile);
    const candidates = Object.entries(walks).filter(
      ([k, v]) => Array.isArray(v) && (k.includes(String(funcId)) || k.startsWith('f' + funcId))
    );
    if (candidates.length) entryWalk = candidates[0][1];
  }

  return {
    func: funcId,
    build: meta.build,
    role: meta.role,
    source: blob.source || meta.file,
    entryState,
    nArms,
    nodes,
    edges,
    clusterHistogram: clusterHistogram(raw.byCluster),
    notables,
    entryWalk,
    note: 'Structural CFF arm graph from cluster JSON. Not a cipher reconstruction.',
  };
}

const GRAPHS = {};
for (const id of Object.keys(SOURCES).map(Number)) {
  GRAPHS[id] = buildGraph(id);
}

function summaryCounts(g) {
  return {
    func: g.func,
    build: g.build,
    role: g.role,
    entryState: g.entryState,
    nArms: g.nArms,
    nodes: g.nodes.length,
    edges: g.edges.length,
    branchyNodes: g.nodes.filter((n) => n.nextStates.length > 1).length,
    host_gate: g.notables.host_gate.map((h) => h.state),
    mba: g.notables.mba.map((m) => m.state),
    result_pack: g.notables.result_pack.map((r) => r.state),
    bulk_count: g.notables.bulk_count,
  };
}

module.exports = {
  SOURCES,
  GRAPHS,
  graphs: GRAPHS,
  buildGraph,
  nextStatesOf,
  summaryCounts,
  // named per-worker aliases
  graph298: GRAPHS[298],
  graph796: GRAPHS[796],
  graph349: GRAPHS[349],
  graph667: GRAPHS[667],
  graph874: GRAPHS[874],
  graph880: GRAPHS[880],
};

if (require.main === module) {
  for (const id of [298, 796, 349, 667, 874, 880]) {
    console.log(JSON.stringify(summaryCounts(GRAPHS[id])));
  }
}
