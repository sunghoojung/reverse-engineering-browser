/* Client of the backend's Triskel route, POST /api/graph-layout
 * (graph-layout-v1, protocol/http-api.md#graph-layout), shared by the flow
 * graph and block graph layout workers, which load it with importScripts; the
 * page loads it for the flow graph's on-thread fallback. It sends the graphs
 * it is given, checks each answer's shape, and keeps Triskel's drawing only
 * where it is not much wider or taller than the caller's own layout. A graph
 * it does not lay out gets a reason, `{code}` with the detail its code
 * names, which each view words for itself:
 *   large           past AUTOMATIC, so only sent when the caller asks (`all`)
 *   cancelled       the caller's signal stopped the request
 *   wider, taller   Triskel's drawing is `ratio` times the caller's
 *   mismatch        the answer does not fit what was sent
 *   failed          Triskel's `status` (failed or timeout) and `detail`
 *   status          the route answered HTTP `status`
 *   route_failed    the request failed; `detail` says how
 * Callers add their own codes: one_card or one_block (nothing to lay out)
 * and not_served (this shell has no route). */
'use strict';

const graphLayoutClient = (() => {
  /* The route lays out graphs of any size with no deadline. Triskel is sent
   * a graph without being asked only up to this size: on structured control
   * flow it takes about 1.5 s at 2,000 nodes, 10 s at 8,000 and a minute at
   * 16,000, and on tree-like graphs its time grows with the square of the
   * node count. Past it, the caller draws its own layout at once and offers
   * Triskel, which then runs on request with no size limit. */
  const AUTOMATIC = Object.freeze({graphNodes: 2000, graphEdges: 8000});
  /* Triskel's drawing is kept unless it is more than `widen` times as wide
   * as the caller's and over `freeWidth` px, or as many times as tall and
   * `freeHeight` px taller: Triskel does not stack a wide fan, and it stacks
   * loop bodies. */
  const ACCEPT = Object.freeze({widen: 1.6, freeWidth: 1400, freeHeight: 1600});
  /* Triskel's answers by graph: a new layout of mostly the same graphs (a
   * chain folded in one realm, a refresh) sends only those that changed. A
   * worker lives while its view is shown; this keeps its last answers. */
  const CACHE_ENTRIES = 64;
  const cache = new Map();

  const round = value => Math.round(value * 100) / 100;
  const near = (a, b) => Math.abs(a - b) < 0.01;

  /** A route's points from a flat x, y list moved by (dx, dy): repeated
   * points, and the middle one of three in a vertical or horizontal line,
   * are dropped. */
  function routePoints(flat, dx = 0, dy = 0) {
    const points = [];
    for (let i = 0; i + 1 < flat.length; i += 2) {
      const x = flat[i] + dx, y = flat[i + 1] + dy, last = points.length - 2;
      if (last >= 0 && near(points[last], x) && near(points[last + 1], y)) continue;
      if (last >= 2) {
        const ax = points[last - 2], ay = points[last - 1], bx = points[last], by = points[last + 1];
        if ((near(ax, bx) && near(bx, x)) || (near(ay, by) && near(by, y))) points.length = last;
      }
      points.push(x, y);
    }
    return points;
  }

  /** A graph's cache key: its counts and a 64-bit hash of its node sizes,
   * as sent, and edges. */
  function graphKey(graph) {
    let a = 0x811c9dc5, b = 0x9747b28c;
    const mix = value => {
      a = Math.imul(a ^ value, 0x01000193);
      b = Math.imul(b ^ value, 0x5bd1e995) ^ (b >>> 15);
    };
    for (const [w, h] of graph.nodes) { mix(Math.round(w * 100)); mix(Math.round(h * 100)); }
    mix(-1);
    for (const [from, to] of graph.edges) { mix(from); mix(to); }
    return `${graph.nodes.length}:${graph.edges.length}:${(a >>> 0).toString(36)}:${(b >>> 0).toString(36)}`;
  }
  function remember(key, entry) {
    cache.delete(key);
    cache.set(key, entry);
    if (cache.size > CACHE_ENTRIES) cache.delete(cache.keys().next().value);
  }

  /** Each graph's place in one request, in order, its cached answer, or the
   * reason it stays out. A cached graph takes no room in the request. */
  function plan(graphs, all) {
    let sent = 0;
    return graphs.map(graph => {
      if (!all && (graph.nodes.length > AUTOMATIC.graphNodes || graph.edges.length > AUTOMATIC.graphEdges)) return {reason: {code: 'large'}};
      const key = graphKey(graph), cached = cache.get(key);
      if (cached) { remember(key, cached); return {cached}; }
      return {position: sent++, key};
    });
  }

  /** The answer's JSON, or an Error that carries the HTTP status. Nothing
   * times it out: `signal` stops it, and the route then stops its worker. */
  async function post(body, signal) {
    const response = await fetch('/api/graph-layout', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body), signal, cache: 'no-store'});
    if (!response.ok) throw Object.assign(Error(`The layout route returned ${response.status}.`), {status: response.status});
    return response.json();
  }

  /** Triskel's drawing of `graph`, or why the caller's own layout stays. */
  function judge(result, graph) {
    if (!result) return {reason: {code: 'mismatch'}};
    if (result.status !== 'laid_out') return {reason: {code: 'failed', status: result.status, detail: result.reason ?? null}};
    const nodes = Array.isArray(result.nodes) && result.nodes.length === graph.nodes.length && result.nodes.every(point => Number.isFinite(point?.[0]) && Number.isFinite(point?.[1]));
    const edges = Array.isArray(result.edges) && result.edges.length === graph.edges.length && result.edges.every(list => Array.isArray(list) && list.length >= 4 && list.every(Number.isFinite));
    if (!nodes || !edges) return {reason: {code: 'mismatch'}};
    if (result.width > Math.max(graph.width * ACCEPT.widen, ACCEPT.freeWidth)) return {reason: {code: 'wider', ratio: result.width / Math.max(1, graph.width)}};
    if (result.height > Math.max(graph.height * ACCEPT.widen, graph.height + ACCEPT.freeHeight)) return {reason: {code: 'taller', ratio: result.height / Math.max(1, graph.height)}};
    return {result};
  }

  /**
   * Lays out `graphs`, each {nodes: [[w, h]], edges: [[from, to]], width,
   * height}, with width and height the caller's own drawing of it. Resolves
   * to {outcomes, revision, failure}: per graph either {result}, Triskel's
   * laid-out graph to use, or {reason}; the engine revision; and why the
   * whole request failed, or null. `all` sends graphs past AUTOMATIC too;
   * `signal` stops the request, which leaves each graph sent `cancelled`;
   * `onSend` is called once a request is sent, never for cached answers.
   */
  async function layOut(graphs, {all = false, signal = null, onSend = null} = {}) {
    const planned = plan(graphs, all);
    const body = {graphs: []};
    planned.forEach((entry, index) => {
      if (entry.position === undefined) return;
      body.graphs.push({nodes: graphs[index].nodes.map(([w, h]) => [round(w), round(h)]), edges: graphs[index].edges});
    });
    // A cached answer is judged afresh: the caller's own layout may differ.
    const unsent = (entry, index) => (entry.cached ? judge(entry.cached.result, graphs[index]) : entry);
    const revision = planned.find(entry => entry.cached)?.cached.revision ?? null;
    // Every graph that was sent shares the request's fate.
    const everySent = (reason, failure) => ({outcomes: planned.map((entry, index) => (entry.position === undefined ? unsent(entry, index) : {reason})), revision, failure});
    if (!body.graphs.length) return everySent(null, null);
    let answer;
    try {
      signal?.throwIfAborted();
      onSend?.();
      answer = await post(body, signal);
    } catch (error) {
      if (signal?.aborted) return everySent({code: 'cancelled'}, null);
      const failure = error?.message ?? 'The layout route failed.';
      return everySent(error?.status ? {code: 'status', status: error.status} : {code: 'route_failed', detail: failure}, failure);
    }
    if (answer?.schema !== 'graph-layout-v1' || !Array.isArray(answer.graphs) || answer.graphs.length !== body.graphs.length)
      return everySent({code: 'mismatch'}, 'The layout route returned an unexpected answer.');
    const fresh = answer.engine?.revision ?? null;
    planned.forEach(entry => {
      // Only a layout is the same next time; a timeout or a failure may not be.
      const result = entry.position === undefined ? null : answer.graphs[entry.position];
      if (result?.status === 'laid_out') remember(entry.key, {result, revision: fresh});
    });
    const outcomes = planned.map((entry, index) => (entry.position === undefined ? unsent(entry, index) : judge(answer.graphs[entry.position], graphs[index])));
    return {outcomes, revision: fresh ?? revision, failure: null};
  }

  return {AUTOMATIC, layOut, routePoints};
})();
