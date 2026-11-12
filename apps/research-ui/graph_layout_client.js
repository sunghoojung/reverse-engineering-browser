/* Client of the backend's Triskel route, POST /api/graph-layout
 * (graph-layout-v1, protocol/http-api.md#graph-layout), shared by the flow
 * graph and block graph layout workers, which load it with importScripts; the
 * page loads it for the flow graph's on-thread fallback. It sends the graphs
 * that fit the route's limits, checks each answer's shape, and keeps
 * Triskel's drawing only where it is not much wider or taller than the
 * caller's own layout. A graph it does not lay out gets a reason, `{code}`
 * with the detail its code names, which each view words for itself:
 *   too_large       past the route's per-graph limits, or Triskel says so
 *   request_budget  past what one request holds: `limit` is graphs or nodes
 *   wider, taller   Triskel's drawing is `ratio` times the caller's
 *   mismatch        the answer does not fit what was sent
 *   failed          Triskel's `status` (failed or timeout) and `detail`
 *   status          the route answered HTTP `status`
 *   route_failed    the request failed; `detail` says how
 * Callers add their own codes: one_card or one_block (nothing to lay out)
 * and not_served (this shell has no route). */
'use strict';

const graphLayoutClient = (() => {
  /* The route's limits (graph_layout.rs MAX_GRAPHS, MAX_TOTAL_NODES,
   * MAX_GRAPH_NODES and MAX_GRAPH_EDGES): a request over them is refused
   * whole with a 400. */
  const LIMITS = Object.freeze({graphs: 64, nodes: 8000, graphNodes: 2000, graphEdges: 8000});
  /* Triskel's drawing is kept unless it is more than `widen` times as wide
   * as the caller's and over `freeWidth` px, or as many times as tall and
   * `freeHeight` px taller: Triskel does not stack a wide fan, and it stacks
   * loop bodies. */
  const ACCEPT = Object.freeze({widen: 1.6, freeWidth: 1400, freeHeight: 1600});
  const TIMEOUT_MS = 20000;

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

  /** Each graph's place in one request, in order, or the reason it stays out. */
  function plan(graphs) {
    let sent = 0, nodes = 0;
    return graphs.map(graph => {
      if (graph.nodes.length > LIMITS.graphNodes || graph.edges.length > LIMITS.graphEdges) return {reason: {code: 'too_large'}};
      if (sent >= LIMITS.graphs) return {reason: {code: 'request_budget', limit: 'graphs'}};
      if (nodes + graph.nodes.length > LIMITS.nodes) return {reason: {code: 'request_budget', limit: 'nodes'}};
      nodes += graph.nodes.length;
      return {position: sent++};
    });
  }

  /** The answer's JSON, or an Error that carries the HTTP status. */
  async function post(body) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const response = await fetch('/api/graph-layout', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body), signal: controller.signal, cache: 'no-store'});
      if (!response.ok) throw Object.assign(Error(`The layout route returned ${response.status}.`), {status: response.status});
      return await response.json();
    } catch (error) {
      if (controller.signal.aborted) throw Error(`The layout route gave no answer in ${TIMEOUT_MS / 1000} s.`);
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Triskel's drawing of `graph`, or why the caller's own layout stays. */
  function judge(result, graph) {
    if (!result) return {reason: {code: 'mismatch'}};
    if (result.status === 'too_large') return {reason: {code: 'too_large'}};
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
   * whole request failed, or null.
   */
  async function layOut(graphs) {
    const planned = plan(graphs);
    const body = {graphs: []};
    planned.forEach((entry, index) => {
      if (entry.position === undefined) return;
      body.graphs.push({nodes: graphs[index].nodes.map(([w, h]) => [round(w), round(h)]), edges: graphs[index].edges});
    });
    // Every graph that was sent shares the request's fate.
    const everySent = (reason, failure) => ({outcomes: planned.map(entry => (entry.position === undefined ? entry : {reason})), revision: null, failure});
    if (!body.graphs.length) return everySent(null, null);
    let answer;
    try {
      answer = await post(body);
    } catch (error) {
      const failure = error?.message ?? 'The layout route failed.';
      return everySent(error?.status ? {code: 'status', status: error.status} : {code: 'route_failed', detail: failure}, failure);
    }
    if (answer?.schema !== 'graph-layout-v1' || !Array.isArray(answer.graphs) || answer.graphs.length !== body.graphs.length)
      return everySent({code: 'mismatch'}, 'The layout route returned an unexpected answer.');
    const outcomes = planned.map((entry, index) => (entry.position === undefined ? entry : judge(answer.graphs[entry.position], graphs[index])));
    return {outcomes, revision: answer.engine?.revision ?? null, failure: null};
  }

  return {LIMITS, layOut, routePoints};
})();
