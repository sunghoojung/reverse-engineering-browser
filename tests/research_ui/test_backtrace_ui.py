"""Exercise trace presentation states and row interaction without network access."""

import json
import shutil
import subprocess
import unittest

from ui_test_support import read_ui_sources


class BacktraceUiTest(unittest.TestCase):
    def test_trace_states_selection_and_retained_evidence(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")
        source = read_ui_sources()
        start = source.index("      function traceStepDetails(model)")
        end = source.index("      function requestInterception()", start)
        script = r"""
class Element {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.dataset = {}; this.attrs = {}; this.handlers = {}; this.className = ''; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(key, value) { this.attrs[key] = value; }
  addEventListener(key, callback) { this.handlers[key] = callback; }
  querySelectorAll(selector) { return this.children.flatMap(child => [
    ...(child.className.split(' ').includes(selector.slice(1)) ? [child] : []), ...child.querySelectorAll(selector)]); }
  click() { this.handlers.click?.(); }
  focus() { focused = this; }
}
let focused = null;
const document = {createElement: tag => new Element(tag)};
const textElement = (tag, className, text) => Object.assign(new Element(tag), {className, textContent: text});
const elements = new Proxy({}, {get: (target, key) => target[key] ??= new Element()});
const sample = {id: 'sample', method: 'POST', path: '/cart', origin: 'sample'};
const live = {id: 'live', method: 'POST', path: '/collect', origin: 'live'};
const state = {requests: [sample, live], selectedRequestId: 'sample', originTrace: null,
  originTraceStatus: 'idle', selectedTraceRow: null, artifacts: []};
const requestTraceRoot = request => request?.origin === 'live' && !request.missingId ? {} : null;
const originTraceSelection = () => state.selectedRequestId === 'live' ? {request: live} : null;
renderBacktrace();
const empty = {hidden: elements.traceContent.hidden, action: !elements.traceFirstRequest.hidden,
  noRows: elements.backtraceSteps.children.length === 0, noEvents: elements.traceEvidence.hidden};
state.selectedRequestId = 'live'; state.originTraceStatus = 'loading';
renderBacktrace();
const loading = elements.traceEmptyTitle.textContent;
const step = (sequence, confidence) => ({event: {process_id: '2', sequence_number: sequence, session_id: '1'},
  monotonic_time_ns: '100', category: 'canvas', operation: 'api_call', relation: 'parent_event',
  confidence, frame_id: '3', request_id: '4', artifact_id: '0', value: '<img src=x onerror=alert(1)>'});
state.originTrace = {steps: [step('8', 'observed'), step('7', 'correlated')],
  gaps: [{after_step: 1, reason: 'missing_event', detail: 'Earlier event was dropped.'}], coverage: {percent: 50}};
state.originTraceStatus = 'ready'; renderBacktrace();
const rows = elements.backtraceSteps.querySelectorAll('.trace-row');
rows[0].handlers.keydown({key: 'ArrowDown', preventDefault() {}});
const selection = {key: state.selectedTraceRow, focus: focused === rows[1], selected: rows[1].attrs['aria-pressed']};
const value = elements.traceStepDetails.children.find(child => child.tag === 'pre');
const inert = value.textContent === '<img src=x onerror=alert(1)>' && value.children.length === 0;
rows[2].click();
const gap = elements.traceStepDetails.children.some(child => child.textContent === 'Earlier event was dropped.');
state.originTraceStatus = 'error'; state.originTraceError = 'Connection closed'; renderBacktrace();
const retained = !elements.traceContent.hidden && elements.backtraceSteps.children.length === 3
  && elements.traceNotice.textContent.includes('Showing the previous trace');
state.selectedRequestId = 'sample'; renderBacktrace();
const unrelatedHidden = elements.traceContent.hidden && elements.backtraceSteps.children.length === 0;
state.requests = [{id: 'no-id', origin: 'live', missingId: true, method: 'GET', path: '/asset'}];
state.selectedRequestId = 'no-id'; state.originTraceStatus = 'idle'; renderBacktrace();
const missingId = elements.traceEmptyTitle.textContent;
process.stdout.write(JSON.stringify({empty, loading, selection, inert, gap, retained, unrelatedHidden, missingId}));
"""
        result = subprocess.run(
            [node, "-e", source[start:end] + script],
            check=True,
            capture_output=True,
            text=True,
        )
        actual = json.loads(result.stdout)
        self.assertEqual(
            actual["empty"],
            {"hidden": True, "action": True, "noRows": True, "noEvents": True},
        )
        self.assertEqual(actual["loading"], "Loading trace…")
        self.assertEqual(
            actual["selection"], {"key": "2:7", "focus": True, "selected": "true"}
        )
        self.assertEqual(actual["missingId"], "This event has no request identifier")
        for key in ("inert", "gap", "retained", "unrelatedHidden"):
            self.assertTrue(actual[key], key)
