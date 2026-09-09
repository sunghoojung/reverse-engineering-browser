"""Exercise the shipped body viewer with bounded, hostile, and missing content."""

import shutil
import subprocess
import unittest

from ui_test_support import UI_DIRECTORY


DOM = r"""
class Node {
  constructor(tag) {
    this.tagName = tag; this.children = []; this.attrs = {}; this.dataset = {};
    this.listeners = {}; this.value = ''; this._text = ''; this.className = '';
    this.classList = {toggle: () => {}};
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(n => n.textContent).join(''); }
  set innerHTML(value) { throw Error('Unsafe HTML sink'); }
  setAttribute(key, value) { this.attrs[key] = value; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ''; this.children = children; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  focus() { this.focused = true; }
  click() { this.listeners.click?.(); }
  querySelectorAll(selector) {
    return this.children.flatMap(child => [
      ...((selector === 'button' && child.tagName === 'button') ||
        (selector === '[aria-pressed]' && child.attrs['aria-pressed'] !== undefined) ? [child] : []),
      ...child.querySelectorAll(selector)
    ]);
  }
}
const document = {createElement: tag => new Node(tag)};
const assert = require('node:assert/strict');
function nodes(root, predicate) {
  return [root, ...root.children.flatMap(child => nodes(child, predicate))].filter(predicate);
}
function byClass(root, cls) { return nodes(root, node => node.className.split(' ').includes(cls)); }
function view(pane, label) { nodes(pane, n => n.tagName === 'button' && n.textContent === label)[0].click(); }

"""


@unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
class TrafficViewTests(unittest.TestCase):
    def run_js(self, exercise: str) -> None:
        source = (UI_DIRECTORY / "traffic_view.js").read_text(encoding="utf-8")
        result = subprocess.run(
            ["node", "-"],
            input=DOM + (UI_DIRECTORY / "source_syntax.js").read_text(encoding="utf-8") + source + exercise,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_metadata_cannot_inherit_sample_content(self) -> None:
        self.run_js(r"""
const live = trafficExchange({origin: 'live', id: '81', method: 'POST', status: 200});
assert.equal(live.request.state, 'missing');
assert.equal(live.response.state, 'missing');
assert.equal(trafficExchange({origin: 'live', method: 'HEAD'}).response.state, 'empty');
assert.equal(trafficExchange({origin: 'live', status: 304}).response.state, 'empty');
assert.equal(trafficExchange({origin: 'sample', id: '__proto__'}).response.state, 'missing');
for (const state of ['missing', 'empty', 'redacted', 'loading', 'error']) {
  const model = trafficBodyModel({state, text: 'do not reveal'}, 'Response');
  assert.equal(model.text, undefined);
  assert.ok(model.message.length > 0);
}
const pane = createTrafficPane('Request', live.request, {origin:'live', path:'example.test'}, () => {});
view(pane, 'Query');
assert.match(pane.textContent, /Query parameters were not captured/);
""")

    def test_mime_parsing_binary_and_truncation(self) -> None:
        self.run_js(r"""
assert.equal(trafficBodyModel({state:'available', mime:'application/json', text:'null'}, 'Response').json, null);
assert.equal(trafficBodyModel({state:'available', mime:'application/json', text:'{'}, 'Response').malformed, true);
const long = trafficBodyModel({state:'available', mime:'application/json', text:'"'+'x'.repeat(200000)+'"'}, 'Response');
assert.equal(long.truncated, true); assert.equal(long.json, undefined);
assert.equal(new TextEncoder().encode(long.text).length, TRAFFIC_BODY_LIMIT);
const partial = trafficBodyModel({state:'available', mime:'application/json', text:'{}', truncated:true}, 'Response');
assert.equal(partial.truncated, true); assert.equal(partial.json, undefined);
const exact = trafficBodyModel({state:'available', mime:'application/json', text:'{"id":9007199254740993123,"x":1,"x":2,"v":1e400}'}, 'Response');
assert.ok(exact.formatted.text.includes('9007199254740993123'));
assert.ok(exact.formatted.text.includes('1e400'));
assert.equal((exact.formatted.text.match(/"x"/g) || []).length, 2);
assert.equal(exact.treeSafe, false);
const deep = trafficBodyModel({state:'available', mime:'application/json', text:'['.repeat(30)+'0'+']'.repeat(30)}, 'Response');
assert.equal(deep.formatted.limited, true);
const binary = trafficBodyModel({state:'available', mime:'application/octet-stream', bytes:new Uint8Array([0,60,255])}, 'Response');
assert.equal(binary.binary, true); assert.match(binary.text, /00 3c ff/);
assert.equal(trafficBodyModel({state:'available', text:''}, 'Request').bytes, 0);
""")

    def test_tree_selection_search_raw_and_inert_content(self) -> None:
        self.run_js(r"""
const attack = '<img src=x onerror=alert(1)>';
const long = 'token-' + 'x'.repeat(400);
let decoded;
const pane = createTrafficPane('Response', {state:'available', mime:'application/json', text:JSON.stringify({nested:{attack,long}, list:[true,null,12]})}, {origin:'sample'}, value => decoded = value);
view(pane, 'JSON tree');
assert.equal(nodes(pane, n => n.tagName === 'img').length, 0);
assert.ok(pane.textContent.includes(attack));
const row = byClass(pane, 'exchange-leaf').find(n => n.textContent.startsWith('long'));
assert.ok(row.textContent.length < long.length);
row.listeners.click();
assert.equal(byClass(pane, 'exchange-selected-value')[0].textContent, long);
const decode = nodes(pane, n => n.tagName === 'button' && n.textContent === 'Decode')[0];
decode.listeners.click(); assert.equal(decoded, long);
const search = byClass(pane, 'exchange-search')[0];
search.value = 'onerror'; search.listeners.input();
assert.ok(pane.textContent.includes(attack)); assert.ok(!byClass(pane, 'exchange-content')[0].textContent.includes('token-'));
search.value = 'no-match'; search.listeners.input(); assert.match(pane.textContent, /No matches/);
search.value = ''; view(pane, 'Raw body');
assert.ok(byClass(pane, 'exchange-code-line').length > 0);
assert.ok(pane.textContent.includes(attack));
""")

    def test_limits_and_refresh_preserve_view_state(self) -> None:
        self.run_js(r"""
const pane = createTrafficPane('Response', {state:'available', mime:'application/json', text:JSON.stringify(Array.from({length:5000}, (_,i) => i))}, {}, () => {});
view(pane, 'JSON tree');
assert.ok(byClass(pane, 'exchange-leaf').length <= TRAFFIC_TREE_LIMIT);
assert.match(pane.textContent, /Tree limited/);
const root = new Node('div');
const request = {id:'80', origin:'sample', method:'GET', status:200};
renderTrafficExchange(root, request, () => {});
const first = root.children[1];
renderTrafficExchange(root, {...request}, () => {});
assert.equal(root.children[1], first);
renderTrafficExchange(root, {...request, id:'81'}, () => {});
assert.notEqual(root.children[1], first);
""")
