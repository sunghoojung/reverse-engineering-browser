"""Exercise the shipped request-value controller without a browser dependency."""

import shutil
import subprocess
import unittest

from ui_test_support import UI_DIRECTORY


DOM = r'''
const assert = require('node:assert/strict');
class Element {
  constructor() { this.value = ''; this.checked = false; this.disabled = false;
    this.dataset = {}; this.firstChild = {}; this.children = []; this.listeners = {}; }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  querySelectorAll() { return []; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  focus() { this.focused = true; }
  scrollIntoView() { this.scrolled = true; }
}
const elements = new Proxy({}, {get(target, key) { return target[key] ??= new Element(); }});
const document = {createElement: () => new Element(), createTextNode: value => value};
const textElement = (tag, cls, text) => ({textContent: text});
const state = {debuggerActionPending: false};
const requestAnimationFrame = callback => callback();
let renders = 0;
const renderRuntimeHooks = () => { renders++; };
const actions = [];
const runExperimentAction = async action => { actions.push(action); return {ok: true}; };
const observation = (id, target = 'page-1', status = 'available') => ({
  id, target_id: target, target_type: 'page', status, method: 'POST',
  url: 'https://example.test/send', preview: 'value', bytes: 5,
  occurred_at_ms: 0, request_id: String(id), sha256: 'digest',
});
'''


class RequestValueUiTests(unittest.TestCase):
    def run_controller(self, exercise):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js is not installed')
        module = (UI_DIRECTORY / 'request_value_test.js').read_text()
        subprocess.run([node, '-e', DOM + module + exercise], check=True, capture_output=True, text=True)

    def test_refresh_selects_distinct_pair_and_preserves_researcher_choice(self):
        self.run_controller(r'''
assert.deepEqual(runtimeFieldSelection([], '', ''), {baseline: '', variant: ''});
assert.deepEqual(runtimeFieldSelection([observation(1)], '', ''), {baseline: '1', variant: ''});
const rows = [observation(1), observation(2), observation(3, 'worker-1'), observation(4, 'page-1', 'pending')];
assert.deepEqual(runtimeFieldSelection(rows, '1', '1'), {baseline: '1', variant: '2'});
assert.deepEqual(runtimeFieldSelection([...rows, observation(5)], '1', '2'), {baseline: '1', variant: '2'});
assert.deepEqual(runtimeFieldSelection(rows.slice(1), '1', '1'), {baseline: '2', variant: ''});
assert.deepEqual(runtimeFieldSelection(rows, '3', '2'), {baseline: '3', variant: ''});
''')

    def test_armed_capture_can_compare_but_cannot_be_reconfigured(self):
        self.run_controller(r'''
elements.hooksFieldKind.value = 'query';
elements.hooksFieldPointer.value = 'value';
elements.hooksFieldUrl.value = 'https://example.test/send';
elements.hooksFieldConfirm.checked = true;
const hooks = {hits: [], field_test: {enabled: true, method: 'POST', url: 'https://example.test/send',
  kind: 'query', pointer: 'value', observation_evictions: 2, observations: [observation(1)]}};
renderRuntimeFieldTest(hooks, false, true);
assert.equal(elements.hooksFieldCompare.disabled, true);
hooks.field_test.observations.push(observation(2));
renderRuntimeFieldTest(hooks, false, true);
assert.equal(elements.hooksFieldBaseline.value, '1');
assert.equal(elements.hooksFieldVariant.value, '2');
assert.equal(elements.hooksFieldCompare.disabled, false);
assert.equal(elements.hooksFieldConfigure.disabled, true);
assert.equal(elements.hooksFieldErase.disabled, true);
assert.match(elements.hooksFieldStatus.textContent, /Disarm hooks/);
assert.match(elements.hooksFieldStatus.textContent, /2 older observations evicted/);
renderRuntimeFieldTest(hooks, false, false);
assert.equal(elements.hooksFieldCompare.disabled, true);
''')

    def test_capture_confirmation_selector_and_focus_follow_actual_configuration(self):
        self.run_controller(r'''
(async () => {
  bindRuntimeFieldTest();
  elements.hooksFieldKind.value = 'form';
  elements.hooksFieldPointer.value = ' exact field ';
  elements.hooksFieldUrl.value = 'https://example.test/send';
  elements.hooksFieldMethod.value = 'post';
  elements.hooksFieldConfirm.checked = true;
  await elements.hooksFieldForm.listeners.submit({preventDefault() {}});
  assert.equal(actions[0].pointer, ' exact field ');
  assert.equal(actions[0].confirmed, true);
  assert.equal(elements.hooksFieldConfirm.checked, false);
  assert.equal(renders, 1);
  elements.hooksFieldConfirm.checked = true;
  elements.hooksFieldForm.listeners.input({target: elements.hooksFieldUrl});
  assert.equal(elements.hooksFieldConfirm.checked, false);
  elements.hooksFieldKind.value = 'body';
  await elements.hooksFieldForm.listeners.submit({preventDefault() {}});
  assert.equal(actions[1].pointer, '');
  elements.hooksFieldPointer.disabled = true;
  focusRuntimeFieldTest();
  assert.equal(elements.hooksFieldCard.scrolled, true);
  assert.equal(elements.hooksFieldCard.focused, true);
})().catch(error => { console.error(error); process.exitCode = 1; });
''')
