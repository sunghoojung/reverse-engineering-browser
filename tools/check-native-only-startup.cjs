#!/usr/bin/env node
// Execute every shipped script in HTML order against a DOM model. This is NOT
// browser rendering, focus, layout, live capture or Brave-build acceptance.
// Install the explicit dev-only lockfile with:
// npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {setImmediate: nextTurn} = require('node:timers/promises');
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');
const root = path.resolve(__dirname, '..');
const ui = path.join(root, 'apps/research-ui');

async function main() {
  const {window} = parseHTML(fs.readFileSync(path.join(ui, 'index.html'), 'utf8'));
  const storage = new Map(), forbidden = [], asyncErrors = [];
  const onRejection = error => asyncErrors.push(error);
  process.on('unhandledRejection', onRejection);
  Object.assign(window, {
    location: {protocol: 'file:', href: 'file:///index.html', search: '', hash: '', origin: 'null'},
    URL, URLSearchParams, TextEncoder, TextDecoder, AbortController, Blob, Headers, Request, Response,
    atob, btoa, performance, console,
    localStorage: {
      getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, String(value)),
      removeItem: key => storage.delete(key)
    },
    matchMedia: () => ({matches: false, addEventListener() {}, removeEventListener() {}}),
    getComputedStyle: () => ({getPropertyValue: () => '', display: 'block'}),
    // Deliberately no rendering/focus/timer simulation. Synchronous controller
    // execution and asynchronous rejection handling are the tested boundary.
    requestAnimationFrame: () => 0, cancelAnimationFrame() {},
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
    ResizeObserver: class {observe() {} disconnect() {}},
    IntersectionObserver: class {observe() {} disconnect() {}},
    WebSocket: class {
      constructor() {forbidden.push('WebSocket'); throw Error('WebSocket forbidden in native-only viewer');}
    },
    fetch: async input => {
      const url = new URL(typeof input === 'string' ? input : input.url, 'https://fixture.invalid');
      if (url.pathname.startsWith('/api/debugger')) forbidden.push(url.pathname);
      throw Error('Offline DOM-model fixture: network is unavailable');
    },
    CSS: {escape: text => text}, devicePixelRatio: 1, innerWidth: 1440, innerHeight: 900
  });
  window.navigator.clipboard = {writeText: async () => {}};
  window.HTMLElement.prototype.getBoundingClientRect = function () {
    return {x: 0, y: 0, width: 100, height: 30, top: 0, left: 0, right: 100, bottom: 30};
  };
  window.HTMLElement.prototype.scrollIntoView = function () {};
  window.HTMLElement.prototype.showModal = function () {this.open = true;};
  window.HTMLElement.prototype.close = function () {this.open = false;};
  // LinkeDOM omits the browser's first-option default selection behavior.
  Object.defineProperty(window.HTMLSelectElement.prototype, 'value', {
    configurable: true,
    get() {return this._testValue ?? this.querySelector('option[selected]')?.value ?? this.querySelector('option')?.value ?? '';},
    set(value) {this._testValue = String(value);}
  });
  const context = vm.createContext(window);
  context.window = window;
  context.globalThis = window;
  const scripts = [...window.document.querySelectorAll('script[src]')];
  assert(scripts.length > 0, 'the real entrypoint must declare scripts');
  for (const script of scripts) {
    const relative = script.getAttribute('src');
    const filename = path.resolve(ui, relative);
    assert(filename.startsWith(ui + path.sep), 'only shipped local scripts may execute');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), context, {filename: relative, timeout: 10000});
  }
  // These are the actual production controllers, not copied definitions.
  vm.runInContext(`
    showScreen('sources'); showScreen('traffic'); showScreen('api-collection');
    showScreen('vm'); showScreen('tools');
    openFieldProvenance({request:{method:'GET',path:'https://fixture.invalid/?a=b'},
      value:'b',selector:'a',kind:'query'});
  `, context, {timeout: 10000});
  // Positive live capture is tested by the separate C++→Rust→viewer golden gate.
  // This authored row only tests startup's real native panel and truthful labels.
  const fixture = process.env.REB_NATIVE_WASM_WORKSPACE_INPUT
    ? JSON.parse(fs.readFileSync(process.env.REB_NATIVE_WASM_WORKSPACE_INPUT, 'utf8')).workspaces[0]
    : {native_wasm_observation_count: 1, native_wasm_observations: [{
      event: {session_id: '1', process_id: 1, sequence_number: '1'},
      function_index: 0, module_byte_offset: 47, selector: 0xffffffff,
      table_count: 2, sample_index: 0, selected_arm: 2, is_default: true
    }]};
  context.nativeStartupFixture = fixture;
  const text = vm.runInContext('renderNativeWasmObservations(nativeStartupFixture).textContent', context);
  assert(text.includes('guest PC unknown'));
  assert(text.includes('4294967295'));
  assert(text.includes('default arm'));
  assert(text.includes('No host causality is inferred'));
  await nextTurn();
  await nextTurn();
  assert.deepEqual(forbidden, [], 'startup/navigation must not attempt CDP transport');
  assert.deepEqual(asyncErrors, [], 'all asynchronous startup failures must be handled');
  process.removeListener('unhandledRejection', onRejection);
  console.log(`PASS ${scripts.length} actual shipped scripts, retained navigation and native observation panel (offline DOM model; no browser rendering/focus or live capture claimed)`);
}
main().catch(error => {console.error(error); process.exitCode = 1;});
