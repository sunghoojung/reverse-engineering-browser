// Self-check of the rendered layout probe (tools/origin-trace-rendered-ui/probes.js)
// against a minimal DOM with fixed boxes: a row its scroller has almost scrolled
// out is skipped, but a control whose own box has collapsed is still reported.
// Layout, clipping and hit testing are modelled here, not rendered.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('origin-trace-rendered-ui/probes.js', import.meta.url), 'utf8');

class Element {
  constructor(tagName, {id = '', rect, style = {}, text = '', scrollWidth, clientWidth, scrollHeight, clientHeight} = {}) {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.rect = rect;
    this.computed = {display: 'block', visibility: 'visible', opacity: '1', overflowX: 'visible',
      overflowY: 'visible', textOverflow: 'clip', ...style};
    this.textContent = text;
    this.children = [];
    this.parentElement = null;
    this.isConnected = true;
    this.scrollWidth = scrollWidth ?? rect.width;
    this.clientWidth = clientWidth ?? rect.width;
    this.scrollHeight = scrollHeight ?? rect.height;
    this.clientHeight = clientHeight ?? rect.height;
  }
  append(...children) {
    for (const child of children) {
      child.parentElement = this;
      this.children.push(child);
    }
    return this;
  }
  descendants() { return this.children.flatMap(child => [child, ...child.descendants()]); }
  getBoundingClientRect() { return {...this.rect}; }
  getAttribute() { return null; }
  contains(other) { return other === this || this.descendants().includes(other); }
  closest(selector) {
    for (let node = this; node; node = node.parentElement) {
      if (selector === 'label' && node.tagName === 'LABEL') return node;
    }
    return null;
  }
  matches(selector) {
    return selector.split(',').some(part => part.trim().toUpperCase() === this.tagName);
  }
  querySelectorAll() { return this.descendants().filter(node => node.tagName === 'BUTTON'); }
  querySelector() { return null; }
}

const box = (left, top, width, height) => ({left, top, width, height, right: left + width, bottom: top + height});

// Paint order is document order, so a later element is drawn on top.
function probe(root) {
  const all = () => [root, ...root.descendants()];
  const clipped = element => {
    let {left, top, right, bottom} = element.rect;
    for (let node = element.parentElement; node; node = node.parentElement) {
      if (/(hidden|clip|auto|scroll)/.test(node.computed.overflowX + node.computed.overflowY)) {
        left = Math.max(left, node.rect.left); right = Math.min(right, node.rect.right);
        top = Math.max(top, node.rect.top); bottom = Math.min(bottom, node.rect.bottom);
      }
    }
    return {left, top, right, bottom};
  };
  const document = {
    body: root,
    documentElement: {scrollWidth: 800},
    querySelector: selector => (selector === `#${root.id}` ? root : null),
    elementFromPoint(x, y) {
      return all().reverse().find(node => {
        const area = clipped(node);
        return x >= area.left && x < area.right && y >= area.top && y < area.bottom;
      }) ?? null;
    },
  };
  const window = {};
  const context = vm.createContext({window, document, innerWidth: 800, innerHeight: 600,
    getComputedStyle: element => element.computed});
  vm.runInContext(source, context);
  // Copied out of the probe's realm, so assert compares plain arrays.
  return [...window.__rebUiProbe.layoutIssues(`#${root.id}`).issues];
}

// A list scrolled so that 0.5 px of a row stays under its scroller's top edge,
// with the next row snapped half a pixel up over it, as WebKit hit testing does.
const scroller = new Element('div', {id: 'list', rect: box(0, 100, 300, 50), style: {overflowY: 'auto'},
  scrollHeight: 200, clientHeight: 50});
const above = new Element('button', {rect: box(0, 78.5, 300, 22), text: 'item-8.scroll.test'});
const selected = new Element('button', {rect: box(0, 100, 300, 22), text: 'inert.test'});
const below = new Element('button', {rect: box(0, 122, 300, 22), text: 'item-6.scroll.test'});
scroller.append(above, selected, below);
assert.deepEqual(probe(scroller), [], 'A sliver of a scrolled-out row is not a covered control');

// A real collision is still a defect: two rows drawn over each other.
const collided = new Element('div', {id: 'collided', rect: box(0, 0, 300, 100)});
collided.append(new Element('button', {rect: box(0, 10, 300, 22), text: 'first'}),
  new Element('button', {rect: box(0, 16, 300, 22), text: 'second'}));
assert(probe(collided).some(issue => issue.startsWith('covered:') || issue.startsWith('overlap:')),
  'Rows drawn over each other are reported');

// A control whose own box collapsed to 1 px, its label hidden past it, is checked.
const toolbar = new Element('div', {id: 'toolbar', rect: box(0, 0, 300, 40)});
toolbar.append(new Element('button', {rect: box(10, 10, 1, 20), text: 'Export',
  style: {overflowX: 'hidden'}, scrollWidth: 40, clientWidth: 1}));
assert(probe(toolbar).some(issue => issue.startsWith('label overflows its control')),
  'A collapsed control with a hidden label still fails');

console.log('PASS rendered layout probe: a scrolled-out row sliver is skipped, a collapsed control and ' +
  'overlapping rows still fail (modelled boxes, not rendered QA)');
