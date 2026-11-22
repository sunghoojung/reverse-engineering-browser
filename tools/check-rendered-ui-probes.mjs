// Self-check of the rendered layout probe (tools/origin-trace-rendered-ui/probes.js)
// against a minimal DOM with fixed boxes: a row its scroller has almost scrolled
// out is skipped, but a control whose own box has collapsed is still reported,
// and a scroller clips at its padding box when a divider's reach is measured.
// Layout, clipping and hit testing are modelled here, not rendered.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('origin-trace-rendered-ui/probes.js', import.meta.url), 'utf8');

class Element {
  constructor(tagName, {id = '', rect, style = {}, text = '', scrollWidth, clientWidth, scrollHeight, clientHeight, borderTop = 0} = {}) {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.rect = rect;
    this.computed = {display: 'block', visibility: 'visible', opacity: '1', overflowX: 'visible',
      overflowY: 'visible', textOverflow: 'clip', position: 'static', transform: 'none', perspective: 'none',
      filter: 'none', backdropFilter: 'none', contain: 'none', willChange: 'auto', ...style};
    this.textContent = text;
    this.children = [];
    this.parentElement = null;
    this.isConnected = true;
    this.scrollWidth = scrollWidth ?? rect.width;
    this.clientWidth = clientWidth ?? rect.width;
    this.scrollHeight = scrollHeight ?? rect.height;
    // Only a top border is modelled; clientTop is its width, as in the DOM.
    this.clientLeft = 0;
    this.clientTop = borderTop;
    this.clientHeight = clientHeight ?? rect.height - borderTop;
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
        const inner = node.rect.top + node.clientTop;
        left = Math.max(left, node.rect.left); right = Math.min(right, node.rect.right);
        top = Math.max(top, inner); bottom = Math.min(bottom, inner + node.clientHeight);
      }
    }
    return {left, top, right, bottom};
  };
  const document = {
    body: root,
    documentElement: {scrollWidth: 800},
    querySelector: selector => all().find(node => `#${node.id}` === selector) ?? null,
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
  return window.__rebUiProbe;
}
// Copied out of the probe's realm, so assert compares plain arrays.
const issues = root => [...probe(root).layoutIssues(`#${root.id}`).issues];
const reach = (root, panes = []) => [...probe(root).dividerReach('#divider', `#${root.id}`, panes).offenders];

// A list scrolled so that 0.5 px of a row stays under its scroller's top edge,
// with the next row snapped half a pixel up over it, as WebKit hit testing does.
const scroller = new Element('div', {id: 'list', rect: box(0, 100, 300, 50), style: {overflowY: 'auto'},
  scrollHeight: 200, clientHeight: 50});
const above = new Element('button', {rect: box(0, 78.5, 300, 22), text: 'item-8.scroll.test'});
const selected = new Element('button', {rect: box(0, 100, 300, 22), text: 'inert.test'});
const below = new Element('button', {rect: box(0, 122, 300, 22), text: 'item-6.scroll.test'});
scroller.append(above, selected, below);
assert.deepEqual(issues(scroller), [], 'A sliver of a scrolled-out row is not a covered control');

// A real collision is still a defect: two rows drawn over each other.
const collided = new Element('div', {id: 'collided', rect: box(0, 0, 300, 100)});
collided.append(new Element('button', {rect: box(0, 10, 300, 22), text: 'first'}),
  new Element('button', {rect: box(0, 16, 300, 22), text: 'second'}));
assert(issues(collided).some(issue => issue.startsWith('covered:') || issue.startsWith('overlap:')),
  'Rows drawn over each other are reported');

// A control whose own box collapsed to 1 px, its label hidden past it, is checked.
const toolbar = new Element('div', {id: 'toolbar', rect: box(0, 0, 300, 40)});
toolbar.append(new Element('button', {rect: box(10, 10, 1, 20), text: 'Export',
  style: {overflowX: 'hidden'}, scrollWidth: 40, clientWidth: 1}));
assert(issues(toolbar).some(issue => issue.startsWith('label overflows its control')),
  'A collapsed control with a hidden label still fails');

// A divider straddles the edge between a footer and a scroller below it at
// y 100, reaching 4 px into each. A row scrolled up under the scroller's top
// border paints nothing there, so only its part inside the padding box counts.
const split = borderTop => {
  const root = new Element('div', {id: `split-${borderTop}`, rect: box(0, 0, 300, 200)});
  const footer = new Element('div', {rect: box(0, 70, 300, 30)});
  footer.append(new Element('button', {rect: box(250, 74, 40, 20), text: 'Key'}));
  const linear = new Element('div', {id: `linear-${borderTop}`, rect: box(0, 100, 300, 100), style: {overflowY: 'auto'},
    scrollHeight: 400, borderTop});
  linear.append(new Element('button', {rect: box(0, 90, 60, 18), text: 'Rename row'}));
  root.append(footer, linear, new Element('div', {id: 'divider', rect: box(0, 96, 300, 8)}));
  return root;
};
assert.deepEqual(reach(split(5)), [], 'A row clipped below a scroller border that clears the reach is not under the divider');
assert.deepEqual(reach(split(1)), ['button "Rename row" meets 60x3px'], 'A row sliver inside the reach is under the divider');
// A control's edge counts as well as its center, and a named pane is skipped.
const edge = split(5);
edge.children[0].children[0].rect = box(250, 78, 40, 20);
const pane = edge.children[1];
pane.tagName = 'BUTTON';
assert.deepEqual(reach(edge, [`#${pane.id}`]), ['button "Key" meets 40x2px'], 'A control edge inside the reach is under the divider');

// A sentence fixed to the window above a short table's footer paints whole:
// the table's overflow does not hold a fixed box. An absolute one is cut by
// the positioned table, and a transformed table holds the fixed one too.
const popover = (position, tableStyle = {}) => {
  const table = new Element('div', {id: 'table', rect: box(0, 200, 400, 100),
    style: {overflowX: 'hidden', overflowY: 'hidden', position: 'relative', ...tableStyle}});
  const footer = new Element('div', {rect: box(0, 270, 400, 30), style: {overflowY: 'hidden'}});
  const sentence = new Element('span', {id: 'sentence', rect: box(100, 160, 300, 74), style: {position}});
  table.append(footer.append(sentence));
  return probe(table).box('#sentence').visibleHeight;
};
assert.equal(popover('fixed'), 74, 'A fixed box is not clipped by an ancestor that does not contain it');
assert.equal(popover('absolute'), 34, 'An absolute box is clipped by its positioned containing block only');
assert.equal(popover('fixed', {transform: 'translateX(0px)'}), 34, 'A transformed ancestor clips a fixed box');
assert.equal(popover('static'), 0, 'An in-flow box is clipped by every overflow ancestor');

console.log('PASS rendered layout probe: a scrolled-out row sliver is skipped, a collapsed control and ' +
  'overlapping rows still fail, a divider reach clips at padding boxes, and only containing ancestors ' +
  'clip a positioned box (modelled boxes, not rendered QA)');
