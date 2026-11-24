// Rendered-layout probes evaluated by the hosted XCTest inside the packaged
// Origin Trace WKWebView. They inspect the DOM and computed layout and scroll
// targets into view; clicks and keys are native AppKit events from the Swift test.
(() => {
  if (window.__rebUiProbe) return;
  const CONTROLS = 'button,a[href],input:not([type=hidden]),select,textarea,summary,[role=tab],[role=treeitem],[role=option],[tabindex]:not([tabindex="-1"])';

  const describe = element => {
    if (!element || element === document.body) return element ? 'body' : 'none';
    const id = element.id ? `#${element.id}` : '';
    const label = (element.getAttribute('aria-label') || element.textContent || element.value || '').replace(/\s+/g, ' ').trim().slice(0, 60);
    return `${element.tagName.toLowerCase()}${id}${label ? ` "${label}"` : ''}`;
  };

  const rendered = element => {
    if (!element.isConnected || element.closest('[hidden],[inert]')) return false;
    for (let node = element; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
      // A closed disclosure shows only its own summary. A summary of a
      // disclosure nested inside it is hidden with the rest, though WebKit
      // still gives it a box.
      if (node.tagName === 'DETAILS' && !node.open && node !== element &&
          element.closest('summary')?.parentElement !== node) return false;
    }
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };

  // The ancestors whose overflow can clip a node. As CSS paints it, an
  // absolute box escapes the ancestors short of its positioned containing
  // block, and a fixed box every ancestor short of one that contains fixed
  // boxes, so a popover fixed to the window is not cut by a short table.
  const holdsFixed = style => style.transform !== 'none' || style.perspective !== 'none' || style.filter !== 'none' ||
    (style.backdropFilter || 'none') !== 'none' || /(paint|layout|strict|content)/.test(style.contain) ||
    /(transform|perspective|filter)/.test(style.willChange);
  const clippingAncestors = element => {
    const ancestors = [];
    let position = getComputedStyle(element).position;
    for (let node = element.parentElement; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      const holds = position === 'fixed' ? holdsFixed(style)
        : position === 'absolute' ? style.position !== 'static' || holdsFixed(style) : true;
      if (!holds) continue;
      ancestors.push({node, style});
      position = style.position;
    }
    return ancestors;
  };

  // Boxes stuck to the top edge of a scroll container (position: sticky)
  // paint over what scrolls under them, so they hide it as the edge itself
  // does. Each probe call finds a scroller's stuck boxes once.
  let stuckCache = null;
  const scrollerOf = node => {
    for (let parent = node.parentElement; parent; parent = parent.parentElement) {
      if (/(auto|scroll)/.test(getComputedStyle(parent).overflowY)) return parent;
    }
    return null;
  };
  const stuckBoxes = scroller => {
    if (stuckCache?.has(scroller)) return stuckCache.get(scroller);
    const edge = scroller.getBoundingClientRect().top + scroller.clientTop;
    const stuck = [];
    for (const node of scroller.querySelectorAll('*')) {
      const style = getComputedStyle(node);
      if (style.position !== 'sticky' || style.top === 'auto' || scrollerOf(node) !== scroller || !rendered(node)) continue;
      const rect = node.getBoundingClientRect();
      if (rect.top <= edge + parseFloat(style.top) + 1) stuck.push({node, rect});
    }
    stuckCache?.set(scroller, stuck);
    return stuck;
  };
  const withStuckBoxes = probe => (...args) => {
    stuckCache = new Map();
    try { return probe(...args); } finally { stuckCache = null; }
  };

  // The visible part of a node after every clipping ancestor, and every box
  // stuck over it in a scrolling one, is applied.
  const visibleRect = element => {
    let rect = element.getBoundingClientRect();
    let {left, top, right, bottom} = rect;
    for (const {node, style} of clippingAncestors(element)) {
      if (/(hidden|clip|auto|scroll)/.test(style.overflowX + style.overflowY)) {
        // Overflow clips at the padding box: content never paints over a
        // border or a classic scrollbar. Overflow does not apply to inline boxes.
        const box = node.getBoundingClientRect();
        const clip = style.display === 'inline' ? box : {left: box.left + node.clientLeft, top: box.top + node.clientTop,
          right: box.left + node.clientLeft + node.clientWidth, bottom: box.top + node.clientTop + node.clientHeight};
        left = Math.max(left, clip.left); right = Math.min(right, clip.right);
        top = Math.max(top, clip.top); bottom = Math.min(bottom, clip.bottom);
      }
      if (/(auto|scroll)/.test(style.overflowY)) {
        for (const stuck of stuckBoxes(node)) {
          if (stuck.node.contains(element) || element.contains(stuck.node)) continue;
          if (stuck.rect.left < right && stuck.rect.right > left) top = Math.max(top, stuck.rect.bottom);
        }
      }
    }
    left = Math.max(left, 0); top = Math.max(top, 0);
    right = Math.min(right, innerWidth); bottom = Math.min(bottom, innerHeight);
    return {left, top, right, bottom, width: Math.max(0, right - left), height: Math.max(0, bottom - top)};
  };

  // A control that extends past a clipping ancestor is acceptable only when
  // that ancestor actually scrolls in that direction. Otherwise return the
  // ancestor that cuts it off.
  const cutBy = element => {
    const rect = element.getBoundingClientRect();
    for (const {node, style} of clippingAncestors(element)) {
      const clip = node.getBoundingClientRect();
      const beyondX = rect.left < clip.left - 1 || rect.right > clip.right + 1;
      const beyondY = rect.top < clip.top - 1 || rect.bottom > clip.bottom + 1;
      const clipsX = beyondX && style.overflowX !== 'visible', clipsY = beyondY && style.overflowY !== 'visible';
      if (!clipsX && !clipsY) continue;
      const scrollsX = /(auto|scroll)/.test(style.overflowX) && node.scrollWidth > node.clientWidth + 1;
      const scrollsY = /(auto|scroll)/.test(style.overflowY) && node.scrollHeight > node.clientHeight + 1;
      if ((!clipsX || scrollsX) && (!clipsY || scrollsY)) return null;
      return node;
    }
    return rect.right > innerWidth + 1 || rect.bottom > innerHeight + 1 ? document.documentElement : null;
  };

  const ellipsized = element => {
    const style = getComputedStyle(element);
    return style.textOverflow === 'ellipsis' && /(hidden|clip)/.test(style.overflowX);
  };

  // A control is clipped when part of its box is cut off without a scroll
  // container the researcher can use, or when its own label overflows
  // without an explicit ellipsis.
  function layoutIssues(rootSelector) {
    const root = document.querySelector(rootSelector) || document.body;
    const controls = [...root.querySelectorAll(CONTROLS)].filter(rendered);
    const issues = [];
    if (document.documentElement.scrollWidth > innerWidth + 1) {
      issues.push(`page scrolls horizontally: ${document.documentElement.scrollWidth}px > ${innerWidth}px`);
    }
    const inView = [];
    for (const control of controls) {
      const rect = control.getBoundingClientRect();
      const visible = visibleRect(control);
      const cutter = cutBy(control);
      if (cutter) {
        issues.push(`cut off: ${describe(control)} shows ${Math.round(visible.width)}x${Math.round(visible.height)} of ${Math.round(rect.width)}x${Math.round(rect.height)}px inside ${describe(cutter)}`);
        continue;
      }
      if (visible.width === 0 || visible.height === 0) continue; // scrolled out of a usable scroll container
      // Nearly scrolled out: under 2 px of a box at least that large shows in
      // its scroller. Hit testing snaps to device pixels there, so the sliver's
      // center can land on the neighbouring row drawn where it should be. A
      // control whose own box is that small is still checked.
      if ((rect.width >= 2 && visible.width < 2) || (rect.height >= 2 && visible.height < 2)) continue;
      inView.push({control, visible});
      if (control.matches('button,summary,[role=tab]') && control.scrollWidth > control.clientWidth + 1 && !ellipsized(control) &&
          getComputedStyle(control).overflowX !== 'visible') {
        issues.push(`label overflows its control: ${describe(control)}`);
      }
      const centerX = (visible.left + visible.right) / 2, centerY = (visible.top + visible.bottom) / 2;
      const hit = document.elementFromPoint(centerX, centerY);
      if (hit && !control.contains(hit) && !hit.contains(control) && !hit.closest('label')?.contains(control)) {
        issues.push(`covered: ${describe(control)} is under ${describe(hit)} at ${Math.round(centerX)},${Math.round(centerY)}`);
      }
    }
    for (let first = 0; first < inView.length; first += 1) {
      for (let second = first + 1; second < inView.length; second += 1) {
        const a = inView[first], b = inView[second];
        if (a.control.contains(b.control) || b.control.contains(a.control)) continue;
        const width = Math.min(a.visible.right, b.visible.right) - Math.max(a.visible.left, b.visible.left);
        const height = Math.min(a.visible.bottom, b.visible.bottom) - Math.max(a.visible.top, b.visible.top);
        if (width > 2 && height > 2) issues.push(`overlap: ${describe(a.control)} and ${describe(b.control)} (${Math.round(width)}x${Math.round(height)}px)`);
      }
    }
    return {controls: controls.length, inView: inView.length, issues: [...new Set(issues)].slice(0, 40)};
  }

  function focusState() {
    const element = document.activeElement;
    if (!element || element === document.body) return {element: describe(element), visible: false, indicator: 'none', inViewport: false};
    const style = getComputedStyle(element);
    const outline = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0 ? `outline ${style.outlineWidth} ${style.outlineStyle} ${style.outlineColor}` : '';
    const shadow = style.boxShadow && style.boxShadow !== 'none' ? `box-shadow ${style.boxShadow}` : '';
    const visible = visibleRect(element);
    return {
      element: describe(element), id: element.id || '', tag: element.tagName.toLowerCase(),
      focusVisible: element.matches(':focus-visible'), indicator: outline || shadow || 'none',
      inViewport: visible.width > 0 && visible.height > 0, rendered: rendered(element),
      top: Math.round(element.getBoundingClientRect().top), left: Math.round(element.getBoundingClientRect().left),
    };
  }

  // Traffic mounts only rows near the view; scroll to a read row so the next poll finds it mounted.
  function revealListRow(text) {
    for (const container of document.querySelectorAll('.request-rows')) {
      const block = container.trafficBlock;
      const at = block ? block.requests.findIndex(request => request && `${request.method} ${request.path}`.includes(text)) : -1;
      if (at < 0) continue;
      const height = Number(container.dataset.rowHeight) || 28;
      container.scrollTop = Math.max(0, (block.start + at) * height - container.clientHeight / 2);
      return true;
    }
    return false;
  }

  function center(selector, text, block = 'nearest') {
    const candidates = [...document.querySelectorAll(selector)].filter(rendered)
      .filter(element => !text || element.textContent.replace(/\s+/g, ' ').includes(text));
    const element = candidates[0];
    if (!element) {
      if (text && selector.includes('.request-row')) revealListRow(text);
      return null;
    }
    element.scrollIntoView({block, inline: 'nearest'});
    const visible = visibleRect(element);
    if (visible.width === 0 || visible.height === 0) return null;
    return {x: (visible.left + visible.right) / 2, y: (visible.top + visible.bottom) / 2, element: describe(element)};
  }

  // Captured strings must stay text: no injected element, handler or global.
  function inertness(markers) {
    const executed = window.__rebInjected !== undefined;
    const injectedElements = document.querySelectorAll('img[src="x"], svg[onload], #reb-injected-markup').length;
    const text = document.body.innerText;
    return {executed, injectedElements, visibleMarkers: markers.filter(marker => text.includes(marker))};
  }

  // Text that is clipped by its own box without an ellipsis or scroll path.
  function clippedText(rootSelector) {
    const root = document.querySelector(rootSelector) || document.body;
    const issues = [];
    for (const element of root.querySelectorAll('*')) {
      if (!rendered(element) || element.children.length > 0 || !element.textContent.trim()) continue;
      // A box of a pixel or less shows no text: it is kept for assistive readers.
      const box = element.getBoundingClientRect();
      if (box.width <= 1 && box.height <= 1) continue;
      const style = getComputedStyle(element);
      // A line clamp is an explicit, visible truncation with an ellipsis.
      const clamped = style.webkitLineClamp && style.webkitLineClamp !== 'none';
      const clipsY = !clamped && /(hidden|clip)/.test(style.overflowY) && element.scrollHeight > element.clientHeight + 2;
      const clipsX = /(hidden|clip)/.test(style.overflowX) && element.scrollWidth > element.clientWidth + 1 && style.textOverflow !== 'ellipsis';
      if (clipsY || clipsX) issues.push(`text clipped ${clipsY ? 'vertically' : 'horizontally'}: ${describe(element)}`);
    }
    return [...new Set(issues)].slice(0, 20);
  }

  function scrollContainer(selector) {
    for (let node = document.querySelector(selector); node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (/(auto|scroll)/.test(style.overflowY) && node.scrollHeight > node.clientHeight + 1) return node;
    }
    return null;
  }

  // Scrolls the list that owns `selector` to its end and back, through the
  // same scroll position a wheel gesture would change.
  function scrollToEnd(selector, lastSelector) {
    const container = scrollContainer(selector);
    if (!container) return {scrollable: false};
    const before = container.scrollTop;
    container.scrollTop = container.scrollHeight;
    const moved = container.scrollTop > before;
    const items = [...container.querySelectorAll(lastSelector)];
    const last = items.at(-1);
    const lastVisible = last ? visibleRect(last).height > 0 : false;
    return {scrollable: true, moved, lastVisible, last: last ? describe(last) : 'none', before, after: container.scrollTop};
  }

  function scrollProbe(selector) {
    const element = document.querySelector(selector);
    if (!element || !rendered(element)) return {found: false};
    const before = element.scrollTop;
    element.scrollTop = element.scrollHeight;
    const after = element.scrollTop;
    const scrollable = element.scrollHeight > element.clientHeight + 1;
    const last = element.lastElementChild;
    const lastVisible = last ? visibleRect(last).height > 0 : false;
    element.scrollTop = before;
    return {found: true, scrollable, moved: after > before, lastVisible, scrollHeight: element.scrollHeight, clientHeight: element.clientHeight};
  }

  const text = selector => [...document.querySelectorAll(selector)].filter(rendered).map(element => element.innerText).join('\n');
  const visibleText = () => document.body.innerText;
  const count = selector => [...document.querySelectorAll(selector)].filter(rendered).length;
  const exists = selector => document.querySelectorAll(selector).length;

  function box(selector) {
    const node = document.querySelector(selector);
    if (!node) return {};
    const rect = node.getBoundingClientRect(), visible = visibleRect(node);
    return {left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
      width: rect.width, height: rect.height, visibleHeight: visible.height, visibleWidth: visible.width,
      scrollTop: node.scrollTop, scrollHeight: node.scrollHeight, clientHeight: node.clientHeight};
  }

  // Controls in scope whose visible part meets the divider's hit target. A
  // shared edge is touching, not overlapping. layoutIssues tests only centers,
  // so a control's edge or a scrolled row's sliver could sit under the divider.
  // The divider straddles its panes' shared edge by design, so focusable panes
  // themselves are named and skipped; everything inside them is checked.
  function dividerReach(dividerSelector, rootSelector, paneSelectors = []) {
    const divider = document.querySelector(dividerSelector), root = document.querySelector(rootSelector) || document.body;
    if (!divider || divider.hidden) return {shown: false, offenders: []};
    const panes = new Set(paneSelectors.map(selector => document.querySelector(selector)));
    const reach = divider.getBoundingClientRect();
    const offenders = [];
    for (const control of root.querySelectorAll(CONTROLS)) {
      if (panes.has(control) || !rendered(control)) continue;
      const visible = visibleRect(control);
      const width = Math.min(visible.right, reach.right) - Math.max(visible.left, reach.left);
      const height = Math.min(visible.bottom, reach.bottom) - Math.max(visible.top, reach.top);
      if (width > 0.01 && height > 0.01) offenders.push(`${describe(control)} meets ${Math.round(width * 10) / 10}x${Math.round(height * 10) / 10}px`);
    }
    return {shown: true, offenders: offenders.slice(0, 20)};
  }

  window.__rebUiProbe = {layoutIssues: withStuckBoxes(layoutIssues), clippedText, scrollToEnd, focusState, center, inertness, scrollProbe,
    text, visibleText, count, exists, describe, box, dividerReach: withStuckBoxes(dividerReach)};
})();
