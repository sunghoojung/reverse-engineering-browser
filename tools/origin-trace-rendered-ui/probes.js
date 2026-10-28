// Rendered-layout probes evaluated by the hosted XCTest inside the packaged
// Origin Trace WKWebView. They only read the DOM and computed layout; every
// interaction is a native AppKit event sent by the Swift test.
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
      if (node.tagName === 'DETAILS' && !node.open && node !== element && !element.matches('summary') &&
          node.querySelector(':scope > summary') !== element && !element.closest('summary')) return false;
    }
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };

  // The visible part of a node after every clipping ancestor is applied.
  const visibleRect = element => {
    let rect = element.getBoundingClientRect();
    let {left, top, right, bottom} = rect;
    for (let node = element.parentElement; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (/(hidden|clip|auto|scroll)/.test(style.overflowX + style.overflowY)) {
        const clip = node.getBoundingClientRect();
        left = Math.max(left, clip.left); right = Math.min(right, clip.right);
        top = Math.max(top, clip.top); bottom = Math.min(bottom, clip.bottom);
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
    for (let node = element.parentElement; node; node = node.parentElement) {
      const style = getComputedStyle(node);
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

  function center(selector, text) {
    const candidates = [...document.querySelectorAll(selector)].filter(rendered)
      .filter(element => !text || element.textContent.replace(/\s+/g, ' ').includes(text));
    const element = candidates[0];
    if (!element) return null;
    element.scrollIntoView({block: 'nearest', inline: 'nearest'});
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

  window.__rebUiProbe = {layoutIssues, clippedText, scrollToEnd, focusState, center, inertness, scrollProbe, text, visibleText, count, exists, describe};
})();
