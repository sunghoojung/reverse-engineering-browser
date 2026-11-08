/* The Traffic timing strip: request starts over the session, one bar per
 * time bucket. Dragging across it, or Shift+Arrow keys, selects a time range
 * that filters the table; Escape or Clear range removes it. */
function mountTrafficOverview(root, {onRange}) {
  const track = root.querySelector('.overview-track');
  const label = root.querySelector('.overview-range');
  const clear = root.querySelector('.overview-clear');
  const selection = document.createElement('span');
  selection.className = 'overview-selection';
  selection.hidden = true;
  let model = null, drag = null;
  root.dataset.renderKey = '';

  const fraction = event => {
    const box = track.getBoundingClientRect();
    return box.width > 0 ? Math.max(0, Math.min(1, (event.clientX - box.left) / box.width)) : 0;
  };
  // Bucket edges in nanoseconds; the last bucket ends at the last record.
  const edge = index => {
    const span = model.last - model.first + 1n;
    return model.first + span * BigInt(index) / BigInt(model.buckets.length);
  };
  const bucketOf = value => Math.max(0, Math.min(model.buckets.length - 1,
    Number((value - model.first) * BigInt(model.buckets.length) / (model.last - model.first + 1n))));
  // The strip shows a choice at once; the table follows when its query answers.
  const select = range => {
    if (model) model.range = range;
    paint();
    describe();
    onRange(range);
  };
  const choose = (from, to) => {
    const [low, high] = from <= to ? [from, to] : [to, from];
    select({from: edge(low), to: edge(high + 1) - 1n});
  };
  const ms = value => trafficTimeLabel(Number(value) / 1e6);

  track.addEventListener('pointerdown', event => {
    if (!model || event.button !== 0) return;
    event.preventDefault();
    track.setPointerCapture?.(event.pointerId);
    track.focus({preventScroll: true});
    const bucket = Math.min(model.buckets.length - 1, Math.floor(fraction(event) * model.buckets.length));
    drag = {start: bucket, end: bucket};
    paint();
  });
  track.addEventListener('pointermove', event => {
    if (!drag) return;
    drag.end = Math.min(model.buckets.length - 1, Math.floor(fraction(event) * model.buckets.length));
    paint();
  });
  const finish = () => {
    if (!drag) return;
    const {start, end} = drag;
    drag = null;
    choose(start, end);
  };
  track.addEventListener('pointerup', finish);
  track.addEventListener('pointercancel', () => { drag = null; paint(); });
  track.addEventListener('keydown', event => {
    if (!model) return;
    const last = model.buckets.length - 1;
    if (['Escape', 'Delete', 'Backspace'].includes(event.key) && model.range) {
      event.preventDefault();
      event.stopPropagation();
      select(null);
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
      event.preventDefault();
      const step = event.key === 'ArrowRight' ? 1 : -1;
      if (!model.range) {
        const at = step > 0 ? 0 : last;
        choose(at, at);
        return;
      }
      const low = bucketOf(model.range.from), high = bucketOf(model.range.to);
      // Shift moves the end; a plain arrow moves the whole range.
      if (event.shiftKey) choose(low, Math.max(low, Math.min(last, high + step)));
      else {
        const shift = Math.max(-low, Math.min(last - high, step));
        choose(low + shift, high + shift);
      }
    }
  });
  clear.addEventListener('click', () => { select(null); track.focus({preventScroll: true}); });

  function describe() {
    const range = model?.range;
    const total = model ? ms(model.last - model.first) : '';
    label.textContent = !model ? 'No request timeline yet'
      : range ? `${ms(range.from - model.first)} – ${ms(range.to - model.first)} of ${total}` : `${total} · drag to filter by time`;
    clear.hidden = !range;
    root.dataset.range = String(Boolean(range));
  }

  function paint() {
    const count = model?.buckets.length ?? 0;
    const range = drag ? {low: Math.min(drag.start, drag.end), high: Math.max(drag.start, drag.end)}
      : model?.range && count ? {low: bucketOf(model.range.from), high: bucketOf(model.range.to)} : null;
    selection.hidden = !range;
    if (range) {
      selection.style.left = `${range.low * 100 / count}%`;
      selection.style.width = `${(range.high - range.low + 1) * 100 / count}%`;
    }
  }

  return {
    // `timeline` is {first, last, buckets} with BigInt bounds; `range` is {from, to} or null.
    render(timeline, range) {
      const empty = !timeline || timeline.first === null;
      const key = empty ? 'empty' : `${timeline.first}:${timeline.last}:${timeline.buckets.join(',')}:${range ? `${range.from}:${range.to}` : ''}`;
      if (root.dataset.renderKey === key) return;
      root.dataset.renderKey = key;
      root.dataset.empty = String(empty);
      model = empty ? null : {...timeline, range};
      const peak = empty ? 0 : Math.max(...timeline.buckets);
      const bars = empty ? [] : timeline.buckets.map(count => {
        const bar = document.createElement('span');
        bar.className = 'overview-bar';
        bar.style.height = `${count ? Math.max(8, count * 100 / peak) : 0}%`;
        return bar;
      });
      track.replaceChildren(...bars, selection);
      paint();
      describe();
    }
  };
}
