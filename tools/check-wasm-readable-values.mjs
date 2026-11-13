#!/usr/bin/env node
// Value-level check of the readable Wasm lift (protocol/wasm-pseudocode-v1.md).
// `make wasm-readable-values-check` has the Rust tests write a corpus of
// generated i32 modules with their lifted listings; this script runs each
// module in V8 and interprets its listing with the same logging imports, then
// requires the same result or trap or escaping exception, the same import call
// log, the same g0, memory pages and first 600 bytes of memory, for every
// input. The imports throw (f on 13, thr on odd values) into try_table
// handlers that read locals, so a listing that moves a local write across a
// call a handler can catch reads a different value here. A mutated listing
// (an addition read as a subtraction) must then differ, so the check cannot
// pass by comparing nothing.
import fs from 'node:fs';

const [, , file, limitArg] = process.argv;
if (!file) { console.error('usage: check-wasm-readable-values.mjs CORPUS.jsonl [LIMIT]'); process.exit(2); }
const rows = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
const limit = Number(limitArg || rows.length);
const INPUTS = [[0, 0], [1, 2], [-1, 7], [5, -3], [3, 3]];
const FUEL = 60;

class Trap extends Error {}
class Fuel extends Error {}
class Br { constructor(label, values) { this.label = label; } }
class Ret { constructor(values) { this.values = values; } }
// A tail call leaves the function, and so every handler in it, before the
// callee runs; the call is made at the top, outside every try.
class TailCall { constructor(fn, args) { this.fn = fn; this.args = args; } }
const catchable = e => (e && e.wasmExc !== undefined) || e instanceof Fuel;

function makeEnv(tag, state) {
  const log = state.log;
  return {
    f: x => { log.push(`f(${x})`); if (x === 13) throw state.makeExc(x); return (Math.imul(x, 7) + 1) | 0; },
    g: () => { log.push('g'); state.counter += 1; return state.counter; },
    h: x => { log.push(`h(${x})`); },
    two: () => { log.push('two'); return [state.counter + 10, state.counter + 20]; },
    tick: () => { log.push('tick'); state.ticks += 1; if (state.ticks > FUEL) throw new Fuel('fuel'); },
    thr: x => { log.push(`thr(${x})`); if (x & 1) throw state.makeExc(x); },
    // mv throws on 13 so a tail call to it from inside a handler shows
    // whether the listing lets the exception escape, as V8 does.
    mv: x => { log.push(`mv(${x})`); if (x === 13) throw state.makeExc(x); return [x ^ 5, (x + 100) | 0]; },
  };
}

function runEngine(bytes, a, b) {
  const tag = new WebAssembly.Tag({parameters: ['i32']});
  const state = {log: [], counter: 0, ticks: 0, makeExc: x => new WebAssembly.Exception(tag, [x])};
  const env = makeEnv(tag, state);
  const {instance} = { instance: new WebAssembly.Instance(new WebAssembly.Module(bytes), {env}) };
  let outcome;
  try { const r = instance.exports.run(a, b); outcome = `ret ${r[0]},${r[1]}`; }
  catch (e) {
    if (e instanceof WebAssembly.RuntimeError) outcome = 'trap';
    else if (e instanceof Fuel) outcome = 'fuel';
    else if (e instanceof WebAssembly.Exception) outcome = 'exception';
    else outcome = `error ${e}`;
  }
  const mem = new Uint8Array(instance.exports.mem.buffer);
  return {outcome, log: state.log.join(' '), g0: instance.exports.g0.value, pages: mem.length / 65536, mem: Buffer.from(mem.slice(0, 600)).toString('hex')};
}

// ---- listing parser -------------------------------------------------------
function tokenize(s) {
  const out = []; let i = 0;
  const ops = ['>>>', '<=u', '>=u', '==', '!=', '<u', '>u', '/u', '%u', '>>', '<<', '<=', '>=', '+', '-', '*', '/', '%', '&', '|', '^', '<', '>', '=', '(', ')', ',', ';', '{', '}', ':'];
  while (i < s.length) {
    const c = s[i];
    if (c === ' ') { i++; continue; }
    const prev = out[out.length - 1];
    const unaryCtx = !prev || (prev.t === 'op' && prev.v !== ')') || (prev.t === 'id' && !/^[plgt][0-9]+$/.test(prev.v));
    if (/[0-9]/.test(c) || (c === '-' && unaryCtx && /[0-9]/.test(s[i + 1]))) {
      let j = i + 1; while (j < s.length && /[0-9]/.test(s[j])) j++;
      out.push({t: 'num', v: Number(s.slice(i, j)) | 0}); i = j; continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1; while (j < s.length && /[A-Za-z0-9_$.]/.test(s[j])) j++;
      out.push({t: 'id', v: s.slice(i, j)}); i = j; continue;
    }
    const op = ops.find(o => s.startsWith(o, i) && !(/^[<>\/%]u$|^[<>]=u$/.test(o) && /[A-Za-z0-9_]/.test(s[i + o.length] ?? '')));
    if (!op) throw Error(`token at ${s.slice(i)}`);
    out.push({t: 'op', v: op}); i += op.length;
  }
  return out;
}
class P {
  constructor(text) { this.k = tokenize(text); this.i = 0; this.text = text; }
  peek(n = 0) { return this.k[this.i + n]; }
  is(v, n = 0) { const t = this.peek(n); return t && t.t === 'op' && t.v === v; }
  eat(v) { if (!this.is(v)) throw Error(`expected ${v} at ${this.i} in: ${this.text}`); this.i++; }
  id() { const t = this.k[this.i++]; if (!t || t.t !== 'id') throw Error(`expected id in ${this.text}`); return t.v; }
  done() { return this.i >= this.k.length; }
  // expr := lvalue '=' expr | operand [binop operand]
  expr() {
    const t = this.peek();
    if (t && t.t === 'id' && /^[plgt][0-9]+$/.test(t.v) && this.is('=', 1)) {
      this.i += 2; const value = this.expr(); return {k: 'assign', name: t.v, value};
    }
    const left = this.operand();
    const o = this.peek();
    if (o && o.t === 'op' && !['(', ')', ',', ';', '{', '}', ':', '='].includes(o.v)) {
      this.i++; const right = this.operand(); return {k: 'bin', op: o.v, left, right};
    }
    return left;
  }
  operand() {
    const t = this.k[this.i++];
    if (!t) throw Error(`eof in ${this.text}`);
    if (t.t === 'num') return {k: 'num', v: t.v};
    if (t.t === 'op' && t.v === '(') { const e = this.expr(); this.eat(')'); return e; }
    if (t.t === 'id') {
      if (this.is('(')) {
        this.i++;
        const args = []; let named = {};
        if (t.v === 'call_indirect') {
          if (!this.is(';') && !(this.peek().t === 'id' && this.peek().v === 'index')) { args.push(this.expr()); while (this.is(',')) { this.i++; args.push(this.expr()); } }
          if (this.is(';')) this.i++;
          if (this.id() !== 'index') throw Error('index');
          const idx = this.expr();
          let type = null;
          while (this.is(',')) { this.i++; const n = this.id(); const v = this.operand(); if (n === 'type') type = v.v; }
          this.eat(')');
          return {k: 'ci', args, idx, type};
        }
        while (!this.is(')')) {
          if (this.peek().t === 'id' && this.peek().v === 'offset' && this.peek(1)?.t === 'num') { this.i++; named.offset = this.k[this.i++].v; }
          else args.push(this.expr());
          if (this.is(',')) this.i++;
        }
        this.eat(')');
        return {k: 'call', name: t.v, args, named};
      }
      return {k: 'var', name: t.v};
    }
    throw Error(`operand ${JSON.stringify(t)} in ${this.text}`);
  }
}
function withList(p) {
  // with t3 = e, t4 = e
  const pairs = [];
  do { if (pairs.length) p.eat(','); const name = p.id(); p.eat('='); pairs.push({name, value: p.expr()}); } while (p.is(','));
  return pairs;
}

function parseListing(text) {
  const lines = text.split('\n').filter(l => l.length).map(l => l.trim());
  let pos = 1; // skip header
  function block(stopAtElse) {
    const items = [];
    while (pos < lines.length) {
      const line = lines[pos];
      if (line === '}' || line.startsWith('} else') || line.startsWith('} catch') || line.startsWith('} delegate')) return items;
      pos++;
      if (line.startsWith('var ')) continue;
      let m;
      if ((m = /^block x(\d+) L(\d+)\.\.L(\d+) \{$/.exec(line))) {
        const n = Number(m[1]), first = Number(m[2]);
        // n nested frames, each closed by its own line
        const node = nest(n, first);
        items.push(node); continue;
      }
      if (/^(block|loop|try_table|try |if \(|switch \()/.test(line) && line.endsWith('{')) {
        items.push(frame(line)); continue;
      }
      items.push({k: 'stmt', line});
    }
    return items;
  }
  function nest(n, first) {
    // Build innermost-last nested blocks; each consumes one closing '}'.
    const root = {k: 'block', label: `L${first}`, body: null};
    let cur = root; const chain = [root];
    for (let i = 1; i < n; i++) { const c = {k: 'block', label: `L${first + i}`, body: null}; chain.push(c); }
    for (let i = n - 1; i >= 0; i--) {
      const body = block();
      if (lines[pos] !== '}') throw Error('run close');
      pos++;
      if (i === n - 1) chain[i].body = body; else chain[i].body = [chain[i + 1], ...body];
    }
    // The above reads innermost first, which matches line order only when the
    // inner bodies come first; the lift places them so.
    return root;
  }
  function frame(line) {
    let m;
    // A legacy try: its body, then catch_all arms. A tagged catch or a
    // delegate is outside this corpus, so it reads as unsupported.
    if ((m = /^try( L\d+)? \{$/.exec(line))) {
      const label = m[1]?.trim() ?? null;
      const body = block();
      const arms = [];
      for (;;) {
        const close = lines[pos++];
        if (close === '}') break;
        if (close === '} catch_all {') { arms.push(block()); continue; }
        return {k: 'unsupported', line: close};
      }
      return {k: 'ltry', label, body, arms};
    }
    if (line.startsWith('switch (')) {
      const p = new P(line.slice(0, -1).trim()); p.id(); p.eat('('); const sel = p.expr(); p.eat(')');
      const cases = [];
      while (lines[pos] !== '}') {
        const c = lines[pos++];
        const mm = /^(case ([0-9, \-.+()a-z]+)|default): (.*)$/.exec(c);
        if (!mm) throw Error(`case ${c}`);
        const set = new Set();
        if (mm[2]) for (const part of mm[2].split(', ')) { const r = /^(\d+)(?:-(\d+))?$/.exec(part); if (!r) throw Error('case list'); for (let x = Number(r[1]); x <= Number(r[2] ?? r[1]); x++) set.add(x); }
        cases.push({def: !mm[2], set, stmt: mm[3]});
      }
      pos++;
      return {k: 'switch', sel, cases};
    }
    if (line.startsWith('if (')) {
      // if (expr) [Lk] {
      const inner = line.slice(0, -1).trim();
      const lm = / (L\d+)$/.exec(inner);
      const head = lm ? inner.slice(0, lm.index) : inner;
      const p = new P(head); p.id(); p.eat('('); const cond = p.expr(); p.eat(')');
      const then = block();
      let els = [], inline = null;
      const close = lines[pos++];
      if (close === '} else {') { els = block(); if (lines[pos++] !== '}') throw Error('else close'); }
      else if (close.startsWith('} else { ')) { const p2 = new P(close.slice('} else { '.length, -2)); inline = withList(p2); }
      else if (close !== '}') throw Error(`if close ${close}`);
      return {k: 'if', label: lm?.[1], cond, then, els, inline};
    }
    const kind = line.startsWith('block') ? 'block' : line.startsWith('loop') ? 'loop' : 'try';
    let rest = line.slice(kind === 'try' ? 'try_table'.length : kind.length, -1).trim();
    let label = null;
    if ((m = /^(L\d+)\b ?/.exec(rest))) { label = m[1]; rest = rest.slice(m[0].length); }
    let init = [], catches = [];
    if (kind === 'loop' && rest.startsWith('with ')) { const p = new P(rest.slice(5)); init = withList(p); }
    if (kind === 'try' && rest) {
      for (const c of rest.split(', ')) { const cm = /^catch_all -> (L\d+)$/.exec(c); if (!cm) return {k: 'unsupported', line}; catches.push(cm[1]); }
    }
    const body = block();
    if (lines[pos++] !== '}') throw Error(`frame close for ${line}`);
    return {k: kind, label, init, catches, body};
  }
  const body = block();
  return body;
}

// ---- interpreter ----------------------------------------------------------
function interpret(listing, a, b, tagless) {
  const state = {log: [], counter: 0, ticks: 0, makeExc: x => ({wasmExc: x})};
  const env = makeEnv(null, state);
  let pages = 1; let mem = new Uint8Array(65536);
  const vars = {p0: a | 0, p1: b | 0, l2: 0, l3: 0, g0: 0};
  const names = {f: env.f, g: env.g, h: env.h, two: env.two, tick: env.tick, thr: env.thr, mv: env.mv};
  const table = [names.mv, names.f];
  const u = x => x >>> 0;
  function bin(op, x, y) {
    switch (op) {
      case '+': return (x + y) | 0; case '-': return (x - y) | 0; case '*': return Math.imul(x, y);
      case '/': if (y === 0 || (x === -2147483648 && y === -1)) throw new Trap('div'); return (x / y) | 0;
      case '%u': if (y === 0) throw new Trap('rem'); return (u(x) % u(y)) | 0;
      case '%': if (y === 0) throw new Trap('rem'); return (x % y) | 0;
      case '/u': if (y === 0) throw new Trap('div'); return (u(x) / u(y)) | 0;
      case '^': return x ^ y; case '&': return x & y; case '|': return x | y;
      case '<': return x < y ? 1 : 0; case '<u': return u(x) < u(y) ? 1 : 0;
      case '>>>': return (x >>> (y & 31)) | 0; case '>>': return x >> (y & 31); case '<<': return x << (y & 31);
      case '==': return x === y ? 1 : 0; case '!=': return x !== y ? 1 : 0;
      default: throw Error(`op ${op}`);
    }
  }
  function load(addr, offset) { const at = u(addr) + offset; if (at + 4 > pages * 65536) throw new Trap('oob'); return (mem[at] | mem[at + 1] << 8 | mem[at + 2] << 16 | mem[at + 3] << 24) | 0; }
  function store(addr, offset, v) { const at = u(addr) + offset; if (at + 4 > pages * 65536) throw new Trap('oob'); mem[at] = v & 255; mem[at + 1] = v >> 8 & 255; mem[at + 2] = v >> 16 & 255; mem[at + 3] = v >> 24 & 255; }
  function callv(name, args) {
    if (name === 'i32.load') return load(args[0], 0);
    if (name === 'memory.size') return pages;
    if (name === 'memory.grow') { const n = u(args[0]); if (pages + n > 65536) return -1; const old = pages; pages += n; const m2 = new Uint8Array(pages * 65536); m2.set(mem); mem = m2; return old; }
    if (name === 'select') return args[2] !== 0 ? args[0] : args[1];
    const fn = names[name]; if (!fn) throw Error(`call ${name}`);
    return fn(...args);
  }
  function ev(e) {
    switch (e.k) {
      case 'num': return e.v;
      case 'var': if (!(e.name in vars)) throw Error(`unassigned ${e.name}`); return vars[e.name];
      case 'assign': { const v = ev(e.value); vars[e.name] = v; return v; }
      case 'bin': { const x = ev(e.left); const y = ev(e.right); return bin(e.op, x, y); }
      case 'call': {
        const args = e.args.map(ev);
        if (e.name === 'i32.load') return load(args[0], e.named.offset ?? 0);
        const r = callv(e.name, args);
        return Array.isArray(r) ? r : r;
      }
      case 'ci': { const args = e.args.map(ev); const i = ev(e.idx); const fn = table[u(i)]; if (!fn) throw new Trap('table'); if (fn !== (e.type === 1 ? table[0] : table[1])) throw new Trap('sig'); return fn(...args); }
    }
    throw Error(`ev ${e.k}`);
  }
  function assignPairs(pairs) {
    const vals = pairs.map(p => ev(p.value));
    pairs.forEach((p, i) => { vars[p.name] = vals[i]; });
  }
  function stmt(line) {
    let m;
    if (line === 'nop') return;
    if (line === 'unreachable') throw new Trap('unreachable');
    if (line === 'return') throw new Ret([]);
    if ((m = /^if \((.*)\) return(?: (.*))?$/.exec(line))) {
      const p = new P(line); p.id(); p.eat('('); const c = p.expr(); p.eat(')'); p.id();
      const vals = []; if (!p.done()) { vals.push(p.expr()); while (p.is(',')) { p.i++; vals.push(p.expr()); } }
      if (ev(c) !== 0) throw new Ret(vals.map(ev));
      return;
    }
    if (line.startsWith('return_call ')) {
      const call = new P(line.slice('return_call '.length)).expr();
      if (call.k === 'call') {
        const args = call.args.map(ev);
        const fn = names[call.name]; if (!fn) throw Error(`call ${call.name}`);
        throw new TailCall(fn, args);
      }
      if (call.k === 'ci') {
        const args = call.args.map(ev); const i = ev(call.idx); const fn = table[u(i)];
        if (!fn) throw new Trap('table');
        if (fn !== (call.type === 1 ? table[0] : table[1])) throw new Trap('sig');
        throw new TailCall(fn, args);
      }
      throw Error(`tail call ${line}`);
    }
    if (line.startsWith('return ')) {
      const p = new P(line.slice(7)); const vals = [p.expr()]; while (p.is(',')) { p.i++; vals.push(p.expr()); }
      const out = vals.map(ev);
      throw new Ret(out.length === 1 && Array.isArray(out[0]) ? out[0] : out);
    }
    if (line.startsWith('br_if ')) {
      const p = new P(line); p.id(); const label = p.id(); p.eat('('); const c = p.expr(); p.eat(')');
      let pairs = []; if (!p.done()) { if (p.id() !== 'with') throw Error('with'); pairs = withList(p); }
      if (ev(c) !== 0) { assignPairs(pairs); throw new Br(label); }
      return;
    }
    if (line.startsWith('br ')) {
      const p = new P(line); p.id(); const label = p.id();
      let pairs = []; if (!p.done()) { if (p.id() !== 'with') throw Error('with'); pairs = withList(p); }
      assignPairs(pairs); throw new Br(label);
    }
    if ((m = /^drop\((.*)\)$/.exec(line))) { ev(new P(m[1]).expr()); return; }
    if ((m = /^(t\d+(?:, t\d+)+) = (.*)$/.exec(line))) {
      const r = ev(new P(m[2]).expr()); m[1].split(', ').forEach((n, i) => { vars[n] = r[i]; }); return;
    }
    if ((m = /^i32\.store\((.*)\) = (.*)$/.exec(line))) {
      // the address part may contain ', offset N'
      const p = new P(`i32.store(${m[1]})`); const call = p.operand();
      const addr = ev(call.args[0]); const v = ev(new P(m[2]).expr()); store(addr, call.named.offset ?? 0, v); return;
    }
    const p = new P(line); const e = p.expr(); if (!p.done()) throw Error(`trailing in ${line}`);
    const r = ev(e);
    void r;
  }
  function exec(items) {
    for (const it of items) {
      switch (it.k) {
        case 'stmt': stmt(it.line); break;
        case 'block': try { exec(it.body); } catch (e) { if (!(e instanceof Br && e.label === it.label)) throw e; } break;
        case 'loop': {
          assignPairs(it.init);
          for (;;) { try { exec(it.body); break; } catch (e) { if (e instanceof Br && e.label === it.label) continue; throw e; } }
          break;
        }
        case 'if': {
          let taken;
          try {
            taken = ev(it.cond) !== 0;
            if (taken) exec(it.then); else if (it.inline) assignPairs(it.inline); else exec(it.els);
          } catch (e) { if (!(e instanceof Br && e.label === it.label)) throw e; }
          break;
        }
        case 'try': {
          try { exec(it.body); }
          catch (e) {
            if (e instanceof Br && e.label === it.label) break;
            // A handler catches a thrown exception, or the Fuel error a JS
            // import throws (catch_all catches JS exceptions too). Anything
            // else, an interpreter error included, passes through and fails
            // the check instead of reading as a caught throw.
            if (it.catches.length && catchable(e)) throw new Br(it.catches[0]);
            throw e;
          }
          break;
        }
        case 'ltry': {
          let caught = false;
          try { exec(it.body); }
          catch (e) {
            if (e instanceof Br && e.label === it.label) break;
            if (!it.arms.length || !catchable(e)) throw e;
            caught = true;
          }
          if (caught) {
            try { exec(it.arms[0]); }
            catch (e) { if (!(e instanceof Br && e.label === it.label)) throw e; }
          }
          break;
        }
        case 'switch': {
          const s = u(ev(it.sel));
          const c = it.cases.find(c => !c.def && c.set.has(s)) ?? it.cases.find(c => c.def);
          stmt(c.stmt);
          throw Error('switch fell through');
        }
        case 'unsupported': throw new Error('UNSUPPORTED');
      }
    }
  }
  let outcome;
  try {
    try { exec(listing); throw Error('fell off function'); }
    catch (e) {
      if (!(e instanceof TailCall)) throw e;
      const r = e.fn(...e.args);
      throw new Ret(r);
    }
  }
  catch (e) {
    if (e instanceof Ret) outcome = `ret ${e.values[0]},${e.values[1]}`;
    else if (e instanceof Trap) outcome = 'trap';
    else if (e instanceof Fuel) outcome = 'fuel';
    else if (e && e.wasmExc !== undefined) outcome = 'exception';
    else throw e;
  }
  return {outcome, log: state.log.join(' '), g0: vars.g0, pages, mem: Buffer.from(mem.slice(0, 600)).toString('hex')};
}

function check(mutate) {
  let compared = 0, mismatched = 0, skipped = 0, parseErrors = 0, executed = 0;
  const firstMismatches = [];
  for (const source of rows.slice(0, limit)) {
    const row = {...source};
    const otherFallbacks = row.fallbacks - (row.exception_handlers ?? 0);
    if (row.status !== 'complete' || otherFallbacks > 0 || row.next !== null) { skipped++; continue; }
    // The sanity mutation reads every addition as a subtraction, and the
    // epilogue's first store as storing p1 instead of p0.
    if (mutate) {
      const t = row.text.replaceAll(' + ', ' - ').replace('i32.store(0, offset 16) = p0', 'i32.store(0, offset 16) = p1');
      if (t === row.text) { skipped++; continue; }
      row.text = t;
    }
    let listing;
    try { listing = parseListing(row.text); }
    catch (e) { parseErrors++; if (!mutate && parseErrors <= 3) console.log(`PARSE seed ${row.seed}: ${e.message}\n${row.text}`); continue; }
    const bytes = Buffer.from(row.wasm, 'hex');
    executed++;
    for (const [a, b] of INPUTS) {
      const want = runEngine(bytes, a, b);
      let got;
      try { got = interpret(listing, a, b); }
      catch (e) { if (e.message === 'UNSUPPORTED') { skipped++; break; } parseErrors++; if (!mutate && parseErrors <= 3) console.log(`EVAL seed ${row.seed}: ${e.stack}\n${row.text}`); break; }
      compared++;
      // After a trap or an escaping exception there are no results; the log,
      // g0 and memory up to that point still must match.
      const same = want.outcome === got.outcome && want.log === got.log && want.g0 === got.g0 && want.pages === got.pages && want.mem === got.mem;
      if (!same) {
        mismatched++;
        if (firstMismatches.length < 6) firstMismatches.push({seed: row.seed, input: [a, b], want: {...want, mem: undefined}, got: {...got, mem: undefined}, memSame: want.mem === got.mem, body: row.body, text: row.text});
        break;
      }
    }
  }
  return {compared, mismatched, skipped, parseErrors, executed, firstMismatches};
}

const started = Date.now();
const real = check(false);
console.log(JSON.stringify({rows: Math.min(limit, rows.length), compared: real.compared, mismatched: real.mismatched, skipped: real.skipped, parseErrors: real.parseErrors}));
for (const m of real.firstMismatches) console.log(JSON.stringify(m, null, 1));
const mutated = check(true);
const failures = [];
// An interpreter error inside a handler is a failure of the check, never a
// caught exception.
let masked = false;
try {
  interpret(parseListing('func run(p0: i32, p1: i32) -> (i32, i32) {\n  block L1 {\n    try_table catch_all -> L1 {\n      no_such_import(1)\n    }\n  }\n  return p0, p1\n}\n'), 0, 0);
  masked = true;
} catch {}
if (masked) failures.push('an interpreter error inside a handler was taken for a caught exception');
if (real.mismatched) failures.push(`${real.mismatched} listings read a different value than V8 ran`);
if (real.parseErrors) failures.push(`${real.parseErrors} listings could not be read`);
if (real.compared < 0.8 * INPUTS.length * Math.min(limit, rows.length)) failures.push(`only ${real.compared} runs were compared`);
// The mutated listings must differ from V8 in a minimum share: about a third
// do (their epilogue or results show it); a much lower share means the check
// stopped seeing what listings compute.
const MIN_CAUGHT_SHARE = 0.25;
if (mutated.mismatched < MIN_CAUGHT_SHARE * mutated.executed) failures.push(`only ${mutated.mismatched} of ${mutated.executed} mutated listings were caught (at least ${MIN_CAUGHT_SHARE * 100}% must be)`);
if (failures.length) { console.error(`FAIL readable lift values: ${failures.join('; ')}`); process.exit(1); }
console.log(`PASS readable lift values: ${real.compared} runs of ${Math.min(limit, rows.length)} modules match V8; ${mutated.mismatched} of ${mutated.executed} mutated listings caught (${Date.now() - started} ms)`);
