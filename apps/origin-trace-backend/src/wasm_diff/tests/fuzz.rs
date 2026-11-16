//! Mutated-module fuzz: a random program, a later build of it with changed,
//! swapped, removed, added and renumbered functions and moved data, and the
//! true correspondence, to count what matching gets right and wrong.
use super::super::*;
use super::{rows, untimed};
use std::collections::BTreeMap as Map;

fn long() -> Limits {
    untimed()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

#[derive(Clone, Debug)]
enum Unit {
    Const(i64),
    Arith(i64, u8),
    Call(usize),
    Load(i64),
    Local,
    Block(Vec<Unit>),
    Loop(Vec<Unit>),
}

#[derive(Clone, Debug)]
struct F {
    ty: u8, // 0 = (func), 1 = (func (param i32)), 2 = (func (result i32))
    units: Vec<Unit>,
    tail: i64, // the result constant for ty 2
    export: Option<String>,
    name: Option<String>,
}

fn gen_units(r: &mut Rng, n: usize, depth: u32, count: usize, ty: u8) -> Vec<Unit> {
    (0..n)
        .map(|_| match r.below(if depth < 2 { 8 } else { 6 }) {
            0 => Unit::Const(r.below(900) as i64),
            1 => Unit::Arith(r.below(900) as i64, r.below(4) as u8),
            2 | 3 => Unit::Call(r.below(count as u64) as usize),
            4 => Unit::Load(4096 + 4 * r.below(200) as i64),
            5 => {
                if ty == 1 {
                    Unit::Local
                } else {
                    Unit::Const(r.below(900) as i64)
                }
            }
            6 => {
                let k = 1 + r.below(4) as usize;
                Unit::Block(gen_units(r, k, depth + 1, count, ty))
            }
            _ => {
                let k = 1 + r.below(4) as usize;
                Unit::Loop(gen_units(r, k, depth + 1, count, ty))
            }
        })
        .collect()
}

fn gen_module(r: &mut Rng, count: usize) -> Vec<F> {
    (0..count)
        .map(|i| {
            let ty = r.below(3) as u8;
            let n = 1 + r.below(10) as usize;
            F {
                ty,
                units: gen_units(r, n, 0, count, ty),
                tail: r.below(900) as i64,
                export: r.chance(15).then(|| format!("e{i}")),
                name: r.chance(30).then(|| format!("n{i}")),
            }
        })
        .collect()
}

fn emit_units(
    out: &mut String,
    units: &[Unit],
    tys: &[u8],
    index_of: &dyn Fn(usize) -> Option<usize>,
    shift: i64,
) {
    for u in units {
        match u {
            Unit::Const(k) => out.push_str(&format!(" i32.const {k} drop")),
            Unit::Arith(k, op) => {
                let op = ["add", "sub", "mul", "xor"][*op as usize];
                out.push_str(&format!(" i32.const {k} i32.const 3 i32.{op} drop"));
            }
            Unit::Call(t) => match index_of(*t) {
                Some(idx) => match tys[*t] {
                    0 => out.push_str(&format!(" call {idx}")),
                    1 => out.push_str(&format!(" i32.const 0 call {idx}")),
                    _ => out.push_str(&format!(" call {idx} drop")),
                },
                None => out.push_str(" i32.const 77 drop"),
            },
            Unit::Load(addr) => out.push_str(&format!(" i32.const {} i32.load drop", addr + shift)),
            Unit::Local => out.push_str(" local.get 0 drop"),
            Unit::Block(inner) => {
                out.push_str(" block");
                emit_units(out, inner, tys, index_of, shift);
                out.push_str(" end");
            }
            Unit::Loop(inner) => {
                out.push_str(" loop");
                emit_units(out, inner, tys, index_of, shift);
                out.push_str(" end");
            }
        }
    }
}

/// `order[k]` is which logical function sits at position k.
fn emit(funcs: &[F], order: &[usize], shift: i64) -> Vec<u8> {
    let tys = funcs.iter().map(|f| f.ty).collect::<Vec<_>>();
    let mut position = vec![None; funcs.len()];
    for (k, f) in order.iter().enumerate() {
        position[*f] = Some(k);
    }
    let index_of = |f: usize| position[f];
    let mut out = String::from("(module (memory 1)");
    out.push_str(&format!(
        " (data (i32.const {}) \"{}\")",
        4096 + shift,
        "x".repeat(1024)
    ));
    for f in order {
        let func = &funcs[*f];
        out.push_str(" (func");
        if let Some(name) = &func.name {
            out.push_str(&format!(" ${name}"));
        }
        if let Some(e) = &func.export {
            out.push_str(&format!(" (export \"{e}\")"));
        }
        match func.ty {
            0 => {}
            1 => out.push_str(" (param i32)"),
            _ => out.push_str(" (result i32)"),
        }
        emit_units(&mut out, &func.units, &tys, &index_of, shift);
        if func.ty == 2 {
            out.push_str(&format!(" i32.const {}", func.tail));
        }
        out.push(')');
    }
    out.push(')');
    wat::parse_str(&out).unwrap_or_else(|e| panic!("{e}\n{out}"))
}

fn call_positions(units: &[Unit], out: &mut Vec<usize>) {
    for (i, u) in units.iter().enumerate() {
        if let Unit::Call(_) = u {
            out.push(i);
        }
    }
}

struct Case {
    a: Vec<u8>,
    b: Vec<u8>,
    /// A index -> B index for functions that survived.
    truth: Vec<Option<u32>>,
    changed_a: Vec<bool>,
}

fn make_case(seed: u64, count: usize) -> Case {
    let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let base = gen_module(&mut r, count);
    let mut later = base.clone();
    let mut changed = vec![false; count];
    for (i, f) in later.iter_mut().enumerate() {
        if r.chance(8) {
            // a changed body
            changed[i] = true;
            match r.below(3) {
                0 => f.units.push(Unit::Const(r.below(900) as i64)),
                1 => {
                    if let Some(u) = f.units.iter_mut().find(|u| matches!(u, Unit::Const(_))) {
                        *u = Unit::Const(r.below(900) as i64);
                    } else {
                        f.units.push(Unit::Arith(1, 1));
                    }
                }
                _ => {
                    if f.units.len() > 1 {
                        f.units.pop();
                    } else {
                        f.units.push(Unit::Const(5));
                    }
                }
            }
        } else if r.chance(5) {
            // swapped calls
            let mut at = Vec::new();
            call_positions(&f.units, &mut at);
            if at.len() >= 2 {
                f.units.swap(at[0], at[1]);
                changed[i] = true;
            }
        }
        if r.chance(10) {
            f.name = f.name.take().map(|n| format!("{n}_renamed"));
        }
    }
    // Remove ~3% and add ~3%.
    let removed = (0..count).map(|_| r.chance(3)).collect::<Vec<_>>();
    let extra = (count as u64 * 3 / 100) as usize;
    let added_funcs = gen_module(&mut r, extra.max(1));
    let total = count + added_funcs.len();
    for f in added_funcs {
        let mut f = f;
        // remap added functions' calls into the full logical range
        fn remap(units: &mut [Unit], total: usize, r: &mut Rng) {
            for u in units {
                match u {
                    Unit::Call(t) => *t = r.below(total as u64) as usize,
                    Unit::Block(inner) | Unit::Loop(inner) => remap(inner, total, r),
                    _ => {}
                }
            }
        }
        remap(&mut f.units, total, &mut r);
        f.export = None;
        f.name = None;
        later.push(f);
    }
    let mut order_b = (0..total)
        .filter(|i| *i >= count || !removed[*i])
        .collect::<Vec<_>>();
    // Fisher-Yates
    for i in (1..order_b.len()).rev() {
        let j = r.below(i as u64 + 1) as usize;
        order_b.swap(i, j);
    }
    let order_a = (0..count).collect::<Vec<_>>();
    // A must not reference added functions; added only exist in B.
    let a = emit(&base, &order_a, 0);
    let b = emit(&later, &order_b, 256);
    let mut truth = vec![None; count];
    for (k, f) in order_b.iter().enumerate() {
        if *f < count {
            truth[*f] = Some(k as u32);
        }
    }
    Case {
        a,
        b,
        truth,
        changed_a: changed,
    }
}

#[derive(Default, Debug)]
struct Tally {
    pairs: u64,
    right: u64,
    wrong_unique: u64,
    wrong_twin: u64,
    false_removed: u64,
    false_added: u64,
    ambiguous_rows: u64,
    biggest_group: usize,
    nondeterministic: u64,
    removed_to_added: u64,
    norm_equal_missed: u64,
    incomplete: u64,
}

#[test]
#[ignore = "fuzz; set RR3_SEEDS and RR3_COUNT, run with --ignored --nocapture"]
fn fuzz_mutated_modules() {
    let seeds = std::env::var("RR3_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150u64);
    let count = std::env::var("RR3_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120usize);
    let mut t = Tally::default();
    let mut examples = Vec::new();
    for seed in 1..=seeds {
        let case = make_case(seed, count);
        let report = compare_with(
            &case.a,
            &case.b,
            json!({}),
            json!({}),
            long(),
            Instant::now(),
        )
        .unwrap();
        let again = compare_with(
            &case.a,
            &case.b,
            json!({}),
            json!({}),
            long(),
            Instant::now(),
        )
        .unwrap();
        if rows(&report) != rows(&again) || report.groups != again.groups {
            t.nondeterministic += 1;
        }
        if !report.complete {
            t.incomplete += 1;
        }
        // twins: A functions sharing a normalized hash with another A
        let mut by_hash = Map::<u64, u32>::new();
        for s in &report.a_sides {
            *by_hash.entry(s.normalized).or_default() += 1;
        }
        let twin = |a: u32| by_hash[&report.a_sides[a as usize].normalized] > 1;
        let has_pre = {
            let mut has = vec![false; report.b_sides.len()];
            for b in case.truth.iter().flatten() {
                has[*b as usize] = true;
            }
            has
        };
        for g in &report.groups {
            t.biggest_group = t.biggest_group.max(g.0 + g.1);
        }
        for row in &report.rows {
            match (row.a, row.b) {
                (Some(a), Some(b)) => {
                    t.pairs += 1;
                    if case.truth[a as usize] == Some(b) {
                        t.right += 1;
                    } else if case.truth[a as usize].is_none() {
                        t.removed_to_added += 1;
                    } else if twin(a) {
                        t.wrong_twin += 1;
                    } else {
                        t.wrong_unique += 1;
                        if examples.len() < 12 {
                            examples.push(format!(
                                "seed {seed}: A{a} -> B{b} by {} (truth {:?}, changed {}) score {:.3}",
                                METHODS[row.method.unwrap() as usize],
                                case.truth[a as usize],
                                case.changed_a[a as usize],
                                row.score
                            ));
                        }
                    }
                }
                (Some(a), None) if row.status == REMOVED => {
                    if let Some(tb) = case.truth[a as usize]
                        && report.a_sides[a as usize].normalized
                            == report.b_sides[tb as usize].normalized
                    {
                        t.norm_equal_missed += 1;
                        if examples.len() < 40 {
                            let fa = &report.a_sides[a as usize];
                            let peers_a = report
                                .a_sides
                                .iter()
                                .filter(|s| s.normalized == fa.normalized)
                                .count();
                            let peers_b = report
                                .b_sides
                                .iter()
                                .filter(|s| s.normalized == fa.normalized)
                                .count();
                            let brow = report.rows.iter().find(|r| r.b == Some(tb)).map(|r| {
                                (
                                    STATUSES[r.status as usize],
                                    r.a,
                                    r.method.map(|m| METHODS[m as usize]),
                                )
                            });
                            examples.push(format!("seed {seed}: NORM-EQUAL A{a} removed, truth B{tb} row {brow:?}, normalized peers A{peers_a} B{peers_b}"));
                        }
                    }
                    if case.truth[a as usize].is_some() {
                        t.false_removed += 1;
                        if examples.len() < 24 && !case.changed_a[a as usize] {
                            examples.push(format!(
                                "seed {seed}: unchanged A{a} removed (truth {:?})",
                                case.truth[a as usize]
                            ));
                        }
                    }
                }
                (None, Some(b)) if row.status == ADDED && has_pre[b as usize] => {
                    t.false_added += 1;
                }
                _ => {}
            }
            if row.status == AMBIGUOUS {
                t.ambiguous_rows += 1;
            }
        }
    }
    println!("RR3 FUZZ count={count} seeds={seeds} {t:?}");
    for e in &examples {
        println!("RR3 EX {e}");
    }
    assert_eq!(t.nondeterministic, 0);
}
