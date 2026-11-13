use super::*;

fn report(a: &str, b: &str) -> Report {
    report_with(a, b, Limits::DEFAULT)
}
fn report_with(a: &str, b: &str, limits: Limits) -> Report {
    let a = wat::parse_str(a).unwrap();
    let b = wat::parse_str(b).unwrap();
    compare_with(
        &a,
        &b,
        json!({"artifact_id":"1"}),
        json!({"artifact_id":"2"}),
        limits,
        Instant::now(),
    )
    .unwrap()
}
type Found = (String, Option<String>, Option<u32>, Option<u32>);

fn rows(report: &Report) -> Vec<Found> {
    report
        .rows
        .iter()
        .map(|row| {
            (
                STATUSES[row.status as usize].to_owned(),
                row.method.map(|m| METHODS[m as usize].to_owned()),
                row.a,
                row.b,
            )
        })
        .collect()
}
fn row(status: &str, method: Option<&str>, a: Option<u32>, b: Option<u32>) -> Found {
    (status.into(), method.map(Into::into), a, b)
}
fn stop_in(step: &'static str) -> Limits {
    Limits {
        stop_in: Some((step, 0)),
        ..Limits::DEFAULT
    }
}

/// Minimal binary builders, so the bounded-work tests can make inputs far
/// larger than a wat string would comfortably hold.
mod bin {
    pub fn uleb(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }
    pub fn sleb(mut n: i64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if (n == 0 && byte & 0x40 == 0) || (n == -1 && byte & 0x40 != 0) {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }
    pub fn vec(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = uleb(items.len() as u64);
        for item in items {
            out.extend(item);
        }
        out
    }
    pub fn section(id: u8, payload: Vec<u8>) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(uleb(payload.len() as u64));
        out.extend(payload);
        out
    }
    /// Types, one type index per function, bodies (each without its size
    /// prefix), and optional globals and exports.
    pub fn module(
        types: &[&[u8]],
        funcs: &[u32],
        bodies: &[Vec<u8>],
        globals: &[Vec<u8>],
        exports: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        out.extend(section(
            1,
            vec(&types.iter().map(|t| t.to_vec()).collect::<Vec<_>>()),
        ));
        out.extend(section(
            3,
            vec(&funcs
                .iter()
                .map(|t| uleb(u64::from(*t)))
                .collect::<Vec<_>>()),
        ));
        if !globals.is_empty() {
            out.extend(section(6, vec(globals)));
        }
        if !exports.is_empty() {
            out.extend(section(7, vec(exports)));
        }
        let sized = bodies
            .iter()
            .map(|b| {
                let mut v = uleb(b.len() as u64);
                v.extend(b);
                v
            })
            .collect::<Vec<_>>();
        out.extend(section(10, vec(&sized)));
        out
    }
    pub const VOID: &[u8] = b"\x60\x00\x00";
    pub const I32: &[u8] = b"\x60\x00\x01\x7f";
    pub fn body(code: &[u8]) -> Vec<u8> {
        let mut out = vec![0];
        out.extend(code);
        out.push(0x0b);
        out
    }
    pub fn export(name: &str, index: u32) -> Vec<u8> {
        let mut out = uleb(name.len() as u64);
        out.extend(name.as_bytes());
        out.push(0);
        out.extend(uleb(u64::from(index)));
        out
    }
}

/// One function reading `n` globals: first-use numbering must stay linear.
fn many_globals(n: usize, variant: i64) -> Vec<u8> {
    let mut global = b"\x7f\x00\x41".to_vec();
    global.extend(bin::sleb(variant));
    global.push(0x0b);
    let mut code = Vec::new();
    for index in 0..n {
        code.push(0x23);
        code.extend(bin::uleb(index as u64));
        code.push(0x1a);
    }
    bin::module(
        &[bin::VOID],
        &[0],
        &[bin::body(&code)],
        &vec![global; n],
        &[],
    )
}
/// `n` bodies of about 7.6 MB each: the deadline must stop inside a body.
fn big_bodies(n: usize, variant: i64) -> Vec<u8> {
    let mut code = vec![0x41];
    code.extend(bin::sleb(variant));
    for _ in 0..7_600_000 / 3 {
        code.extend([0x41, 0x00, 0x6a]);
    }
    let body = bin::body(&code);
    bin::module(&[bin::I32], &vec![0; n], &vec![body; n], &[], &[])
}
/// `n` near-identical functions of one signature.
fn similar(n: usize, variant: i64) -> Vec<u8> {
    let bodies = (0..n)
        .map(|i| {
            let mut code = Vec::new();
            for j in 0..1 + i % 5 {
                code.push(0x41);
                code.extend(bin::sleb(i as i64 * 3 + variant + j as i64));
                code.push(0x1a);
            }
            bin::body(&code)
        })
        .collect::<Vec<_>>();
    bin::module(&[bin::VOID], &vec![0; n], &bodies, &[], &[])
}
/// `n` functions of one shape, each with its own constant.
fn similar_shape(n: usize, variant: i64) -> Vec<u8> {
    let bodies = (0..n)
        .map(|i| {
            let mut code = vec![0x41];
            code.extend(bin::sleb(i as i64 * 3 + variant));
            code.push(0x1a);
            bin::body(&code)
        })
        .collect::<Vec<_>>();
    bin::module(&[bin::VOID], &vec![0; n], &bodies, &[], &[])
}
/// A call chain: function i calls i + 1, with a distinct constant in each.
fn chain(n: usize, variant: i64) -> Vec<u8> {
    let bodies = (0..n)
        .map(|i| {
            let mut code = vec![0x41];
            code.extend(bin::sleb(i as i64 * 7 + variant));
            code.push(0x1a);
            if i + 1 < n {
                code.push(0x10);
                code.extend(bin::uleb(i as u64 + 1));
            }
            bin::body(&code)
        })
        .collect::<Vec<_>>();
    bin::module(
        &[bin::VOID],
        &vec![0; n],
        &bodies,
        &[],
        &[bin::export("root", 0)],
    )
}

#[test]
fn renumbered_calls_locals_and_data_addresses_normalize_to_the_same_hash() {
    // B inserts an import and a helper, so every call index shifts, and
    // moves its static data, so the address constant changes.
    let a = r#"(module (memory 1) (data (i32.const 2048) "hello")
        (func $leaf (param i32) (result i32) local.get 0 i32.const 3 i32.mul)
        (func $root (export "root") (param i32) (result i32) (local i32 i64)
          local.get 0 call $leaf local.set 1 i32.const 2048 i32.load local.get 1 i32.add))"#;
    let b = r#"(module (import "env" "log" (func $log (param i32))) (memory 1)
        (data (i32.const 4096) "hello")
        (func $extra (param f64) (result f64) local.get 0)
        (func $leaf (param i32) (result i32) local.get 0 i32.const 3 i32.mul)
        (func $root (export "root") (param i32) (result i32) (local i64 i32)
          local.get 0 call $leaf local.set 2 i32.const 4096 i32.load local.get 2 i32.add))"#;
    let report = report(a, b);
    let found = rows(&report);
    for expected in [
        row("identical", Some("identical"), Some(0), Some(2)),
        row("renumbered", Some("normalized"), Some(1), Some(3)),
        row("added", None, None, Some(0)),
        row("added", None, None, Some(1)),
    ] {
        assert!(found.contains(&expected), "{expected:?} not in {found:?}");
    }
    assert!(report.complete);
}

#[test]
fn a_changed_constant_inside_the_data_span_is_changed_not_renumbered() {
    // Both constants are inside the same data segment, so the coarse hash
    // treats them as addresses, but they point at different bytes.
    let data = "\\00".repeat(60_000);
    let module = |value: u32| {
        format!(
            r#"(module (memory 2) (data (i32.const 1024) "{data}")
            (func (export "f") (result i32) i32.const {value} i32.load))"#
        )
    };
    let found = rows(&report(&module(2000), &module(50_000)));
    assert_eq!(
        found,
        vec![row("changed", Some("normalized"), Some(0), Some(0))]
    );
}

#[test]
fn calling_a_different_function_of_the_same_signature_is_changed() {
    let helpers =
        "(func (result i32) i32.const 1) (func (result i32) i32.const 2 i32.const 3 i32.add)";
    let a = format!(r#"(module {helpers} (func (export "root") (result i32) call 0))"#);
    let b = format!(r#"(module {helpers} (func (export "root") (result i32) call 1))"#);
    let found = rows(&report(&a, &b));
    assert!(
        found.contains(&row("changed", Some("normalized"), Some(2), Some(2))),
        "{found:?}"
    );
}

#[test]
fn changed_bodies_match_by_export_call_graph_and_structure() {
    // Unnamed functions: wat would otherwise emit a name section.
    let a = r#"(module
        (func (param i32) (result i32) local.get 0 i32.const 3 i32.mul)
        (func (param i32) (result i32) local.get 0 call 0 i32.const 1 i32.add)
        (func (export "run") (param i32) (result i32) local.get 0 call 1 i32.const 7 i32.xor))"#;
    let b = r#"(module
        (func (param i32) (result i32) local.get 0 i32.const 5 i32.mul)
        (func (param i32) (result i32) local.get 0 call 0 i32.const 2 i32.add)
        (func (export "run") (param i32) (result i32) local.get 0 call 1 i32.const 9 i32.xor))"#;
    let found = rows(&report(a, b));
    for expected in [
        row("changed", Some("export_name"), Some(2), Some(2)),
        row("changed", Some("call_graph"), Some(1), Some(1)),
        row("changed", Some("call_graph"), Some(0), Some(0)),
    ] {
        assert!(found.contains(&expected), "{expected:?} not in {found:?}");
    }
}

#[test]
fn swapped_call_order_does_not_carry_wrong_pairs() {
    // Two leaves of different shapes, each under its own helper, both under
    // the root. B calls the helpers in the other order and changes every
    // constant. Position alone would pair each helper with the other one
    // and then each leaf with the other one.
    let leaves = |k: u32| {
        format!(
            "(func i32.const {k} drop)
             (func i32.const {k} i32.const 1 i32.add i32.const 2 i32.mul drop)"
        )
    };
    let helpers = |k: u32| {
        format!(
            "(func call 0 i32.const {k} drop)
             (func call 1 i32.const {k} i32.const {k} i32.add drop i32.const 0 drop)"
        )
    };
    let a = format!(
        r#"(module {} {} (func (export "root") call 2 call 3))"#,
        leaves(1),
        helpers(5)
    );
    let b = format!(
        r#"(module {} {} (func (export "root") call 3 call 2))"#,
        leaves(7),
        helpers(9)
    );
    let found = rows(&report(&a, &b));
    for expected in [
        row("changed", Some("call_graph"), Some(0), Some(0)),
        row("changed", Some("call_graph"), Some(1), Some(1)),
        row("changed", Some("call_graph"), Some(2), Some(2)),
        row("changed", Some("call_graph"), Some(3), Some(3)),
    ] {
        assert!(found.contains(&expected), "{expected:?} not in {found:?}");
    }
    // The root's bodies normalize equally, but its calls now reach the
    // helpers in the other order, so it changed.
    assert!(
        found.contains(&row("changed", Some("normalized"), Some(4), Some(4))),
        "{found:?}"
    );
}

#[test]
fn name_section_names_match_changed_functions() {
    let a = r#"(module (func $parse (result i32) i32.const 1) (func $emit (param i32)))"#;
    let b = r#"(module (func $emit (param i32)) (func $parse (result i32) i32.const 2))"#;
    let found = rows(&report(a, b));
    assert!(
        found.contains(&row("changed", Some("name"), Some(0), Some(1))),
        "{found:?}"
    );
    assert!(
        found.contains(&row("identical", Some("identical"), Some(1), Some(0))),
        "{found:?}"
    );
}

#[test]
fn identical_twins_stay_ambiguous_with_every_member_listed() {
    let twin = "(func (result i32) i32.const 42)";
    let a = format!("(module {})", twin.repeat(2));
    let b = format!("(module {})", twin.repeat(3));
    let report = report(&a, &b);
    assert_eq!(
        rows(&report),
        vec![
            row("ambiguous", Some("identical"), Some(0), None),
            row("ambiguous", Some("identical"), Some(1), None),
            row("ambiguous", Some("identical"), None, Some(0)),
            row("ambiguous", Some("identical"), None, Some(1)),
            row("ambiguous", Some("identical"), None, Some(2)),
        ]
    );
    assert!(report.rows.iter().all(|row| row.group == Some(0)));
    assert_eq!(report.groups, vec![(2, 3)]);
}

#[test]
fn a_large_tie_pages_every_member() {
    let twin = "(func (result i32) i32.const 42)";
    let module = format!("(module {})", twin.repeat(40));
    let report = report(&module, &module);
    assert_eq!(report.groups, vec![(40, 40)]);
    let mut seen = 0;
    let mut offset = 0;
    loop {
        let page = render(
            &report,
            &Page {
                offset,
                limit: 30,
                statuses: Some(vec!["ambiguous".into()]),
            },
        )
        .unwrap();
        seen += page["rows"].as_array().unwrap().len();
        assert!(page["rows"][0]["group"] == json!({"id": 0, "a": 40, "b": 40}));
        match page["row_window"]["next_offset"].as_u64() {
            Some(next) => offset = next as usize,
            None => break,
        }
    }
    assert_eq!(seen, 80);
}

#[test]
fn imports_match_by_name_and_report_a_signature_change() {
    let a = r#"(module (import "env" "f" (func (param i32))) (import "env" "g" (func)))"#;
    let b = r#"(module (import "env" "g" (func)) (import "env" "f" (func (param i64))))"#;
    let found = rows(&report(a, b));
    assert!(
        found.contains(&row("changed", Some("import_name"), Some(0), Some(1))),
        "{found:?}"
    );
    assert!(
        found.contains(&row("identical", Some("import_name"), Some(1), Some(0))),
        "{found:?}"
    );
}

#[test]
fn a_renamed_import_paired_through_its_caller_is_changed() {
    let a = r#"(module (import "env" "f" (func))
        (func (export "run") call 0))"#;
    let b = r#"(module (import "env" "f2" (func))
        (func (export "run") call 0))"#;
    let found = rows(&report(a, b));
    assert!(
        found.contains(&row("changed", Some("call_graph"), Some(0), Some(0))),
        "{found:?}"
    );
}

#[test]
fn a_module_importing_one_name_twice_matches_itself() {
    let module = r#"(module (import "env" "f" (func (param i32))) (import "env" "f" (func (param i64)))
        (import "env" "f" (func (param i32))))"#;
    let found = rows(&report(module, module));
    assert_eq!(
        found,
        vec![
            row("identical", Some("import_name"), Some(0), Some(0)),
            row("identical", Some("import_name"), Some(1), Some(1)),
            row("identical", Some("import_name"), Some(2), Some(2)),
        ]
    );
}

fn fixtures() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/fixtures/wasm-module-diff")
}
fn fixture_builds() -> Vec<Vec<u8>> {
    ["build-a", "build-b"]
        .iter()
        .map(|name| std::fs::read(fixtures().join(format!("{name}.wasm"))).unwrap())
        .collect()
}

/// The checked-in builds are exactly what the pinned assembler makes from
/// their sources, and they keep the rows their README lists. Run
/// `make wasm-diff-fixtures` after editing a `.wat`.
#[test]
fn checked_in_builds_match_their_sources_and_expected_rows() {
    let mut bytes = Vec::new();
    for name in ["build-a", "build-b"] {
        let built = wat::parse_file(fixtures().join(format!("{name}.wat"))).unwrap();
        wasmparser::Validator::new().validate_all(&built).unwrap();
        let checked_in = std::fs::read(fixtures().join(format!("{name}.wasm")))
            .unwrap_or_else(|_| panic!("{name}.wasm is missing; run make wasm-diff-fixtures"));
        assert!(
            built == checked_in,
            "{name}.wasm drifted; run make wasm-diff-fixtures"
        );
        bytes.push(checked_in);
    }
    let report = compare(&bytes[0], &bytes[1], json!({}), json!({})).unwrap();
    assert!(report.complete, "{:?}", report.omissions);
    assert_eq!(
        rows(&report),
        vec![
            row("changed", Some("call_graph"), Some(3), Some(4)),
            row("changed", Some("structural"), Some(8), Some(8)),
            row("added", None, None, Some(1)),
            row("added", None, None, Some(9)),
            row("removed", None, Some(5), None),
            row("ambiguous", Some("identical"), Some(6), None),
            row("ambiguous", Some("identical"), Some(7), None),
            row("ambiguous", Some("identical"), None, Some(6)),
            row("ambiguous", Some("identical"), None, Some(7)),
            row("renumbered", Some("normalized"), Some(2), Some(3)),
            row("renumbered", Some("normalized"), Some(4), Some(5)),
            row("identical", Some("import_name"), Some(0), Some(0)),
            row("identical", Some("identical"), Some(1), Some(2)),
        ]
    );
}

#[test]
#[ignore = "writes fixtures; run through make wasm-diff-fixtures"]
fn write_wasm_diff_fixtures() {
    for name in ["build-a", "build-b"] {
        let built = wat::parse_file(fixtures().join(format!("{name}.wat"))).unwrap();
        std::fs::write(fixtures().join(format!("{name}.wasm")), built).unwrap();
    }
}

#[test]
fn structural_matching_keeps_to_one_signature() {
    // Same shape, different signatures: they must not pair.
    let a = r#"(module (func (param i32) (result i32) local.get 0 i32.const 3 i32.add))"#;
    let b = r#"(module (func (param i64) (result i64) local.get 0 i64.const 5 i64.add))"#;
    assert_eq!(
        rows(&report(a, b)),
        vec![
            row("added", None, None, Some(0)),
            row("removed", None, Some(0), None)
        ]
    );
}

/// Two A functions with B's shape: neither may be picked.
const TIE_A: &str = r#"(module (func i32.const 1 drop) (func i32.const 2 drop))"#;
const TIE_B: &str = r#"(module (func i32.const 3 drop))"#;

#[test]
fn a_structural_tie_is_ambiguous_not_a_pick() {
    let report = report(TIE_A, TIE_B);
    assert_eq!(
        rows(&report),
        vec![
            row("ambiguous", Some("structural"), Some(0), None),
            row("ambiguous", Some("structural"), Some(1), None),
            row("ambiguous", Some("structural"), None, Some(0)),
        ]
    );
    assert!(report.complete);
}

#[test]
fn a_structural_pass_the_budget_stops_keeps_no_pair() {
    // With room for one score, A0 sees B0 as its only candidate and A1 is
    // never scored, so a mutual best would be a guess.
    let report = report_with(
        TIE_A,
        TIE_B,
        Limits {
            max_comparisons: 1,
            ..Limits::DEFAULT
        },
    );
    assert_eq!(
        rows(&report),
        vec![
            row("unclassified", None, Some(0), None),
            row("unclassified", None, Some(1), None),
            row("unclassified", None, None, Some(0)),
        ]
    );
    assert!(!report.complete);
    assert!(
        report
            .omissions
            .iter()
            .any(|o| o.contains("comparison limit")),
        "{:?}",
        report.omissions
    );
}

#[test]
fn a_function_outside_every_window_is_not_called_added() {
    // One A function and 70 B functions of its shape: A scores only its 64
    // nearest, and the other six must join the tie rather than look new.
    let a = similar_shape(1, 1);
    let b = similar_shape(70, 100);
    let report = compare(&a, &b, json!({}), json!({})).unwrap();
    assert!(report.complete, "{:?}", report.omissions);
    assert_eq!(report.groups, vec![(1, 70)]);
    assert!(report.rows.iter().all(|row| row.status == AMBIGUOUS));
}

#[test]
fn a_tight_comparison_cap_narrows_the_window_instead_of_stopping() {
    // 2,000 open functions of one signature with room for 8 scores each:
    // the pass scores 8 nearest candidates per function and finishes.
    let limits = Limits {
        max_comparisons: 16_000,
        ..Limits::DEFAULT
    };
    let (a, b) = (similar(2000, 1), similar(2000, 2));
    let report = compare_with(&a, &b, json!({}), json!({}), limits, Instant::now()).unwrap();
    assert!(report.complete, "{:?}", report.omissions);
    assert!(report.rows.iter().all(|row| row.status != UNCLASSIFIED));
    assert!(report.summary["comparisons"].as_u64().unwrap() <= 16_000);
}

#[test]
fn a_structural_pass_stopped_after_some_scores_keeps_no_pair() {
    // A0 is scored and would look like B0's only claimant; the pass stops
    // before A1, which ties it. Nothing from the pass may stand.
    let limits = Limits {
        stop_in: Some((STRUCTURAL, 1)),
        ..Limits::DEFAULT
    };
    let report = report_with(TIE_A, TIE_B, limits);
    assert!(
        report.rows.iter().all(|row| row.status == UNCLASSIFIED),
        "{:?}",
        rows(&report)
    );
}

#[test]
fn every_step_the_budget_stops_leaves_honest_unclassified_rows() {
    let builds = fixture_builds();
    let run = |step| {
        compare_with(
            &builds[0],
            &builds[1],
            json!({}),
            json!({}),
            stop_in(step),
            Instant::now(),
        )
        .unwrap()
    };
    // Fingerprinting: nothing is compared, and nothing is called empty.
    let report = run(FINGERPRINTING);
    assert!(report.rows.iter().all(|row| row.status == UNCLASSIFIED));
    assert!(
        report
            .omissions
            .iter()
            .any(|o| o.contains("Module A: 1 of its 9 functions")),
        "{:?}",
        report.omissions
    );
    assert!(
        !report
            .omissions
            .iter()
            .any(|o| o.contains("declares no functions"))
    );
    // Exact matching: no pass runs, so nothing is matched.
    let report = run(EXACT);
    assert!(report.rows.iter().all(|row| row.status == UNCLASSIFIED));
    // Propagation: exact matches stand; the step pair is left open.
    let found = rows(&run(PROPAGATION));
    assert!(found.contains(&row("identical", Some("identical"), Some(1), Some(2))));
    assert!(found.contains(&row("unclassified", None, Some(3), None)));
    // Structural: the checksum pair that only structure finds is not kept.
    let report = run(STRUCTURAL);
    let found = rows(&report);
    assert!(found.contains(&row("changed", Some("call_graph"), Some(3), Some(4))));
    assert!(found.contains(&row("unclassified", None, Some(8), None)));
    assert!(
        report
            .omissions
            .iter()
            .any(|o| o.contains("structural matching step stopped")),
        "{:?}",
        report.omissions
    );
}

#[test]
fn the_deadline_bounds_adversarial_inputs() {
    // Each of these took well over the deadline before the deadline was
    // checked inside bodies and global numbering was made linear.
    let deadline = Duration::from_millis(250);
    let limits = Limits {
        deadline,
        ..Limits::DEFAULT
    };
    for (label, a, b) in [
        (
            "globals",
            many_globals(100_000, 1),
            many_globals(100_000, 2),
        ),
        ("bodies", big_bodies(2, 1), big_bodies(2, 2)),
        ("similar", similar(60_000, 1), similar(60_000, 2)),
    ] {
        let started = Instant::now();
        let report = compare_with(&a, &b, json!({}), json!({}), limits, Instant::now()).unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < deadline + Duration::from_millis(2500),
            "{label} took {elapsed:?}"
        );
        // A fast machine may finish an input; a stopped one must say so.
        assert!(
            report.complete || report.omissions.iter().any(|o| o.contains("deadline")),
            "{label}: {:?}",
            report.omissions
        );
    }
}

#[test]
fn the_deadline_is_checked_inside_one_long_body() {
    // The first check, before the body, passes; the next one falls inside
    // it, after CHECK_EVERY instructions, and stops it there.
    let bytes = big_bodies(1, 1);
    let limits = Limits {
        stop_after_checks: Some(2),
        ..Limits::DEFAULT
    };
    let report =
        compare_with(&bytes, &bytes, json!({}), json!({}), limits, Instant::now()).unwrap();
    assert!(
        report
            .omissions
            .iter()
            .any(|o| o.contains("Module A: 0 of its 1 functions")),
        "{:?}",
        report.omissions
    );
}

#[test]
fn many_globals_in_one_body_are_numbered_in_linear_work() {
    // First-use numbering by a scan was quadratic here and ran past the
    // deadline; a table indexed by global is linear and finishes.
    let report = compare(
        &many_globals(100_000, 1),
        &many_globals(100_000, 2),
        json!({}),
        json!({}),
    )
    .unwrap();
    assert!(report.complete, "{:?}", report.omissions);
    assert_eq!(
        rows(&report),
        vec![row("identical", Some("identical"), Some(0), Some(0))]
    );
}

#[test]
fn opcode_classes_follow_the_contract() {
    let class = |text: &str| {
        let bytes = wat::parse_str(format!("(module (memory 1) (func {text}))")).unwrap();
        let mut found = Vec::new();
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::CodeSectionEntry(body) = payload.unwrap() {
                let mut reader = body.get_operators_reader().unwrap();
                while !reader.eof() {
                    let op = reader.read().unwrap();
                    found.push(category(&op, wasm::operator_name(&op)));
                }
            }
        }
        found
    };
    assert_eq!(
        class("i32.const 1 i32.const 2 i32.lt_s drop"),
        vec![8, 8, 11, 16, 0]
    );
    assert_eq!(class("i32.const 1 i32.eqz drop"), vec![8, 11, 16, 0]);
    assert_eq!(class("i64.const 1 i32.wrap_i64 drop"), vec![8, 12, 16, 0]);
    assert_eq!(class("i32.const 0 i32.load drop"), vec![8, 6, 16, 0]);
    assert_eq!(
        class("i32.const 1 i32.const 2 i32.add drop"),
        vec![8, 8, 9, 16, 0]
    );
    assert_eq!(class("f32.const 1 f32.neg drop"), vec![8, 10, 16, 0]);
}

#[test]
fn a_long_call_chain_propagates_in_linear_work() {
    let report = compare(&chain(10_000, 1), &chain(10_000, 2), json!({}), json!({})).unwrap();
    assert!(report.complete, "{:?}", report.omissions);
    let changed = report.rows.iter().filter(|r| r.status == CHANGED).count();
    assert_eq!(changed, 10_000);
}

#[test]
fn malformed_and_empty_modules_are_named_errors() {
    let error = compare(&[], b"\0asm\x01\0\0\0", json!({}), json!({}))
        .err()
        .unwrap();
    assert_eq!(error.status, 422);
    assert!(error.message.contains("module A is empty"));
    let error = compare(
        b"\0asm\x01\0\0\0\x0a\x05",
        b"\0asm\x01\0\0\0",
        json!({}),
        json!({}),
    )
    .err()
    .unwrap();
    assert_eq!(error.status, 422);
}

#[test]
fn pages_filter_by_status_and_stop_at_the_window() {
    let report = report(
        r#"(module (func (export "x") (result i32) i32.const 1) (func (result i32) i32.const 2))"#,
        r#"(module (func (export "x") (result i32) i32.const 5) (func (param i32)))"#,
    );
    let page = render(
        &report,
        &Page {
            offset: 0,
            limit: 1,
            statuses: Some(vec!["changed".into()]),
        },
    )
    .unwrap();
    assert_eq!(page["rows"].as_array().unwrap().len(), 1);
    assert_eq!(page["rows"][0]["status"], "changed");
    assert_eq!(page["row_window"]["total_rows"], 1);
    assert!(page["row_window"]["next_offset"].is_null());
    let error = render(
        &report,
        &Page {
            offset: 9,
            limit: 1,
            statuses: None,
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.status, 400);
    assert!(requested_statuses("changed,bogus").is_err());
    assert!(requested_statuses("changed,changed").is_err());
}

#[test]
fn a_default_page_of_long_names_fits_the_mcp_inline_limit_pretty_printed() {
    // Mangled Rust names make each row long; the MCP server compares the
    // pretty-printed document with its 131,072-byte limit.
    let module = |variant: i64| {
        let n = 5000;
        let bodies = (0..n)
            .map(|i| {
                let mut code = vec![0x41];
                code.extend(bin::sleb(i as i64 * 3 + variant));
                code.push(0x1a);
                bin::body(&code)
            })
            .collect::<Vec<_>>();
        let exports = (0..n)
            .map(|i| bin::export(&format!("_ZN4core3fmt9Formatter3pad17h{i:016x}E"), i as u32))
            .collect::<Vec<_>>();
        bin::module(&[bin::VOID], &vec![0; n], &bodies, &[], &exports)
    };
    let report = compare(&module(1), &module(2), json!({}), json!({})).unwrap();
    let page = render(&report, &Page::new(0, PAGE_DEFAULT_ROWS, None).unwrap()).unwrap();
    let pretty = serde_json::to_string_pretty(&page).unwrap().len();
    assert!(pretty <= PAGE_BYTES, "{pretty} bytes");
    let kept = page["rows"].as_array().unwrap().len();
    assert!(kept > 50, "only {kept} rows fit");
    assert_eq!(page["row_window"]["next_offset"], json!(kept));
}
