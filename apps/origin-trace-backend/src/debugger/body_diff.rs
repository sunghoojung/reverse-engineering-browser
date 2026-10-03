use serde::Serialize;

const INPUT_LINES: usize = 1000;
const OUTPUT_LINES: usize = 200;
const OUTPUT_BYTES: usize = 32 * 1024;
const LINE_BYTES: usize = 4096;
const CONTEXT: usize = 2;

#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Context,
    Added,
    Removed,
}

#[derive(Serialize)]
struct Line {
    kind: Kind,
    baseline_line: Option<usize>,
    current_line: Option<usize>,
    text: String,
    ending: &'static str,
    text_truncated: bool,
}

#[derive(Serialize)]
pub(super) struct BodyDiff {
    protocol_version: u8,
    baseline_lines: usize,
    current_lines: usize,
    baseline_inspected: usize,
    current_inspected: usize,
    added: usize,
    removed: usize,
    pub(super) partial: bool,
    limits_reached: Vec<&'static str>,
    lines: Vec<Line>,
}

struct Edit<'a> {
    kind: Kind,
    baseline_line: Option<usize>,
    current_line: Option<usize>,
    raw: &'a str,
}

// Keep terminators in alignment tokens: CRLF and final-newline changes are
// evidence too. Prefixes borrow immutable retained bodies instead of cloning them.
pub(super) fn compare(baseline: &str, current: &str, capture_truncated: bool) -> BodyDiff {
    let baseline_lines = baseline.split_inclusive('\n').count();
    let current_lines = current.split_inclusive('\n').count();
    let mut diff = BodyDiff {
        protocol_version: 1,
        baseline_lines,
        current_lines,
        baseline_inspected: baseline_lines,
        current_inspected: current_lines,
        added: 0,
        removed: 0,
        partial: capture_truncated,
        limits_reached: if capture_truncated {
            vec!["capture_truncated"]
        } else {
            Vec::new()
        },
        lines: Vec::new(),
    };
    // Exact byte equality does not need bounded alignment or a displayed excerpt.
    if baseline == current {
        return diff;
    }
    let a = baseline
        .split_inclusive('\n')
        .take(INPUT_LINES)
        .collect::<Vec<_>>();
    let b = current
        .split_inclusive('\n')
        .take(INPUT_LINES)
        .collect::<Vec<_>>();
    diff.baseline_inspected = a.len();
    diff.current_inspected = b.len();
    if a.len() < baseline_lines || b.len() < current_lines {
        diff.limits_reached.push("line_limit");
    }
    // LCS uses at most 1,000,000 comparisons and a 2 MiB table. Deletion wins
    // ties, giving deterministic alignment for repeated lines without a dependency.
    let width = b.len() + 1;
    let mut lengths = vec![0_u16; (a.len() + 1) * width];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lengths[i * width + j] = if a[i] == b[j] {
                1 + lengths[(i + 1) * width + j + 1]
            } else {
                lengths[(i + 1) * width + j].max(lengths[i * width + j + 1])
            };
        }
    }
    let mut edits = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let kind = if i < a.len() && j < b.len() && a[i] == b[j] {
            Kind::Context
        } else if i < a.len()
            && (j == b.len() || lengths[(i + 1) * width + j] >= lengths[i * width + j + 1])
        {
            Kind::Removed
        } else {
            Kind::Added
        };
        edits.push(Edit {
            kind,
            baseline_line: (kind != Kind::Added).then_some(i + 1),
            current_line: (kind != Kind::Removed).then_some(j + 1),
            raw: if kind == Kind::Added { b[j] } else { a[i] },
        });
        if kind != Kind::Added {
            i += 1;
        }
        if kind != Kind::Removed {
            j += 1;
        }
        diff.added += usize::from(kind == Kind::Added);
        diff.removed += usize::from(kind == Kind::Removed);
    }
    let mut visible = vec![false; edits.len()];
    for (index, edit) in edits.iter().enumerate() {
        if edit.kind != Kind::Context {
            let end = (index + CONTEXT + 1).min(edits.len());
            visible[index.saturating_sub(CONTEXT)..end].fill(true);
        }
    }
    let mut bytes = 0;
    for (edit, visible) in edits.into_iter().zip(visible) {
        if !visible {
            continue;
        }
        if diff.lines.len() == OUTPUT_LINES || bytes == OUTPUT_BYTES {
            diff.limits_reached.push("output_limit");
            break;
        }
        let (text, ending) = if let Some(text) = edit.raw.strip_suffix("\r\n") {
            (text, "crlf")
        } else if let Some(text) = edit.raw.strip_suffix('\n') {
            (text, "lf")
        } else {
            (edit.raw, "none")
        };
        let budget_limited = text.len().min(LINE_BYTES) > OUTPUT_BYTES - bytes;
        let mut end = text.len().min(LINE_BYTES).min(OUTPUT_BYTES - bytes);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let truncated = end < text.len();
        if text.len() > LINE_BYTES && !diff.limits_reached.contains(&"line_text_limit") {
            diff.limits_reached.push("line_text_limit");
        }
        bytes += end;
        diff.lines.push(Line {
            kind: edit.kind,
            baseline_line: edit.baseline_line,
            current_line: edit.current_line,
            text: text[..end].into(),
            ending,
            text_truncated: truncated,
        });
        if budget_limited {
            diff.limits_reached.push("output_limit");
            break;
        }
    }
    diff.partial = !diff.limits_reached.is_empty();
    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_changes_endings_and_empty_bodies() {
        let d = compare("same\nold\r\nend", "same\nnew\nend\n", false);
        assert_eq!((d.added, d.removed), (2, 2));
        assert!(!d.partial);
        let rows = serde_json::to_value(d).unwrap();
        assert_eq!(rows["lines"][0]["kind"], "context");
        assert_eq!(rows["lines"][1]["baseline_line"], 2);
        assert_eq!(rows["lines"][1]["ending"], "crlf");
        assert_eq!(rows["lines"][2]["ending"], "none");
        assert_eq!(rows["lines"][3]["text"], "new");
        assert!(rows["lines"][3]["baseline_line"].is_null());
        let d = compare("", "\n", false);
        assert_eq!((d.baseline_lines, d.current_lines, d.added), (0, 1, 1));
    }
    #[test]
    fn equality_and_limits_are_explicit() {
        let a = "old\n".repeat(1100);
        let b = "new\n".repeat(1100);
        let d = compare(&a, &b, false);
        assert_eq!(d.lines.len(), OUTPUT_LINES);
        assert_eq!(d.limits_reached, ["line_limit", "output_limit"]);
        assert_eq!((d.added, d.removed), (1000, 1000));
        let d = compare(&a, &a, true);
        assert!(d.lines.is_empty());
        assert_eq!(d.baseline_inspected, 1100);
        assert_eq!(d.limits_reached, ["capture_truncated"]);
        let text = "雪".repeat(21000);
        let d = compare("", &text, false);
        assert_eq!(d.lines[0].text.len(), 4095);
        assert!(d.lines[0].text_truncated);
        assert_eq!(d.limits_reached, ["line_text_limit"]);
    }
    #[test]
    fn small_repeated_sequences_reconstruct_both_bodies() {
        let mut bodies = vec![String::new()];
        for length in 1..=3 {
            for bits in 0..(1 << length) {
                bodies.push(
                    (0..length)
                        .map(|i| if bits & (1 << i) == 0 { "a\n" } else { "b\n" })
                        .collect(),
                );
            }
        }
        for a in &bodies {
            for b in &bodies {
                if a == b {
                    continue;
                }
                let d = compare(a, b, false);
                let reconstruct = |side: Kind| {
                    d.lines
                        .iter()
                        .filter(|line| line.kind != side)
                        .map(|line| {
                            format!(
                                "{}{}",
                                line.text,
                                match line.ending {
                                    "lf" => "\n",
                                    "crlf" => "\r\n",
                                    _ => "",
                                }
                            )
                        })
                        .collect::<String>()
                };
                assert_eq!(reconstruct(Kind::Added), *a);
                assert_eq!(reconstruct(Kind::Removed), *b);
                assert!(!d.partial);
            }
        }
    }

    #[test]
    fn output_byte_limit_and_uninspected_changes_are_explicit() {
        let body = format!("{}\n", "雪".repeat(1300)).repeat(10);
        let d = compare("", &body, false);
        assert_eq!(d.added, 10);
        assert!(d.lines.iter().map(|line| line.text.len()).sum::<usize>() <= OUTPUT_BYTES);
        assert_eq!(d.limits_reached, ["output_limit"]);
        assert!(d.lines.last().unwrap().text_truncated);
        let prefix = "same\n".repeat(INPUT_LINES);
        let d = compare(&format!("{prefix}old"), &format!("{prefix}new"), false);
        assert_eq!((d.added, d.removed), (0, 0));
        assert!(d.lines.is_empty());
        assert_eq!(d.limits_reached, ["line_limit"]);
    }
}
