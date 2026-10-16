//! Retained-byte accounting. Handler counts are never a byte numerator.
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MAX_PREVIEW_BYTES: usize = 4096;
pub(crate) const MAX_ATTRIBUTIONS: usize = 4096;
const MAX_OMISSIONS: usize = 256;

fn omit(omissions: &mut Vec<Value>, reason: &str) {
    if !omissions.iter().any(|row| row["reason"] == reason) {
        omissions.push(json!({"reason": reason}));
    }
}

/// Attributions must come from an explicit byte layout, never a guessed PC unit.
/// Intersect them with retained previews and count each byte once per artifact.
pub(crate) fn coverage(
    snapshots: &[Value],
    handler_count: usize,
    attributions: &[Value],
    unknowns: &[String],
    mut omissions: Vec<Value>,
) -> Value {
    let mut retained = BTreeMap::<String, Vec<bool>>::new();
    for snapshot in snapshots.iter().take(16) {
        let Some(artifact_id) = snapshot["artifact_id"].as_str() else {
            omit(&mut omissions, "invalid-snapshot");
            continue;
        };
        if retained.contains_key(artifact_id) {
            omit(&mut omissions, "duplicate-snapshot");
            continue;
        }
        let Some(bytes) = snapshot["preview_hex"]
            .as_str()
            .and_then(|text| hex::decode(text).ok())
        else {
            omit(&mut omissions, "snapshot-unavailable");
            continue;
        };
        let byte_count = snapshot["byte_count"].as_u64().unwrap_or(0);
        let count = bytes
            .len()
            .min(MAX_PREVIEW_BYTES)
            .min(usize::try_from(byte_count).unwrap_or(usize::MAX));
        if byte_count > count as u64 || snapshot["truncated"] == true {
            omit(&mut omissions, "snapshot-preview-truncated");
        }
        if bytes.len() > MAX_PREVIEW_BYTES || bytes.len() as u64 > byte_count {
            omit(&mut omissions, "invalid-snapshot-size");
        }
        retained.insert(artifact_id.to_owned(), vec![false; count]);
    }
    if snapshots.is_empty()
        && !omissions
            .iter()
            .any(|row| row["reason"] == "static-initializer-only")
    {
        omit(&mut omissions, "runtime-snapshot-unavailable");
    }
    if snapshots.len() > 16 {
        omit(&mut omissions, "snapshot-limit");
    }
    let mut accepted = Vec::new();
    for attribution in attributions.iter().take(MAX_ATTRIBUTIONS) {
        let Some(cells) = attribution["artifact_id"]
            .as_str()
            .and_then(|id| retained.get_mut(id))
        else {
            omit(&mut omissions, "attribution-snapshot-unavailable");
            continue;
        };
        let start = attribution["byte_offset"].as_u64();
        let size = attribution["byte_size"].as_u64();
        let Some((start, end)) = start
            .zip(size)
            .and_then(|(start, size)| (size > 0).then_some((start, start.checked_add(size)?)))
        else {
            omit(&mut omissions, "invalid-byte-attribution");
            continue;
        };
        if !matches!(attribution["kind"].as_str(), Some("opcode" | "operand"))
            || !matches!(
                attribution["evidence_class"].as_str(),
                Some("inferred" | "observed")
            )
            || attribution["opcode"]
                .as_u64()
                .is_none_or(|code| code > u32::MAX.into())
        {
            omit(&mut omissions, "invalid-byte-attribution");
            continue;
        }
        if end > cells.len() as u64 {
            omit(&mut omissions, "attribution-outside-preview");
            continue;
        }
        let start = start.min(cells.len() as u64) as usize;
        let end = end.min(cells.len() as u64) as usize;
        if start < end {
            cells[start..end].fill(true);
            let mut accepted_range = attribution.clone();
            accepted_range["byte_size"] = json!(end - start);
            accepted.push(accepted_range);
        }
    }
    if attributions.len() > MAX_ATTRIBUTIONS {
        omit(&mut omissions, "attribution-limit");
    }
    let retained_bytes = retained.values().map(Vec::len).sum::<usize>();
    let characterized = retained
        .values()
        .flatten()
        .filter(|characterized| **characterized)
        .count();
    let uncharacterized = retained_bytes - characterized;
    if uncharacterized > 0 {
        omit(&mut omissions, "uncharacterized-bytecode");
    }
    if retained_bytes == 0 {
        omit(&mut omissions, "snapshot-bytes-unavailable");
    }
    if omissions.len() > MAX_OMISSIONS {
        omissions.truncate(MAX_OMISSIONS - 1);
        omissions.push(json!({"reason": "omission-limit"}));
    }
    json!({
        "complete": retained_bytes > 0 && uncharacterized == 0 && omissions.is_empty() && unknowns.is_empty(),
        "handler_count": handler_count,
        "retained_snapshot_bytes": retained_bytes,
        "characterized_bytes": characterized,
        "uncharacterized_bytes": uncharacterized,
        "attributions": accepted,
        "omissions": omissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(id: &str, preview: &str, byte_count: usize) -> Value {
        json!({"artifact_id": id, "preview_hex": preview, "byte_count": byte_count, "truncated": false})
    }

    fn range(id: &str, offset: usize, size: usize, kind: &str) -> Value {
        json!({"artifact_id": id, "byte_offset": offset, "byte_size": size,
            "opcode": 1, "kind": kind, "evidence_class": "inferred"})
    }

    #[test]
    fn complete_requires_all_retained_bytes_and_no_unknowns_or_omissions() {
        let snapshots = [snapshot("1", "0107ff", 3)];
        let ranges = [
            range("1", 0, 1, "opcode"),
            range("1", 1, 1, "operand"),
            range("1", 2, 1, "opcode"),
        ];
        let result = coverage(&snapshots, 2, &ranges, &[], vec![]);
        assert_eq!(result["complete"], true);
        assert_eq!(result["characterized_bytes"], 3);
        assert_eq!(result["handler_count"], 2);
        assert_eq!(
            coverage(&snapshots, 2, &ranges, &["unknown cell".into()], vec![])["complete"],
            false
        );
        assert_eq!(
            coverage(
                &snapshots,
                2,
                &ranges,
                &[],
                vec![json!({"reason": "sampler-unavailable"})]
            )["complete"],
            false
        );
    }

    #[test]
    fn partial_bytes_name_the_omission_and_ranges_are_a_union() {
        let snapshots = [snapshot("1", "0107ffaa", 4), snapshot("2", "0107", 2)];
        let ranges = [
            range("1", 0, 2, "opcode"),
            range("1", 1, 1, "operand"),
            range("2", 0, 1, "opcode"),
        ];
        let result = coverage(&snapshots, 400, &ranges, &[], vec![]);
        assert_eq!(result["retained_snapshot_bytes"], 6);
        assert_eq!(result["characterized_bytes"], 3);
        assert_eq!(result["uncharacterized_bytes"], 3);
        assert_eq!(result["complete"], false);
        assert!(
            result["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["reason"] == "uncharacterized-bytecode")
        );
    }

    #[test]
    fn omitted_preview_bytes_never_increase_the_numerator() {
        let snapshots = [snapshot("1", &"01".repeat(4096), 5000)];
        let result = coverage(
            &snapshots,
            1,
            &[range("1", 0, 5000, "operand")],
            &[],
            vec![],
        );
        assert_eq!(result["retained_snapshot_bytes"], 4096);
        assert_eq!(result["characterized_bytes"], 0);
        assert!(result["attributions"].as_array().unwrap().is_empty());
        assert_eq!(result["complete"], false);
        assert!(
            result["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["reason"] == "snapshot-preview-truncated")
        );
    }

    #[test]
    fn absent_snapshot_is_not_empty_success() {
        let result = coverage(&[], 3, &[], &[], vec![]);
        assert_eq!(result["complete"], false);
        assert_eq!(result["retained_snapshot_bytes"], 0);
        assert_eq!(result["characterized_bytes"], 0);
        assert!(!result["omissions"].as_array().unwrap().is_empty());
    }
    #[test]
    fn static_initializer_omission_does_not_also_claim_runtime_capture_absence() {
        let result = coverage(
            &[],
            1,
            &[],
            &[],
            vec![json!({"reason": "static-initializer-only"})],
        );
        assert!(
            !result["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["reason"] == "runtime-snapshot-unavailable")
        );
    }

    #[test]
    fn attribution_work_is_bounded_and_omission_is_visible() {
        let snapshots = [snapshot("1", "01", 1)];
        let rows = vec![range("1", 0, 1, "opcode"); MAX_ATTRIBUTIONS + 1];
        let result = coverage(&snapshots, 1, &rows, &[], vec![]);
        assert_eq!(
            result["attributions"].as_array().unwrap().len(),
            MAX_ATTRIBUTIONS
        );
        assert_eq!(result["complete"], false);
        assert!(
            result["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["reason"] == "attribution-limit")
        );
    }
}
