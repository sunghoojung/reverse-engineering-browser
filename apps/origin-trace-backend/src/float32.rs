//! Inert, bounded binary32 diagnostics. Raw words remain authoritative, including NaNs.
use crate::{
    error::{Code, Error, Result},
    evidence, validation,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const MAX_SAMPLES: usize = 65536;
pub const MAX_BYTES: usize = MAX_SAMPLES * 4;
pub const MAX_BODY: usize = 2 * 1024 * 1024;
pub const MAX_ROWS: usize = 256;
pub const MAX_RESPONSE: usize = 512 * 1024;
const PROFILE: &str = "binary32-finite-steps-v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol_version: u32,
    input: Input,
    reference: Option<Input>,
    tolerances: Tolerances,
    detail: Detail,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    representation: Representation,
    channels: u32,
    frames: u32,
    source: Source,
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Representation {
    Float32Le,
    Float32Be,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Source {
    Bits {
        words: Vec<String>,
    },
    Bytes {
        base64: String,
    },
    Artifact {
        session_id: String,
        artifact_id: String,
        sha256: String,
        byte_length: usize,
    },
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tolerances {
    absolute: f64,
    relative: f64,
    ulps: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Detail {
    start: usize,
    limit: usize,
}
struct Loaded {
    bytes: Vec<u8>,
    words: Vec<u32>,
    identity: Value,
    description: Value,
}

fn limit() -> Error {
    Error::new(413, "Float32 diagnostic resource limit exceeded").with_code(Code::ResourceLimit)
}
fn invalid() -> Error {
    Error::bad("Float32 request does not match the versioned contract")
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn load(root: &Path, input: &Input) -> Result<Loaded> {
    if input.channels == 0 || input.channels > 64 || input.frames > MAX_SAMPLES as u32 {
        return Err(invalid());
    }
    let count = (input.channels as usize)
        .checked_mul(input.frames as usize)
        .filter(|n| *n <= MAX_SAMPLES)
        .ok_or_else(limit)?;
    let (bytes, origin, session, artifact) = match &input.source {
        Source::Bits { words } => {
            if words.len() > MAX_SAMPLES {
                return Err(limit());
            }
            let mut bytes = Vec::with_capacity(words.len() * 4);
            for word in words {
                if word.len() != 8
                    || !word
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid());
                }
                let bits = u32::from_str_radix(word, 16).map_err(|_| invalid())?;
                bytes.extend_from_slice(&match input.representation {
                    Representation::Float32Le => bits.to_le_bytes(),
                    Representation::Float32Be => bits.to_be_bytes(),
                });
            }
            (bytes, "supplied_bits", None, None)
        }
        Source::Bytes { base64 } => {
            if base64.len() > MAX_BYTES.div_ceil(3) * 4 {
                return Err(limit());
            }
            let bytes = STANDARD.decode(base64).map_err(|_| invalid())?;
            if bytes.len() > MAX_BYTES {
                return Err(limit());
            }
            if STANDARD.encode(&bytes) != *base64 {
                return Err(invalid());
            }
            (bytes, "supplied_bytes", None, None)
        }
        Source::Artifact {
            session_id,
            artifact_id,
            sha256,
            byte_length,
        } => {
            validation::canonical(&json!(session_id), 64, false, "Session ID")
                .map_err(|_| invalid())?;
            validation::canonical(&json!(artifact_id), 64, false, "Artifact ID")
                .map_err(|_| invalid())?;
            if sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid());
            }
            if *byte_length > MAX_BYTES {
                return Err(limit());
            }
            let record = evidence::find_artifact_bounded(root, artifact_id, 8192, 8 * 1024 * 1024)
                .map_err(|error| match error.status {
                    404 => error.with_code(Code::TargetUnavailable),
                    408 => error.with_code(Code::Timeout),
                    _ => error,
                })?;
            if record["session_id"] != *session_id {
                return Err(Error::new(
                    404,
                    "Float32 artifact is unavailable in the selected session",
                )
                .with_code(Code::TargetUnavailable));
            }
            if record["sha256"] != *sha256 || record["byte_size"] != *byte_length {
                return Err(Error::conflict("Float32 artifact identity changed"));
            }
            let bytes = evidence::content(root, &record, MAX_BYTES).map_err(|_| {
                Error::protocol("Float32 artifact bytes failed complete integrity verification")
            })?;
            (
                bytes,
                "verified_artifact",
                Some(session_id),
                Some(artifact_id),
            )
        }
    };
    if bytes.len() != count * 4 {
        return Err(Error::bad(
            "Float32 byte length does not match the complete declared interleaved layout",
        ));
    }
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| {
            let bytes = *chunk;
            match input.representation {
                Representation::Float32Le => u32::from_le_bytes(bytes),
                Representation::Float32Be => u32::from_be_bytes(bytes),
            }
        })
        .collect();
    let identity = json!({"origin":origin,"sha256":digest(&bytes),"byte_length":bytes.len(),"sample_count":words.len(),"session_id":session,"artifact_id":artifact,
        "representation":input.representation,"channels":input.channels,"frames":input.frames,"layout":"interleaved"});
    let description = describe(&words);
    Ok(Loaded {
        bytes,
        words,
        identity,
        description,
    })
}

fn class(bits: u32) -> &'static str {
    let magnitude = bits & 0x7fff_ffff;
    match magnitude {
        0 => "zero",
        1..=0x007f_ffff => "subnormal",
        0x0080_0000..=0x7f7f_ffff => "normal",
        0x7f80_0000 => "infinity",
        _ => "nan",
    }
}
fn finite(bits: u32) -> bool {
    bits & 0x7fff_ffff < 0x7f80_0000
}
fn number(bits: u32) -> Option<f64> {
    finite(bits).then(|| f32::from_bits(bits) as f64)
}
fn sample(bits: u32) -> Value {
    json!({"bits":format!("{bits:08x}"),"class":class(bits),"sign_bit":bits >> 31,"value":number(bits)})
}
// Monotone finite lattice with the two zeros collapsed. This is a distance in
// representable binary32 steps, not delta divided by an exponent-dependent epsilon.
fn rank(bits: u32) -> u32 {
    if bits >> 31 == 1 {
        0x8000_0000 - (bits & 0x7fff_ffff)
    } else {
        0x8000_0000 + bits
    }
}
fn describe(words: &[u32]) -> Value {
    let mut counts = [0usize; 7];
    let mut sum_abs = 0.0f64;
    for bits in words {
        let index = match class(*bits) {
            "zero" => {
                if bits >> 31 == 1 {
                    1
                } else {
                    0
                }
            }
            "subnormal" => 2,
            "normal" => 3,
            "infinity" => {
                if bits >> 31 == 1 {
                    5
                } else {
                    4
                }
            }
            _ => 6,
        };
        counts[index] += 1;
        if let Some(n) = number(*bits) {
            sum_abs += n.abs();
        }
    }
    json!({"positive_zero":counts[0],"negative_zero":counts[1],"subnormal":counts[2],"normal":counts[3],"positive_infinity":counts[4],"negative_infinity":counts[5],"nan":counts[6],
        "finite_count":counts[..4].iter().sum::<usize>(),"finite_sum_absolute":sum_abs})
}
struct Difference {
    bit_equal: bool,
    numeric_equal: bool,
    absolute: Option<f64>,
    relative: Option<f64>,
    ulps: Option<u32>,
    within: Option<bool>,
}
fn difference(left: u32, right: u32, tolerance: Tolerances) -> Difference {
    let (absolute, relative, ulps, within) = match (number(left), number(right)) {
        (Some(a), Some(b)) => {
            let delta = (a - b).abs();
            let scale = a.abs().max(b.abs());
            let relative = if scale == 0.0 { 0.0 } else { delta / scale };
            let steps = rank(left).abs_diff(rank(right));
            (
                Some(delta),
                Some(relative),
                Some(steps),
                Some(
                    delta <= tolerance.absolute
                        || relative <= tolerance.relative
                        || steps <= tolerance.ulps,
                ),
            )
        }
        _ => (None, None, None, None),
    };
    // Never feed any NaN representation through floating arithmetic.
    let numeric_equal = class(left) != "nan"
        && class(right) != "nan"
        && (left == right || (left & 0x7fff_ffff == 0 && right & 0x7fff_ffff == 0));
    Difference {
        bit_equal: left == right,
        numeric_equal,
        absolute,
        relative,
        ulps,
        within,
    }
}
fn difference_json(d: &Difference) -> Value {
    json!({"bit_equal":d.bit_equal,"numeric_equal":d.numeric_equal,"absolute_delta":d.absolute,"relative_delta":d.relative,"ulp_distance":d.ulps,"within_tolerance":d.within})
}

fn parse_request(bytes: &[u8]) -> Result<Request> {
    if bytes.len() > MAX_BODY {
        return Err(limit());
    }
    // Typed deserialization rejects duplicate and unknown members before Value
    // could silently collapse them. Diagnostics never echo caller content.
    let request: Request = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if request.protocol_version != 1
        || request.detail.start > MAX_SAMPLES
        || request.detail.limit == 0
        || request.detail.limit > MAX_ROWS
        || !request.tolerances.absolute.is_finite()
        || request.tolerances.absolute < 0.0
        || request.tolerances.absolute > 1e80
        || !request.tolerances.relative.is_finite()
        || request.tolerances.relative < 0.0
        || request.tolerances.relative > 2.0
    {
        return Err(invalid());
    }
    Ok(request)
}
/// Shared inert CLI preflight. Does not load artifacts or compute diagnostics.
pub fn validate_request_bytes(bytes: &[u8]) -> Result<()> {
    parse_request(bytes).map(|_| ())
}
pub fn compare_bytes(root: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    let request = parse_request(bytes)?;
    let input = load(root, &request.input)?;
    let reference = request
        .reference
        .as_ref()
        .map(|source| load(root, source))
        .transpose()?;
    let total = input
        .words
        .len()
        .max(reference.as_ref().map_or(0, |r| r.words.len()));
    if request.detail.start > total {
        return Err(Error::bad(
            "Float32 detail start exceeds the available samples",
        ));
    }
    let end = total.min(request.detail.start + request.detail.limit);
    let mut rows = Vec::with_capacity(end - request.detail.start);
    for index in request.detail.start..end {
        let a = input.words.get(index).copied();
        let b = reference.as_ref().and_then(|r| r.words.get(index)).copied();
        rows.push(json!({"index":index,"byte_offset":index * 4,"input":a.map(sample),"reference":b.map(sample),"difference":a.zip(b).map(|(a,b)|difference_json(&difference(a,b,request.tolerances)))}));
    }
    let comparison = reference.as_ref().map(|reference| {
        let compared = input.words.len().min(reference.words.len());
        let mut bit_equal = 0usize;
        let mut numeric_equal = 0usize;
        let mut finite_pairs = 0usize;
        let mut within = 0usize;
        let (mut max_abs, mut max_relative, mut sum_squared) = (0.0f64,0.0f64,0.0f64);
        let mut max_ulps = 0u32;
        let mut histogram = [0usize; 5];
        let mut first_bit_mismatch = None;
        for (index, (a,b)) in input.words.iter().zip(&reference.words).enumerate() {
            let d = difference(*a,*b,request.tolerances);
            bit_equal += usize::from(d.bit_equal);
            numeric_equal += usize::from(d.numeric_equal);
            if !d.bit_equal && first_bit_mismatch.is_none() { first_bit_mismatch = Some(index); }
            if let (Some(abs),Some(relative),Some(ulps),Some(passed)) = (d.absolute,d.relative,d.ulps,d.within) {
                finite_pairs += 1; within += usize::from(passed);
                max_abs = max_abs.max(abs); max_relative = max_relative.max(relative); max_ulps = max_ulps.max(ulps); sum_squared += abs * abs;
                histogram[match ulps { 0=>0,1=>1,2..=4=>2,5..=16=>3,_=>4 }] += 1;
            }
        }
        let same_length = input.words.len() == reference.words.len();
        let same_layout = input.identity["channels"] == reference.identity["channels"] && input.identity["frames"] == reference.identity["frames"];
        let comparable = same_length && same_layout && compared > 0;
        json!({"status":if compared == 0 {"empty"} else if !same_length {"unequal_length"} else if !same_layout {"layout_mismatch"} else {"complete"},
            "compared_pairs":compared,"input_tail":input.words.len()-compared,"reference_tail":reference.words.len()-compared,
            "raw_bytes_equal":input.bytes == reference.bytes,"representations_match":input.identity["representation"] == reference.identity["representation"],"layouts_match":same_layout,
            "all_bits_equal":comparable.then_some(bit_equal==compared),"all_numeric_equal":comparable.then_some(numeric_equal==compared),
            "bit_equal_pairs":bit_equal,"numeric_equal_pairs":numeric_equal,"first_bit_mismatch":first_bit_mismatch,
            "finite_pairs":finite_pairs,"excluded_nonfinite_pairs":compared-finite_pairs,"within_tolerance_pairs":within,
            "all_within_tolerance":(comparable && finite_pairs==compared).then_some(within==compared),
            "maximum_absolute_delta":(finite_pairs>0).then_some(max_abs),"maximum_relative_delta":(finite_pairs>0).then_some(max_relative),
            "rms_delta":(finite_pairs>0).then(||(sum_squared/finite_pairs as f64).sqrt()),"maximum_ulp_distance":(finite_pairs>0).then_some(max_ulps),
            "ulp_histogram":{"zero":histogram[0],"one":histogram[1],"two_to_four":histogram[2],"five_to_sixteen":histogram[3],"over_sixteen":histogram[4]}})
    });
    let result = json!({"protocol_version":1,"profile":PROFILE,"input":input.identity,"reference":reference.as_ref().map(|r| &r.identity),
        "input_summary":input.description,"reference_summary":reference.as_ref().map(|r| &r.description),"comparison":comparison,
        "tolerances":request.tolerances,"policies":{"zero":"numeric_equal_bits_distinct","nonfinite":"excluded_from_delta_ulp_tolerance","nan":"never_numeric_equal_payload_preserved","relative":"absolute_delta_over_maximum_magnitude_zero_is_zero","tolerance":"absolute_or_relative_or_ulp_finite_only","accumulation":"binary64_sequential_index_order","coverage":"complete_supplied_buffers_not_capture_completeness"},
        "detail":{"start":request.detail.start,"limit":request.detail.limit,"total":total,"returned":rows.len(),"next_start":(end<total).then_some(end),"rows":rows},
        "limits":{"samples_per_input":MAX_SAMPLES,"bytes_per_input":MAX_BYTES,"detail_rows":MAX_ROWS,"request_bytes":MAX_BODY,"response_bytes":MAX_RESPONSE,"manifest_bytes":8388608,"manifest_records":8192},
        "source_ids":["rust-f32-representation","oracle-binary32-format"]});
    let bytes = serde_json::to_vec(&result)
        .map_err(|_| Error::new(500, "Float32 result serialization failed"))?;
    if bytes.len() > MAX_RESPONSE {
        return Err(limit());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(words: &[u32]) -> Value {
        json!({"representation":"float32-le","channels":1,"frames":words.len(),"source":{"kind":"bits","words":words.iter().map(|word|format!("{word:08x}")).collect::<Vec<_>>()}})
    }
    fn request(a: &[u32], b: Option<&[u32]>) -> Value {
        json!({"protocol_version":1,"input":input(a),"reference":b.map(input),"tolerances":{"absolute":0,"relative":0,"ulps":0},"detail":{"start":0,"limit":256}})
    }
    fn run(value: Value) -> Value {
        let bytes = compare_bytes(
            Path::new("/nonexistent-float32-input"),
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        validation::schema("Float32Result", &result, 500).unwrap();
        result
    }
    #[test]
    fn float32_bits_classification_and_nonfinite_payloads_are_lossless() {
        let words = [
            0, 0x80000000, 1, 0x807fffff, 0x00800000, 0x3f800000, 0x7f7fffff, 0xff7fffff,
            0x7f800000, 0xff800000, 0x7fc00001, 0x7f800001, 0xffc01234,
        ];
        let report = run(request(&words, Some(&words)));
        assert_eq!(report["comparison"]["all_bits_equal"], true);
        assert_eq!(report["comparison"]["all_numeric_equal"], false);
        assert_eq!(report["comparison"]["finite_pairs"], 8);
        assert_eq!(report["comparison"]["excluded_nonfinite_pairs"], 5);
        assert!(report["comparison"]["all_within_tolerance"].is_null());
        assert_eq!(report["input_summary"]["nan"], 3);
        for (row, bits) in report["detail"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .zip(words)
        {
            assert_eq!(row["input"]["bits"], format!("{bits:08x}"));
            assert_eq!(row["input"]["value"].is_null(), !finite(bits));
        }
        let zeros = run(request(&[0], Some(&[0x80000000])));
        assert_eq!(zeros["comparison"]["all_bits_equal"], false);
        assert_eq!(zeros["comparison"]["all_numeric_equal"], true);
        assert_eq!(zeros["comparison"]["maximum_ulp_distance"], 0);
        let infinities = run(request(&[0x7f800000], Some(&[0x7f800000])));
        assert_eq!(infinities["comparison"]["all_numeric_equal"], true);
        assert!(infinities["comparison"]["maximum_absolute_delta"].is_null());
        assert!(infinities["comparison"]["rms_delta"].is_null());
        assert_eq!(
            run(request(&[0x7f800000], Some(&[0xff800000])))["comparison"]["all_numeric_equal"],
            false
        );
    }
    #[test]
    fn float32_finite_lattice_handles_negative_zero_exponent_and_extreme_boundaries() {
        let t = Tolerances {
            absolute: 0.0,
            relative: 0.0,
            ulps: 0,
        };
        for (a, b, steps) in [
            (0x3f800000, 0x3f800001, 1),
            (0xbf800001, 0xbf800000, 1),
            (0x3f7fffff, 0x3f800000, 1),
            (0x007fffff, 0x00800000, 1),
            (0x80000001, 1, 2),
            (0x80000000, 0, 0),
            (0xff7fffff, 0x7f7fffff, 0xfeffffff - 1),
        ] {
            let d = difference(a, b, t);
            assert_eq!(d.ulps, Some(steps), "{a:x} {b:x}");
            assert_eq!(difference(b, a, t).ulps, d.ulps);
        }
        let adjacent = run(request(&[0x3f800000], Some(&[0x3f800001])));
        assert_eq!(
            adjacent["comparison"]["maximum_absolute_delta"],
            2f64.powi(-23)
        );
        let extremes = run(request(&[0x7f7fffff], Some(&[0xff7fffff])));
        assert!(
            extremes["comparison"]["rms_delta"]
                .as_f64()
                .unwrap()
                .is_finite()
        );
        // Original deterministic property fixtures: adjacent representable values
        // checked against Rust's primitive next_up, including both sign halves.
        let mut bits = 0x12345678u32;
        for _ in 0..10000 {
            bits = bits.wrapping_mul(1664525).wrapping_add(1013904223);
            if finite(bits) {
                let next = f32::from_bits(bits).next_up().to_bits();
                if finite(next) {
                    assert_eq!(rank(bits).abs_diff(rank(next)), 1);
                }
            }
        }
    }
    #[test]
    fn float32_tolerances_are_explicit_and_aggregate_collisions_never_pass() {
        let report = run(request(
            &[1f32.to_bits(), (-1f32).to_bits()],
            Some(&[0.5f32.to_bits(), (-1.5f32).to_bits()]),
        ));
        assert_eq!(
            report["input_summary"]["finite_sum_absolute"],
            report["reference_summary"]["finite_sum_absolute"]
        );
        assert_eq!(report["comparison"]["all_bits_equal"], false);
        assert_eq!(report["comparison"]["all_numeric_equal"], false);
        assert_eq!(report["comparison"]["all_within_tolerance"], false);
        for tolerance in [
            json!({"absolute":2f64.powi(-23),"relative":0,"ulps":0}),
            json!({"absolute":0,"relative":1e-6,"ulps":0}),
            json!({"absolute":0,"relative":0,"ulps":1}),
        ] {
            let mut req = request(&[0x3f800000], Some(&[0x3f800001]));
            req["tolerances"] = tolerance.clone();
            let report = run(req);
            for key in ["absolute", "relative", "ulps"] {
                assert_eq!(report["tolerances"][key].as_f64(), tolerance[key].as_f64());
            }
            assert_eq!(report["comparison"]["all_within_tolerance"], true);
            assert_eq!(report["comparison"]["all_numeric_equal"], false);
        }
    }
    #[test]
    fn float32_empty_unequal_layout_and_detail_coverage_are_explicit() {
        let empty = run(request(&[], Some(&[])));
        assert_eq!(empty["comparison"]["status"], "empty");
        assert!(empty["comparison"]["all_bits_equal"].is_null());
        let unequal = run(request(&[1, 2], Some(&[1])));
        assert_eq!(unequal["comparison"]["status"], "unequal_length");
        assert_eq!(unequal["comparison"]["input_tail"], 1);
        assert!(unequal["comparison"]["all_bits_equal"].is_null());
        assert!(unequal["detail"]["rows"][1]["difference"].is_null());
        let mut req = request(&[1, 2], Some(&[1, 2]));
        req["reference"]["channels"] = json!(2);
        req["reference"]["frames"] = json!(1);
        assert_eq!(run(req)["comparison"]["status"], "layout_mismatch");
        let mut req = request(&[0; MAX_SAMPLES], Some(&[0; MAX_SAMPLES]));
        req["detail"] = json!({"start":65535,"limit":256});
        let report = run(req);
        assert_eq!(report["comparison"]["compared_pairs"], 65536);
        assert_eq!(report["detail"]["returned"], 1);
        assert_eq!(report["detail"]["rows"][0]["byte_offset"], 262140);
        assert!(report["detail"]["next_start"].is_null());
        let mut req = request(&[1, 2, 3], None);
        req["detail"] = json!({"start":0,"limit":1});
        let report = run(req);
        assert_eq!(report["detail"]["next_start"], 1);
        assert!(report["comparison"].is_null());
    }
    #[test]
    fn float32_endian_and_bytes_have_exact_identity() {
        let mut req = request(&[0x3f800000, 0x7f800001], Some(&[0x3f800000, 0x7f800001]));
        req["reference"]["representation"] = json!("float32-be");
        let report = run(req);
        assert_eq!(report["comparison"]["all_bits_equal"], true);
        assert_eq!(report["comparison"]["raw_bytes_equal"], false);
        assert_eq!(report["comparison"]["representations_match"], false);
        let mut req = request(&[0x80000000, 0x7fc01234], None);
        req["input"]["source"] =
            json!({"kind":"bytes","base64":STANDARD.encode([0,0,0,128,52,18,192,127])});
        let bytes = run(req);
        assert_eq!(bytes["detail"]["rows"][1]["input"]["bits"], "7fc01234");
        assert_eq!(bytes["input"]["origin"], "supplied_bytes");
    }
    #[test]
    fn float32_contract_rejects_malformed_duplicate_unknown_and_oversized_inputs() {
        let base = request(&[0], None);
        for (pointer, value) in [
            ("/protocol_version", json!(2)),
            ("/input/channels", json!(0)),
            ("/input/frames", json!(2)),
            ("/input/representation", json!("native")),
            ("/input/source/words", json!(["NaN"])),
            ("/detail/limit", json!(0)),
            ("/detail/limit", json!(257)),
            ("/detail/start", json!(2)),
            ("/tolerances/relative", json!(2.1)),
            ("/tolerances/absolute", json!(-1)),
            ("/input/source/words", json!([0])),
        ] {
            let mut req = base.clone();
            *req.pointer_mut(pointer).unwrap() = value;
            assert!(
                compare_bytes(Path::new("."), &serde_json::to_vec(&req).unwrap()).is_err(),
                "{pointer}"
            );
        }
        let raw = serde_json::to_string(&base).unwrap();
        for raw in [
            raw.replace(
                "\"protocol_version\":1",
                "\"protocol_version\":1,\"protocol_version\":1",
            ),
            raw.replace("\"channels\":1", "\"channels\":1,\"channels\":1"),
            raw.replace("\"kind\":\"bits\"", "\"kind\":\"bits\",\"kind\":\"bits\""),
            raw.replace(
                "\"kind\":\"bits\"",
                "\"kind\":\"bits\",\"secret\":\"do-not-echo\"",
            ),
            "[]".into(),
            "{\"secret\":\"do-not-echo\"}".into(),
        ] {
            let error = compare_bytes(Path::new("."), raw.as_bytes()).unwrap_err();
            assert_eq!(error.status, 400);
            assert!(!error.message.contains("do-not-echo"));
        }
        let mut req = base.clone();
        req["input"]["source"] = json!({"kind":"bytes","base64":"AAAA"});
        assert!(compare_bytes(Path::new("."), req.to_string().as_bytes()).is_err());
        let mut req = base;
        req["input"]["source"] = json!({"kind":"bits","words":vec!["00000000";MAX_SAMPLES+1]});
        assert_eq!(
            compare_bytes(Path::new("."), req.to_string().as_bytes())
                .unwrap_err()
                .status,
            413
        );
        assert_eq!(
            compare_bytes(Path::new("."), &vec![b' '; MAX_BODY + 1])
                .unwrap_err()
                .status,
            413
        );
    }
    #[test]
    fn float32_original_ui_fixture_matches_authoritative_engine() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../tools/fixtures/float32-v1.json")).unwrap();
        assert_eq!(run(fixture["request"].clone()), fixture["result"]);
    }
}
