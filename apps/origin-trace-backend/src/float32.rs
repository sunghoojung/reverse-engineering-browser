//! Inert binary32 diagnostics over complete buffers of any size. Raw words
//! remain authoritative, including NaNs.
use crate::{
    error::{Code, Error, Result, check_cancelled},
    evidence, validation,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{BufReader, Read},
    path::Path,
    sync::atomic::AtomicBool,
};

const PROFILE: &str = "binary32-finite-steps-v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
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
    frames: u64,
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
        byte_length: u64,
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
/// One side's words, read once in index order. Supplied words or bytes are
/// already in the request; an artifact is streamed through a reader that
/// verifies its size and hash when it reaches the end, so memory stays the
/// same at any artifact size.
enum Words {
    Memory { bytes: Vec<u8>, position: usize },
    Artifact(BufReader<evidence::VerifiedReader>),
}
struct Side {
    representation: Representation,
    words: Words,
    count: usize,
    identity: Value,
    summary: Summary,
}

fn invalid() -> Error {
    Error::bad("Float32 request does not match the versioned contract")
}
fn layout() -> Error {
    Error::bad("Float32 byte length does not match the complete declared interleaved layout")
}
fn integrity(_: std::io::Error) -> Error {
    Error::protocol("Float32 artifact bytes failed complete integrity verification")
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn lowercase_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn open(root: &Path, input: &Input) -> Result<Side> {
    if input.channels == 0 {
        return Err(invalid());
    }
    let count = usize::try_from(input.frames)
        .ok()
        .and_then(|frames| frames.checked_mul(input.channels as usize))
        .filter(|count| count.checked_mul(4).is_some())
        .ok_or_else(layout)?;
    let memory = |bytes: Vec<u8>| -> Result<(Words, String, usize)> {
        if bytes.len() != count * 4 {
            return Err(layout());
        }
        let sha256 = digest(&bytes);
        let length = bytes.len();
        Ok((Words::Memory { bytes, position: 0 }, sha256, length))
    };
    let (words, sha256, byte_length, origin, session, artifact) = match &input.source {
        Source::Bits { words } => {
            let mut bytes = Vec::with_capacity(words.len().saturating_mul(4));
            for word in words {
                if !lowercase_hex(word, 8) {
                    return Err(invalid());
                }
                let bits = u32::from_str_radix(word, 16).map_err(|_| invalid())?;
                bytes.extend_from_slice(&match input.representation {
                    Representation::Float32Le => bits.to_le_bytes(),
                    Representation::Float32Be => bits.to_be_bytes(),
                });
            }
            let (words, sha256, length) = memory(bytes)?;
            (words, sha256, length, "supplied_bits", None, None)
        }
        Source::Bytes { base64 } => {
            let bytes = STANDARD.decode(base64).map_err(|_| invalid())?;
            if STANDARD.encode(&bytes) != *base64 {
                return Err(invalid());
            }
            let (words, sha256, length) = memory(bytes)?;
            (words, sha256, length, "supplied_bytes", None, None)
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
            if !lowercase_hex(sha256, 64) {
                return Err(invalid());
            }
            let record =
                evidence::find_artifact(root, artifact_id).map_err(|error| match error.status {
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
            // The answer spells out the input words, so this route would return
            // a body, header block or cookie list to whoever asks. Anything not
            // recorded as non-sensitive stays closed, before a byte is read.
            if record["sensitive"] != false {
                return Err(Error::bad(
                    "Float32 diagnostics do not read sensitive artifacts",
                ));
            }
            if record["sha256"] != *sha256 || record["byte_size"] != *byte_length {
                return Err(Error::conflict("Float32 artifact identity changed"));
            }
            if *byte_length != count as u64 * 4 {
                return Err(layout());
            }
            let reader = evidence::VerifiedReader::open(root, &record).map_err(|_| {
                Error::protocol("Float32 artifact bytes failed complete integrity verification")
            })?;
            (
                Words::Artifact(BufReader::with_capacity(64 * 1024, reader)),
                sha256.clone(),
                count * 4,
                "verified_artifact",
                Some(session_id),
                Some(artifact_id),
            )
        }
    };
    let identity = json!({"origin":origin,"sha256":sha256,"byte_length":byte_length,"sample_count":count,"session_id":session,"artifact_id":artifact,
        "representation":input.representation,"channels":input.channels,"frames":input.frames,"layout":"interleaved"});
    Ok(Side {
        representation: input.representation,
        words,
        count,
        identity,
        summary: Summary::default(),
    })
}
impl Side {
    /// The next sample's four bytes as stored, and its bits.
    fn next(&mut self) -> Result<([u8; 4], u32)> {
        let mut bytes = [0u8; 4];
        match &mut self.words {
            Words::Memory {
                bytes: all,
                position,
            } => {
                bytes.copy_from_slice(&all[*position..*position + 4]);
                *position += 4;
            }
            Words::Artifact(reader) => reader.read_exact(&mut bytes).map_err(integrity)?,
        }
        let bits = match self.representation {
            Representation::Float32Le => u32::from_le_bytes(bytes),
            Representation::Float32Be => u32::from_be_bytes(bytes),
        };
        self.summary.add(bits);
        Ok((bytes, bits))
    }
    /// Reads an artifact to its end, where its size and hash are checked:
    /// no result is returned from bytes that were not the recorded ones.
    fn finish(&mut self) -> Result<()> {
        if let Words::Artifact(reader) = &mut self.words {
            let mut rest = [0u8; 1];
            if reader.read(&mut rest).map_err(integrity)? != 0 {
                return Err(integrity(std::io::ErrorKind::InvalidData.into()));
            }
        }
        Ok(())
    }
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
#[derive(Default)]
struct Summary {
    counts: [usize; 7],
    sum_abs: f64,
}
impl Summary {
    fn add(&mut self, bits: u32) {
        let index = match class(bits) {
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
        self.counts[index] += 1;
        if let Some(n) = number(bits) {
            self.sum_abs += n.abs();
        }
    }
    fn json(&self) -> Value {
        let counts = &self.counts;
        json!({"positive_zero":counts[0],"negative_zero":counts[1],"subnormal":counts[2],"normal":counts[3],"positive_infinity":counts[4],"negative_infinity":counts[5],"nan":counts[6],
            "finite_count":counts[..4].iter().sum::<usize>(),"finite_sum_absolute":self.sum_abs})
    }
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
/// Pairwise totals, accumulated in index order as the pairs are read.
#[derive(Default)]
struct Comparison {
    bit_equal: usize,
    numeric_equal: usize,
    finite_pairs: usize,
    within: usize,
    max_abs: f64,
    max_relative: f64,
    sum_squared: f64,
    max_ulps: u32,
    histogram: [usize; 5],
    first_bit_mismatch: Option<usize>,
    raw_bytes_equal: bool,
}
impl Comparison {
    fn add(&mut self, index: usize, d: &Difference) {
        self.bit_equal += usize::from(d.bit_equal);
        self.numeric_equal += usize::from(d.numeric_equal);
        if !d.bit_equal && self.first_bit_mismatch.is_none() {
            self.first_bit_mismatch = Some(index);
        }
        if let (Some(abs), Some(relative), Some(ulps), Some(passed)) =
            (d.absolute, d.relative, d.ulps, d.within)
        {
            self.finite_pairs += 1;
            self.within += usize::from(passed);
            self.max_abs = self.max_abs.max(abs);
            self.max_relative = self.max_relative.max(relative);
            self.max_ulps = self.max_ulps.max(ulps);
            self.sum_squared += abs * abs;
            self.histogram[match ulps {
                0 => 0,
                1 => 1,
                2..=4 => 2,
                5..=16 => 3,
                _ => 4,
            }] += 1;
        }
    }
    fn json(&self, input: &Side, reference: &Side) -> Value {
        let compared = input.count.min(reference.count);
        let (finite_pairs, histogram) = (self.finite_pairs, &self.histogram);
        let same_length = input.count == reference.count;
        let same_layout = input.identity["channels"] == reference.identity["channels"]
            && input.identity["frames"] == reference.identity["frames"];
        let comparable = same_length && same_layout && compared > 0;
        json!({"status":if compared == 0 {"empty"} else if !same_length {"unequal_length"} else if !same_layout {"layout_mismatch"} else {"complete"},
            "compared_pairs":compared,"input_tail":input.count-compared,"reference_tail":reference.count-compared,
            "raw_bytes_equal":same_length && self.raw_bytes_equal,"representations_match":input.identity["representation"] == reference.identity["representation"],"layouts_match":same_layout,
            "all_bits_equal":comparable.then_some(self.bit_equal==compared),"all_numeric_equal":comparable.then_some(self.numeric_equal==compared),
            "bit_equal_pairs":self.bit_equal,"numeric_equal_pairs":self.numeric_equal,"first_bit_mismatch":self.first_bit_mismatch,
            "finite_pairs":finite_pairs,"excluded_nonfinite_pairs":compared-finite_pairs,"within_tolerance_pairs":self.within,
            "all_within_tolerance":(comparable && finite_pairs==compared).then_some(self.within==compared),
            "maximum_absolute_delta":(finite_pairs>0).then_some(self.max_abs),"maximum_relative_delta":(finite_pairs>0).then_some(self.max_relative),
            "rms_delta":(finite_pairs>0).then(||(self.sum_squared/finite_pairs as f64).sqrt()),"maximum_ulp_distance":(finite_pairs>0).then_some(self.max_ulps),
            "ulp_histogram":{"zero":histogram[0],"one":histogram[1],"two_to_four":histogram[2],"five_to_sixteen":histogram[3],"over_sixteen":histogram[4]}})
    }
}

/// Typed deserialization rejects duplicate and unknown members before Value
/// could silently collapse them. Diagnostics never echo caller content.
pub fn parse_reader(reader: impl Read) -> Result<Request> {
    let request: Request = serde_json::from_reader(reader).map_err(|_| invalid())?;
    if request.protocol_version != 1
        || request.detail.limit == 0
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
    parse_reader(bytes).map(|_| ())
}
/// Full metrics over every sample of both sides, read once in lockstep, with
/// the caller's detail page. Reading stops between blocks once `cancelled`
/// is set.
pub fn compare(root: &Path, request: &Request, cancelled: &AtomicBool) -> Result<Vec<u8>> {
    let mut input = open(root, &request.input)?;
    let mut reference = request
        .reference
        .as_ref()
        .map(|source| open(root, source))
        .transpose()?;
    let total = input.count.max(reference.as_ref().map_or(0, |r| r.count));
    let start = request.detail.start;
    if start > total {
        return Err(Error::bad(
            "Float32 detail start exceeds the available samples",
        ));
    }
    let end = total.min(start.saturating_add(request.detail.limit));
    let mut rows = Vec::with_capacity(end - start);
    let mut comparison = Comparison {
        raw_bytes_equal: true,
        ..Comparison::default()
    };
    for index in 0..total {
        if index % 65_536 == 0 {
            check_cancelled(cancelled, "Float32 comparison")?;
        }
        let a = (index < input.count).then(|| input.next()).transpose()?;
        let b = match reference.as_mut() {
            Some(side) if index < side.count => Some(side.next()?),
            _ => None,
        };
        let d = a.zip(b).map(|((a_bytes, a), (b_bytes, b))| {
            comparison.raw_bytes_equal &= a_bytes == b_bytes;
            let d = difference(a, b, request.tolerances);
            comparison.add(index, &d);
            d
        });
        if (start..end).contains(&index) {
            rows.push(json!({"index":index,"byte_offset":index * 4,"input":a.map(|(_, bits)| sample(bits)),"reference":b.map(|(_, bits)| sample(bits)),"difference":d.as_ref().map(difference_json)}));
        }
    }
    input.finish()?;
    if let Some(side) = reference.as_mut() {
        side.finish()?;
    }
    let comparison = reference.as_ref().map(|r| comparison.json(&input, r));
    let result = json!({"protocol_version":2,"profile":PROFILE,"input":input.identity,"reference":reference.as_ref().map(|r| &r.identity),
        "input_summary":input.summary.json(),"reference_summary":reference.as_ref().map(|r| r.summary.json()),"comparison":comparison,
        "tolerances":request.tolerances,"policies":{"zero":"numeric_equal_bits_distinct","nonfinite":"excluded_from_delta_ulp_tolerance","nan":"never_numeric_equal_payload_preserved","relative":"absolute_delta_over_maximum_magnitude_zero_is_zero","tolerance":"absolute_or_relative_or_ulp_finite_only","accumulation":"binary64_sequential_index_order","coverage":"complete_supplied_buffers_not_capture_completeness"},
        "detail":{"start":start,"limit":request.detail.limit,"total":total,"returned":rows.len(),"next_start":(end<total).then_some(end),"rows":rows},
        "source_ids":["rust-f32-representation","oracle-binary32-format"]});
    serde_json::to_vec(&result).map_err(|_| Error::new(500, "Float32 result serialization failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn compare_bytes(root: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
        compare(root, &parse_reader(bytes)?, &AtomicBool::new(false))
    }
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
        // Past the 65,536 samples a side once held, and a page past the 256
        // rows it once returned.
        let mut req = request(&[0; 200_000], Some(&[0; 200_000]));
        req["detail"] = json!({"start":199_999,"limit":256});
        let report = run(req);
        assert_eq!(report["comparison"]["compared_pairs"], 200_000);
        assert_eq!(report["detail"]["returned"], 1);
        assert_eq!(report["detail"]["rows"][0]["byte_offset"], 799_996);
        assert!(report["detail"]["next_start"].is_null());
        let mut req = request(&[0x3f80_0000; 1000], None);
        req["detail"] = json!({"start":0,"limit":1000});
        let report = run(req);
        assert_eq!(report["detail"]["returned"], 1000);
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
        // No size refuses a request: what is malformed is refused as such.
        assert_eq!(
            compare_bytes(Path::new("."), &vec![b' '; 2 * 1024 * 1024 + 1])
                .unwrap_err()
                .status,
            400
        );
        let mut req = base;
        req["input"]["channels"] = json!(65);
        req["input"]["frames"] = json!(1009);
        req["input"]["source"] = json!({"kind":"bits","words":vec!["00000000";65 * 1009]});
        assert_eq!(run(req)["input_summary"]["positive_zero"], 65 * 1009);
    }
    #[test]
    fn float32_comparison_stops_once_its_request_goes_away() {
        let bytes = serde_json::to_vec(&request(&[0; 70_000], Some(&[0; 70_000]))).unwrap();
        let error = compare(
            Path::new("."),
            &parse_reader(bytes.as_slice()).unwrap(),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert_eq!(error.status, 499);
    }
    #[test]
    fn float32_original_ui_fixture_matches_authoritative_engine() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../tools/fixtures/float32-v1.json")).unwrap();
        assert_eq!(run(fixture["request"].clone()), fixture["result"]);
    }
}
