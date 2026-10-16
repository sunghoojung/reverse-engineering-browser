//! Bounded recognition of literal typed-array initializers. This module never
//! evaluates JavaScript or invokes captured constructors, mappers, or decoders.
use base64::{Engine, engine::general_purpose};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

const PREVIEW_BYTES: usize = 256;
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONSTRUCTORS: usize = 4096;

static CONSTRUCTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(new\s+)?Uint8Array(?:\s*\.\s*(of|from|fromBase64))?\s*\(")
        .expect("literal typed-array constructor")
});
static REBOUND_BUILTIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Uint8Array|TextEncoder)\b\s*(?:[,)}\]]|(?:\.\s*[A-Za-z_$][\w$]*|\[[^\]]*\])*\s*=(?:[^=]|$))|\b(?:const|let|var|function|class|import)\s+(?:Uint8Array|TextEncoder)\b|\b(?:String|Uint8Array|TextEncoder)\s*\.\s*prototype\b")
        .expect("rebound initializer builtin")
});

fn unavailable(id: &str, reason: &str) -> Value {
    json!({"artifact_id":id,"snapshot_hex":null,"unavailable_reason":reason})
}

fn closing_paren(source: &str, opening: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in source.bytes().enumerate().skip(opening) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => (),
        }
    }
    None
}

fn numeric_list(source: &str) -> Option<Vec<u8>> {
    let source = source.trim();
    if source.is_empty() {
        return Some(Vec::new());
    }
    let source = source.strip_suffix(',').unwrap_or(source).trim();
    source
        .split(',')
        .map(|token| {
            let token = token.trim();
            if let Some(hex) = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
            {
                (!hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                    .then(|| u8::from_str_radix(hex, 16).ok())
                    .flatten()
            } else {
                (!token.is_empty()
                    && (token.len() == 1 || !token.starts_with('0'))
                    && token.bytes().all(|b| b.is_ascii_digit()))
                .then(|| token.parse().ok())
                .flatten()
            }
        })
        .collect()
}

// Preserve UTF-16 units, including lone surrogates, until the explicitly named
// conversion is known. charCodeAt(0) and TextEncoder have different semantics.
fn string_literal(source: &str) -> Option<(Vec<u16>, &str)> {
    let source = source.trim_start();
    let quote = *source.as_bytes().first()?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let mut units = Vec::new();
    let mut chars = source[1..].char_indices().peekable();
    while let Some((offset, character)) = chars.next() {
        if character as u32 == u32::from(quote) {
            return Some((units, &source[offset + 2..]));
        }
        if matches!(character, '\n' | '\r') {
            return None;
        }
        let character = if character == '\\' {
            match chars.next()?.1 {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'b' => '\u{8}',
                'f' => '\u{c}',
                'v' => '\u{b}',
                '0' if chars.peek().is_none_or(|(_, c)| !c.is_ascii_digit()) => '\0',
                '\\' => '\\',
                '\'' => '\'',
                '"' => '"',
                '/' => '/',
                escape @ ('x' | 'u') => {
                    if escape == 'u' && chars.peek().is_some_and(|(_, c)| *c == '{') {
                        chars.next();
                        let mut hex = String::new();
                        loop {
                            let digit = chars.next()?.1;
                            if digit == '}' {
                                break;
                            }
                            if hex.len() == 6 || !digit.is_ascii_hexdigit() {
                                return None;
                            }
                            hex.push(digit);
                        }
                        char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?
                    } else {
                        let mut value = 0u16;
                        for _ in 0..if escape == 'x' { 2 } else { 4 } {
                            value = value
                                .checked_mul(16)?
                                .checked_add(chars.next()?.1.to_digit(16)? as u16)?;
                        }
                        units.push(value);
                        continue;
                    }
                }
                _ => return None,
            }
        } else {
            character
        };
        units.extend_from_slice(character.encode_utf16(&mut [0; 2]));
    }
    None
}

fn character_bytes(units: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut index = 0;
    while index < units.len() {
        bytes.push(units[index] as u8);
        // A string iterator yields one value for a surrogate pair; charCodeAt
        // reads only its first UTF-16 unit before Uint8Array truncates to u8.
        index += if (0xd800..=0xdbff).contains(&units[index])
            && units
                .get(index + 1)
                .is_some_and(|unit| (0xdc00..=0xdfff).contains(unit))
        {
            2
        } else {
            1
        };
    }
    bytes
}

fn initializer(arguments: &str, method: Option<&str>, new: bool) -> Option<Vec<u8>> {
    let arguments = arguments.trim();
    match (method, new) {
        (Some("of"), false) => numeric_list(arguments),
        (None, true) if arguments.starts_with('[') => {
            numeric_list(arguments.strip_prefix('[')?.strip_suffix(']')?)
        }
        (Some("from"), false) => {
            let (units, rest) = string_literal(arguments)?;
            static MAPPER: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(r"^\s*,\s*(?:([A-Za-z_$][\w$]*)|\(\s*([A-Za-z_$][\w$]*)\s*\))\s*=>\s*([A-Za-z_$][\w$]*)\.charCodeAt\(\s*0\s*\)\s*$")
                    .expect("literal character mapper")
            });
            let mapper = MAPPER.captures(rest)?;
            (mapper.get(1).or_else(|| mapper.get(2))?.as_str() == &mapper[3])
                .then(|| character_bytes(&units))
        }
        (Some("fromBase64"), false) => {
            let (units, rest) = string_literal(arguments)?;
            if !rest.trim().is_empty() || units.iter().any(|unit| *unit > 127) {
                return None;
            }
            let encoded = units
                .into_iter()
                .map(|unit| unit as u8)
                .filter(|byte| !matches!(byte, b'\t' | b'\n' | b'\x0c' | b'\r' | b' '))
                .collect::<Vec<_>>();
            general_purpose::STANDARD
                .decode(&encoded)
                .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(&encoded))
                .ok()
        }
        (None, true) => {
            let encoded = arguments
                .strip_prefix("new TextEncoder().encode(")?
                .strip_suffix(')')?;
            let (units, rest) = string_literal(encoded)?;
            rest.trim()
                .is_empty()
                .then(|| String::from_utf16_lossy(&units).into_bytes())
        }
        _ => None,
    }
}

pub(crate) fn snapshot(source: &str, id: &str) -> Value {
    if source.len() > MAX_SOURCE_BYTES {
        return unavailable(
            id,
            "Static initializer source exceeds the 16 MiB analysis bound.",
        );
    }
    let masked = crate::vm::mask(source);
    if REBOUND_BUILTIN.is_match(&masked) {
        return unavailable(
            id,
            "A typed-array constructor or encoder is rebound or shadowed; its initializer is unknown.",
        );
    }
    for (index, captures) in CONSTRUCTOR.captures_iter(&masked).enumerate() {
        if index == MAX_CONSTRUCTORS {
            return unavailable(
                id,
                "The bounded static initializer search reached 4096 constructors.",
            );
        }
        let matched = captures.get(0).expect("constructor match");
        if masked[..matched.start()].trim_end().ends_with(['.', '$']) {
            continue;
        }
        let Some(closing) = closing_paren(&masked, matched.end() - 1) else {
            continue;
        };
        let Some(full) = initializer(
            &source[matched.end()..closing],
            captures.get(2).map(|m| m.as_str()),
            captures.get(1).is_some(),
        ) else {
            continue;
        };
        let size = full.len().min(PREVIEW_BYTES);
        return json!({
            "artifact_id":id,
            "producer":{"kind":"static-initializer","byte_offset":matched.start()},
            "consumer":{"kind":"indexed-read","status":"inferred"},
            "sha256":hex::encode(Sha256::digest(&full)),
            "original_byte_count":full.len(),"snapshot_byte_count":size,
            "snapshot_hex":hex::encode(&full[..size]),"truncated":size<full.len(),"unavailable_reason":null,
        });
    }
    unavailable(
        id,
        "No complete supported literal typed-array initializer was recognized; assignments and computed values remain unknown.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn assert_preview(source: &str, expected: &[u8]) -> Value {
        let value = snapshot(source, "7");
        assert_eq!(
            value["snapshot_hex"],
            hex::encode(&expected[..expected.len().min(256)]),
            "{source}"
        );
        assert_eq!(value["sha256"], hex::encode(Sha256::digest(expected)));
        assert_eq!(value["original_byte_count"], expected.len());
        assert_eq!(value["snapshot_byte_count"], expected.len().min(256));
        assert_eq!(value["truncated"], expected.len() > 256);
        assert_eq!(value["producer"]["kind"], "static-initializer");
        assert!(value["unavailable_reason"].is_null());
        value
    }

    #[test]
    fn numeric_initializers_keep_full_hash_and_bounded_preview() {
        let bytes = (0..600)
            .map(|index| (index % 256) as u8)
            .collect::<Vec<_>>();
        let numbers = bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        for source in [
            format!("const program=new Uint8Array([{numbers}]);"),
            format!("const program=Uint8Array.of({numbers});"),
        ] {
            assert_preview(&source, &bytes);
        }
        assert_preview("new Uint8Array([0x50, 49,0Xff,])", &[80, 49, 255]);
        assert_preview("Uint8Array.of()", &[]);
        assert_preview("new Uint8Array([])", &[]);
    }

    #[test]
    fn canonical_string_and_base64_constructions_are_static_previews() {
        let prefix = "/*é*/ function run(){ const program = ";
        let source = format!("{prefix}Uint8Array.from('P1P2QS', c => c.charCodeAt(0));}}");
        let value = assert_preview(&source, b"P1P2QS");
        assert_eq!(value["producer"]["byte_offset"], prefix.len());
        assert_preview(
            r#"Uint8Array.from("P\x31\u0050\u{32}QS", (letter) => letter.charCodeAt(0))"#,
            b"P1P2QS",
        );
        assert_preview("Uint8Array.fromBase64('UDFQMlFT')", b"P1P2QS");
        assert_preview("Uint8Array.fromBase64('UDE=')", b"P1");
        assert_preview("Uint8Array.fromBase64('UDE')", b"P1");
        assert_preview(r#"Uint8Array.fromBase64('UD\nFQ MlFT')"#, b"P1P2QS");
        let text = "A".repeat(600);
        assert_preview(
            &format!("Uint8Array.from('{text}', c => c.charCodeAt(0))"),
            text.as_bytes(),
        );
        assert_preview(
            &format!(
                "Uint8Array.fromBase64('{}')",
                general_purpose::STANDARD.encode(&text)
            ),
            text.as_bytes(),
        );
    }

    #[test]
    fn character_units_and_utf8_have_distinct_non_ascii_semantics() {
        assert_preview(
            "Uint8Array.from('é😀', c => c.charCodeAt(0))",
            &[0xe9, 0x3d],
        );
        assert_preview(
            r#"Uint8Array.from('\ud83d\ude00\ud800', c => c.charCodeAt(0))"#,
            &[0x3d, 0],
        );
        assert_preview(
            "new Uint8Array(new TextEncoder().encode('é😀'))",
            "é😀".as_bytes(),
        );
        assert_preview(
            r#"new Uint8Array(new TextEncoder().encode('\ud800'))"#,
            "�".as_bytes(),
        );
        assert_preview(
            r#"Uint8Array.from('\0\n\t', c => c.charCodeAt(0))"#,
            &[0, 10, 9],
        );
    }

    #[test]
    fn unresolved_partial_and_shadowed_inputs_never_invent_bytes() {
        for source in [
            "Uint8Array.of(,)",
            "new Uint8Array([,])",
            "new Uint8Array([010])",
            "String.prototype.charCodeAt=custom;Uint8Array.from('AB',c=>c.charCodeAt(0))",
            "const [Uint8Array] = [custom]; Uint8Array.of(1)",
            "Uint8Array.fromBase64('UD\\vFQMlFT')",
            "$Uint8Array.of(1)",
            "new Uint8Array([1, dynamic])",
            "new Uint8Array([1, 2 + 3])",
            "Uint8Array.of(1, 2.5)",
            "new Uint8Array([1, 256])",
            "Uint8Array.of(1, -2)",
            "new Uint8Array(8)",
            "new Uint8Array('P1P2QS')",
            "Uint8Array.from('P1P2QS')",
            "Uint8Array.fromBase64('!notbase64!')",
            "Uint8Array.fromBase64('UDE=', options)",
            "Uint8Array.fromBase64(encoded)",
            "const encoded='UDE='; new Uint8Array(decode(encoded));",
            "const program=new Uint8Array(8);program[0]=80;",
            "Uint8Array.from('AB', c=>other.charCodeAt(0))",
            "Uint8Array.from('AB', c=>decode(c))",
            "Uint8Array.from(`A${value}`, c=>c.charCodeAt(0))",
            "Uint8Array.from('\\q', c=>c.charCodeAt(0))",
            "Uint8Array([1,2])",
            "new Uint8Array.of(1,2)",
            "custom.Uint8Array.of(1,2)",
            "// new Uint8Array([1,2])",
            "const text='new Uint8Array([1,2])';",
            "function f(Uint8Array){return Uint8Array.of(1);}",
            "const Uint8Array = other; Uint8Array.of(1);",
            "let Uint8Array; Uint8Array.of(1);",
            "Uint8Array.from = custom; Uint8Array.from('AB', c=>c.charCodeAt(0));",
            "function f(TextEncoder){return new Uint8Array(new TextEncoder().encode('AB'));}",
        ] {
            let value = snapshot(source, "7");
            assert!(value["snapshot_hex"].is_null(), "{source}: {value}");
            assert!(value.get("sha256").is_none(), "{source}");
            assert!(value["unavailable_reason"].is_string(), "{source}");
        }
    }

    #[test]
    fn constructor_scan_and_input_bounds_are_explicit() {
        let prefix = "new Uint8Array(unknown);".repeat(MAX_CONSTRUCTORS - 1);
        assert_preview(&format!("{prefix}Uint8Array.of(80)"), &[80]);
        let over = snapshot(
            &format!("{prefix}new Uint8Array(unknown);Uint8Array.of(80)"),
            "7",
        );
        assert!(over["snapshot_hex"].is_null());
        assert!(
            over["unavailable_reason"]
                .as_str()
                .unwrap()
                .contains("4096")
        );
        let oversized = snapshot(&" ".repeat(MAX_SOURCE_BYTES + 1), "7");
        assert!(oversized["snapshot_hex"].is_null());
        assert!(
            oversized["unavailable_reason"]
                .as_str()
                .unwrap()
                .contains("16 MiB")
        );
    }

    fn documents(initializer: &str) -> (Value, Value) {
        let root = tempfile::tempdir().expect("artifact store");
        fs::create_dir(root.path().join("blobs")).unwrap();
        let source = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/fixtures/vm-dynamic-debug/stack-vm.js"),
        )
        .unwrap()
        .replace("new Uint8Array([80, 49, 80, 50, 81, 83])", initializer);
        let hash = hex::encode(Sha256::digest(source.as_bytes()));
        fs::write(root.path().join(format!("blobs/{hash}.bin")), &source).unwrap();
        let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"dynamic_javascript","kind":"javascript","url":"fixture://static-initializer.js","mime_type":"text/javascript","byte_size":source.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        fs::write(root.path().join("manifest.jsonl"), format!("{artifact}\n")).unwrap();
        let events = root.path().join("events.jsonl");
        fs::write(&events, b"").unwrap();
        let analysis = crate::vm::store(root.path(), &events).unwrap();
        let workspace = serde_json::from_slice(
            &fs::read(root.path().join("analysis/vm-opcode-workspace-v1.json")).unwrap(),
        )
        .unwrap();
        let schema: Value =
            serde_json::from_str(include_str!("../../../protocol/vm-analysis-v1.schema.json"))
                .unwrap();
        jsonschema::validator_for(&schema)
            .unwrap()
            .validate(&analysis)
            .unwrap();
        (analysis, workspace)
    }

    #[test]
    fn persisted_workspace_distinguishes_static_preview_from_missing_runtime() {
        for initializer in [
            "Uint8Array.from('P1P2QS',c=>c.charCodeAt(0))",
            "Uint8Array.fromBase64('UDFQMlFT')",
            "new Uint8Array(decode(encoded))",
        ] {
            let (analysis, workspace) = documents(initializer);
            assert_eq!(analysis["results"][0]["tier"], "likely-vm");
            assert_eq!(workspace["summary"]["workspace_count"], 1);
            assert_eq!(workspace["workspaces"][0]["snapshots"], json!([]));
            let has_preview =
                analysis["results"][0]["bytecode_snapshot"]["snapshot_hex"].is_string();
            let omissions = workspace["workspaces"][0]["coverage"]["omissions"]
                .as_array()
                .unwrap();
            assert_eq!(
                omissions
                    .iter()
                    .any(|o| o["reason"] == "static-initializer-only"),
                has_preview
            );
            assert_eq!(
                omissions
                    .iter()
                    .any(|o| o["reason"] == "runtime-snapshot-unavailable"),
                !has_preview
            );
        }
    }
}
