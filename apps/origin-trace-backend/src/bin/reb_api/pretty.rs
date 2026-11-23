use std::io::{self, BufRead, Write};

/// Reindents validated JSON as serde_json's two-space pretty form, so a
/// response larger than memory prints in constant space. Strings and numbers
/// are copied as they arrive: serde_json wrote them the way it reprints them.
pub fn write(mut input: impl BufRead, output: &mut impl Write) -> io::Result<()> {
    let mut depth = 0usize;
    // Inside a string, and whether the previous byte was its backslash.
    let (mut string, mut escaped) = (false, false);
    // A container was opened and its first member, if any, is still to come.
    let mut opened = false;
    let mut out = Vec::new();
    loop {
        let chunk = input.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        for &byte in chunk {
            if string {
                out.push(byte);
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    string = false;
                }
                continue;
            }
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' => {}
                b']' | b'}' => {
                    depth = depth.saturating_sub(1);
                    if !opened {
                        line(&mut out, depth);
                    }
                    opened = false;
                    out.push(byte);
                }
                b',' => {
                    out.push(b',');
                    line(&mut out, depth);
                }
                b':' => out.extend_from_slice(b": "),
                _ => {
                    if opened {
                        line(&mut out, depth);
                        opened = false;
                    }
                    out.push(byte);
                    match byte {
                        b'[' | b'{' => {
                            depth += 1;
                            opened = true;
                        }
                        b'"' => string = true,
                        _ => {}
                    }
                }
            }
        }
        let consumed = chunk.len();
        input.consume(consumed);
        output.write_all(&out)?;
        out.clear();
    }
    Ok(())
}

fn line(out: &mut Vec<u8>, depth: usize) {
    out.push(b'\n');
    out.resize(out.len() + 2 * depth, b' ');
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    fn pretty(compact: &[u8], chunk: usize) -> String {
        let reader = std::io::BufReader::with_capacity(chunk, compact);
        let mut output = Vec::new();
        super::write(reader, &mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn reindents_exactly_as_serde_json_across_chunk_boundaries() {
        let document = json!({
            "empty_array": [], "empty_object": {}, "nested": [[], {}, [[]], {"a": {}}],
            "strings": ["", "a\"b", "\\", "\\\"", "[{,:}] ", "tab\tline\n\u{1}", "é漢😀"],
            "numbers": [0, -1, 1.5, -2.25e-10, 1e300, 18446744073709551615u64],
            "literals": [true, false, null],
            "rows": [{"id": "1", "list": [1, {"k": [null]}]}, {"id": "2"}]
        });
        let expected = serde_json::to_string_pretty(&document).unwrap();
        let compact = serde_json::to_vec(&document).unwrap();
        let spaced = serde_json::to_vec_pretty(&document).unwrap();
        for chunk in [1, 2, 3, 7, 64, 1 << 16] {
            assert_eq!(pretty(&compact, chunk), expected, "chunk {chunk}");
            assert_eq!(pretty(&spaced, chunk), expected, "chunk {chunk}");
        }
        for scalar in [json!(1), json!("x"), json!(null), json!([]), json!({})] {
            let bytes = serde_json::to_vec(&scalar).unwrap();
            assert_eq!(
                pretty(&bytes, 1),
                serde_json::to_string_pretty(&scalar).unwrap()
            );
        }
        let reparsed: Value = serde_json::from_str(&pretty(&compact, 5)).unwrap();
        assert_eq!(reparsed, document);
    }
}
