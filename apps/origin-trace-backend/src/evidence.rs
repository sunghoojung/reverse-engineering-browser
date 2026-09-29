use serde_json::Value;
use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::path::Path;

const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;

#[derive(Debug)]
pub enum ReadError {
    Io(std::io::Error),
    TooLarge,
    Malformed { line: usize },
}

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Unable to read evidence store: {error}"),
            Self::TooLarge => formatter.write_str("Evidence store exceeds the 64 MiB read limit"),
            Self::Malformed { line } => write!(formatter, "Malformed JSON evidence at line {line}"),
        }
    }
}

pub fn read_json_lines(path: &Path) -> Result<Vec<Value>, ReadError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(ReadError::Io(error)),
    };
    if metadata.len() > MAX_STORE_BYTES {
        return Err(ReadError::TooLarge);
    }

    let text = fs::read_to_string(path).map_err(ReadError::Io)?;
    let mut records = VecDeque::with_capacity(MAX_RECORDS);
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let value =
            serde_json::from_str(line).map_err(|_| ReadError::Malformed { line: index + 1 })?;
        if records.len() == MAX_RECORDS {
            records.pop_front();
        }
        records.push_back(value);
    }
    Ok(records.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_record_reports_its_line() {
        let path = std::env::temp_dir().join(format!("reb-evidence-{}.jsonl", std::process::id()));
        fs::write(&path, "{\"ok\":true}\nnot-json\n").unwrap();
        let error = read_json_lines(&path).unwrap_err();
        fs::remove_file(path).unwrap();
        assert_eq!(error.to_string(), "Malformed JSON evidence at line 2");
    }
}
