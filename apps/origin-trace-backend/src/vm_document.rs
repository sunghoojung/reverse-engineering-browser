//! The VM analysis document, held by reference. A long session analyzes
//! hundreds of thousands of artifacts, so each result is spooled in canonical
//! form to an unnamed private file in the artifact store as it is produced.
//! Memory keeps the document without its results, the byte range of each
//! result, and the two indexes the views read. The document is digested,
//! published and served as a stream of those bytes, and a view reads only the
//! results it lists.

use crate::error::{Error, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufWriter, Read, Write},
    path::Path,
};

/// An exact native request root: request, session, process and sequence.
type Root = (u64, u64, u32, u64);

/// Bytes read or streamed at a time.
const CHUNK: usize = 1 << 20;

/// Results VM Lab lists: failures and candidate or likely-vm tiers. A failed
/// result has no tier.
fn listed(result: &Value) -> bool {
    result["tier"] != "none"
}

fn root(link: &Value) -> Option<Root> {
    let number = |value: &Value| value.as_str()?.parse::<u64>().ok();
    let event = &link["root_event"];
    Some((
        number(&link["request_id"])?,
        number(&event["session_id"])?,
        u32::try_from(event["process_id"].as_u64()?).ok()?,
        number(&event["sequence_number"])?,
    ))
}

#[cfg(unix)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}
#[cfg(windows)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

/// Results in document order, written as they are produced.
pub(crate) struct Spool {
    file: BufWriter<File>,
    written: u64,
    ranges: Vec<(u64, u32)>,
    findings: Vec<u32>,
    linked: HashMap<Root, Vec<u32>>,
}

impl Spool {
    /// The file has no name, so nothing is left behind if the process ends,
    /// and it shares the store's volume rather than the system's. Publication
    /// creates the store anyway.
    pub(crate) fn new(directory: &Path) -> Result<Self> {
        std::fs::create_dir_all(directory)?;
        Ok(Self {
            file: BufWriter::with_capacity(CHUNK, tempfile::tempfile_in(directory)?),
            written: 0,
            ranges: Vec::new(),
            findings: Vec::new(),
            linked: HashMap::new(),
        })
    }

    pub(crate) fn push(&mut self, result: &Value) -> Result<()> {
        let index = u32::try_from(self.ranges.len())
            .map_err(|_| Error::new(500, "VM analysis has more results than it can index"))?;
        let bytes = crate::vm::canonical(result)?;
        let length = u32::try_from(bytes.len())
            .map_err(|_| Error::new(500, "A VM analysis result is larger than it can index"))?;
        if index > 0 {
            self.file.write_all(b",")?;
            self.written += 1;
        }
        self.file.write_all(&bytes)?;
        self.ranges.push((self.written, length));
        self.written += u64::from(length);
        if listed(result) {
            self.findings.push(index);
        }
        for link in result["exact_request_links"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if let Some(root) = root(link) {
                self.linked.entry(root).or_default().push(index);
            }
        }
        Ok(())
    }

    /// Completes the document around the spooled results. `head` holds every
    /// other field, and the digest covers the result bytes as written.
    pub(crate) fn finish(self, mut head: Value) -> Result<Analysis> {
        let object = head.as_object().expect("an analysis document");
        assert!(!object.contains_key("results") && !object.contains_key("document_digest"));
        let spool = self
            .file
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        let mut analysis = Analysis {
            prefix: Vec::new(),
            suffix: Vec::new(),
            head: Value::Null,
            spool,
            spool_length: self.written,
            ranges: self.ranges,
            findings: self.findings,
            linked: self.linked,
        };
        (analysis.prefix, analysis.suffix) = split(&head)?;
        let mut hash = Sha256::new();
        let mut reader = analysis.reader();
        let mut buffer = vec![0; CHUNK];
        loop {
            match reader.read(&mut buffer)? {
                0 => break,
                read => hash.update(&buffer[..read]),
            }
        }
        head["document_digest"] = json!(hex::encode(hash.finalize()));
        (analysis.prefix, analysis.suffix) = split(&head)?;
        analysis.head = head;
        Ok(analysis)
    }
}

/// The canonical bytes before and after the results array. Keys are sorted,
/// so the fields that sort before `results` precede it.
fn split(head: &Value) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut prefix = b"{".to_vec();
    let mut suffix = b"]".to_vec();
    for (key, value) in head.as_object().expect("an analysis document") {
        let entry = [
            crate::vm::canonical(&json!(key))?,
            b":".to_vec(),
            crate::vm::canonical(value)?,
        ]
        .concat();
        if key.as_str() < "results" {
            prefix.extend(entry);
            prefix.push(b',');
        } else {
            suffix.push(b',');
            suffix.extend(entry);
        }
    }
    prefix.extend_from_slice(b"\"results\":[");
    suffix.push(b'}');
    Ok((prefix, suffix))
}

pub struct Analysis {
    /// The document without its results.
    head: Value,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    spool: File,
    spool_length: u64,
    ranges: Vec<(u64, u32)>,
    findings: Vec<u32>,
    linked: HashMap<Root, Vec<u32>>,
}

impl Analysis {
    /// Every field except `results`.
    pub fn head(&self) -> &Value {
        &self.head
    }

    pub fn digest(&self) -> &str {
        self.head["document_digest"].as_str().unwrap_or("")
    }

    /// Bytes of the canonical document.
    pub fn byte_length(&self) -> u64 {
        (self.prefix.len() + self.suffix.len()) as u64 + self.spool_length
    }

    /// The canonical document, as published.
    pub fn reader(&self) -> Reader<'_> {
        Reader {
            analysis: self,
            position: 0,
        }
    }

    /// The whole document as one value, for callers that hold it anyway.
    pub fn document(&self) -> Result<Value> {
        Ok(serde_json::from_reader(io::BufReader::with_capacity(
            CHUNK,
            self.reader(),
        ))?)
    }

    fn result(&self, index: u32) -> Result<Value> {
        let (offset, length) = self.ranges[index as usize];
        let mut bytes = vec![0; length as usize];
        let mut read = 0;
        while read < bytes.len() {
            match read_at(&self.spool, &mut bytes[read..], offset + read as u64)? {
                0 => return Err(Error::new(500, "VM analysis spool ended early")),
                count => read += count,
            }
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// The findings view of the whole document.
    pub(crate) fn findings(&self) -> Result<Value> {
        let mut document = self.head.clone();
        document["results"] = Value::Array(
            self.findings
                .iter()
                .map(|&index| self.result(index))
                .collect::<Result<_>>()?,
        );
        document["results_view"] = json!({"kind":"findings","listed_results":self.findings.len(),
            "omitted_results":self.ranges.len() - self.findings.len()});
        Ok(document)
    }

    /// The exact native request projection, read through the link index.
    pub(crate) fn select(
        &self,
        request: &str,
        session: &str,
        process: u64,
        sequence: &str,
    ) -> Result<Value> {
        let key = (|| {
            Some((
                request.parse().ok()?,
                session.parse().ok()?,
                u32::try_from(process).ok()?,
                sequence.parse().ok()?,
            ))
        })();
        let indexes = key
            .and_then(|key| self.linked.get(&key))
            .map_or(&[][..], Vec::as_slice);
        let results = indexes
            .iter()
            .map(|&index| self.result(index))
            .collect::<Result<_>>()?;
        Ok(crate::vm_request_links::select(
            &self.head, results, request, session, process, sequence,
        ))
    }
}

/// Narrows a selected document to its findings, counting the rest.
pub(crate) fn findings_of(document: &mut Value) {
    let results = document["results"]
        .as_array_mut()
        .expect("analysis results");
    let total = results.len();
    results.retain(listed);
    let listed = results.len();
    document["results_view"] =
        json!({"kind":"findings","listed_results":listed,"omitted_results":total - listed});
}

/// Streams the canonical document in chunks until it ends or the receiver
/// has gone.
pub(crate) fn stream(
    analysis: std::sync::Arc<Analysis>,
    sender: tokio::sync::mpsc::Sender<io::Result<Vec<u8>>>,
) {
    let mut reader = analysis.reader();
    loop {
        let mut chunk = Vec::with_capacity(CHUNK);
        match (&mut reader).take(CHUNK as u64).read_to_end(&mut chunk) {
            Ok(0) => return,
            Ok(_) => {
                if sender.blocking_send(Ok(chunk)).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.blocking_send(Err(error));
                return;
            }
        }
    }
}

pub struct Reader<'a> {
    analysis: &'a Analysis,
    position: u64,
}

impl Read for Reader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let analysis = self.analysis;
        let prefix = analysis.prefix.len() as u64;
        let results_end = prefix + analysis.spool_length;
        let copy = |buffer: &mut [u8], bytes: &[u8], at: u64| {
            let bytes = &bytes[(at as usize).min(bytes.len())..];
            let count = buffer.len().min(bytes.len());
            buffer[..count].copy_from_slice(&bytes[..count]);
            count
        };
        let count = if self.position < prefix {
            copy(buffer, &analysis.prefix, self.position)
        } else if self.position < results_end {
            let at = self.position - prefix;
            let wanted = buffer.len().min((analysis.spool_length - at) as usize);
            match read_at(&analysis.spool, &mut buffer[..wanted], at)? {
                0 if wanted > 0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VM analysis spool ended early",
                    ));
                }
                count => count,
            }
        } else {
            copy(buffer, &analysis.suffix, self.position - results_end)
        };
        self.position += count as u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: u32, tier: &str, link: Option<(&str, &str, u64, &str)>) -> Value {
        let mut result = json!({"artifact_id":id.to_string(),"tier":tier,"status":"complete",
            "note":"caf\u{e9}"});
        if let Some((request, session, process, sequence)) = link {
            result["exact_request_links"] = json!([{"request_id":request,
                "root_event":{"session_id":session,"process_id":process,"sequence_number":sequence}}]);
        }
        result
    }

    fn analysis(results: &[Value]) -> Analysis {
        let directory = tempfile::tempdir().unwrap();
        let mut spool = Spool::new(directory.path()).unwrap();
        for result in results {
            spool.push(result).unwrap();
        }
        let analysis = spool
            .finish(
                json!({"contract_version":1,"summary":{"analyzed_artifacts":results.len()},
                "mixed_findings":[],"profile":{"name":"\u{2603}"}}),
            )
            .unwrap();
        // The spool has no name, so the directory empties with it.
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        analysis
    }

    #[test]
    fn streamed_document_is_the_canonical_document_and_its_digest() {
        for results in [
            vec![],
            vec![result(1, "none", None)],
            (0..2_000)
                .map(|id| {
                    result(
                        id,
                        ["none", "candidate", "likely-vm"][id as usize % 3],
                        None,
                    )
                })
                .collect(),
        ] {
            let analysis = analysis(&results);
            let mut bytes = Vec::new();
            analysis.reader().read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes.len() as u64, analysis.byte_length());
            let document: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(bytes, crate::vm::canonical(&document).unwrap());
            assert_eq!(document["results"], json!(results));
            let mut unsigned = document.clone();
            unsigned.as_object_mut().unwrap().remove("document_digest");
            assert_eq!(analysis.digest(), crate::vm::digest(&unsigned).unwrap());
            assert_eq!(analysis.document().unwrap(), document);
        }
    }

    #[test]
    fn views_read_only_the_results_they_list() {
        let link = ("7", "9", 12, "10");
        let results = [
            result(1, "none", Some(link)),
            json!({"artifact_id":"2","status":"failed","error":"x"}),
            result(3, "candidate", Some(link)),
            result(4, "none", Some(("7", "9", 12, "11"))),
            result(5, "likely-vm", None),
        ];
        let analysis = analysis(&results);
        let findings = analysis.findings().unwrap();
        assert_eq!(
            findings["results"],
            json!([results[1], results[2], results[4]])
        );
        assert_eq!(
            findings["results_view"],
            json!({"kind":"findings","listed_results":3,"omitted_results":2})
        );
        assert_eq!(findings["document_digest"], analysis.digest());
        let mut selected = analysis.select("7", "9", 12, "10").unwrap();
        assert_eq!(selected["results"], json!([results[0], results[2]]));
        assert!(selected.get("results_view").is_none());
        findings_of(&mut selected);
        assert_eq!(selected["results"], json!([results[2]]));
        assert_eq!(
            selected["results_view"],
            json!({"kind":"findings","listed_results":1,"omitted_results":1})
        );
        for (request, session, process, sequence) in [
            ("8", "9", 12, "10"),
            ("7", "9", 13, "10"),
            ("7", "9", 12, "12"),
        ] {
            let none = analysis
                .select(request, session, process, sequence)
                .unwrap();
            assert_eq!(none["results"], json!([]));
        }
    }
}
