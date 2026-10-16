//! Persisted launch provenance. A missing or unrelated record never proves stealth.
use crate::{
    durable,
    error::{Error, Result},
    evidence,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(crate) const FILE_NAME: &str = "capture-provenance-v1.json";
const MAX_BYTES: usize = 65536;
const MAX_SESSIONS: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    NativeStealth,
    CdpAttached,
    Unknown,
}
impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::NativeStealth => "native-stealth",
            Self::CdpAttached => "cdp-attached",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    session_id: String,
    capture_mode: Mode,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    contract_version: u8,
    sessions: Vec<Session>,
}

pub(crate) struct Provenance {
    sessions: BTreeMap<String, Mode>,
    pub digest: Option<String>,
}
impl Provenance {
    pub(crate) fn read(root: &Path) -> Result<Self> {
        let Some(bytes) = durable::read_private(&root.join(FILE_NAME), MAX_BYTES)? else {
            return Ok(Self {
                sessions: BTreeMap::new(),
                digest: None,
            });
        };
        // Typed structs reject duplicate JSON keys as well as unknown fields.
        let document: Document = serde_json::from_slice(&bytes)
            .map_err(|_| Error::bad("The VM capture provenance contains an invalid record"))?;
        if document.contract_version != 1 || document.sessions.len() > MAX_SESSIONS {
            return Err(Error::bad(
                "The VM capture provenance version or session limit is invalid",
            ));
        }
        let mut sessions = BTreeMap::new();
        for session in document.sessions {
            if !evidence::canonical(&json!(session.session_id), 64, true)
                || sessions
                    .insert(session.session_id, session.capture_mode)
                    .is_some()
            {
                return Err(Error::bad(
                    "The VM capture provenance contains an invalid or duplicate session",
                ));
            }
        }
        Ok(Self {
            sessions,
            digest: Some(hex::encode(Sha256::digest(bytes))),
        })
    }

    pub(crate) fn mode(&self, session_id: &Value) -> &'static str {
        session_id
            .as_str()
            .and_then(|id| self.sessions.get(id))
            .copied()
            .unwrap_or(Mode::Unknown)
            .label()
    }

    pub(crate) fn aggregate<'a>(&self, records: impl Iterator<Item = &'a Value>) -> &'static str {
        let modes = records
            .map(|record| self.mode(&record["session_id"]))
            .collect::<BTreeSet<_>>();
        if modes.len() == 1 {
            modes.into_iter().next().unwrap()
        } else {
            "unknown"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn missing_unknown_mixed_and_exact_sessions() {
        let root = tempfile::tempdir().unwrap();
        let absent = Provenance::read(root.path()).unwrap();
        assert_eq!(absent.mode(&json!("1")), "unknown");
        assert!(absent.digest.is_none());
        fs::write(root.path().join(FILE_NAME), br#"{"contract_version":1,"sessions":[{"session_id":"1","capture_mode":"native-stealth"},{"session_id":"2","capture_mode":"cdp-attached"},{"session_id":"3","capture_mode":"unknown"}]}"#).unwrap();
        let modes = Provenance::read(root.path()).unwrap();
        assert_eq!(modes.mode(&json!("1")), "native-stealth");
        assert_eq!(modes.mode(&json!("2")), "cdp-attached");
        assert_eq!(modes.mode(&json!("3")), "unknown");
        assert_eq!(modes.mode(&json!("4")), "unknown");
        assert_eq!(modes.mode(&json!(1)), "unknown");
        let first = json!({"session_id":"1"});
        let second = json!({"session_id":"2"});
        assert_eq!(modes.aggregate([&first].into_iter()), "native-stealth");
        assert_eq!(modes.aggregate([&first, &second].into_iter()), "unknown");
        assert_eq!(modes.aggregate(std::iter::empty()), "unknown");
    }

    #[test]
    fn invalid_or_ambiguous_provenance_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        for bytes in [
            r#"{"contract_version":1,"sessions":[{"session_id":"1","capture_mode":"undetectable"}]}"#,
            r#"{"contract_version":1,"sessions":[{"session_id":"1","capture_mode":"unknown","capture_mode":"native-stealth"}]}"#,
            r#"{"contract_version":1,"sessions":[{"session_id":"1","capture_mode":"unknown"},{"session_id":"1","capture_mode":"native-stealth"}]}"#,
            r#"{"contract_version":1,"sessions":[{"session_id":"01","capture_mode":"unknown"}]}"#,
            r#"{"contract_version":1,"sessions":[],"extra":true}"#,
            r#"{"contract_version":2,"sessions":[]}"#,
        ] {
            fs::write(root.path().join(FILE_NAME), bytes).unwrap();
            assert!(Provenance::read(root.path()).is_err());
        }
        fs::write(root.path().join(FILE_NAME), vec![b' '; MAX_BYTES + 1]).unwrap();
        assert!(Provenance::read(root.path()).is_err());
    }
}
