use crate::{
    durable,
    error::{Code, Error, Reason, Result},
    validation::{self, MAX_SAFE_INTEGER},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Mutex,
};
use unicode_casefold::UnicodeCaseFold;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Collection,
    Analyst,
}
impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Collection => "API Collection",
            Self::Analyst => "Analyst",
        }
    }
    fn root(self) -> &'static str {
        match self {
            Self::Collection => "API Collection",
            Self::Analyst => "Analyst Workspace",
        }
    }
    fn document(self) -> &'static str {
        match self {
            Self::Collection => "api-collection",
            Self::Analyst => "local-analyst-workspace",
        }
    }
    fn items(self) -> &'static str {
        match self {
            Self::Collection => "requests",
            Self::Analyst => "files",
        }
    }
    fn maximum(self) -> usize {
        match self {
            Self::Collection => 2 * 1024 * 1024,
            Self::Analyst => 1024 * 1024,
        }
    }
    pub fn limits(self) -> Value {
        match self {
            Self::Collection => {
                json!({"folders":32,"requests":128,"folder_depth":4,"variables_per_scope":32,"variable_bytes_per_scope":32768,"request_body_bytes":65536,"document_bytes":2097152})
            }
            Self::Analyst => {
                json!({"folders":32,"files":64,"folder_depth":4,"file_bytes":32768,"total_file_bytes":524288,"document_bytes":1048576,"variables":32,"variable_value_bytes":4096,"variable_bytes":16384,"evidence_bytes":786432,"selected_artifact_bytes":65536,"execution_timeout_ms":2000,"logs":64,"log_bytes":1024,"result_bytes":32768})
            }
        }
    }
    pub fn empty(self) -> Value {
        let mut folder = json!({"id":1,"name":self.root(),"parent_id":null});
        if self == Self::Collection {
            folder["variables"] = json!([]);
        }
        json!({"contract_version":1,"document_kind":self.document(),"generation":0,"updated_at_ms":0,"folders":[folder],self.items():[],"limits":self.limits()})
    }
}
pub struct Store {
    pub path: PathBuf,
    pub kind: Kind,
    lock: Mutex<()>,
}
impl Store {
    pub fn new(path: PathBuf, kind: Kind) -> Self {
        Self {
            path,
            kind,
            lock: Mutex::new(()),
        }
    }
    fn read(&self) -> Result<Value> {
        match durable::read_private(&self.path, self.kind.maximum())? {
            Some(bytes) => normalize(
                self.kind,
                &serde_json::from_slice(&bytes)
                    .map_err(|_| Error::bad(format!("{} store is malformed", self.kind.label())))?,
            ),
            None => Ok(self.kind.empty()),
        }
    }
    pub fn load(&self) -> Result<Value> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::new(500, "Workspace store is unavailable"))?;
        self.read()
    }
    pub fn replace(&self, request: &Value) -> Result<Value> {
        let kind = self.kind;
        let items = kind.items();
        validation::fields(
            request,
            &["action", "expected_generation", "folders", items],
            kind.label(),
        )?;
        let expected_action = match kind {
            Kind::Collection => "replace_api_collection",
            Kind::Analyst => "replace_local_analyst_workspace",
        };
        if request["action"] != expected_action {
            return Err(Error::bad(format!("{} action is invalid", kind.label())));
        }
        let generation = validation::integer(
            &request["expected_generation"],
            "Expected workspace generation",
            0,
            MAX_SAFE_INTEGER,
        )?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::new(500, "Workspace store is unavailable"))?;
        let current = self.read()?;
        if current["generation"] != generation {
            return Err(Error::conflict(format!(
                "{} changed in another window; refresh before saving",
                kind.root()
            ))
            .with_reason(Reason::stale(
                generation,
                current["generation"].as_u64().unwrap(),
            )));
        }
        let folders = array(&request["folders"], 32, "Workspace folders")?
            .iter()
            .map(|v| folder(kind, v))
            .collect::<Result<Vec<_>>>()?;
        let mut values = Vec::new();
        let now = validation::now_ms();
        for raw in array(
            &request[items],
            if kind == Kind::Collection { 128 } else { 64 },
            "Workspace items",
        )? {
            let mut value = item(kind, raw, false)?;
            let previous = current[items]
                .as_array()
                .and_then(|a| a.iter().find(|v| v["id"] == value["id"]));
            let unchanged = previous.is_some_and(|old| {
                value
                    .as_object()
                    .is_some_and(|object| object.iter().all(|(key, v)| old[key] == *v))
            });
            value["created_at_ms"] =
                previous.map_or_else(|| json!(now), |old| old["created_at_ms"].clone());
            value["updated_at_ms"] = if unchanged {
                previous.unwrap()["updated_at_ms"].clone()
            } else {
                json!(now)
            };
            values.push(value);
        }
        let candidate = normalize(
            kind,
            &json!({"contract_version":1,"document_kind":kind.document(),"generation":generation.checked_add(1).ok_or_else(||Error::bad("Workspace generation exhausted").with_code(Code::ResourceLimit))?,"updated_at_ms":now,"folders":folders,items:values,"limits":kind.limits()}),
        )?;
        if candidate["folders"] == current["folders"] && candidate[items] == current[items] {
            return Ok(current);
        }
        let mut bytes = serde_json::to_vec(&candidate)?;
        bytes.push(b'\n');
        if bytes.len() > kind.maximum() {
            return Err(
                Error::bad("Workspace store exceeds its byte limit").with_code(Code::ResourceLimit)
            );
        }
        durable::write_private(&self.path, &bytes)?;
        Ok(candidate)
    }
}
fn array<'a>(value: &'a Value, limit: usize, label: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .filter(|a| a.len() <= limit)
        .ok_or_else(|| Error::bad(format!("{label} are invalid or oversized")))
}
fn id(value: &Value, label: &str) -> Result<u64> {
    validation::integer(value, label, 1, MAX_SAFE_INTEGER)
}
fn name(value: &Value, label: &str) -> Result<String> {
    let s = value
        .as_str()
        .ok_or_else(|| Error::bad(format!("{label} must be text")))?
        .trim();
    if s.is_empty() || s.len() > 128 || s.contains('/') || s.chars().any(char::is_control) {
        return Err(Error::bad(format!("{label} is invalid")));
    }
    Ok(s.into())
}
pub fn variables(
    value: &Value,
    name_limit: usize,
    total_limit: usize,
    object: bool,
) -> Result<Value> {
    let pairs: Vec<_> = if object {
        value
            .as_object()
            .filter(|o| o.len() <= 32)
            .ok_or_else(|| Error::bad("Variables are invalid or oversized"))?
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    } else {
        let mut pairs = Vec::new();
        for v in array(value, 32, "Variables")? {
            validation::fields(v, &["name", "value"], "Variable")?;
            pairs.push((
                validation::text(&v["name"], "Variable name", name_limit, false, false)?.into(),
                v["value"].clone(),
            ));
        }
        pairs
    };
    let mut seen = BTreeMap::new();
    let mut total = 0;
    for (key, value) in pairs {
        if key.len() > name_limit || !validation::variable_name(&key) || seen.contains_key(&key) {
            return Err(Error::bad("Variable name is invalid or duplicated"));
        }
        let value = validation::text(&value, "Variable value", 4096, true, object)?;
        total += key.len() + value.len();
        if total > total_limit {
            return Err(Error::bad("Variable scope exceeds its byte limit"));
        }
        seen.insert(key, value.to_owned());
    }
    if object {
        Ok(json!(seen))
    } else {
        Ok(Value::Array(
            seen.into_iter()
                .map(|(name, value)| json!({"name":name,"value":value}))
                .collect(),
        ))
    }
}
pub fn headers(value: &Value) -> Result<Value> {
    const FORBIDDEN: [&str; 8] = [
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "host",
        "proxy-authorization",
        "set-cookie",
        "transfer-encoding",
    ];
    let mut seen = BTreeSet::new();
    let mut total = 0;
    let mut output = Vec::new();
    for v in array(value, 64, "Request headers")? {
        validation::fields(v, &["name", "value"], "Request header")?;
        let name = validation::text(&v["name"], "Request header name", 128, false, false)?;
        let value = validation::text(&v["value"], "Request header value", 2048, true, false)?;
        let lower = name.to_ascii_lowercase();
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || FORBIDDEN.contains(&lower.as_str())
            || !seen.insert(lower)
        {
            return Err(Error::bad(
                "Request header is forbidden, invalid, or duplicated",
            ));
        }
        total += name.len() + value.len();
        if total > 16384 {
            return Err(Error::bad("Request headers exceed 16 KiB"));
        }
        output.push(json!({"name":name,"value":value}));
    }
    Ok(json!(output))
}
fn folder(kind: Kind, value: &Value) -> Result<Value> {
    let mut expected = vec!["id", "name", "parent_id"];
    if kind == Kind::Collection {
        expected.push("variables");
    }
    validation::fields(value, &expected, "Workspace folder")?;
    let parent = if value["parent_id"].is_null() {
        Value::Null
    } else {
        json!(id(&value["parent_id"], "Parent folder ID")?)
    };
    let mut folder = json!({"id":id(&value["id"],"Folder ID")?,"name":name(&value["name"],"Folder name")?,"parent_id":parent});
    if kind == Kind::Collection {
        folder["variables"] = variables(&value["variables"], 64, 32768, false)?;
    }
    Ok(folder)
}
fn item(kind: Kind, value: &Value, metadata: bool) -> Result<Value> {
    let mut expected = match kind {
        Kind::Collection => vec![
            "id",
            "folder_id",
            "name",
            "url",
            "method",
            "headers",
            "body",
            "timeout_ms",
            "variables",
        ],
        Kind::Analyst => vec!["id", "folder_id", "name", "kind", "language", "content"],
    };
    if metadata {
        expected.extend(["created_at_ms", "updated_at_ms"]);
        if kind == Kind::Analyst {
            expected.push("content_bytes");
        }
    }
    validation::fields(value, &expected, "Workspace item")?;
    let mut result = json!({"id":id(&value["id"],"Item ID")?,"folder_id":id(&value["folder_id"],"Item folder ID")?,"name":name(&value["name"],"Item name")?});
    match kind {
        Kind::Collection => {
            for (field, limit) in [("url", 8192), ("method", 256)] {
                let text = validation::text(&value[field], field, limit, false, false)?.trim();
                if text.is_empty() {
                    return Err(Error::bad(format!("{field} is required")));
                }
                result[field] = json!(text);
            }
            result["body"] = json!(validation::text(
                &value["body"],
                "Request body",
                65536,
                true,
                true
            )?);
            result["timeout_ms"] = json!(validation::integer(
                &value["timeout_ms"],
                "Request timeout",
                100,
                30000
            )?);
            result["headers"] = headers(&value["headers"])?;
            result["variables"] = variables(&value["variables"], 64, 32768, false)?;
        }
        Kind::Analyst => {
            let kind = validation::text(&value["kind"], "File kind", 32, false, false)?;
            let language = validation::text(&value["language"], "File language", 32, false, false)?;
            if !["analyst-script", "scratchpad"].contains(&kind)
                || !["javascript", "json", "markdown", "text"].contains(&language)
                || (kind == "analyst-script" && language != "javascript")
            {
                return Err(Error::bad("Analyst file kind or language is invalid"));
            }
            let content =
                validation::text(&value["content"], "Analyst file content", 32768, true, true)?;
            result["kind"] = json!(kind);
            result["language"] = json!(language);
            if content
                .bytes()
                .any(|b| (b < 32 && !b"\t\n\r".contains(&b)) || b == 127)
            {
                return Err(Error::bad(
                    "Analyst file content contains control characters",
                ));
            }
            result["content"] = json!(content);
            result["content_bytes"] = json!(content.len());
            if metadata && value["content_bytes"] != content.len() {
                return Err(Error::bad("Analyst file byte count is invalid"));
            }
        }
    }
    if metadata {
        let created = validation::integer(
            &value["created_at_ms"],
            "Item creation time",
            0,
            MAX_SAFE_INTEGER,
        )?;
        let updated = validation::integer(
            &value["updated_at_ms"],
            "Item update time",
            created,
            MAX_SAFE_INTEGER,
        )?;
        result["created_at_ms"] = json!(created);
        result["updated_at_ms"] = json!(updated);
    }
    Ok(result)
}
pub fn normalize(kind: Kind, value: &Value) -> Result<Value> {
    let items = kind.items();
    validation::fields(
        value,
        &[
            "contract_version",
            "document_kind",
            "generation",
            "updated_at_ms",
            "folders",
            items,
            "limits",
        ],
        "Workspace document",
    )?;
    if value["contract_version"] != 1
        || value["document_kind"] != kind.document()
        || value["limits"] != kind.limits()
    {
        return Err(Error::bad("Workspace document contract is unsupported"));
    }
    let generation = validation::integer(
        &value["generation"],
        "Workspace generation",
        0,
        MAX_SAFE_INTEGER,
    )?;
    let updated = validation::integer(
        &value["updated_at_ms"],
        "Workspace update time",
        0,
        MAX_SAFE_INTEGER,
    )?;
    let mut folders = array(&value["folders"], 32, "Workspace folders")?
        .iter()
        .map(|v| folder(kind, v))
        .collect::<Result<Vec<_>>>()?;
    let mut values = array(
        &value[items],
        if kind == Kind::Collection { 128 } else { 64 },
        "Workspace items",
    )?
    .iter()
    .map(|v| item(kind, v, true))
    .collect::<Result<Vec<_>>>()?;
    let by_id: BTreeMap<u64, &Value> = folders
        .iter()
        .map(|f| (f["id"].as_u64().unwrap(), f))
        .collect();
    if by_id.len() != folders.len() {
        return Err(Error::bad("Workspace folder IDs are duplicated"));
    }
    let root = by_id
        .get(&1)
        .ok_or_else(|| Error::bad("Workspace root folder is invalid"))?;
    if !root["parent_id"].is_null() || root["name"] != kind.root() {
        return Err(Error::bad("Workspace root folder is invalid"));
    }
    let mut names = BTreeSet::new();
    for folder in &folders {
        let identifier = folder["id"].as_u64().unwrap();
        let mut seen = BTreeSet::from([identifier]);
        let mut current = folder;
        let mut depth = 0;
        if identifier != 1 && folder["parent_id"].is_null() {
            return Err(Error::bad("Workspace has multiple root folders"));
        }
        while let Some(parent) = current["parent_id"].as_u64() {
            if !seen.insert(parent) || !by_id.contains_key(&parent) {
                return Err(Error::bad("Workspace folder hierarchy is invalid"));
            }
            current = by_id[&parent];
            depth += 1;
            if depth > 4 {
                return Err(Error::bad("Workspace folder depth exceeds four levels"));
            }
        }
        let key = (
            folder["parent_id"].as_u64(),
            folder["name"]
                .as_str()
                .unwrap()
                .case_fold()
                .collect::<String>(),
        );
        if !names.insert(key) {
            return Err(Error::bad("Workspace sibling name is duplicated"));
        }
    }
    if kind == Kind::Collection {
        names.clear();
    }
    let mut identifiers = BTreeSet::new();
    let mut total_content = 0;
    for item in &values {
        let identifier = item["id"].as_u64().unwrap();
        let parent = item["folder_id"].as_u64().unwrap();
        if !identifiers.insert(identifier) || !by_id.contains_key(&parent) {
            return Err(Error::bad("Workspace item ID or folder is invalid"));
        }
        if !names.insert((
            Some(parent),
            item["name"]
                .as_str()
                .unwrap()
                .case_fold()
                .collect::<String>(),
        )) {
            return Err(Error::bad("Workspace sibling name is duplicated"));
        }
        total_content += item["content_bytes"].as_u64().unwrap_or(0);
    }
    if total_content > 524288 {
        return Err(Error::bad("Analyst file content exceeds 512 KiB"));
    }
    folders.sort_by_key(|v| v["id"].as_u64());
    values.sort_by_key(|v| v["id"].as_u64());
    let output = json!({"contract_version":1,"document_kind":kind.document(),"generation":generation,"updated_at_ms":updated,"folders":folders,items:values,"limits":kind.limits()});
    if serde_json::to_vec(&output)?.len() > kind.maximum() {
        return Err(Error::bad("Workspace document exceeds its byte limit"));
    }
    if generation == 0
        && (updated != 0
            || output["folders"] != kind.empty()["folders"]
            || output[items].as_array().is_some_and(|a| !a.is_empty()))
    {
        return Err(Error::bad("Workspace generation zero must be empty"));
    }
    Ok(output)
}
