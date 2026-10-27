//! Cold-path, read-only interpretations of the existing bounded Traffic window.
//! Shape path/type accumulation is adapted from morluto/rea's MIT-licensed
//! src/domain/jsonShape.ts at bb540826d65316c164d2de8ba4ef10f81a8ad073.
//! Copyright (c) 2026 morluto. See third_party/rea/LICENSE and README.md.
use super::Debugger;
use crate::error::{Error, Result};
use serde::{
    Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use url::Url;

const MAX_RECORDS: usize = 64;
const MAX_URL: usize = 8192;
const MAX_BODY: usize = 32768;
const MAX_NAMES: usize = 64;
const MAX_NAME: usize = 256;
const MAX_NODES: usize = 2048;
const MAX_DEPTH: usize = 16;
const MAX_FIELDS: usize = 64;
const MAX_PATH_BYTES: usize = 16384;

impl Debugger {
    pub fn api_catalog(&self) -> Result<Value> {
        // Copy only this small tail and approved analysis inputs. Inference and
        // URL parsing run after releasing the live debugger's state lock.
        let (context, records) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let network = &state["network"];
            let rows = network["requests"].as_array();
            let total = rows.map_or(0, Vec::len);
            let records: Vec<Value> = rows
                .into_iter()
                .flatten()
                .rev()
                .take(MAX_RECORDS)
                .map(select_record)
                .collect();
            (
                json!({
                    "instance_id": network["instance_id"],
                    "capture_epoch": network["capture_epoch"],
                    "debugger_generation": state["generation"],
                    "capture_enabled": network["capture_enabled"],
                    "debugger_state": state["state"],
                    "retained_records": total,
                    "window_records": records.len(),
                    "older_records_not_examined": total.saturating_sub(records.len()),
                    "capture_dropped_records": network["dropped"],
                }),
                records,
            )
        };
        catalog(context, records)
    }
}

fn selected_text(value: &Value, max: usize) -> Value {
    value
        .as_str()
        .filter(|s| s.len() <= max)
        .map_or(Value::Null, |s| json!(s))
}
fn select_record(row: &Value) -> Value {
    json!({
        "id": selected_text(&row["id"], 8192),
        "target_id": selected_text(&row["target_id"], 4096),
        "started_monotonic_ms": row["started_monotonic_ms"],
        "method": selected_text(&row["method"], 32),
        "url": selected_text(&row["url"], MAX_URL),
        "url_truncated": row["url_truncated"],
        "method_truncated": row["method_truncated"],
        "state": selected_text(&row["state"], 32),
        "status": row["status"],
        "request": select_side(&row["request"]),
        "response": select_side(&row["response"]),
    })
}
fn select_side(side: &Value) -> Value {
    let body = &side["body"];
    let mut names = BTreeSet::new();
    let mut omitted = 0;
    for header in side["headers"].as_array().into_iter().flatten() {
        add_name(
            &mut names,
            header[0].as_str().map(str::to_ascii_lowercase),
            &mut omitted,
        );
    }
    json!({
        "header_names": names,
        "header_names_omitted": omitted,
        "headers_truncated": side["headers_truncated"],
        "body": {
            "state": selected_text(&body["state"], 32),
            "mime": media_type(&body["mime"]),
            "truncated": body["truncated"],
            "text": selected_text(&body["text"], MAX_BODY),
            "has_base64": body["base64"].as_str().is_some_and(|s| !s.is_empty()),
        }
    })
}
fn add_name(names: &mut BTreeSet<String>, name: Option<String>, omitted: &mut usize) {
    match name {
        Some(name)
            if name.len() <= MAX_NAME && (names.len() < MAX_NAMES || names.contains(&name)) =>
        {
            names.insert(name);
        }
        _ => *omitted += 1,
    }
}

fn endpoint(row: &Value) -> Option<(String, String, String, Value)> {
    if row["url_truncated"] != false || row["method_truncated"] != false {
        return None;
    }
    let raw = row["url"].as_str()?;
    if raw.bytes().any(|b| b <= b' ' || b == 127 || b == b'\\') {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    let method = row["method"].as_str()?;
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return None;
    }
    // Preserve the observed path spelling, including percent encoding and dot
    // segments; URL::path would normalize it. Do not infer REST route variables.
    let authority = raw.split_once("://")?.1;
    if authority.is_empty() || authority.starts_with(['/', '?', '#']) {
        return None;
    }
    let rest = authority
        .find(['/', '?', '#'])
        .map_or("", |i| &authority[i..]);
    let path = rest.split(['?', '#']).next().unwrap_or("");
    let path = if path.is_empty() { "/" } else { path };
    let mut names = BTreeSet::new();
    let mut omitted = 0;
    for pair in url
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        add_name(&mut names, query_name(name), &mut omitted);
    }
    Some((
        method.into(),
        url.origin().ascii_serialization(),
        path.into(),
        json!({"names": names, "omitted": omitted}),
    ))
}

// url::query_pairs replaces malformed UTF-8. Never turn that replacement into
// a claimed observed parameter name; count invalid percent/UTF-8 names instead.
fn query_name(raw: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut input = raw.bytes();
    while let Some(byte) = input.next() {
        let byte = match byte {
            b'+' => b' ',
            b'%' => {
                let high = (input.next()? as char).to_digit(16)?;
                let low = (input.next()? as char).to_digit(16)?;
                (high * 16 + low) as u8
            }
            byte => byte,
        };
        if bytes.len() == MAX_NAME {
            return None;
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes).ok()
}

fn catalog(context: Value, records: Vec<Value>) -> Result<Value> {
    let mut groups: BTreeMap<(String, String, String), Vec<Value>> = BTreeMap::new();
    let mut skipped = 0;
    for row in records {
        let Some((method, origin, path, query)) = endpoint(&row) else {
            skipped += 1;
            continue;
        };
        if row["id"].as_str().is_none_or(str::is_empty)
            || row["target_id"].as_str().is_none_or(str::is_empty)
            || row["started_monotonic_ms"].as_f64().is_none()
        {
            skipped += 1;
            continue;
        }
        let mut observation = json!({
            "source": {"request_id": row["id"], "target_id": row["target_id"],
                "started_monotonic_ms": row["started_monotonic_ms"]},
            "state": row["state"], "status": row["status"], "query_parameters": query,
        });
        for side in ["request", "response"] {
            let mut value = row[side].clone();
            value["body"] = body_shape(&row[side]["body"]);
            observation[side] = value;
        }
        groups
            .entry((method, origin, path))
            .or_default()
            .push(observation);
    }
    let endpoints: Vec<Value> = groups.into_iter().map(|((method, origin, path), observations)|
        json!({"method": method, "origin": origin, "path": path, "observations": observations})).collect();
    let mut coverage = context;
    coverage["skipped_records"] = json!(skipped);
    let output = json!({
        "format": "reb-api-observation-catalog-v1", "coverage": coverage,
        "limits": {"records": MAX_RECORDS, "url_bytes": MAX_URL, "body_bytes": MAX_BODY,
            "names_per_surface": MAX_NAMES, "name_bytes": MAX_NAME, "shape_nodes": MAX_NODES,
            "shape_depth": MAX_DEPTH, "shape_fields": MAX_FIELDS, "shape_path_bytes": MAX_PATH_BYTES},
        "endpoints": endpoints,
        "limitations": [
            "Derived observations of the newest retained Traffic records only; not an API specification or proof of required/optional fields, authentication, stability, or exhaustive capture.",
            "Sources are exact ephemeral CDP instance/epoch/request/target/start identities, not native stored-evidence identities. Reconnects and eviction can make them unavailable.",
            "Origin is URL-normalized; path spelling is preserved (an absent path is /). Query names are form-decoded and header names lowercased. Paths and names may contain sensitive data; review before sharing.",
            "Body values, URL credentials/query values/fragments, and header values are omitted from this additional structural view. Raw local Traffic is unchanged. Omission is not a guarantee of secret-free output.",
            "JSON shapes describe each complete retained text body independently. Repeated array positions share typed paths. Base64, truncated, non-JSON, malformed, duplicate-key, and over-budget bodies remain explicit unknowns. No replay, source fetching, SDK authentication, or required-field inference occurs."
        ]
    });
    // Defense in depth over independent count/string/path budgets, not a claim
    // about process heap. Never publish a partially serialized catalog.
    if serde_json::to_vec(&output)
        .map_err(|_| Error::new(500, "Catalog serialization failed"))?
        .len()
        > 4 * 1024 * 1024
    {
        return Err(Error::new(500, "Catalog response budget exceeded"));
    }
    Ok(output)
}

// Only retain the validated media type, never Content-Type parameters such as
// boundary values, profile URLs, or private application tokens.
fn media_type(value: &Value) -> String {
    let candidate = value
        .as_str()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if candidate.len() > 512 {
        return String::new();
    }
    let Some((kind, subtype)) = candidate.split_once('/') else {
        return String::new();
    };
    let token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    };
    if !token(kind) || !token(subtype) {
        return String::new();
    }
    candidate.to_ascii_lowercase()
}

fn body_shape(body: &Value) -> Value {
    let state = body["state"].as_str().unwrap_or("unknown");
    let mime = media_type(&body["mime"]);
    let reason = if state != "available" {
        Some("body_unavailable")
    } else if body["truncated"] != false {
        Some("body_truncated")
    } else if body["has_base64"] == true {
        Some("base64_not_analyzed")
    } else if mime != "application/json"
        && !mime
            .strip_prefix("application/")
            .is_some_and(|v| v.len() > 5 && v.ends_with("+json"))
    {
        Some("not_json_media_type")
    } else if body["text"].as_str().is_none() {
        Some("body_byte_limit")
    } else {
        None
    };
    let result = reason.map_or_else(|| infer_shape(body["text"].as_str().unwrap()), Err);
    match result {
        Ok(shape) => {
            json!({"state": state, "mime": mime, "status": "observed", "reason": null, "shape": shape})
        }
        Err(reason) => {
            json!({"state": state, "mime": mime, "status": "unavailable", "reason": reason, "shape": null})
        }
    }
}

#[derive(Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Segment {
    Property { name: String },
    ArrayElement,
}
#[derive(Default)]
struct Field {
    types: BTreeSet<&'static str>,
    observations: usize,
}
#[derive(Default)]
struct Shape {
    fields: BTreeMap<Vec<Segment>, Field>,
    nodes: usize,
    depth: usize,
    path_bytes: usize,
    fault: Option<&'static str>,
}
impl Shape {
    fn fail<E: de::Error>(&mut self, reason: &'static str) -> E {
        self.fault = Some(reason);
        E::custom(reason)
    }
    fn record<E: de::Error>(
        &mut self,
        path: &[Segment],
        kind: &'static str,
    ) -> std::result::Result<(), E> {
        if self.nodes >= MAX_NODES || path.len() > MAX_DEPTH {
            return Err(self.fail("shape_resource_limit"));
        }
        if !self.fields.contains_key(path) {
            let bytes = serde_json::to_vec(path).map_err(E::custom)?.len();
            if self.fields.len() > MAX_FIELDS || self.path_bytes + bytes > MAX_PATH_BYTES {
                return Err(self.fail("shape_resource_limit"));
            }
            self.path_bytes += bytes;
        }
        self.nodes += 1;
        self.depth = self.depth.max(path.len());
        let field = self.fields.entry(path.to_vec()).or_default();
        field.types.insert(kind);
        field.observations += 1;
        Ok(())
    }
}
struct ShapeSeed<'a> {
    shape: &'a mut Shape,
    path: Vec<Segment>,
}
impl<'de> DeserializeSeed<'de> for ShapeSeed<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ShapeSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON body")
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<(), E> {
        self.shape.record(&self.path, "null")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<(), E> {
        self.shape.record(&self.path, "boolean")
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<(), E> {
        self.shape.record(&self.path, "number")
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<(), E> {
        self.shape.record(&self.path, "number")
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<(), E> {
        self.shape.record(&self.path, "number")
    }
    fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<(), E> {
        self.shape.record(&self.path, "string")
    }
    fn visit_string<E: de::Error>(self, _: String) -> std::result::Result<(), E> {
        self.shape.record(&self.path, "string")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        self.shape.record(&self.path, "array")?;
        let mut path = self.path;
        path.push(Segment::ArrayElement);
        while seq
            .next_element_seed(ShapeSeed {
                shape: self.shape,
                path: path.clone(),
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        self.shape.record(&self.path, "object")?;
        let mut keys = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if name.len() > MAX_NAME {
                return Err(self.shape.fail("shape_resource_limit"));
            }
            if !keys.insert(name.clone()) {
                return Err(self.shape.fail("duplicate_json_key"));
            }
            let mut path = self.path.clone();
            path.push(Segment::Property { name });
            map.next_value_seed(ShapeSeed {
                shape: self.shape,
                path,
            })?;
        }
        Ok(())
    }
}
fn infer_shape(text: &str) -> std::result::Result<Value, &'static str> {
    if text.len() > MAX_BODY {
        return Err("body_byte_limit");
    }
    let mut shape = Shape::default();
    let mut parser = serde_json::Deserializer::from_str(text);
    ShapeSeed {
        shape: &mut shape,
        path: Vec::new(),
    }
    .deserialize(&mut parser)
    .map_err(|_| shape.fault.unwrap_or("malformed_json"))?;
    parser.end().map_err(|_| "malformed_json")?;
    let root = shape.fields.remove(&Vec::new()).ok_or("malformed_json")?;
    let properties: Vec<Value> = shape.fields.into_iter().map(|(path, field)|
        json!({"path": path, "types": field.types, "observations": field.observations})).collect();
    Ok(
        json!({"root_type": root.types.first(), "node_count": shape.nodes,
        "max_depth_observed": shape.depth, "properties": properties}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn request(id: usize, url: &str, body: &str) -> Value {
        json!({"requestId": id.to_string(), "timestamp": id as f64 + 1.0,
            "request": {"url": url, "method": "POST", "postData": body,
                "headers": {"Content-Type": "Application/JSON; token=synthetic-request-mime", "Authorization": "Bearer synthetic-header", "Cookie": "synthetic-cookie"}}})
    }
    fn debugger(enabled: bool) -> std::sync::Arc<Debugger> {
        let options = crate::config::Options::parse_from(["test"]);
        let debugger = Debugger::new(&options);
        debugger.update(|s| {
            s["target"] = json!({"id": "synthetic-target"});
            s["network"]["capture_enabled"] = json!(enabled);
        });
        debugger
    }
    // Authored retained-record fixture builder, compiled only in these reader
    // tests. It has no socket, target, browser, or executable protocol path.
    impl Debugger {
        pub(crate) async fn historical_fixture(&self, kind: &str, event: &Value) {
            self.update(|s| {
                if s["network"]["capture_enabled"] != true { return; }
                let headers = |value: &Value| -> Vec<Value> {
                    value.as_object().into_iter().flatten().map(|(k,v)|json!([k,v])).collect()
                };
                let respond = |row: &mut Value, response: &Value, redirected: bool| {
                    row["status"] = response["status"].clone();
                    row["response"]["headers"] = json!(headers(&response["headers"]));
                    row["response"]["body"]["mime"] = response["mimeType"].as_str().unwrap_or("").into();
                    if redirected {
                        row["state"] = json!("complete");
                        row["response"]["body"]["state"] = json!("missing");
                        row["response"]["body"]["reason"] = json!("Historical redirect body unavailable");
                    }
                };
                let id = event["requestId"].as_str().unwrap_or("");
                if kind == "Network.requestWillBeSent" {
                    let request = &event["request"];
                    let mime = request["headers"].as_object().into_iter().flatten()
                        .find(|(key,_)|key.eq_ignore_ascii_case("content-type"))
                        .and_then(|(_,v)|v.as_str()).unwrap_or("text/plain");
                    let epoch=s["network"]["capture_epoch"].as_u64().unwrap_or(0);
                    let target=s["target"]["id"].as_str().unwrap_or("synthetic-target").to_owned();
                    let title=s["target"]["title"].as_str().unwrap_or("").to_owned();
                    let rows=s["network"]["requests"].as_array_mut().unwrap();
                    if event["redirectResponse"].is_object() {
                        if let Some(row)=rows.iter_mut().rev().find(|r|r["protocol_request_id"]==id) {
                            respond(row,&event["redirectResponse"],true);
                        }
                    }
                    let public_id=format!("historical-{epoch}-{}-{id}", rows.len());
                    rows.push(json!({
                        "id":public_id,"protocol_request_id":id,"target_id":target,"target_title":title,
                        "started_monotonic_ms":event["timestamp"].as_f64().unwrap()*1000.0,
                        "method":request["method"],"method_truncated":false,
                        "url":request["url"],"url_truncated":false,
                        "resource_type":event["type"].as_str().unwrap_or(""),
                        "document_url":event["documentURL"].as_str().unwrap_or(""),"document_url_truncated":false,
                        "wall_time_ms":0,"state":"pending","status":null,"status_text":"",
                        "protocol":"","mime_type":"","duration_ms":null,"encoded_data_length":0,
                        "from_disk_cache":false,"from_service_worker":false,"error_text":"",
                        "initiator":{"sites":[],"gaps":["initiator_unavailable"]},
                        "request":{"headers":headers(&request["headers"]),"headers_truncated":false,
                            "body":{"state":if request["postData"].is_string(){"available"}else{"empty"},
                            "mime":mime,"text":request["postData"].as_str().unwrap_or(""),"base64":"","truncated":false,"reason":""}},
                        "response":{"headers":[],"headers_truncated":false,"body":{"state":"loading","mime":"","text":"","base64":"","truncated":false,"reason":"Historical response pending"}}
                    }));
                    if rows.len()>1000 {
                        rows.remove(0);
                        s["network"]["dropped"]=json!(s["network"]["dropped"].as_u64().unwrap_or(0)+1);
                    }
                } else if kind == "Network.responseReceived" {
                    if let Some(row)=s["network"]["requests"].as_array_mut().unwrap().iter_mut().rev().find(|r|r["protocol_request_id"]==id) {
                        respond(row,&event["response"],false);
                    }
                }
            });
        }
    }
    fn validate(output: &Value) {
        let spec: Value =
            serde_json::from_str(include_str!("../../../../protocol/openapi.json")).unwrap();
        let schema = json!({"$ref":"#/components/schemas/ApiObservationCatalog", "components":spec["components"]});
        let validator = jsonschema::validator_for(&schema).unwrap();
        if let Some(error) = validator.iter_errors(output).next() {
            panic!("Catalog schema: {error}");
        }
    }

    #[tokio::test]
    async fn catalog_reads_authored_historical_records_without_mutating_values() {
        let debugger = debugger(true);
        let raw_url = "https://synthetic-user:synthetic-pass@example.test/v1/items?token=synthetic-query&id=3&id=4#synthetic-fragment";
        debugger.historical_fixture("Network.requestWillBeSent", &request(1, raw_url,
            r#"{"items":[{"id":1,"value":"synthetic-body"},{"id":"two"}],"empty":[],"nested.key":{"/":true}}"#)).await;
        debugger.historical_fixture("Network.responseReceived", &json!({"requestId":"1", "response":{
            "status": 201, "headers":{"Content-Type":"application/problem+json; profile=synthetic-response-mime","Set-Cookie":"synthetic-response"}}})).await;
        debugger.update(|s| {
            s["network"]["requests"][0]["response"]["body"] = json!({"state":"available", "mime":"application/problem+json; profile=synthetic-response-mime", "text":"{\"ok\":true}", "base64":"", "truncated":false});
        });
        let before = debugger.snapshot();
        let output = debugger.api_catalog().unwrap();
        validate(&output);
        assert_eq!(
            before,
            debugger.snapshot(),
            "Derivation must not alter raw Traffic"
        );
        assert_eq!(
            output["coverage"]["instance_id"],
            before["network"]["instance_id"]
        );
        assert_eq!(output["coverage"]["capture_epoch"], 0);
        let endpoint = &output["endpoints"][0];
        assert_eq!(endpoint["path"], "/v1/items");
        assert_eq!(endpoint["origin"], "https://example.test");
        let observation = &endpoint["observations"][0];
        assert_eq!(
            observation["source"]["request_id"],
            before["network"]["requests"][0]["id"]
        );
        assert_eq!(observation["source"]["started_monotonic_ms"], 2000.0);
        assert_eq!(
            observation["query_parameters"]["names"],
            json!(["id", "token"])
        );
        assert_eq!(
            observation["request"]["header_names"],
            json!(["authorization", "content-type", "cookie"])
        );
        assert_eq!(observation["status"], 201);
        assert_eq!(observation["response"]["body"]["status"], "observed");
        assert_eq!(observation["request"]["body"]["mime"], "application/json");
        assert_eq!(
            observation["response"]["body"]["mime"],
            "application/problem+json"
        );
        let text = output.to_string();
        for secret in [
            "synthetic-user",
            "synthetic-pass",
            "synthetic-query",
            "synthetic-fragment",
            "synthetic-header",
            "synthetic-cookie",
            "synthetic-body",
            "synthetic-response",
            "synthetic-request-mime",
            "synthetic-response-mime",
        ] {
            assert!(!text.contains(secret), "Unexpected value: {secret}");
        }
        let shape = &observation["request"]["body"]["shape"];
        let id = shape["properties"].as_array().unwrap().iter().find(|field|
            field["path"] == json!([{"kind":"property","name":"items"},{"kind":"array-element"},{"kind":"property","name":"id"}])).unwrap();
        assert_eq!(id["types"], json!(["number", "string"]));
        assert_eq!(id["observations"], 2);
        assert_eq!(
            output,
            debugger.api_catalog().unwrap(),
            "Stable snapshot yields canonical output"
        );
    }

    #[test]
    fn shape_paths_are_typed_and_every_parse_or_resource_failure_is_explicit() {
        assert_eq!(query_name("%C3%A9+key"), Some("é key".into()));
        assert_eq!(
            media_type(&json!(" Application/JSON; private=synthetic-secret ")),
            "application/json"
        );
        for invalid in [
            "application/json secret",
            "application/json/extra",
            "application/",
            "/json",
            "application/\\json",
            "application/\u{7f}json",
        ] {
            assert_eq!(media_type(&json!(invalid)), "");
        }
        assert_eq!(
            media_type(&json!(format!("application/{}", "x".repeat(512)))),
            ""
        );
        for bad in ["%FF", "%ZZ", "%", "%0"] {
            assert_eq!(query_name(bad), None);
        }
        let shape = infer_shape(r#"{"*":1,"":null,"a/b":{"~":true},"items":[[],["x"]]}"#).unwrap();
        assert_eq!(shape["root_type"], "object");
        assert!(
            shape["properties"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["path"] == json!([{"kind":"property","name":"*"}]))
        );
        assert_eq!(infer_shape("{\"a\":1,\"a\":2}"), Err("duplicate_json_key"));
        assert_eq!(
            infer_shape("{\"a\":1,\"\\u0061\":2}"),
            Err("duplicate_json_key")
        );
        for invalid in ["{", "null null", "1e9999", "[1,]", "\u{feff}{}"] {
            assert!(infer_shape(invalid).is_err());
        }
        assert_eq!(
            infer_shape(&" ".repeat(MAX_BODY + 1)),
            Err("body_byte_limit")
        );
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(infer_shape(&deep), Err("shape_resource_limit"));
        let nodes = format!("[{}]", vec!["0"; MAX_NODES].join(","));
        assert_eq!(infer_shape(&nodes), Err("shape_resource_limit"));
        let fields = (0..MAX_FIELDS + 1)
            .map(|i| format!("\"p{i}\":0"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            infer_shape(&format!("{{{fields}}}")),
            Err("shape_resource_limit")
        );
        let long = format!("{{\"{}\":0}}", "x".repeat(MAX_NAME + 1));
        assert_eq!(infer_shape(&long), Err("shape_resource_limit"));
        for text in [
            "null",
            "false",
            "1.3",
            "9007199254740993",
            "\"x\"",
            "[]",
            "{}",
        ] {
            assert!(infer_shape(text).is_ok());
        }
    }

    #[tokio::test]
    async fn tail_bounds_drops_capture_off_and_body_unknowns_are_not_complete_claims() {
        let disabled = debugger(false);
        disabled
            .historical_fixture(
                "Network.requestWillBeSent",
                &request(0, "https://example.test/", "{}"),
            )
            .await;
        let empty = disabled.api_catalog().unwrap();
        validate(&empty);
        assert_eq!(empty["coverage"]["capture_enabled"], false);
        assert_eq!(empty["endpoints"], json!([]));
        let debugger = debugger(true);
        for id in 0..70 {
            debugger
                .historical_fixture(
                    "Network.requestWillBeSent",
                    &request(id, "https://example.test/same", "{}"),
                )
                .await;
        }
        debugger.update(|s| s["network"]["dropped"] = json!(7));
        let output = debugger.api_catalog().unwrap();
        validate(&output);
        assert_eq!(output["coverage"]["window_records"], MAX_RECORDS);
        assert_eq!(output["coverage"]["older_records_not_examined"], 6);
        assert_eq!(output["coverage"]["capture_dropped_records"], 7);
        assert_eq!(output["endpoints"].as_array().unwrap().len(), 1);
        assert_eq!(
            output["endpoints"][0]["observations"]
                .as_array()
                .unwrap()
                .len(),
            MAX_RECORDS
        );
        for (field, value, reason) in [
            ("state", json!("loading"), "body_unavailable"),
            ("truncated", json!(true), "body_truncated"),
            ("has_base64", json!(true), "base64_not_analyzed"),
            ("mime", json!("text/plain"), "not_json_media_type"),
            ("text", Value::Null, "body_byte_limit"),
            ("text", json!("{\"a\":1,\"a\":2}"), "duplicate_json_key"),
        ] {
            let mut body = json!({"state":"available", "mime":"application/json", "text":"{}", "truncated":false, "has_base64":false});
            body[field] = value;
            let result = body_shape(&body);
            assert_eq!(result["reason"], reason);
            assert!(result["shape"].is_null());
        }
    }

    #[tokio::test]
    async fn reused_request_identity_keeps_capture_epoch_and_exact_group_boundaries() {
        let debugger = debugger(true);
        let original = request(1, "https://example.test/same", "{}");
        debugger
            .historical_fixture("Network.requestWillBeSent", &original)
            .await;
        let first = debugger.api_catalog().unwrap();
        debugger.update(|state| {
            state["network"]["requests"] = json!([]);
            state["network"]["capture_epoch"] = json!(1);
        });
        debugger
            .historical_fixture("Network.requestWillBeSent", &original)
            .await;
        let second = debugger.api_catalog().unwrap();
        validate(&second);
        assert_ne!(
            first["coverage"]["capture_epoch"],
            second["coverage"]["capture_epoch"]
        );
        // Public IDs are never reused, even after ledger eviction/reset.
        assert_ne!(
            first["endpoints"][0]["observations"][0]["source"]["request_id"],
            second["endpoints"][0]["observations"][0]["source"]["request_id"]
        );
        let mut second_endpoints = second["endpoints"].clone();
        second_endpoints[0]["observations"][0]["source"]["request_id"] =
            first["endpoints"][0]["observations"][0]["source"]["request_id"].clone();
        assert_eq!(first["endpoints"], second_endpoints);
        for (id, method, url) in [
            (2, "GET", "https://example.test/same"),
            (3, "get", "https://example.test/same"),
            (4, "POST", "http://example.test/same"),
        ] {
            let mut event = request(id, url, "{}");
            event["request"]["method"] = json!(method);
            debugger
                .historical_fixture("Network.requestWillBeSent", &event)
                .await;
        }
        let output = debugger.api_catalog().unwrap();
        validate(&output);
        assert_eq!(output["endpoints"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn header_omissions_and_path_budget_are_explicit() {
        let headers: Vec<Value> = (0..MAX_NAMES + 2)
            .map(|index| json!([format!("X-Field-{index}"), "synthetic-private-value"]))
            .collect();
        let side = select_side(&json!({"headers": headers, "headers_truncated": true}));
        assert_eq!(side["header_names"].as_array().unwrap().len(), MAX_NAMES);
        assert_eq!(side["header_names_omitted"], 2);
        assert_eq!(side["headers_truncated"], true);
        assert!(!side.to_string().contains("synthetic-private-value"));
        let mut deep = json!(null);
        for _ in 0..12 {
            let mut object = serde_json::Map::new();
            object.insert("x".repeat(MAX_NAME), deep);
            deep = Value::Object(object);
        }
        assert_eq!(infer_shape(&deep.to_string()), Err("shape_resource_limit"));
    }

    #[tokio::test]
    async fn exact_paths_methods_query_names_and_omission_counts_stay_distinct() {
        let debugger = debugger(true);
        for (id, path) in ["/v1/1", "/v1/2", "/a/../b", "/b", "/%62"]
            .iter()
            .enumerate()
        {
            debugger
                .historical_fixture(
                    "Network.requestWillBeSent",
                    &request(id, &format!("https://example.test{path}"), "{}"),
                )
                .await;
        }
        let query = (0..MAX_NAMES + 1)
            .map(|i| format!("p{i}=synthetic"))
            .collect::<Vec<_>>()
            .join("&");
        debugger
            .historical_fixture(
                "Network.requestWillBeSent",
                &request(5, &format!("https://example.test/q?{query}"), "{}"),
            )
            .await;
        debugger
            .historical_fixture(
                "Network.requestWillBeSent",
                &request(6, "data:text/plain,hello", "{}"),
            )
            .await;
        debugger
            .historical_fixture(
                "Network.requestWillBeSent",
                &request(
                    7,
                    &format!("https://example.test/{}", "x".repeat(MAX_URL)),
                    "{}",
                ),
            )
            .await;
        let output = debugger.api_catalog().unwrap();
        validate(&output);
        assert_eq!(output["coverage"]["skipped_records"], 2);
        assert_eq!(output["endpoints"].as_array().unwrap().len(), 6);
        let q = output["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["path"] == "/q")
            .unwrap();
        assert_eq!(q["observations"][0]["query_parameters"]["omitted"], 1);
        assert_eq!(
            q["observations"][0]["query_parameters"]["names"]
                .as_array()
                .unwrap()
                .len(),
            MAX_NAMES
        );
    }

    #[tokio::test]
    async fn graphql_operations_and_pagination_values_never_invent_endpoints() {
        let debugger = debugger(true);
        for (id, url, body) in [
            (
                1,
                "https://example.test/graphql?cursor=synthetic-page-one&limit=20&tag=a&%74ag=b&space+key=c&space%20key=d&%FF=e&%=f",
                r#"{"operationName":"SyntheticRead","query":"query SyntheticRead { items { id } }","variables":{"cursor":"synthetic-page-one"},"unusedUrl":"https://unobserved.test/admin"}"#,
            ),
            (
                2,
                "https://example.test/graphql?cursor=synthetic-page-two&limit=10",
                r#"{"operationName":"SyntheticMutation","query":"mutation SyntheticMutation { update }","variables":{"cursor":null}}"#,
            ),
        ] {
            debugger
                .historical_fixture("Network.requestWillBeSent", &request(id, url, body))
                .await;
        }
        let before = debugger.snapshot();
        let output = debugger.api_catalog().unwrap();
        validate(&output);
        assert_eq!(before, debugger.snapshot());
        assert_eq!(output["coverage"]["window_records"], 2);
        assert_eq!(output["endpoints"].as_array().unwrap().len(), 1);
        let endpoint = &output["endpoints"][0];
        assert_eq!(endpoint["path"], "/graphql");
        let observations = endpoint["observations"].as_array().unwrap();
        assert_eq!(observations.len(), 2);
        assert_eq!(
            observations[1]["query_parameters"]["names"],
            json!(["cursor", "limit", "space key", "tag"])
        );
        assert_eq!(observations[1]["query_parameters"]["omitted"], 2);
        assert_eq!(observations[0]["query_parameters"]["omitted"], 0);
        let cursor_path = json!([
            {"kind":"property","name":"variables"},
            {"kind":"property","name":"cursor"}
        ]);
        let expected_types = [json!(["null"]), json!(["string"])];
        for (index, types) in expected_types.into_iter().enumerate() {
            let properties = observations[index]["request"]["body"]["shape"]["properties"]
                .as_array()
                .unwrap();
            let cursor = properties
                .iter()
                .find(|field| field["path"] == cursor_path)
                .unwrap();
            assert_eq!(cursor["types"], types);
        }
        let text = output.to_string();
        for value in [
            "synthetic-page-one",
            "synthetic-page-two",
            "SyntheticRead",
            "SyntheticMutation",
            "unobserved.test",
        ] {
            assert!(!text.contains(value));
        }
    }

    #[test]
    fn mixed_arrays_null_and_empty_json_keep_per_body_observation_semantics() {
        let shape =
            infer_shape(r#"[null,{},[],1,1.5,true,"synthetic-value",{"id":0},{"id":null}]"#)
                .unwrap();
        assert_eq!(shape["root_type"], "array");
        assert_eq!(shape["node_count"], 12);
        assert_eq!(shape["max_depth_observed"], 2);
        let fields = shape["properties"].as_array().unwrap();
        let element = fields
            .iter()
            .find(|field| field["path"] == json!([{"kind":"array-element"}]))
            .unwrap();
        assert_eq!(
            element["types"],
            json!(["array", "boolean", "null", "number", "object", "string"])
        );
        assert_eq!(element["observations"], 9);
        let id = fields
            .iter()
            .find(|field| {
                field["path"]
                    == json!([
                        {"kind":"array-element"},
                        {"kind":"property","name":"id"}
                    ])
            })
            .unwrap();
        assert_eq!(id["types"], json!(["null", "number"]));
        assert_eq!(id["observations"], 2);
        assert!(!shape.to_string().contains("synthetic-value"));
        for (text, root_type) in [("null", "null"), ("[]", "array"), ("{}", "object")] {
            let empty = infer_shape(text).unwrap();
            assert_eq!(empty["root_type"], root_type);
            assert_eq!(empty["node_count"], 1);
            assert_eq!(empty["properties"], json!([]));
        }
    }

    #[tokio::test]
    async fn unsupported_bodies_and_streams_remain_explicit_unknowns() {
        for (state, mime, text, base64, truncated, reason) in [
            (
                "missing",
                "multipart/form-data",
                "",
                "",
                false,
                "body_unavailable",
            ),
            (
                "empty",
                "application/json",
                "",
                "",
                false,
                "body_unavailable",
            ),
            (
                "loading",
                "text/event-stream",
                "",
                "",
                false,
                "body_unavailable",
            ),
            (
                "error",
                "application/json",
                "",
                "",
                false,
                "body_unavailable",
            ),
            (
                "available",
                "application/json",
                "{}",
                "",
                true,
                "body_truncated",
            ),
            (
                "available",
                "application/octet-stream",
                "",
                "AAEC",
                false,
                "base64_not_analyzed",
            ),
            (
                "available",
                "multipart/form-data; boundary=synthetic-boundary",
                "synthetic-file-content",
                "",
                false,
                "not_json_media_type",
            ),
            (
                "available",
                "application/x-www-form-urlencoded",
                "token=synthetic-token",
                "",
                false,
                "not_json_media_type",
            ),
            (
                "available",
                "text/event-stream",
                "data: {\"ok\":true}\n\n",
                "",
                false,
                "not_json_media_type",
            ),
            (
                "available",
                "application/x-ndjson",
                "{}\n{}\n",
                "",
                false,
                "not_json_media_type",
            ),
            (
                "available",
                "application/json",
                "{}\n{}\n",
                "",
                false,
                "malformed_json",
            ),
            (
                "available",
                "application/json; charset=utf-8",
                "{\"id\":1,\"id\":2}",
                "",
                false,
                "duplicate_json_key",
            ),
        ] {
            let side = select_side(&json!({
                "headers": [], "headers_truncated": false,
                "body": {"state": state, "mime": mime, "text": text,
                    "base64": base64, "truncated": truncated}
            }));
            let body = body_shape(&side["body"]);
            assert_eq!(body["status"], "unavailable", "{state}: {mime}");
            assert_eq!(body["reason"], reason, "{state}: {mime}");
            assert!(body["shape"].is_null());
            assert!(!body.to_string().contains("synthetic-"));
        }
        let json_body = body_shape(&json!({
            "state": "available", "mime": "application/problem+json; charset=utf-8",
            "text": "{\"title\":null}", "truncated": false, "has_base64": false
        }));
        assert_eq!(json_body["status"], "observed");
        assert_eq!(json_body["mime"], "application/problem+json");
        let debugger = debugger(true);
        for method in ["Network.webSocketCreated", "Network.webSocketFrameReceived"] {
            debugger
                .historical_fixture(
                    method,
                    &json!({"requestId":"socket", "url":"wss://example.test/socket"}),
                )
                .await;
        }
        let output = debugger.api_catalog().unwrap();
        validate(&output);
        assert_eq!(output["coverage"]["window_records"], 0);
        assert_eq!(output["endpoints"], json!([]));
        debugger
            .historical_fixture(
                "Network.requestWillBeSent",
                &request(1, "wss://example.test/socket", "{}"),
            )
            .await;
        let unsupported = debugger.api_catalog().unwrap();
        validate(&unsupported);
        assert_eq!(unsupported["coverage"]["window_records"], 1);
        assert_eq!(unsupported["coverage"]["skipped_records"], 1);
        assert_eq!(unsupported["endpoints"], json!([]));
    }

    #[tokio::test]
    async fn redirects_and_auth_statuses_preserve_only_observed_http_hops() {
        let debugger = debugger(true);
        debugger
            .historical_fixture(
                "Network.requestWillBeSent",
                &request(1, "https://first.test/start?token=synthetic-redirect", "{}"),
            )
            .await;
        let mut redirected = request(1, "https://second.test/final", "{}");
        redirected["timestamp"] = json!(3.0);
        redirected["request"]["method"] = json!("GET");
        redirected["request"]
            .as_object_mut()
            .unwrap()
            .remove("postData");
        redirected["redirectResponse"] = json!({
            "status": 302,
            "headers": {"Location":"https://second.test/final", "Set-Cookie":"synthetic-session"}
        });
        debugger
            .historical_fixture("Network.requestWillBeSent", &redirected)
            .await;
        debugger
            .historical_fixture(
                "Network.responseReceived",
                &json!({"requestId":"1", "response":{
                    "status":401, "headers":{"WWW-Authenticate":"Bearer synthetic-realm"}
                }}),
            )
            .await;
        let before = debugger.snapshot();
        let output = debugger.api_catalog().unwrap();
        validate(&output);
        assert_eq!(before, debugger.snapshot());
        assert_eq!(output["endpoints"].as_array().unwrap().len(), 2);
        let final_observation = &output["endpoints"][0]["observations"][0];
        let redirect_observation = &output["endpoints"][1]["observations"][0];
        assert_eq!(output["endpoints"][0]["method"], "GET");
        assert_eq!(output["endpoints"][0]["origin"], "https://second.test");
        assert_eq!(final_observation["status"], 401);
        assert_eq!(final_observation["request"]["body"]["state"], "empty");
        assert_eq!(final_observation["source"]["started_monotonic_ms"], 3000.0);
        assert_eq!(redirect_observation["status"], 302);
        assert_eq!(
            redirect_observation["source"]["started_monotonic_ms"],
            2000.0
        );
        assert_ne!(
            final_observation["source"]["request_id"],
            redirect_observation["source"]["request_id"]
        );
        assert_eq!(redirect_observation["response"]["body"]["state"], "missing");
        assert_eq!(
            redirect_observation["response"]["body"]["reason"],
            "body_unavailable"
        );
        assert_eq!(
            final_observation["response"]["header_names"],
            json!(["www-authenticate"])
        );
        let text = output.to_string();
        for value in ["synthetic-redirect", "synthetic-session", "synthetic-realm"] {
            assert!(!text.contains(value));
        }
    }

    #[tokio::test]
    async fn eviction_and_invalid_sources_never_fall_back_to_matching_urls() {
        let debugger = debugger(true);
        for id in 0..1002 {
            debugger
                .historical_fixture(
                    "Network.requestWillBeSent",
                    &request(id, "https://example.test/same", "{}"),
                )
                .await;
        }
        let output = debugger.api_catalog().unwrap();
        validate(&output);
        assert_eq!(output["coverage"]["retained_records"], 1000);
        assert_eq!(output["coverage"]["older_records_not_examined"], 936);
        assert_eq!(output["coverage"]["capture_dropped_records"], 2);
        let observations = output["endpoints"][0]["observations"].as_array().unwrap();
        assert_eq!(observations.len(), MAX_RECORDS);
        assert_eq!(
            observations[0]["source"]["request_id"],
            debugger.snapshot()["network"]["requests"][999]["id"]
        );
        assert_eq!(
            observations[MAX_RECORDS - 1]["source"]["request_id"],
            debugger.snapshot()["network"]["requests"][936]["id"]
        );
        debugger.update(|state| {
            let rows = state["network"]["requests"].as_array_mut().unwrap();
            rows[999]["id"] = json!("");
            rows[998]["target_id"] = json!("");
            rows[997]["started_monotonic_ms"] = Value::Null;
        });
        let invalid = debugger.api_catalog().unwrap();
        validate(&invalid);
        assert_eq!(invalid["coverage"]["window_records"], MAX_RECORDS);
        assert_eq!(invalid["coverage"]["skipped_records"], 3);
        assert_eq!(
            invalid["endpoints"][0]["observations"]
                .as_array()
                .unwrap()
                .len(),
            MAX_RECORDS - 3
        );
    }
}
