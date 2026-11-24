use super::*;
use crate::request_stack::tests::{frame, identity_bytes, segment, stack_artifact};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Write, path::Path};

fn request_record(
    digest: &[u8],
    innermost: &[u8],
    recorded: u32,
    segments: u16,
    wasm: u32,
) -> Vec<u8> {
    let mut p = vec![2, 0, 128, 0, 1, 0];
    p.extend(segments.to_le_bytes());
    for value in [recorded, recorded, 0] {
        p.extend(value.to_le_bytes());
    }
    p.extend(0u16.to_le_bytes());
    p.extend(segments.to_le_bytes());
    p.extend(wasm.to_le_bytes());
    p.extend(1u32.to_le_bytes());
    p.extend(digest);
    p.extend(innermost);
    p.resize(128, 0);
    p
}

fn scheduling_record(kind: u8, recorded: u32, digest: &[u8], innermost: &[u8]) -> Vec<u8> {
    let mut p = vec![1, 0, 128, 0, kind, 0, 0, 0];
    p.extend(recorded.to_le_bytes());
    p.extend(0u32.to_le_bytes());
    p.extend(1u32.to_le_bytes());
    p.resize(32, 0);
    p.extend(digest);
    p.extend(innermost);
    p.resize(128, 0);
    p
}

/// An event store and artifact store in a temporary directory, written out
/// whole on each read: what was written before is a prefix of what is
/// written after, as a live capture appends.
struct Fixture {
    root: tempfile::TempDir,
    events: Vec<Value>,
    artifacts: Vec<Value>,
    indexes: Arc<Mutex<Indexes>>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("artifacts/blobs")).unwrap();
        let indexes = Indexes::new(
            &root.path().join("events.jsonl"),
            &root.path().join("trace.jsonl"),
            &root.path().join("signals.jsonl"),
        );
        Self {
            root,
            events: Vec::new(),
            artifacts: Vec::new(),
            indexes: Arc::new(Mutex::new(indexes)),
        }
    }
    fn event(&mut self, kind: &str, process: u64, request: u64, frame: u64, payload: &[u8]) {
        let sequence = self.events.len() as u64 + 1;
        self.events.push(json!({"protocol_version":3,"session_id":"9","sequence_number":sequence.to_string(),
            "monotonic_time_ns":sequence.to_string(),"navigation_id":"0","frame_id":frame.to_string(),"artifact_id":"0",
            "parent_event_id":"0","request_id":request.to_string(),"process_id":process,"thread_id":1,"tab_id":5,
            "category":"network","type":kind,"flags":0,"payload_encoding":"hex","payload":hex::encode(payload),
            "payload_size":payload.len(),"payload_truncated":false}));
    }
    fn text_event(&mut self, kind: &str, process: u64, request: u64, text: &str) {
        self.event(kind, process, request, 1, text.as_bytes());
    }
    /// Writes the blob and returns its SHA-256; `record` adds its manifest
    /// record, which a test can hold back.
    fn blob(&mut self, bytes: &[u8]) -> String {
        let sha = hex::encode(Sha256::digest(bytes));
        std::fs::write(
            self.root.path().join(format!("artifacts/blobs/{sha}.bin")),
            bytes,
        )
        .unwrap();
        sha
    }
    fn record(&mut self, kind: &str, url: &str, bytes: &[u8]) {
        let sha = hex::encode(Sha256::digest(bytes));
        let id = self.artifacts.len() + 1;
        self.artifacts.push(json!({"protocol_version": 1, "artifact_id": id.to_string(), "session_id": "9",
            "navigation_id": "0", "frame_id": "0", "parent_artifact_id": "0", "creator_event_id": "1", "kind": kind,
            "execution_context_id": "99", "capture_origin": match kind {
                "stack" => "request_stack",
                "wasm" => "webassembly_module",
                _ => "stack_script",
            },
            "url": url, "mime_type": "application/octet-stream", "sensitive": false, "sha256": sha,
            "byte_size": bytes.len(), "content_path": format!("blobs/{sha}.bin")}));
    }
    fn artifact(&mut self, kind: &str, url: &str, bytes: &[u8]) -> String {
        let sha = self.blob(bytes);
        self.record(kind, url, bytes);
        sha
    }
    fn inputs(&self) -> Inputs {
        let store = self.root.path().join("events.jsonl");
        let mut file = std::fs::File::create(&store).unwrap();
        for event in &self.events {
            writeln!(file, "{event}").unwrap();
        }
        let mut manifest =
            std::fs::File::create(self.root.path().join("artifacts/manifest.jsonl")).unwrap();
        for artifact in &self.artifacts {
            writeln!(manifest, "{artifact}").unwrap();
        }
        Inputs {
            store,
            artifacts: self.root.path().join("artifacts"),
            indexes: self.indexes.clone(),
        }
    }
}

/// Every answer must match the published contract.
fn assert_contract(value: &Value, schema: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/openapi.json");
    let spec: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let document = json!({"$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/components/schemas/{schema}"), "components": spec["components"]});
    let validator = jsonschema::validator_for(&document).unwrap();
    if let Err(error) = validator.validate(value) {
        panic!("{schema} contract: {error}");
    }
}

fn no_names() -> Arc<Names> {
    Arc::new(crate::wasm_names::test_names(json!([])))
}

/// The answer once the indexes have caught up with the stores: each request
/// lets them catch up for a short slice, which a loaded machine can need a
/// few of.
fn page(
    graphs: &Graphs,
    inputs: &Inputs,
    session: u64,
    generation: Option<&str>,
    cursor: u32,
    limit: usize,
    names: &Arc<Names>,
) -> Result<Value> {
    let page = Page {
        generation,
        cursor,
        limit,
    };
    let pieces = super::graph(
        graphs,
        inputs,
        session,
        page,
        &AtomicBool::new(false),
        names,
    )?;
    let value: Value = serde_json::from_slice(&pieces.concat()).unwrap();
    assert_contract(&value, "FlowGraph");
    Ok(value)
}

/// Nodes and edges a test page holds, so every test reads its graph in
/// several pages.
const TEST_PAGE: usize = 3;

/// The whole graph once the fold is complete, read a page at a time from
/// one generation. Each page holds the nodes from its cursor on and every
/// edge whose later end is among them.
fn answer(graphs: &Graphs, inputs: &Inputs, session: u64, names: &Arc<Names>) -> Value {
    for _ in 0..600 {
        let first = page(graphs, inputs, session, None, 0, TEST_PAGE, names).unwrap();
        if first["complete"] != true {
            continue;
        }
        let generation = first["generation"].as_str().unwrap().to_owned();
        let mut whole = first.clone();
        let mut next = first["next_cursor"].clone();
        let mut pages = vec![first];
        while let Some(cursor) = next.as_u64() {
            let more = page(
                graphs,
                inputs,
                session,
                Some(&generation),
                cursor as u32,
                TEST_PAGE,
                names,
            )
            .unwrap();
            assert_eq!(more["contexts"], whole["contexts"]);
            assert_eq!(more["stacks"], whole["stacks"]);
            next = more["next_cursor"].clone();
            pages.push(more);
        }
        let (mut nodes, mut edges) = (Vec::new(), Vec::new());
        for page in &pages {
            let cursor = page["cursor"].as_u64().unwrap();
            let held = page["nodes"].as_array().unwrap();
            let end = cursor + held.len() as u64;
            assert!(!held.is_empty() || page["node_count"] == 0);
            for (offset, node) in held.iter().enumerate() {
                assert_eq!(node["id"], cursor + offset as u64, "a page is a run of IDs");
            }
            for edge in page["edges"].as_array().unwrap() {
                let later = edge["from"]
                    .as_u64()
                    .unwrap()
                    .max(edge["to"].as_u64().unwrap());
                assert!(
                    (cursor..end).contains(&later),
                    "an edge comes with its later end"
                );
            }
            if page["next_cursor"].is_u64() {
                assert_eq!(page["next_cursor"], end);
            }
            nodes.extend(held.iter().cloned());
            edges.extend(page["edges"].as_array().unwrap().iter().cloned());
        }
        assert_eq!(whole["node_count"], nodes.len());
        assert_eq!(whole["edge_count"], edges.len());
        for context in whole["contexts"].as_array().unwrap() {
            let first = context["first_node"].as_u64().unwrap() as usize;
            assert_eq!(nodes[first]["context"], context["id"]);
            assert!(first == 0 || nodes[first - 1]["context"] != context["id"]);
        }
        whole["nodes"] = json!(nodes);
        whole["edges"] = json!(edges);
        whole["next_cursor"] = Value::Null;
        return whole;
    }
    panic!("the indexes never caught up");
}

fn graph(fixture: &Fixture) -> Value {
    answer(&Graphs::default(), &fixture.inputs(), 9, &no_names())
}

fn paths_of(graphs: &Graphs, inputs: &Inputs, generation: &Value, query: PathQuery) -> Value {
    let bytes = super::paths(
        graphs,
        inputs,
        9,
        Page {
            generation: generation.as_str(),
            cursor: 0,
            limit: PATHS_PAGE,
        },
        &query,
        &AtomicBool::new(false),
    )
    .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap();
    assert_contract(&value, "FlowGraphPaths");
    value
}

fn node<'a>(graph: &'a Value, name: &str) -> &'a Value {
    graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == name)
        .unwrap_or_else(|| panic!("no node {name}"))
}

fn edge<'a>(graph: &'a Value, from: &str, to: &str) -> &'a Value {
    let (from, to) = (&node(graph, from)["id"], &node(graph, to)["id"]);
    graph["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["from"] == *from && edge["to"] == *to)
        .unwrap_or_else(|| panic!("no edge"))
}

fn edge_index(g: &Value, from: &str, to: &str) -> u64 {
    let wanted = edge(g, from, to);
    g["edges"]
        .as_array()
        .unwrap()
        .iter()
        .position(|e| e == wanted)
        .unwrap() as u64
}

/// The graph with IDs replaced by what they name, in a fixed order: two
/// builds that planned stacks in a different order describe the same graph
/// exactly when these are equal.
fn normalized(g: &Value) -> Value {
    let contexts = g["contexts"].as_array().unwrap();
    let context = |id: &Value| {
        let mut context = contexts[id.as_u64().unwrap() as usize].clone();
        context.as_object_mut().unwrap().remove("id");
        context
    };
    let nodes = g["nodes"].as_array().unwrap();
    let named = |id: &Value| {
        let mut node = nodes[id.as_u64().unwrap() as usize].clone();
        node["context"] = context(&node["context"]);
        node.as_object_mut().unwrap().remove("id");
        node
    };
    let mut all: Vec<String> = nodes
        .iter()
        .map(|node| named(&node["id"]).to_string())
        .collect();
    all.sort();
    let mut edges: Vec<String> = g["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| {
            let mut edge = edge.clone();
            edge["from"] = named(&edge["from"]);
            edge["to"] = named(&edge["to"]);
            edge.to_string()
        })
        .collect();
    edges.sort();
    json!({"nodes": all, "edges": edges, "stacks": g["stacks"], "contexts": contexts.len()})
}

/// A top page posts a message into a same-process iframe, whose handler
/// calls an eval'd helper and a Wasm export, and the Wasm import fetches.
fn iframe_wasm_fixture() -> Fixture {
    let mut f = Fixture::new();
    let top = "function boot() {\n  frames[0].postMessage('go', '*');\n}\nboot();\n";
    let inner = "function onMessage() {\n  helper();\n  exports.run();\n}\nfunction send() {\n  fetch('/beacon', {method: 'POST'});\n}\n";
    let dynamic = "function helper() { return 1; }";
    f.artifact("javascript", "https://top.test/app.js", top.as_bytes());
    f.artifact(
        "javascript",
        "https://frame.test/inner.js",
        inner.as_bytes(),
    );
    f.artifact("javascript", "https://frame.test/", dynamic.as_bytes());
    f.artifact("wasm", "https://frame.test/m.wasm", &module());
    let at = |text: &str, needle: &str| text.find(needle).unwrap() as u32;
    // Scheduling stack in the top realm: boot -> postMessage, from top level.
    let scheduling = [
        frame(1, 0, 10, at(top, "frames[0]"), at(top, "() {")),
        frame(1, 2, 10, at(top, "boot();"), 0),
    ];
    let scheduling_artifact = stack_artifact(1, &scheduling, &[], &[]);
    let scheduling_sha = f.artifact("stack", "reb-stack:x", &scheduling_artifact);
    let scheduling_digest = hex::decode(&scheduling_sha).unwrap();
    // The request stack in the iframe realm, innermost first:
    // send <- wasm run <- onMessage (the posted task).
    let request = [
        frame(1, 0, 20, at(inner, "fetch"), at(inner, "() {\n  fetch")),
        frame(2, 0, 30, 0x2c, 1),
        frame(
            1,
            0,
            20,
            at(inner, "exports.run"),
            at(inner, "() {\n  helper"),
        ),
    ];
    let request_artifact =
        stack_artifact(2, &request, &[], &[segment(5, 1, 2, &scheduling_digest)]);
    let request_sha = f.artifact("stack", "reb-stack:y", &request_artifact);
    let request_digest = hex::decode(&request_sha).unwrap();
    // A second, cookie-free request through the eval'd helper.
    let helper = [
        frame(1, 0, 40, 9, 15),
        frame(
            1,
            0,
            20,
            at(inner, "helper();"),
            at(inner, "() {\n  helper"),
        ),
    ];
    let helper_artifact = stack_artifact(2, &helper, &[], &[]);
    let helper_sha = f.artifact("stack", "reb-stack:z", &helper_artifact);
    let helper_digest = hex::decode(&helper_sha).unwrap();
    for (script, realm, kind, flags, bytes) in [
        (10u32, 99u64, 1u8, 2u8, top.as_bytes().to_vec()),
        (20, 100, 1, 2, inner.as_bytes().to_vec()),
        (40, 100, 1, 3, dynamic.as_bytes().to_vec()),
        (30, 100, 2, 0, module()),
    ] {
        f.event(
            "script_identity",
            41,
            0,
            7,
            &identity_bytes(kind, flags, script, (0, 0), realm, &bytes),
        );
    }
    f.event(
        "async_task_stack",
        41,
        0,
        6,
        &scheduling_record(5, 2, &scheduling_digest, &scheduling[0]),
    );
    for request_id in [70, 71] {
        f.text_event("request_initiated", 41, request_id, "POST frame.test");
        f.event(
            "request_initiator_stack",
            41,
            request_id,
            7,
            &request_record(&request_digest, &request[0], 3, 1, 1),
        );
    }
    f.text_event("request_initiated", 41, 72, "GET frame.test");
    f.event(
        "request_initiator_stack",
        41,
        72,
        7,
        &request_record(&helper_digest, &helper[0], 2, 0, 0),
    );
    f
}

fn module() -> Vec<u8> {
    wat::parse_str(
        r#"(module (import "env" "send" (func $send)) (func $run (export "run") call $send))"#,
    )
    .unwrap()
}

#[test]
fn one_graph_crosses_realms_languages_and_dynamic_code() {
    let f = iframe_wasm_fixture();
    let (graphs, inputs) = (Graphs::default(), f.inputs());
    let g = answer(&graphs, &inputs, 9, &no_names());
    assert_eq!(g["schema"], SCHEMA);
    assert_eq!(g["complete"], true, "{}", g["coverage"]);
    assert_eq!(g["stacks"]["distinct"], 3);
    assert_eq!(g["stacks"]["occurrences"], 4);
    let contexts = g["contexts"].as_array().unwrap();
    assert_eq!(contexts.len(), 2, "one lane per realm");
    let lane = |name: &str| &contexts[node(&g, name)["context"].as_u64().unwrap() as usize];
    assert_eq!(lane("boot")["origin"], "https://top.test");
    assert_eq!(lane("onMessage")["origin"], "https://frame.test");
    assert_eq!(lane("onMessage")["frame_ids"][0]["frame_id"], "7");
    assert_eq!(lane("onMessage")["frame_ids"][0]["records"], 3);
    assert_eq!(lane("onMessage")["tab_ids"], json!([5]));
    assert_eq!(node(&g, "run")["kind"], "wasm");
    assert_eq!(node(&g, "helper")["kind"], "eval");
    assert_eq!(node(&g, "onMessage")["line"], 1);
    assert_eq!(node(&g, "send")["line"], 5);
    assert_eq!(
        (
            node(&g, "send")["artifact_line"].as_u64(),
            node(&g, "send")["artifact_column"].as_u64()
        ),
        (Some(5), Some(14))
    );

    // postMessage from the top realm into the iframe is one task edge.
    let task = edge(&g, "boot", "onMessage");
    assert_eq!(
        (task["kind"].as_str(), task["task"].as_str()),
        (Some("task"), Some("post_message"))
    );
    assert_eq!(task["crosses"], json!(["frame"]));
    assert_eq!(task["count"], 2, "two requests rode the same posted task");
    assert_eq!(edge(&g, "onMessage", "run")["crosses"], json!(["language"]));
    assert_eq!(edge(&g, "run", "send")["crosses"], json!(["language"]));
    assert_eq!(edge(&g, "run", "send")["sites"][0]["module_offset"], 0x2c);
    assert_eq!(
        edge(&g, "onMessage", "helper")["crosses"],
        json!(["dynamic"])
    );
    assert_eq!(edge(&g, "onMessage", "run")["sites"][0]["line"], 3);
    // The top-level frame scheduled boot's call; its source still names it.
    let top = g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["top_level"] == true)
        .unwrap();
    assert_eq!(top["context"], node(&g, "boot")["context"]);
    assert_eq!(
        (top["status"].as_str(), top["url"].as_str()),
        (Some("resolved"), Some("https://top.test/app.js"))
    );

    let sink = node(&g, "POST frame.test");
    assert_eq!(
        (sink["kind"].as_str(), sink["hits"].as_u64()),
        (Some("request"), Some(2))
    );
    assert_eq!(edge(&g, "send", "POST frame.test")["count"], 2);
    assert_eq!(
        node(&g, "onMessage")["hits"],
        3,
        "each stack counts a node once"
    );
    assert_eq!(node(&g, "onMessage")["stacks"], 2);
    assert_eq!(node(&g, "onMessage")["schedules"], Value::Null);
    assert_eq!(node(&g, "boot")["schedules"]["post_message"], 1);

    // A request's path names exactly the edges its stack walked.
    let paths = paths_of(
        &graphs,
        &inputs,
        &g["generation"],
        PathQuery::Request {
            process: 41,
            request: 71,
        },
    );
    assert_eq!(
        (paths["total"].as_u64(), paths["occurrences"].as_u64()),
        (Some(1), Some(2))
    );
    let path = &paths["paths"][0];
    assert_eq!(path["requests"], 2);
    let path_edges: BTreeSet<u64> = path["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_u64().unwrap())
        .collect();
    assert!(path_edges.contains(&edge_index(&g, "boot", "onMessage")));
    assert!(path_edges.contains(&edge_index(&g, "send", "POST frame.test")));
    assert!(!path_edges.contains(&edge_index(&g, "onMessage", "helper")));
    assert_eq!(paths["edges"], path["edges"]);
}

#[test]
fn paths_are_served_by_node_request_and_digest_a_page_at_a_time() {
    let f = iframe_wasm_fixture();
    let (graphs, inputs) = (Graphs::default(), f.inputs());
    let g = answer(&graphs, &inputs, 9, &no_names());
    let id = node(&g, "onMessage")["id"].as_u64().unwrap() as u32;
    let through = paths_of(&graphs, &inputs, &g["generation"], PathQuery::Node(id));
    assert_eq!(
        (through["total"].as_u64(), through["occurrences"].as_u64()),
        (Some(2), Some(3)),
        "the posted request's stack and the helper's"
    );
    // The union lights both stacks; one page holds one of them.
    let page = |cursor: u32| {
        let bytes = super::paths(
            &graphs,
            &inputs,
            9,
            Page {
                generation: g["generation"].as_str(),
                cursor,
                limit: 1,
            },
            &PathQuery::Node(id),
            &AtomicBool::new(false),
        )
        .unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    };
    let (first, second) = (page(0), page(1));
    assert_eq!(first["paths"].as_array().unwrap().len(), 1);
    assert_eq!(first["next_cursor"], 1);
    assert_eq!(second["next_cursor"], Value::Null);
    assert_eq!(first["nodes"], through["nodes"]);
    assert_ne!(first["paths"][0]["digest"], second["paths"][0]["digest"]);
    let digest = first["paths"][0]["digest"].as_str().unwrap();
    let by_digest = paths_of(
        &graphs,
        &inputs,
        &g["generation"],
        PathQuery::Digest {
            digest: super::digest(digest).unwrap(),
            process: Some(41),
        },
    );
    assert_eq!(by_digest["paths"][0], first["paths"][0]);
    let none = paths_of(
        &graphs,
        &inputs,
        &g["generation"],
        PathQuery::Digest {
            digest: super::digest(digest).unwrap(),
            process: Some(42),
        },
    );
    assert_eq!(none["total"], 0);
    // IDs of another generation are refused, never read against this graph.
    let stale = super::paths(
        &graphs,
        &inputs,
        9,
        Page {
            generation: Some("0-0"),
            cursor: 0,
            limit: PATHS_PAGE,
        },
        &PathQuery::Node(id),
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert_eq!(stale.status, 409);
    let missing = super::paths(
        &graphs,
        &inputs,
        9,
        Page {
            generation: None,
            cursor: 0,
            limit: PATHS_PAGE,
        },
        &PathQuery::Node(10_000),
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert_eq!(missing.status, 400);
    assert!(super::digest(&digest.to_uppercase()).is_err());
}

#[test]
fn missing_bytes_stay_visible_and_never_bridge() {
    let mut f = iframe_wasm_fixture();
    // Drop the scheduling stack and the inner script: the task edge goes,
    // inner frames keep their identity and a reason.
    f.artifacts
        .retain(|a| a["url"] != "reb-stack:x" && a["url"] != "https://frame.test/inner.js");
    let g = graph(&f);
    assert_eq!(g["stacks"]["unresolved"]["stack_artifact_missing"], 1);
    assert_eq!(
        g["stacks"]["unresolved"]["segment_not_retained"], 1,
        "two requests share one decoded stack"
    );
    let unresolved: Vec<&Value> = g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["reason"] == "source_artifact_missing")
        .collect();
    assert_eq!(
        unresolved.len(),
        2,
        "onMessage and send keep their identities"
    );
    assert!(
        g["edges"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["kind"] != "task")
    );
    let entry = unresolved
        .iter()
        .find(|n| n["chain_cut"] == true)
        .expect("the cut task entry is marked");
    assert_eq!(entry["kind"], "javascript");
}

#[test]
fn repeated_stacks_are_decoded_once_and_answers_are_reused() {
    let mut f = iframe_wasm_fixture();
    let stack = f
        .events
        .iter()
        .find(|e| e["type"] == "request_initiator_stack")
        .unwrap()
        .clone();
    for request in 100..400u64 {
        let mut copy = stack.clone();
        copy["request_id"] = json!(request.to_string());
        copy["sequence_number"] = json!((f.events.len() + 1).to_string());
        f.events.push(copy);
    }
    let (graphs, inputs, names) = (Graphs::default(), f.inputs(), no_names());
    let first = answer(&graphs, &inputs, 9, &names);
    assert_eq!(first["stacks"]["distinct"], 3);
    assert_eq!(first["stacks"]["occurrences"], 304);
    assert_eq!(edge(&first, "boot", "onMessage")["count"], 302);
    let again = answer(&graphs, &inputs, 9, &names);
    assert_eq!(
        again["generation"], first["generation"],
        "an unchanged store is the same graph"
    );
    assert_eq!(again["nodes"], first["nodes"]);
    // Another session in the same store is not this one.
    let other = answer(&graphs, &inputs, 8, &names);
    assert_eq!(other["nodes"], json!([]));
}

#[test]
fn malformed_and_unwalked_records_are_counted() {
    let mut f = iframe_wasm_fixture();
    f.event("request_initiator_stack", 41, 80, 7, &[0; 128]);
    f.event("script_cookie", 41, 0, 7, &[0; 128]);
    let mut no_script = vec![2, 0, 128, 0, 2, 0, 0, 0];
    no_script.resize(128, 0);
    f.event("request_initiator_stack", 41, 81, 7, &no_script);
    // A line no index row can stand for: the index's damage says so.
    f.events.push(json!({"session_id": "9", "type": "async_task_stack", "payload_encoding": "hex", "payload": "zz"}));
    let g = graph(&f);
    assert_eq!(g["coverage"]["malformed_records"], 2);
    assert!(
        g["coverage"]["index_damage"].is_string(),
        "{}",
        g["coverage"]
    );
    assert_eq!(g["stacks"]["not_walked"]["no_script"], 1);
    assert_eq!(g["stacks"]["distinct"], 3);
}

fn async_record(
    digest: &[u8],
    innermost: &[u8],
    recorded: u32,
    asyncs: u16,
    segments: u16,
) -> Vec<u8> {
    let mut p = request_record(digest, innermost, recorded, segments, 0);
    p[20..22].copy_from_slice(&asyncs.to_le_bytes());
    p[22..24].copy_from_slice(&(asyncs + segments).to_le_bytes());
    p
}

#[test]
fn task_edges_enter_only_a_known_first_frame_and_count_each_stack_once() {
    let mut f = Fixture::new();
    let text = "async function a() {\n  await b();\n}\nfunction b() {\n  fetch('/x');\n}\nfunction x() {\n  setTimeout(a);\n}\nfunction r() {\n  r();\n}\nfunction g() {\n  r();\n}\n";
    let at = |needle: &str| text.find(needle).unwrap() as u32;
    let start = |name: &str| at(&format!("function {name}(")) + 9 + name.len() as u32;
    f.artifact("javascript", "https://top.test/app.js", text.as_bytes());
    f.event(
        "script_identity",
        41,
        0,
        7,
        &identity_bytes(1, 2, 50, (0, 0), 99, text.as_bytes()),
    );
    let b = frame(1, 0, 50, at("fetch"), start("b"));
    let x = frame(1, 0, 50, at("setTimeout"), start("x"));
    let scheduler = stack_artifact(1, std::slice::from_ref(&x), &[], &[]);
    let scheduler = hex::decode(f.artifact("stack", "reb-stack:x", &scheduler)).unwrap();
    // 1. `setTimeout(a)` ran `a`, which awaited `b`: the task enters `a`.
    let awaited = frame(3, 0, 50, at("await b"), start("a"));
    let one = stack_artifact(
        2,
        std::slice::from_ref(&b),
        std::slice::from_ref(&awaited),
        &[segment(1, 1, 1, &scheduler)],
    );
    let one = hex::decode(f.artifact("stack", "reb-stack:1", &one)).unwrap();
    f.event(
        "request_initiator_stack",
        41,
        70,
        7,
        &async_record(&one, &b, 1, 1, 1),
    );
    // 2. The timer was scheduled by a walk that stopped at 256 frames (`r`
    //    recursing), itself posted by `g`: no task edge enters that walk.
    let mut deep = vec![x.clone()];
    deep.extend(std::iter::repeat_n(
        frame(1, 0, 50, at("  r();"), start("r")),
        255,
    ));
    let deep = hex::decode(f.artifact(
        "stack",
        "reb-stack:deep",
        &stack_artifact(1, &deep, &[], &[]),
    ))
    .unwrap();
    let g = frame(1, 0, 50, at("  r();\n}\n"), start("g"));
    let poster = hex::decode(f.artifact(
        "stack",
        "reb-stack:g",
        &stack_artifact(1, std::slice::from_ref(&g), &[], &[]),
    ))
    .unwrap();
    let mut bounded = segment(1, 1, 256, &deep);
    bounded[2] = 1;
    let two = stack_artifact(
        2,
        std::slice::from_ref(&b),
        &[],
        &[bounded, segment(5, 1, 1, &poster)],
    );
    let two = hex::decode(f.artifact("stack", "reb-stack:2", &two)).unwrap();
    f.event(
        "request_initiator_stack",
        41,
        71,
        7,
        &request_record(&two, &b, 1, 2, 0),
    );
    // 3. A microtask hop before the same timer: the shared edge keeps it.
    let microtask = segment(9, 6, 0, &[0; 32]);
    let three = stack_artifact(
        2,
        std::slice::from_ref(&b),
        &[],
        &[microtask, segment(1, 1, 1, &scheduler)],
    );
    let three = hex::decode(f.artifact("stack", "reb-stack:3", &three)).unwrap();
    f.event(
        "request_initiator_stack",
        41,
        72,
        7,
        &request_record(&three, &b, 1, 2, 0),
    );
    // 4. A stack whose artifact is missing names no entry.
    f.event(
        "request_initiator_stack",
        41,
        73,
        7,
        &request_record(&[7; 32], &b, 1, 0, 0),
    );
    let graph = graph(&f);
    let id = |name: &str| node(&graph, name)["id"].clone();
    let edges = graph["edges"].as_array().unwrap();
    let between = |from: &str, to: &str| {
        edges
            .iter()
            .filter(|e| e["from"] == id(from) && e["to"] == id(to))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        between("x", "a").len(),
        1,
        "the timer ran the awaiting function"
    );
    assert_eq!(between("a", "b")[0]["kind"], "await");
    let timer = between("x", "b");
    assert_eq!(timer.len(), 1);
    assert_eq!(
        (timer[0]["count"].as_u64(), timer[0]["via"].clone()),
        (Some(2), json!(["microtask"])),
        "stacks 2 and 3 share the edge; the hop is kept"
    );
    // The chain stops at the cut: the poster past it is neither linked nor
    // drawn on this path (its own async_task_stack record would draw it).
    assert!(
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["name"] != "g"),
        "nothing enters a walk that stopped at 256 frames"
    );
    assert_eq!(node(&graph, "r")["chain_cut"], true);
    let recursion = &between("r", "r")[0];
    assert_eq!(
        (recursion["stacks"].as_u64(), recursion["count"].as_u64()),
        (Some(1), Some(1)),
        "one stack walking r -> r 254 times counts once"
    );
    assert_eq!(
        node(&graph, "x")["entries"],
        2,
        "stacks 1 and 3 began in x's task"
    );
    assert_eq!(
        (
            node(&graph, "b")["entries"].as_u64(),
            node(&graph, "a")["entries"].as_u64()
        ),
        (Some(0), Some(0))
    );
    assert_eq!(graph["stacks"]["unresolved"]["stack_artifact_missing"], 1);
}

/// Two renderers (two tabs of one site) record byte-identical version 1
/// scheduling stacks, whose script 50 is a different script in each.
/// Each request is drawn as scheduled in its own process: one decode of
/// the shared bytes never carries the first stack's process to the next.
#[test]
fn identical_older_segments_resolve_in_each_stack_own_process() {
    let mut f = Fixture::new();
    let first = "function go() {\n  fetch('/a');\n}\nfunction a1() {\n  setTimeout(go);\n}\n";
    let second = "function go() {\n  fetch('/b');\n}\nfunction b1() {\n  setTimeout(go);\n}\n";
    let at = |needle: &str| first.find(needle).unwrap() as u32;
    let start = |name: &str| at(&format!("function {name}(")) + 9 + name.len() as u32;
    for (process, text) in [(41, first), (42, second)] {
        f.artifact("javascript", "https://top.test/app.js", text.as_bytes());
        f.event(
            "script_identity",
            process,
            0,
            7,
            &identity_bytes(1, 2, 50, (0, 0), 99, text.as_bytes()),
        );
    }
    let go = frame(1, 0, 50, at("fetch"), start("go"));
    let timer = frame(1, 0, 50, at("setTimeout"), start("a1"));
    let scheduler = stack_artifact(1, std::slice::from_ref(&timer), &[], &[]);
    let scheduler = hex::decode(f.artifact("stack", "reb-stack:t", &scheduler)).unwrap();
    let stack = stack_artifact(
        2,
        std::slice::from_ref(&go),
        &[],
        &[segment(1, 1, 1, &scheduler)],
    );
    let stack = hex::decode(f.artifact("stack", "reb-stack:go", &stack)).unwrap();
    for process in [41, 42] {
        f.event(
            "request_initiator_stack",
            process,
            70,
            7,
            &request_record(&stack, &go, 1, 1, 0),
        );
    }
    let g = graph(&f);
    let nodes = g["nodes"].as_array().unwrap();
    let contexts = g["contexts"].as_array().unwrap();
    let at_process = |name: &str, process: u64| {
        nodes
            .iter()
            .find(|node| {
                node["name"] == name
                    && contexts[node["context"].as_u64().unwrap() as usize]["process_id"] == process
            })
            .unwrap_or_else(|| panic!("no node {name} in process {process}"))["id"]
            .clone()
    };
    let task = |from: &Value, to: &Value| {
        g["edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge["from"] == *from && edge["to"] == *to && edge["kind"] == "task")
    };
    let (go41, go42) = (at_process("go", 41), at_process("go", 42));
    let (a1, b1) = (at_process("a1", 41), at_process("b1", 42));
    assert!(task(&a1, &go41) && task(&b1, &go42), "{}", g["edges"]);
    assert!(
        !task(&a1, &go42),
        "no edge between processes that never interacted"
    );
    // Only records from before the stack scope: what they could not hold.
    assert_eq!(
        g["not_shown"][0],
        "worker and worklet stacks (stacks are walked on the document main thread only)"
    );
    assert_eq!(g["not_shown"][1], "MessagePort and worker messages");
}

#[test]
fn worker_stacks_resolve_in_their_own_isolate() {
    use crate::request_stack::tests::scoped_artifact;
    let mut f = Fixture::new();
    // Script 7 is a different script in the page and in the worker.
    let page = "function post() {\n  port.postMessage(1);\n}\n";
    let worker = "let n = 0;\nfunction inWorker() {\n  fetch('/w');\n}\n";
    let at = |text: &str, needle: &str| text.find(needle).unwrap() as u32;
    let post = frame(1, 0, 7, at(page, "port"), at(page, "() {"));
    let work = frame(1, 0, 7, at(worker, "fetch"), at(worker, "() {"));
    f.artifact("javascript", "https://app.test/page.js", page.as_bytes());
    f.artifact(
        "javascript",
        "https://app.test/worker.js",
        worker.as_bytes(),
    );
    let mut worker_identity = identity_bytes(1, 0x02, 7, (0, 0), 98, worker.as_bytes());
    worker_identity[0] = 2;
    worker_identity[72] = 2;
    worker_identity[80..88].copy_from_slice(&0x77u64.to_le_bytes());
    f.event(
        "script_identity",
        41,
        0,
        7,
        &identity_bytes(1, 0x02, 7, (0, 0), 99, page.as_bytes()),
    );
    f.event("script_identity", 41, 0, 0x77, &worker_identity);
    // The page posted to a port; the worker's request ran in its handler.
    let posted = scoped_artifact(41, 1, 0, std::slice::from_ref(&post), &[], 0);
    f.artifact("stack", "reb-stack:posted", &posted);
    let carried = segment(10, 1, 1, &Sha256::digest(&posted));
    let stack = scoped_artifact(41, 2, 0x77, std::slice::from_ref(&work), &[carried], 0);
    f.artifact("stack", "reb-stack:worker", &stack);
    let mut record = request_record(&Sha256::digest(&stack), &work, 1, 1, 0);
    record[0] = 3;
    record[80] = 2;
    record[88..96].copy_from_slice(&0x77u64.to_le_bytes());
    f.event("request_initiator_stack", 41, 90, 0x77, &record);
    // A worker past the renderer's table limit is counted, never walked.
    let mut limited = vec![3, 0, 128, 0, 6, 0];
    limited.resize(128, 0);
    limited[80] = 2;
    limited[88..96].copy_from_slice(&0x78u64.to_le_bytes());
    f.event("request_initiator_stack", 41, 91, 0x78, &limited);
    let g = graph(&f);
    // Named from the worker's source: the page's script 7 has no such function.
    assert_eq!(node(&g, "inWorker")["line"], 2);
    assert_eq!(node(&g, "post")["line"], 1);
    let contexts = g["contexts"].as_array().unwrap();
    let lane = |name: &str| &contexts[node(&g, name)["context"].as_u64().unwrap() as usize];
    assert_eq!(lane("inWorker")["isolate_key"], "0000000000000077");
    assert_eq!(lane("post")["isolate_key"], Value::Null);
    let task = edge(&g, "post", "inWorker");
    assert_eq!(
        (task["kind"].as_str(), task["task"].as_str()),
        (Some("task"), Some("message_port"))
    );
    assert_eq!(g["stacks"]["not_walked"]["not_walked_thread_limit"], 1);
    // Scoped records walk workers and carry messages across processes.
    let not_shown = g["not_shown"].to_string();
    assert!(
        not_shown.contains("worklet stacks (worklets have no stack tables)")
            && not_shown.contains("joined to this page's only by MessagePort")
            && !not_shown.contains("MessagePort and worker messages"),
        "{not_shown}"
    );
}

/// A service worker's `cookieStore.set` walk (a version 1 artifact, read
/// in the isolate its version 2 `script_cookie` names) resolves to the
/// worker's script, not to a page script with the same ID.
#[test]
fn service_worker_cookie_writes_resolve_in_the_workers_isolate() {
    let mut f = Fixture::new();
    let page = "function onPage() {\n  document.cookie = 'sid=1';\n}\n";
    let worker = "let n = 0;\nfunction inWorker() {\n  cookieStore.set('sid', '1');\n}\n";
    let at = |text: &str, needle: &str| text.find(needle).unwrap() as u32;
    f.artifact("javascript", "https://app.test/page.js", page.as_bytes());
    f.artifact("javascript", "https://app.test/sw.js", worker.as_bytes());
    f.event(
        "script_identity",
        41,
        0,
        7,
        &identity_bytes(1, 0x02, 7, (0, 0), 99, page.as_bytes()),
    );
    let mut worker_identity = identity_bytes(1, 0x02, 7, (0, 0), 98, worker.as_bytes());
    worker_identity[0] = 2;
    worker_identity[72] = 4;
    worker_identity[80..88].copy_from_slice(&0x5157u64.to_le_bytes());
    f.event("script_identity", 41, 0, 0x5157, &worker_identity);
    let write = frame(1, 0, 7, at(worker, "cookieStore"), at(worker, "() {"));
    let walked = stack_artifact(1, std::slice::from_ref(&write), &[], &[]);
    let digest = hex::decode(f.artifact("stack", "reb-stack:cookie", &walked)).unwrap();
    // Version 2: cookieStore.set, frame and stack recorded, thread 4.
    let mut cookie = vec![2, 0, 128, 0, 3, 0x06, 4, 0];
    cookie.extend(1u32.to_le_bytes());
    cookie.extend(3u32.to_le_bytes());
    cookie.extend(1u32.to_le_bytes());
    cookie.extend(0u32.to_le_bytes());
    cookie.extend(&write);
    cookie.extend(&digest);
    cookie.extend(Sha256::digest(b"1"));
    cookie.extend(b"sid");
    cookie.resize(128, 0);
    f.event("script_cookie", 41, 0, 0x5157, &cookie);
    let record = f.events.last_mut().unwrap();
    for key in ["encoded_data_length", "decoded_body_length"] {
        record[key] = json!("0");
    }
    for key in ["status_code", "error_code", "resource_type"] {
        record[key] = json!(0);
    }
    let g = graph(&f);
    assert_eq!(g["coverage"]["malformed_records"], 0, "{}", g["coverage"]);
    let contexts = g["contexts"].as_array().unwrap();
    let lane = &contexts[node(&g, "inWorker")["context"].as_u64().unwrap() as usize];
    assert_eq!(lane["isolate_key"], "0000000000005157");
    assert_eq!(node(&g, "cookieStore.set")["kind"], "cookie_write");
    assert!(
        !g["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["name"] == "onPage"),
        "the page's script 7 is not the worker's"
    );
}

/// A version 3 request stack of the document main thread, with its
/// artifact, for each chain of task segments.
fn document_request(f: &mut Fixture, request: u64, frames: &[Vec<u8>], segments: &[Vec<u8>]) {
    use crate::request_stack::tests::scoped_artifact;
    let artifact = scoped_artifact(41, 1, 0, frames, segments, 0);
    f.artifact("stack", "reb-stack:r", &artifact);
    let mut record = request_record(
        &Sha256::digest(&artifact),
        &frames[0],
        frames.len() as u32,
        segments.len() as u16,
        0,
    );
    record[0] = 3;
    record[80] = 1;
    f.text_event("request_initiated", 41, request, "GET t.test");
    f.event("request_initiator_stack", 41, request, 7, &record);
}

/// A click the browser dispatched (an event segment in state 7
/// `no_script`) and a message whose origin was rejected (state 8) end
/// their chains with that reason: the handler is a known task entry and
/// is not cut. A frameless microtask hop before the end leaves the
/// frames that registered the reaction unknown, which is a cut.
#[test]
fn tasks_no_script_scheduled_end_the_chain_without_a_cut() {
    let mut f = Fixture::new();
    let text = "function onClick() {\n  send();\n}\nfunction send() {\n  fetch('/x');\n}\nfunction onMessage() {\n  send();\n}\nfunction onReaction() {\n  send();\n}\n";
    let at = |needle: &str| text.find(needle).unwrap() as u32;
    let start = |name: &str| at(&format!("function {name}(")) + 9 + name.len() as u32;
    f.artifact("javascript", "https://t.test/app.js", text.as_bytes());
    f.event(
        "script_identity",
        41,
        0,
        7,
        &identity_bytes(1, 2, 10, (0, 0), 99, text.as_bytes()),
    );
    let send = frame(1, 0, 10, at("fetch"), start("send"));
    let caller = |name: &str| {
        let call = text[start(name) as usize..].find("send();").unwrap() as u32 + start(name);
        frame(1, 0, 10, call, start(name))
    };
    let empty = [0u8; 32];
    document_request(
        &mut f,
        1,
        &[send.clone(), caller("onClick")],
        &[segment(8, 7, 0, &empty)],
    );
    document_request(
        &mut f,
        2,
        &[send.clone(), caller("onMessage")],
        &[segment(10, 8, 0, &empty)],
    );
    document_request(
        &mut f,
        3,
        &[send.clone(), caller("onReaction")],
        &[segment(9, 6, 0, &empty), segment(8, 7, 0, &empty)],
    );
    let g = graph(&f);
    assert_eq!(g["coverage"]["malformed_records"], 0, "{}", g["coverage"]);
    let click = node(&g, "onClick");
    assert_eq!(
        (click["entries"].as_u64(), click.get("chain_cut")),
        (Some(1), None),
        "{click}"
    );
    assert_eq!(
        click["chain_ends"],
        json!([{"reason": "no_script", "task": "event", "count": 1}])
    );
    let message = node(&g, "onMessage");
    assert_eq!(message.get("chain_cut"), None);
    assert_eq!(
        message["chain_ends"],
        json!([{"reason": "origin_rejected", "task": "message_port", "count": 1}])
    );
    let reaction = node(&g, "onReaction");
    assert_eq!(
        (reaction["chain_cut"].as_bool(), reaction.get("chain_ends")),
        (Some(true), None)
    );
}

/// With promise registration stacks on, a request in a `.then` reaction
/// names the stack that called `.then` in its microtask segment (kind 9,
/// state 1). That call is a task edge into the reaction, labelled by the
/// registration, and the chain goes on from the registration's
/// outermost frame. A registration that was not retained is a cut.
#[test]
fn promise_registrations_join_their_reaction() {
    use crate::request_stack::tests::scoped_artifact;
    let mut f = Fixture::new();
    let text = "function onClick() {\n  send();\n}\nfunction send() {\n  fetch('/x');\n}\nfunction arm() {\n  p.then(onClick);\n}\nfunction boot() {\n  arm();\n}\nboot();\nfunction later() {\n  send();\n}\n";
    let at = |needle: &str| text.find(needle).unwrap() as u32;
    let start = |name: &str| at(&format!("function {name}(")) + 9 + name.len() as u32;
    f.artifact("javascript", "https://t.test/app.js", text.as_bytes());
    f.event(
        "script_identity",
        41,
        0,
        7,
        &identity_bytes(1, 2, 10, (0, 0), 99, text.as_bytes()),
    );
    let send = frame(1, 0, 10, at("fetch"), start("send"));
    let click = frame(1, 0, 10, at("send();"), start("onClick"));
    let arm = frame(1, 0, 10, at("p.then"), start("arm"));
    let boot = frame(1, 2, 10, at("boot();\nfunction later"), 0);
    let registered = scoped_artifact(41, 1, 0, &[arm.clone(), boot], &[], 0);
    let digest = hex::decode(f.artifact("stack", "reb-stack:then", &registered)).unwrap();
    let mut record = scheduling_record(9, 2, &digest, &arm);
    (record[0], record[6], record[80]) = (2, 1, 1);
    f.event("async_task_stack", 41, 0, 6, &record);
    let mut then = segment(9, 1, 2, &digest);
    then[3] = 1;
    document_request(&mut f, 1, &[send.clone(), click], &[then]);
    // The same kind of reaction whose registration stack was not retained.
    let later = frame(1, 0, 10, at("send();\n}\n"), start("later"));
    let mut lost = segment(9, 4, 2, &[9; 32]);
    lost[3] = 1;
    document_request(&mut f, 2, &[send, later], &[lost]);
    let g = graph(&f);
    assert_eq!(g["coverage"]["malformed_records"], 0, "{}", g["coverage"]);
    let joined = edge(&g, "arm", "onClick");
    assert_eq!(
        (
            joined["kind"].as_str(),
            joined["task"].as_str(),
            joined["label"].as_str()
        ),
        (Some("task"), Some("microtask"), Some("Promise.then"))
    );
    assert_eq!(joined["sites"][0]["line"], 8, "the .then call");
    assert_eq!(node(&g, "onClick").get("chain_cut"), None);
    assert_eq!(node(&g, "later")["chain_cut"], true);
    assert_eq!(
        g["stacks"]["unresolved"]["segment_not_retained"],
        Value::Null
    );
    // The chain goes on to the top-level script that called boot.
    let top = g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["top_level"] == true)
        .unwrap();
    assert_eq!(top["entries"], 2, "this request and arm's own record");
}

#[test]
fn an_empty_store_is_an_empty_complete_graph() {
    let f = Fixture::new();
    let g = graph(&f);
    assert_eq!(
        (
            g["nodes"].as_array().unwrap().len(),
            g["complete"].as_bool()
        ),
        (0, Some(true))
    );
}

/// A store that grows is folded from where the last answer stopped, and
/// the graph it answers is the one a fresh build of the whole store gives.
#[test]
fn a_growing_store_is_folded_forward_to_the_graph_a_fresh_build_gives() {
    let mut f = iframe_wasm_fixture();
    let (graphs, names) = (Graphs::default(), no_names());
    let before = answer(&graphs, &f.inputs(), 9, &names);
    // More records of a known stack, and a new stack, arrive.
    let known = f
        .events
        .iter()
        .find(|e| e["type"] == "request_initiator_stack")
        .unwrap()
        .clone();
    for request in 200..210u64 {
        let mut copy = known.clone();
        copy["request_id"] = json!(request.to_string());
        copy["sequence_number"] = json!((f.events.len() + 1).to_string());
        f.events.push(copy);
    }
    let text = "function late() {\n  fetch('/late');\n}\n";
    f.artifact("javascript", "https://frame.test/late.js", text.as_bytes());
    f.event(
        "script_identity",
        41,
        0,
        7,
        &identity_bytes(1, 2, 60, (0, 0), 100, text.as_bytes()),
    );
    let late = frame(1, 0, 60, text.find("fetch").unwrap() as u32, 13);
    let stack = stack_artifact(2, std::slice::from_ref(&late), &[], &[]);
    let digest = hex::decode(f.artifact("stack", "reb-stack:late", &stack)).unwrap();
    f.text_event("request_initiated", 41, 300, "GET late.test");
    f.event(
        "request_initiator_stack",
        41,
        300,
        7,
        &request_record(&digest, &late, 1, 0, 0),
    );
    let inputs = f.inputs();
    let after = answer(&graphs, &inputs, 9, &names);
    assert_ne!(after["generation"], before["generation"]);
    assert_eq!(after["stacks"]["occurrences"], 15);
    assert_eq!(edge(&after, "boot", "onMessage")["count"], 12);
    assert_eq!(node(&after, "late")["line"], 1);
    let fresh = answer(&Graphs::default(), &inputs, 9, &names);
    assert_eq!(normalized(&after), normalized(&fresh));
}

/// A client pages through the generation it was answered from while the
/// store grows; the fold moves on only for a request without one, and a page
/// of a generation that is gone is a conflict, never a page of another graph.
#[test]
fn a_client_pages_one_generation_while_the_store_grows() {
    let mut f = iframe_wasm_fixture();
    let (graphs, names) = (Graphs::default(), no_names());
    let inputs = f.inputs();
    let first = (0..600)
        .map(|_| page(&graphs, &inputs, 9, None, 0, 1, &names).unwrap())
        .find(|first| first["complete"] == true)
        .expect("the indexes never caught up");
    let generation = first["generation"].as_str().unwrap().to_owned();
    assert_eq!(first["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(first["next_cursor"], 1);
    let known = f
        .events
        .iter()
        .find(|e| e["type"] == "request_initiator_stack")
        .unwrap()
        .clone();
    for request in 200..210u64 {
        let mut copy = known.clone();
        copy["request_id"] = json!(request.to_string());
        copy["sequence_number"] = json!((f.events.len() + 1).to_string());
        f.events.push(copy);
    }
    let inputs = f.inputs();
    let second = page(&graphs, &inputs, 9, Some(&generation), 1, 1, &names).unwrap();
    assert_eq!(second["generation"], first["generation"]);
    assert_eq!(second["stacks"], first["stacks"], "a page does not fold");
    assert_eq!(second["cursor"], 1);
    let past = first["node_count"].as_u64().unwrap() as u32 + 1;
    let error = page(&graphs, &inputs, 9, Some(&generation), past, 1, &names).unwrap_err();
    assert_eq!(error.status, 400);
    let grown = answer(&graphs, &inputs, 9, &names);
    assert_ne!(grown["generation"], first["generation"]);
    assert_eq!(grown["stacks"]["occurrences"], 14);
    let error = page(&graphs, &inputs, 9, Some(&generation), 1, 1, &names).unwrap_err();
    assert_eq!(error.status, 409);
}

/// Identities and stack artifacts that arrive after the stacks naming them
/// are joined then: the walks that waited are planned again, nothing they
/// added before is counted twice, and the graph is a fresh build's.
#[test]
fn late_identities_and_artifacts_are_joined_when_they_arrive() {
    let full = iframe_wasm_fixture();
    // The same records, with the inner script's identity and the posted
    // request's stack artifact held back to the end.
    let held = |e: &Value| {
        e["type"] == "script_identity" && e["payload"].as_str().unwrap()[16..24] == *"14000000"
    };
    let identity = full.events.iter().find(|e| held(e)).unwrap().clone();
    let stack = full
        .artifacts
        .iter()
        .position(|a| a["url"] == "reb-stack:y")
        .unwrap();
    let mut f = Fixture::new();
    f.events = full.events.iter().filter(|e| !held(e)).cloned().collect();
    f.artifacts = full.artifacts.clone();
    let stack = f.artifacts.remove(stack);
    for entry in std::fs::read_dir(full.root.path().join("artifacts/blobs")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(
            entry.path(),
            f.root
                .path()
                .join("artifacts/blobs")
                .join(entry.file_name()),
        )
        .unwrap();
    }
    for (at, event) in f.events.iter_mut().enumerate() {
        event["sequence_number"] = json!((at + 1).to_string());
    }
    let (graphs, names) = (Graphs::default(), no_names());
    let early = answer(&graphs, &f.inputs(), 9, &names);
    assert_eq!(early["stacks"]["unresolved"]["stack_artifact_missing"], 1);
    assert!(
        early["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["reason"] == "script_identity_missing"),
        "{}",
        early["nodes"]
    );
    let mut identity = identity;
    identity["sequence_number"] = json!((f.events.len() + 1).to_string());
    f.events.push(identity);
    f.artifacts.push(stack);
    let inputs = f.inputs();
    let late = answer(&graphs, &inputs, 9, &names);
    assert_eq!(late["stacks"]["unresolved"], json!({}));
    assert_eq!(edge(&late, "boot", "onMessage")["count"], 2);
    assert_eq!(node(&late, "onMessage")["hits"], 3);
    let fresh = answer(&Graphs::default(), &inputs, 9, &names);
    assert_eq!(normalized(&late), normalized(&fresh));
}

/// A cancelled build stops where it is; the next request goes on from
/// there to the whole graph.
#[test]
fn a_cancelled_build_keeps_a_consistent_fold() {
    let f = iframe_wasm_fixture();
    let (graphs, inputs, names) = (Graphs::default(), f.inputs(), no_names());
    let page = Page {
        generation: None,
        cursor: 0,
        limit: TEST_PAGE,
    };
    let error =
        super::graph(&graphs, &inputs, 9, page, &AtomicBool::new(true), &names).unwrap_err();
    assert_eq!(error.status, 499);
    let after = answer(&graphs, &inputs, 9, &names);
    let fresh = answer(&Graphs::default(), &inputs, 9, &names);
    assert_eq!(normalized(&after), normalized(&fresh));
}

/// Researcher names join Wasm nodes as the answer is written, and a new
/// names document writes the members again without a new graph.
#[test]
fn analyst_names_join_wasm_nodes_as_the_answer_is_written() {
    let f = iframe_wasm_fixture();
    let (graphs, inputs) = (Graphs::default(), f.inputs());
    let plain = answer(&graphs, &inputs, 9, &no_names());
    assert_eq!(node(&plain, "run").get("analyst_name"), None);
    assert_eq!(plain["analyst_names"]["joined"], 0);
    let sha = hex::encode(Sha256::digest(module()));
    let names = Arc::new(crate::wasm_names::test_names(
        json!([{"sha256": sha, "functions": [{"function": 1, "name": "encode_payload"}]}]),
    ));
    let named = answer(&graphs, &inputs, 9, &names);
    assert_eq!(named["generation"], plain["generation"]);
    assert_eq!(node(&named, "run")["analyst_name"], "encode_payload");
    assert_eq!(node(&named, "run")["sha256"], sha);
    assert_eq!(named["analyst_names"]["joined"], 1);
}
