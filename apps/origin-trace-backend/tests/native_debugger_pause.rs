//! The pausing debugger through the HTTP routes, against the contract peer.
//! No Brave process, no invented frame, scope or value.
#![cfg(unix)]

use origin_trace_backend::native_debugger_pause::{
    Engine, FIXTURE_CHILD_TARGET, FIXTURE_SCRIPT_ID, FIXTURE_TARGET, Peer,
};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server {
    child: Child,
    url: String,
    client: reqwest::Client,
    _root: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    async fn start(socket: Option<&Path>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let endpoint = root.path().join("endpoint");
        let mut command = Command::new(env!("CARGO_BIN_EXE_origin-trace-backend"));
        command
            .args(["--port", "0", "--endpoint-file"])
            .arg(&endpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if let Some(socket) = socket {
            command.arg("--native-debugger-socket").arg(socket);
        }
        for (flag, name) in [
            ("--store", "events.jsonl"),
            ("--trace-store", "trace.jsonl"),
            ("--signal-store", "signals.jsonl"),
            ("--artifacts", "artifacts"),
            ("--api-collection", "collection.json"),
            ("--local-analyst", "analyst.json"),
        ] {
            command.arg(flag).arg(root.path().join(name));
        }
        let mut child = command.spawn().unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let url = loop {
            if let Ok(url) = std::fs::read_to_string(&endpoint) {
                break url.trim().to_owned();
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "backend exited before publishing its endpoint"
            );
            assert!(
                Instant::now() < deadline,
                "backend startup exceeded its deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        Self {
            child,
            url,
            client,
            _root: root,
        }
    }

    async fn state(&self) -> Value {
        let response = self
            .client
            .get(format!("{}/api/native-debugger", self.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        response.json().await.unwrap()
    }

    /// The next pause, read the way a client must: a step reply says the page
    /// resumed, and the pause it lands on is a later fact.
    async fn paused(&self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let state = self.state().await;
            if state["paused"] == Value::Bool(true) {
                return state;
            }
            assert!(Instant::now() < deadline, "the page never paused again");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn post(&self, body: &Value) -> (u16, Value) {
        let response = self
            .client
            .post(format!("{}/api/native-debugger/actions", self.url))
            .json(body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (status, response.json().await.unwrap())
    }
}

fn target() -> String {
    FIXTURE_TARGET.to_string()
}

/// The routing field every action repeats, plus whatever it adds.
fn command(action: Value) -> Value {
    let mut body = json!({"target_id": target()});
    for (key, value) in action.as_object().unwrap() {
        body[key] = value.clone();
    }
    body
}

async fn select(server: &Server) {
    let (status, result) = server
        .post(&command(
            json!({"action": "select_document", "confirm_pause": true}),
        ))
        .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["status"], "ok");
}

async fn conditional_breakpoint(server: &Server) -> String {
    let (status, result) = server
        .post(&command(json!({"action": "set_breakpoint",
            "script_id": FIXTURE_SCRIPT_ID, "line": 7, "column": 4,
            "condition": "item === 2", "confirm_pause": true})))
        .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["breakpoint"]["kind"], "conditional");
    assert_eq!(result["breakpoint"]["resolved"], true);
    result["breakpoint"]["breakpoint_id"]
        .as_str()
        .expect("a set breakpoint has an id")
        .to_owned()
}

#[tokio::test]
async fn without_a_peer_the_debugger_is_unsupported_and_sends_nothing() {
    let server = Server::start(None).await;
    let state = server.state().await;
    assert_eq!(state["availability"], "unsupported");
    assert_eq!(state["reason"], "browser_debugger_unsupported");
    assert_eq!(state["policy"], "approved");
    assert_eq!(state["detectable"], true);
    assert_eq!(state["lease_limit_ms"], 60000);
    assert_eq!(state["document"], Value::Null);
    assert_eq!(state["pause"], Value::Null);
    assert_eq!(state["paused"], false);
    assert_eq!(state["quiet_mode"], Value::Null);
    assert_eq!(state["breakpoints"], json!([]));
    // Phase 1 still answers from the local store.
    assert_eq!(state["watch"]["state"], "none");

    let (status, error) = server
        .post(&command(
            json!({"action": "select_document", "confirm_pause": true}),
        ))
        .await;
    assert_eq!(status, 503);
    assert_eq!(error["code"], "dependency_unavailable");
    assert!(
        error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no page paused, stepped or resumed")
    );
}

#[tokio::test]
async fn an_unconfirmed_or_unknown_action_is_refused_before_the_socket() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    for body in [
        command(json!({"action": "select_document"})),
        command(json!({"action": "pause"})),
        command(
            json!({"action": "set_breakpoint", "script_id": FIXTURE_SCRIPT_ID,
            "line": 7, "column": 4}),
        ),
        command(json!({"action": "teleport"})),
        command(json!({"action": "resume", "lease_id": "0"})),
        json!({"action": "resume", "lease_id": "1"}),
    ] {
        let (status, error) = server.post(&body).await;
        assert_eq!(status, 400, "{body} -> {error}");
    }
    assert_eq!(server.state().await["document"], Value::Null);
}

#[tokio::test]
async fn a_conditional_breakpoint_pauses_and_its_scopes_read_in_pages() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    assert_eq!(server.state().await["availability"], "available");
    select(&server).await;
    let breakpoint = conditional_breakpoint(&server).await;

    let state = server.state().await;
    assert_eq!(state["document"]["target_id"], target());
    assert_eq!(state["quiet_mode"], true);
    assert_eq!(state["breakpoints"][0]["breakpoint_id"], breakpoint);
    assert_eq!(state["paused"], false);

    peer.with_engine(Engine::run);
    let state = server.state().await;
    assert_eq!(state["paused"], true);
    assert_eq!(state["pause"]["reason"], "breakpoint");
    assert_eq!(state["pause"]["breakpoint_id"], breakpoint);
    assert_eq!(state["pause"]["frames_recorded"], 2);
    assert_eq!(state["pause"]["frames_truncated"], false);
    assert_eq!(state["pause"]["frames"][0]["function_name"], "collect");
    assert_eq!(state["pause"]["frames"][0]["script_id"], FIXTURE_SCRIPT_ID);
    assert_eq!(state["pause"]["frames"][0]["line"], 7);
    assert_eq!(state["lease"]["state"], "active");
    assert!(state["lease"]["expires_in_ms"].as_u64().unwrap() > 0);
    let lease = state["lease"]["lease_id"].as_str().unwrap().to_owned();
    let scope = state["pause"]["frames"][0]["scopes"][0]["object_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, result) = server
        .post(&command(
            json!({"action": "get_properties", "lease_id": lease,
            "object_id": scope, "offset": 0}),
        ))
        .await;
    assert_eq!(status, 200, "{result}");
    let names: Vec<&str> = result["properties"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["item", "items", "total"]);
    assert_eq!(result["properties"]["next_offset"], Value::Null);

    // An array property expands into its own paged object.
    let items = result["properties"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "items")
        .and_then(|item| item["object_id"].as_str())
        .expect("an array property can be expanded")
        .to_owned();
    let (_, page) = server
        .post(&command(
            json!({"action": "get_properties", "lease_id": lease,
            "object_id": items, "offset": 0}),
        ))
        .await;
    assert_eq!(page["properties"]["total"], 4);
    assert_eq!(page["properties"]["items"][3]["name"], "length");

    let (_, watch) = server
        .post(&command(
            json!({"action": "evaluate_on_frame", "lease_id": lease,
            "call_frame_index": 0, "expression": "total + item"}),
        ))
        .await;
    assert_eq!(watch["status"], "ok");
    assert_eq!(watch["value"]["text"], "3");
    assert_eq!(watch["value"]["threw"], false);

    let (_, threw) = server
        .post(&command(
            json!({"action": "evaluate_on_frame", "lease_id": lease,
            "call_frame_index": 0, "expression": "nope"}),
        ))
        .await;
    assert_eq!(threw["status"], "evaluation_error");
    assert_eq!(threw["value"]["threw"], true);
}

#[tokio::test]
async fn stepping_and_resume_run_the_page_on() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    select(&server).await;
    conditional_breakpoint(&server).await;
    peer.with_engine(Engine::run);
    let mut lease = server.state().await["lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();

    for (action, function, line) in [
        ("step_into", "add", 2),
        ("step_out", "collect", 6),
        ("step_over", "collect", 7),
    ] {
        let (status, result) = server
            .post(&command(json!({"action": action, "lease_id": lease})))
            .await;
        assert_eq!(status, 200, "{result}");
        assert_eq!(result["status"], "ok");
        assert_eq!(result["resumed"], true);
        // The command let the page run. Whether it stopped again is a later
        // fact, so the reply carries no pause and the state is read for it.
        assert_eq!(result["paused"], false, "{action}");
        assert_eq!(result["pause"], Value::Null, "{action}");

        let state = server.paused().await;
        assert_eq!(state["pause"]["reason"], "step");
        assert_eq!(
            state["pause"]["frames"][0]["function_name"], function,
            "{action}"
        );
        assert_eq!(state["pause"]["frames"][0]["line"], line, "{action}");
        assert_eq!(state["active_indication"], "Debugger active (detectable)");
        let next = state["lease"]["lease_id"].as_str().unwrap().to_owned();
        assert_ne!(next, lease, "a step takes a fresh lease");
        // The lease it replaced cannot drive the new pause.
        let (_, stale) = server
            .post(&command(json!({"action": "resume", "lease_id": lease})))
            .await;
        assert_eq!(stale["status"], "stale_lease");
        assert_eq!(stale["paused"], true);
        lease = next;
    }

    let (_, resumed) = server
        .post(&command(json!({"action": "resume", "lease_id": lease})))
        .await;
    assert_eq!(resumed["status"], "ok");
    assert_eq!(resumed["resumed"], true);
    assert_eq!(resumed["paused"], false);
    let state = server.state().await;
    assert_eq!(state["paused"], false);
    assert_eq!(state["pause"], Value::Null);
    assert_eq!(state["lease"]["state"], "released");
    assert_eq!(state["lease"]["expires_in_ms"], 0);
}

#[tokio::test]
async fn navigation_clears_the_authorization_and_the_old_generation_is_gone() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    select(&server).await;
    conditional_breakpoint(&server).await;
    peer.with_engine(Engine::run);
    let lease = server.state().await["lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();

    peer.with_engine(Engine::navigate);
    let state = server.state().await;
    assert_eq!(state["document"], Value::Null);
    assert_eq!(state["last_clear"], "navigated");
    assert_eq!(state["paused"], false);
    assert_eq!(state["breakpoints"], json!([]));
    assert_eq!(
        state["availability"], "available",
        "the peer is still there"
    );

    // The retired generation is gone for every command, and the generation
    // that replaced it is a document nothing selected.
    for body in [
        command(json!({"action": "resume", "lease_id": lease})),
        command(json!({"action": "select_document", "confirm_pause": true})),
    ] {
        let (_, stale) = server.post(&body).await;
        assert_eq!(stale["status"], "stale_document", "{body}");
        assert_eq!(
            stale["action"], body["action"],
            "a refusal names its action"
        );
    }
    let current = peer.with_engine(|engine| engine.target()).to_string();
    let (_, unauthorized) = server
        .post(&json!({"action": "resume", "target_id": current, "lease_id": lease}))
        .await;
    assert_eq!(unauthorized["status"], "not_authorized");
}

#[tokio::test]
async fn an_expired_lease_resumes_the_page_and_the_state_says_so() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    select(&server).await;
    conditional_breakpoint(&server).await;
    peer.with_engine(Engine::run);
    let lease = server.state().await["lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();

    peer.with_engine(Engine::expire_lease);
    let state = server.state().await;
    assert_eq!(state["paused"], false);
    assert_eq!(state["pause"], Value::Null);
    assert_eq!(state["lease"]["state"], "expired");
    assert_eq!(state["lease"]["lease_id"], lease);
    assert_eq!(
        state["document"]["target_id"],
        target(),
        "the authorization outlives the lease"
    );

    let (_, refused) = server
        .post(&command(json!({"action": "step_over", "lease_id": lease})))
        .await;
    assert_eq!(refused["status"], "not_paused");
}

#[tokio::test]
async fn a_peer_that_stops_answering_is_unavailable_and_the_command_outcome_is_unknown() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let socket = peer.socket().to_path_buf();
    let server = Server::start(Some(&socket)).await;
    select(&server).await;
    drop(peer);

    let state = server.state().await;
    assert_eq!(state["availability"], "unsupported");
    assert_eq!(state["reason"], "peer_unavailable");
    assert_eq!(
        state["document"],
        Value::Null,
        "no stale authorization is kept"
    );
    assert_eq!(state["breakpoints"], json!([]));

    let (status, error) = server
        .post(&command(json!({"action": "pause", "confirm_pause": true})))
        .await;
    assert_eq!(status, 503);
    assert_eq!(error["code"], "dependency_unavailable");
}

#[tokio::test]
async fn a_same_process_iframe_is_an_ordinary_selection() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    let child = FIXTURE_CHILD_TARGET.to_string();
    let (status, result) = server
        .post(&json!({"action": "select_document", "target_id": child,
            "confirm_pause": true}))
        .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["status"], "ok");
    let state = server.state().await;
    assert_eq!(state["document"]["target_id"], child);
    assert_eq!(state["document"]["frame"], "child");
    assert_eq!(state["active_indication"], "Debugger active (detectable)");

    // The top document is a current document that nothing selected.
    let (_, refused) = server
        .post(&command(json!({"action": "pause", "confirm_pause": true})))
        .await;
    assert_eq!(refused["status"], "not_authorized");
    assert_eq!(refused["action"], "pause");
    // Refused with no side effect: naming another document is not a way to
    // take the selection away from the one that holds it.
    let state = server.state().await;
    assert_eq!(state["document"]["target_id"], child);
    assert_eq!(state["last_clear"], Value::Null);
}

/// V8 takes any condition and a condition it cannot evaluate just does not
/// stop the page. The contract peer behaves the same way, so a client cannot
/// learn from a refusal here something the browser would not have told it.
#[tokio::test]
async fn a_condition_the_debugger_cannot_evaluate_is_set_and_never_stops_the_page() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    select(&server).await;
    let (status, result) = server
        .post(&command(
            json!({"action": "set_breakpoint", "script_id": 1, "line": 6,
            "column": 0, "condition": "item ===", "confirm_pause": true}),
        ))
        .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["breakpoint"]["kind"], "conditional");
    assert_eq!(result["breakpoint"]["condition_set"], true);

    peer.with_engine(|engine| engine.run());
    assert_eq!(
        server.state().await["paused"],
        false,
        "a condition that cannot be evaluated is not a pause"
    );

    // Removing it answers that it is gone and nothing else.
    let id = result["breakpoint"]["breakpoint_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, removed) = server
        .post(&command(
            json!({"action": "remove_breakpoint", "breakpoint_id": id}),
        ))
        .await;
    assert_eq!(status, 200, "{removed}");
    assert_eq!(removed["status"], "ok");
    assert_eq!(removed["breakpoint"], Value::Null);
    assert_eq!(server.state().await["breakpoints"], json!([]));
}

#[tokio::test]
async fn replacing_a_selection_resumes_and_disarms_the_one_it_replaced() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    select(&server).await;
    conditional_breakpoint(&server).await;
    peer.with_engine(|engine| engine.run());
    assert_eq!(server.paused().await["paused"], true);

    let (status, result) = server
        .post(&json!({"action": "select_document",
            "target_id": FIXTURE_CHILD_TARGET.to_string(), "confirm_pause": true}))
        .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["status"], "ok");
    // The reply describes the new selection, which has not paused and holds
    // no lease: in the browser this is answered by a session created for the
    // document being selected, which knows nothing of the one it replaced.
    assert_eq!(result["resumed"], false);
    assert_eq!(result["pause"], Value::Null);
    assert_eq!(result["lease"], Value::Null);

    let state = server.state().await;
    assert_eq!(
        state["document"]["target_id"],
        FIXTURE_CHILD_TARGET.to_string()
    );
    assert_eq!(state["paused"], false, "the replaced document was resumed");
    assert_eq!(state["breakpoints"], json!([]), "nothing stays armed");
    assert_eq!(state["lease"], Value::Null, "the new selection holds none");
}

/// The back-forward cache and a detached frame both end the authorization the
/// way a navigation does, and only one of them retires the id.
#[tokio::test]
async fn the_cache_and_a_detach_end_the_authorization_as_a_navigation_does() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    select(&server).await;
    conditional_breakpoint(&server).await;
    peer.with_engine(Engine::run);
    assert_eq!(server.paused().await["paused"], true);

    // Stored into the back-forward cache: the document stopped running, so
    // the authorization ends as a navigation ends it, and the page is not
    // left paused. The id is not retired, so it can be selected again.
    peer.with_engine(Engine::store_in_back_forward_cache);
    let state = server.state().await;
    assert_eq!(state["document"], Value::Null);
    assert_eq!(state["last_clear"], "navigated", "not a lost connection");
    assert_eq!(state["paused"], false);
    assert_eq!(state["breakpoints"], json!([]), "nothing stays armed");
    let (status, again) = server
        .post(&command(
            json!({"action": "select_document", "confirm_pause": true}),
        ))
        .await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["status"], "ok", "the restored id still names it");

    // A detached frame takes its document with it, so its id names nothing.
    let child = FIXTURE_CHILD_TARGET.to_string();
    let (_, selected) = server
        .post(&json!({"action": "select_document", "target_id": child,
            "confirm_pause": true}))
        .await;
    assert_eq!(selected["status"], "ok");
    peer.with_engine(Engine::detach_child);
    let state = server.state().await;
    assert_eq!(state["document"], Value::Null);
    assert_eq!(state["last_clear"], "navigated");
    let (_, gone) = server
        .post(&json!({"action": "pause", "target_id": child,
            "confirm_pause": true}))
        .await;
    assert_eq!(gone["status"], "stale_document");
}

/// Selecting the document that is already selected keeps its session: the
/// pause, its lease and its breakpoints are all still there afterwards.
#[tokio::test]
async fn selecting_the_same_document_again_keeps_the_pause_and_its_lease() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    select(&server).await;
    conditional_breakpoint(&server).await;
    peer.with_engine(Engine::run);
    let paused = server.paused().await;
    let lease = paused["lease"]["lease_id"].as_str().unwrap().to_owned();

    let (status, again) = server
        .post(&command(
            json!({"action": "select_document", "confirm_pause": true}),
        ))
        .await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["status"], "ok");
    assert_eq!(again["paused"], true, "the pause is still there");
    assert_eq!(again["lease"]["lease_id"], lease, "and so is its lease");
    assert_eq!(again["lease"]["state"], "active");
    assert_eq!(again["resumed"], false);

    let state = server.state().await;
    assert_eq!(state["paused"], true);
    assert_eq!(state["lease"]["lease_id"], lease);
    assert_eq!(state["breakpoints"].as_array().unwrap().len(), 1);
    assert_eq!(state["last_clear"], Value::Null);
    // The lease it still holds is the one that works.
    let (_, resumed) = server
        .post(&command(json!({"action": "resume", "lease_id": lease})))
        .await;
    assert_eq!(resumed["status"], "ok");
    assert_eq!(resumed["resumed"], true);
}

/// Losing the client is not a way to hold a page: the deadline belongs to the
/// browser and runs whether or not anything can still reach it.
#[tokio::test]
async fn the_browser_resumes_a_pause_after_the_backend_is_gone() {
    let peer = Peer::spawn(Engine::new()).unwrap();
    peer.with_engine(|engine| engine.set_lease_limit_ms(60));
    let server = Server::start(Some(peer.socket())).await;
    select(&server).await;
    conditional_breakpoint(&server).await;
    peer.with_engine(|engine| engine.run());
    assert_eq!(server.paused().await["paused"], true);

    // The whole client goes away mid-pause.
    drop(server);
    let deadline = Instant::now() + Duration::from_secs(10);
    while peer.with_engine(|engine| engine.is_paused()) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !peer.with_engine(|engine| engine.is_paused()),
        "the browser resumed the page with no client left"
    );
    assert!(peer.with_engine(|engine| engine.state_value()["lease"]["state"] == "expired"));
}
