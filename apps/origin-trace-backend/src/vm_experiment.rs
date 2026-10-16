//! Explicit tests of two fixed, owned native operations. No captured code runs.
use crate::{
    durable,
    error::{Error, Result},
    owned_vm_debugger::{Decimal, OwnedVmDebugger},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Semaphore;

const SCHEMA: &str = "reb-owned-opcode-experiments-v1";
const MAX_RECORDS: usize = 64;
const MAX_BYTES: usize = 1024 * 1024;
const REFERENCES: &str = include_str!("../../../tools/fixtures/native-vm-dispatch/references.json");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub left: Decimal,
    pub right: Decimal,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub operation: String,
    pub value: Decimal,
    pub next_pc: Decimal,
    pub branch_taken: Option<bool>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub command_id: String,
    pub fixture: String,
    pub workspace_digest: String,
    pub source_artifact_sha256: String,
    pub interpreter_artifact_id: Decimal,
    pub finding_id: String,
    pub opcode: u32,
    pub effect_id: String,
    pub inputs: Inputs,
    pub expected: Expectation,
}
impl Request {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Error::bad("Owned experiment request exceeds 4 KiB"));
        }
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|_| Error::bad("Invalid owned experiment request"))?;
        let raw: Value = serde_json::from_slice(bytes)?;
        if raw["expected"].get("branch_taken").is_none() {
            return Err(Error::bad("Expected branch_taken must be explicit"));
        }
        let identifier = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
        };
        let digest = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !identifier(&request.command_id)
            || !identifier(&request.finding_id)
            || !identifier(&request.effect_id)
            || !matches!(request.fixture.as_str(), "register" | "stack")
            || !digest(&request.workspace_digest)
            || !digest(&request.source_artifact_sha256)
            || request.interpreter_artifact_id.0 == 0
            || !matches!(
                request.expected.operation.as_str(),
                "constant"
                    | "add_modulo_2_64"
                    | "load"
                    | "store"
                    | "branch_zero"
                    | "branch_nonzero"
                    | "jump"
                    | "halt"
                    | "unknown"
            )
        {
            return Err(Error::bad(
                "Invalid owned experiment identity or expectation",
            ));
        }
        Ok(request)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    backend_instance_id: String,
    session_id: String,
    run_id: String,
    run_generation: Decimal,
    invocation_id: Decimal,
    record_sequence: Decimal,
    build_id: String,
    program_sha256: String,
    opcode: u32,
    handler_index: u32,
    pc_before: Decimal,
    instruction_pointer_units: String,
    inputs: Inputs,
    effect: Expectation,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    request: Request,
    effect_digest: String,
    fixture_revision: u32,
    status: String,
    independent: Option<Expectation>,
    observed: Option<Observation>,
    reason: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    scope: String,
    records: Vec<Record>,
}
fn empty() -> Document {
    Document { schema: SCHEMA.into(), scope: "Only the listed owned fixture, opcode, and explicit inputs are tested; results do not generalize.".into(), records: vec![] }
}
fn path(root: &Path) -> PathBuf {
    root.join("analysis/owned-opcode-experiments-v1.json")
}
fn load(root: &Path, executing: bool) -> Result<Document> {
    let Some(bytes) = durable::read_private(&path(root), MAX_BYTES)? else {
        return Ok(empty());
    };
    let mut document: Document = serde_json::from_slice(&bytes)
        .map_err(|_| Error::bad("Malformed owned experiment store"))?;
    crate::validation::schema(
        "OwnedOpcodeExperiments",
        &serde_json::to_value(&document)?,
        400,
    )?;
    let mut ids = std::collections::BTreeSet::new();
    for record in &document.records {
        Request::parse(&serde_json::to_vec(&record.request)?)?;
        let refs: Value = serde_json::from_str(REFERENCES)?;
        if !refs["sources"].as_array().unwrap().iter().any(|r| {
            r["fixture"] == record.request.fixture
                && r["sha256"] == record.request.source_artifact_sha256
        }) {
            return Err(Error::bad(
                "Stored experiment source does not match the owned fixture",
            ));
        }
        let mut canonical = canonical_effect(&record.request.fixture, record.request.opcode)?;
        let inferred_digest = hex::encode(Sha256::digest(serde_json::to_vec(&canonical)?));
        canonical["evidence_class"] = json!("observed");
        let observed_digest = hex::encode(Sha256::digest(serde_json::to_vec(&canonical)?));
        if record.request.effect_id != canonical["effect_id"].as_str().unwrap()
            || (record.effect_digest != inferred_digest && record.effect_digest != observed_digest)
        {
            return Err(Error::bad(
                "Stored experiment effect binding is inconsistent",
            ));
        }
        if record
            .observed
            .as_ref()
            .is_some_and(|o| !valid_observation(&record.request, o))
        {
            return Err(Error::bad(
                "Stored native observation identity is inconsistent",
            ));
        }
        if !ids.insert(&record.request.command_id)
            || record.independent != predict(&record.request)
            || (record.status == "confirmed"
                && (record.independent.as_ref() != Some(&record.request.expected)
                    || record.observed.as_ref().is_none_or(|o| {
                        Some(&o.effect) != record.independent.as_ref()
                            || o.inputs != record.request.inputs
                            || o.opcode != record.request.opcode
                            || !valid_observation(&record.request, o)
                    })))
        {
            return Err(Error::bad("Inconsistent owned experiment record"));
        }
    }
    if document.schema != SCHEMA || document.records.len() > MAX_RECORDS {
        return Err(Error::bad("Unsupported owned experiment store"));
    }
    // A process restart cannot turn an interrupted experiment into a success.
    for record in &mut document.records {
        if record.status == "pending" && !executing {
            record.status = "unknown".into();
            record.reason = "interrupted-execution".into();
        }
    }
    Ok(document)
}
fn save(root: &Path, document: &Document) -> Result<()> {
    crate::validation::schema(
        "OwnedOpcodeExperiments",
        &serde_json::to_value(document)?,
        500,
    )?;
    let bytes = serde_json::to_vec_pretty(document)?;
    if bytes.len() > MAX_BYTES {
        return Err(Error::bad("Owned experiment store exceeds 1 MiB"));
    }
    durable::write_private(&path(root), &bytes)
}
fn canonical_effect(fixture: &str, opcode: u32) -> Result<Value> {
    let source = if fixture == "register" {
        include_str!("../../../tools/fixtures/vm-workspace-effects/native-register.json")
    } else {
        include_str!("../../../tools/fixtures/vm-workspace-effects/native-stack.json")
    };
    let metadata: Value = serde_json::from_str(source)?;
    metadata["handlers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["opcode"] == opcode)
        .map(|h| h["effects"][0].clone())
        .ok_or_else(|| Error::bad("Unsupported owned effect"))
}
fn valid_observation(request: &Request, observed: &Observation) -> bool {
    let references: Value = serde_json::from_str(REFERENCES).expect("owned reference metadata");
    observed.opcode == request.opcode
        && observed.handler_index == request.opcode
        && observed.pc_before.0 == if request.opcode == 2 { 2 } else { 8 }
        && observed.instruction_pointer_units == "instruction-index"
        && observed.program_sha256 == references["program_manifest_sha256"].as_str().unwrap()
        && observed.run_generation.0 > 0
        && observed.invocation_id.0 > 0
        && observed.record_sequence.0 == if request.opcode == 2 { 3 } else { 8 }
}
fn bind(request: &Request, workspace: &Value) -> Result<String> {
    let refs: Value = serde_json::from_str(REFERENCES)?;
    if workspace["contract_version"] != 2
        || workspace["document_digest"] != request.workspace_digest
        || !refs["sources"].as_array().unwrap().iter().any(|r| {
            r["fixture"] == request.fixture && r["sha256"] == request.source_artifact_sha256
        })
    {
        return Err(Error::conflict(
            "Owned experiment source or workspace selection is stale",
        ));
    }
    let rows = workspace["workspaces"]
        .as_array()
        .ok_or_else(|| Error::bad("Missing workspace rows"))?;
    let selected: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["source_artifact_sha256"] == request.source_artifact_sha256
                && row["interpreter_artifact_id"] == request.interpreter_artifact_id.0.to_string()
                && row["finding_id"] == request.finding_id
        })
        .collect();
    if selected.len() != 1 {
        return Err(Error::conflict("Exact owned workspace is unavailable"));
    }
    let handlers: Vec<_> = selected[0]["handlers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|h| h["opcode"] == request.opcode)
        .collect();
    if handlers.len() != 1
        || handlers[0]["effects"]
            .as_array()
            .is_none_or(|e| e.len() != 1)
    {
        return Err(Error::conflict("Owned opcode declaration is ambiguous"));
    }
    let effect = &handlers[0]["effects"][0];
    if effect["effect_id"] != request.effect_id
        || !matches!(
            effect["evidence_class"].as_str(),
            Some("inferred" | "observed")
        )
    {
        return Err(Error::conflict("Exact owned effect is unavailable"));
    }
    let mut meaning = effect.clone();
    meaning["evidence_class"] = json!("inferred");
    if meaning != canonical_effect(&request.fixture, request.opcode)? {
        return Err(Error::conflict(
            "Selected effect meaning differs from the supported owned declaration",
        ));
    }
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(effect)?)))
}
fn predict(request: &Request) -> Option<Expectation> {
    if request.inputs.left.0 != 7 || request.inputs.right.0 != 5 {
        return None;
    }
    let sum = request.inputs.left.0.wrapping_add(request.inputs.right.0);
    match request.opcode {
        2 => Some(Expectation {
            operation: "add_modulo_2_64".into(),
            value: Decimal(sum),
            next_pc: Decimal(3),
            branch_taken: None,
        }),
        7 => Some(Expectation {
            operation: "branch_nonzero".into(),
            value: Decimal(sum),
            next_pc: Decimal(if sum != 0 { 10 } else { 9 }),
            branch_taken: Some(sum != 0),
        }),
        _ => None,
    }
}
async fn execute(helper: PathBuf, request: &Request) -> Result<Observation> {
    let debugger = OwnedVmDebugger::new(helper);
    let result = async {
        let mut view = debugger.action_bytes(&serde_json::to_vec(&json!({"action":"create", "command_id":"experiment-create", "fixture":request.fixture}))?).await?;
        let target = if request.opcode == 2 { 3 } else { 8 };
        for index in 0..target {
            let session = &view["session"];
            let action = json!({"action":"step", "command_id":format!("experiment-step-{index}"),
                "backend_instance_id":session["backend_instance_id"], "session_id":session["session_id"],
                "run_id":session["run_id"], "run_generation":session["run_generation"],
                "expected_control_revision":session["control_revision"], "expected_executed_count":session["executed_count"]});
            view = debugger.action_bytes(&serde_json::to_vec(&action)?).await?;
            if view["ack"] != "completed" { return Err(Error::conflict("Owned experiment execution is uncertain")); }
        }
        observe(request, &view["session"])
    }.await;
    // Never leave a helper running, including a failed or uncertain exchange.
    debugger.stop().await?;
    result
}
fn decimal(value: &Value) -> Result<Decimal> {
    serde_json::from_value(value.clone())
        .map_err(|_| Error::bad("Malformed native experiment value"))
}
fn observed_bits(value: &Value) -> Result<Decimal> {
    if value["evidence"] != "observed" {
        return Err(Error::conflict("Native experiment value remains unknown"));
    }
    decimal(&value["bits"])
}
fn observe(request: &Request, session: &Value) -> Result<Observation> {
    let records = session["records"]
        .as_array()
        .ok_or_else(|| Error::bad("Missing native experiment trace"))?;
    let record = records
        .last()
        .ok_or_else(|| Error::bad("Missing native experiment transition"))?;
    let before_pc = if request.opcode == 2 { "2" } else { "8" };
    if session["execution_state_known"] != true
        || session["disposal_failed"] != false
        || session["pc_units"] != "instruction-index"
        || record["opcode"] != request.opcode
        || record["opcode_evidence"] != "observed"
        || record["partial"] != false
        || record["before"]["pc"] != before_pc
        || record["before"]["pc_evidence"] != "observed"
        || record["after"]["pc_evidence"] != "observed"
        || record["before"]["partial"] != false
        || record["after"]["partial"] != false
    {
        return Err(Error::conflict("Native experiment dispatch is incomplete"));
    }
    let cells = if request.fixture == "stack" {
        "stack"
    } else {
        "registers"
    };
    let addition = records
        .iter()
        .find(|r| r["opcode"] == 2)
        .ok_or_else(|| Error::bad("Missing input transition"))?;
    let inputs = Inputs {
        left: observed_bits(&addition["before"][cells][0])?,
        right: observed_bits(&addition["before"][cells][1])?,
    };
    let index = if request.opcode == 7 && request.fixture == "register" {
        2
    } else {
        0
    };
    let value = observed_bits(&record["after"][cells][index])?;
    if request.opcode == 7 && observed_bits(&record["before"][cells][index])? != value {
        return Err(Error::conflict(
            "Selected branch state changed unexpectedly",
        ));
    }
    let next_pc = decimal(&record["after"]["pc"])?;
    let effect = Expectation {
        operation: if request.opcode == 2 {
            "add_modulo_2_64"
        } else {
            "branch_nonzero"
        }
        .into(),
        value,
        next_pc,
        branch_taken: if request.opcode == 7 {
            Some(next_pc.0 == 10)
        } else {
            None
        },
    };
    let text = |key: &str| {
        session[key]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| Error::bad("Missing native experiment provenance"))
    };
    Ok(Observation {
        backend_instance_id: text("backend_instance_id")?,
        session_id: text("session_id")?,
        run_id: text("run_id")?,
        run_generation: decimal(&session["run_generation"])?,
        invocation_id: decimal(&session["recorder"]["invocation_id"])?,
        record_sequence: decimal(&record["sequence"])?,
        build_id: text("build_id")?,
        program_sha256: text("program_sha256")?,
        opcode: request.opcode,
        handler_index: request.opcode,
        pc_before: decimal(&record["before"]["pc"])?,
        instruction_pointer_units: "instruction-index".into(),
        inputs,
        effect,
    })
}
pub struct Experiments {
    root: PathBuf,
    helper: PathBuf,
    permit: Arc<Semaphore>,
}
impl Experiments {
    pub fn new(root: PathBuf, helper: PathBuf) -> Self {
        Self {
            root,
            helper,
            permit: Arc::new(Semaphore::new(1)),
        }
    }
    pub fn list(&self) -> Result<Value> {
        Ok(serde_json::to_value(load(
            &self.root,
            self.permit.available_permits() == 0,
        )?)?)
    }
    pub async fn run(&self, bytes: &[u8], workspace: Value) -> Result<Value> {
        let request = Request::parse(bytes)?;
        let effect_digest = bind(&request, &workspace)?;
        let permit = self
            .permit
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::conflict("An owned opcode experiment is already running"))?;
        let root = self.root.clone();
        let helper = self.helper.clone();
        // Once admitted, HTTP cancellation does not cancel disposal or persistence.
        tokio::spawn(async move {
            let _permit = permit;
            let mut document = load(&root, false)?;
            if let Some(previous) = document
                .records
                .iter()
                .find(|r| r.request.command_id == request.command_id)
            {
                return if previous.request == request {
                    Ok(serde_json::to_value(previous)?)
                } else {
                    Err(Error::conflict("Experiment command ID was already used"))
                };
            }
            if document.records.len() >= MAX_RECORDS {
                return Err(Error::conflict(
                    "Owned experiment store has reached its 64-record limit",
                ));
            }
            let mut record = Record {
                independent: predict(&request),
                request,
                effect_digest,
                fixture_revision: 1,
                status: "pending".into(),
                observed: None,
                reason: "execution-not-yet-complete".into(),
            };
            document.records.push(record.clone());
            save(&root, &document)?;
            if record.independent.is_none() {
                record.status = "unsupported".into();
                record.reason = "fixed-owned-inputs-only".into();
            } else {
                match execute(helper, &record.request).await {
                    Ok(observed) => {
                        let matches = observed.inputs == record.request.inputs
                            && Some(&observed.effect) == record.independent.as_ref()
                            && record.independent.as_ref() == Some(&record.request.expected);
                        record.status = if matches { "confirmed" } else { "mismatch" }.into();
                        record.reason = if matches {
                            "agreement-for-listed-inputs-only"
                        } else {
                            "expected-or-observed-effect-differs"
                        }
                        .into();
                        record.observed = Some(observed);
                    }
                    Err(_) => {
                        record.status = "unknown".into();
                        record.reason = "native-execution-or-disposal-unconfirmed".into();
                    }
                }
            }
            *document.records.last_mut().unwrap() = record.clone();
            save(&root, &document)?;
            Ok(serde_json::to_value(record)?)
        })
        .await
        .map_err(|_| Error::new(500, "Owned experiment task failed"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(fixture: &str, opcode: u32) -> Request {
        let refs: Value = serde_json::from_str(REFERENCES).unwrap();
        let source = refs["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["fixture"] == fixture)
            .unwrap();
        let mut request = Request {
            command_id: format!("{fixture}-{opcode}"),
            fixture: fixture.into(),
            workspace_digest: "a".repeat(64),
            source_artifact_sha256: source["sha256"].as_str().unwrap().into(),
            interpreter_artifact_id: Decimal(107),
            finding_id: "finding-1".into(),
            opcode,
            effect_id: format!("effect-{opcode}"),
            inputs: Inputs {
                left: Decimal(7),
                right: Decimal(5),
            },
            expected: Expectation {
                operation: "unknown".into(),
                value: Decimal(0),
                next_pc: Decimal(0),
                branch_taken: None,
            },
        };
        request.effect_id = canonical_effect(fixture, opcode).unwrap()["effect_id"]
            .as_str()
            .unwrap()
            .into();
        request.expected = predict(&request).unwrap();
        request
    }
    fn workspace(request: &Request) -> Value {
        json!({"contract_version":2,"document_digest":request.workspace_digest,"workspaces":[{
        "source_artifact_sha256":request.source_artifact_sha256,"interpreter_artifact_id":"107","finding_id":request.finding_id,
        "handlers":[{"opcode":request.opcode,"effects":[canonical_effect(&request.fixture, request.opcode).unwrap()]}]}]})
    }
    #[test]
    fn owned_experiment_request_is_strict_and_input_prediction_independent() {
        let r = request("register", 2);
        let bytes = serde_json::to_vec(&r).unwrap();
        assert!(Request::parse(&bytes).is_ok());
        let text = String::from_utf8(bytes).unwrap();
        assert!(Request::parse(text.replacen("{", "{\"opcode\":2,", 1).as_bytes()).is_err());
        assert!(Request::parse(text.replace("\"7\"", "\"07\"").as_bytes()).is_err());
        let mut wrong = r.clone();
        wrong.expected.value = Decimal(13);
        assert_eq!(predict(&wrong), predict(&r));
        wrong.inputs.left = Decimal(8);
        assert!(predict(&wrong).is_none());
        let branch = request("stack", 7);
        assert_eq!(predict(&branch).unwrap().next_pc, Decimal(10));
    }
    #[test]
    fn owned_experiment_requires_exact_source_workspace_and_effect() {
        let mut r = request("register", 2);
        let w = workspace(&r);
        assert!(bind(&r, &w).is_ok());
        for field in ["document_digest", "contract_version"] {
            let mut bad = w.clone();
            bad[field] = json!("bad");
            assert!(bind(&r, &bad).is_err());
        }
        r.effect_id = "other".into();
        assert!(bind(&r, &w).is_err());
        r = request("register", 2);
        r.source_artifact_sha256 = "b".repeat(64);
        assert!(bind(&r, &workspace(&r)).is_err());
    }
    #[test]
    fn owned_experiment_rejects_mutated_effect_meaning_and_ambiguity() {
        let r = request("register", 2);
        let w = workspace(&r);
        for (field, value) in [
            (
                "writes",
                json!([{"space":"register","index":"3","operand":null,"value":null}]),
            ),
            (
                "flow",
                json!({"kind":"halt","target_operand":null,"target_offset":null}),
            ),
            ("operand_layout", json!([])),
        ] {
            let mut bad = w.clone();
            bad["workspaces"][0]["handlers"][0]["effects"][0][field] = value;
            assert!(bind(&r, &bad).is_err());
        }
        let mut bad = w.clone();
        let effect = bad["workspaces"][0]["handlers"][0]["effects"][0].clone();
        bad["workspaces"][0]["handlers"][0]["effects"]
            .as_array_mut()
            .unwrap()
            .push(effect);
        assert!(bind(&r, &bad).is_err());
    }
    #[tokio::test]
    async fn owned_experiment_get_preserves_active_pending_and_reports_recovery_unknown() {
        let root = tempfile::tempdir().unwrap();
        let service = Experiments::new(root.path().into(), PathBuf::from("/no-helper"));
        let r = request("register", 2);
        let record = Record {
            effect_digest: bind(&r, &workspace(&r)).unwrap(),
            independent: predict(&r),
            request: r,
            fixture_revision: 1,
            status: "pending".into(),
            observed: None,
            reason: "execution-not-yet-complete".into(),
        };
        let mut doc = empty();
        doc.records.push(record);
        save(root.path(), &doc).unwrap();
        let permit = service.permit.clone().acquire_owned().await.unwrap();
        assert_eq!(service.list().unwrap()["records"][0]["status"], "pending");
        drop(permit);
        assert_eq!(service.list().unwrap()["records"][0]["status"], "unknown");
    }
    #[tokio::test]
    async fn unsupported_owned_inputs_are_stored_without_starting_helper() {
        let root = tempfile::tempdir().unwrap();
        let service = Experiments::new(root.path().into(), PathBuf::from("/no-such-helper"));
        let mut r = request("register", 2);
        r.inputs.left = Decimal(8);
        let bytes = serde_json::to_vec(&r).unwrap();
        let result = service.run(&bytes, workspace(&r)).await.unwrap();
        assert_eq!(result["status"], "unsupported");
        assert!(result["observed"].is_null());
        assert_eq!(service.run(&bytes, workspace(&r)).await.unwrap(), result);
        assert_eq!(
            service.list().unwrap()["records"].as_array().unwrap().len(),
            1
        );
    }
    #[tokio::test]
    #[ignore = "requires REB_OWNED_VM_TEST_HELPER"]
    async fn owned_experiment_real_native_add_branch_and_wrong_expectation() {
        let helper = PathBuf::from(std::env::var_os("REB_OWNED_VM_TEST_HELPER").unwrap());
        let root = tempfile::tempdir().unwrap();
        let service = Experiments::new(root.path().into(), helper);
        for fixture in ["register", "stack"] {
            for opcode in [2, 7] {
                let r = request(fixture, opcode);
                let w = workspace(&r);
                let result = service
                    .run(&serde_json::to_vec(&r).unwrap(), w.clone())
                    .await
                    .unwrap();
                assert_eq!(result["status"], "confirmed", "{result}");
                assert_eq!(result["observed"]["handler_index"], opcode);
                let mut wrong = r;
                wrong.command_id.push_str("-wrong");
                wrong.expected.value = Decimal(13);
                let result = service
                    .run(&serde_json::to_vec(&wrong).unwrap(), w)
                    .await
                    .unwrap();
                assert_eq!(result["status"], "mismatch");
            }
        }
        assert_eq!(
            service.list().unwrap()["records"].as_array().unwrap().len(),
            8
        );
    }
    #[tokio::test]
    #[ignore = "requires REB_OWNED_VM_TEST_HELPER"]
    async fn owned_experiment_cancellation_finishes_and_reaps_before_persisting() {
        let helper = PathBuf::from(std::env::var_os("REB_OWNED_VM_TEST_HELPER").unwrap());
        let root = tempfile::tempdir().unwrap();
        let service = Arc::new(Experiments::new(root.path().into(), helper));
        let r = request("register", 7);
        let w = workspace(&r);
        let bytes = serde_json::to_vec(&r).unwrap();
        let owner = service.clone();
        let caller = tokio::spawn(async move { owner.run(&bytes, w).await });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if service.list().unwrap()["records"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        caller.abort();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if service.permit.available_permits() == 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(service.list().unwrap()["records"][0]["status"], "confirmed");
        let mut doc = load(root.path(), false).unwrap();
        doc.records[0].observed.as_mut().unwrap().pc_before = Decimal(0);
        durable::write_private(&path(root.path()), &serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(service.list().is_err());
    }
}
