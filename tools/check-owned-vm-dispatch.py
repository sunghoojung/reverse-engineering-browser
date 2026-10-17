#!/usr/bin/env python3
"""Verify opt-in owned dispatch export through the actual native event broker."""

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path



def check_artifact_scoped_ui(repository, analyzer, artifacts, store, artifact):
    """Actual analyzer output from authored same-source/session-scoped inputs."""
    other = dict(artifact, artifact_id="207", session_id="201")
    snapshot_bytes = bytes([1, 7, 8])  # Authored manifest fixture, not a browser capture.
    snapshot_hash = hashlib.sha256(snapshot_bytes).hexdigest()
    (artifacts / "blobs" / f"{snapshot_hash}.bin").write_bytes(snapshot_bytes)
    snapshot = dict(artifact, artifact_id="108", parent_artifact_id="107",
                    capture_origin="runtime_typed_array", kind="bytecode_buffer",
                    mime_type="application/octet-stream", byte_size=len(snapshot_bytes),
                    sha256=snapshot_hash, content_path=f"blobs/{snapshot_hash}.bin")
    (artifacts / "manifest.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in [artifact, other, snapshot]))
    (artifacts / "capture-provenance-v1.json").write_text(json.dumps({"contract_version": 1, "sessions": [
        {"session_id": "101", "capture_mode": "native-stealth"},
        {"session_id": "201", "capture_mode": "cdp-attached"}]}))
    subprocess.run([analyzer, "--artifacts", str(artifacts), "--events", str(store)],
                   capture_output=True, check=True, timeout=30)
    analysis = json.loads((artifacts / "analysis/vm-analysis-v1.json").read_text())
    document = json.loads((artifacts / "analysis/vm-opcode-workspace-v2.json").read_text())
    assert len(analysis["results"]) == 2
    assert len({row["finding_id"] for row in analysis["results"]}) == 1
    model = (repository / "apps/research-ui/evidence_models.js").read_text()
    app = (repository / "apps/research-ui/app.js").read_text()
    presentation = app[app.index("      function vmSessionPresentation"):app.index("      function renderVmSessionStatus")]
    exercise = "\nconst analysis=" + json.dumps(analysis) + ";const document=" + json.dumps(document) + ";" + r"""
const assert=require('node:assert/strict');
assert(isVmAnalysisDocument(analysis)); assert(isVmOpcodeWorkspaceDocument(document));
const findings=vmFindingsFromAnalysis(analysis);
assert.equal(new Set(findings.map(row=>row.findingId)).size,2);
for(const [artifact,mode,count,label,samples] of [
  ['107','native-stealth',1,'Native stealth',9], ['207','cdp-attached',0,'CDP attached',0]]) {
  const finding=findings.find(row=>row.sourceArtifactId===artifact);
  const selected=vmOpcodeWorkspaceForFinding(document,finding);
  assert.equal(selected.interpreter_artifact_id,artifact); assert.equal(selected.capture_mode,mode);
  assert.equal(selected.snapshots.length,count); assert.equal(selected.sample_count,samples);
  assert.equal(vmSessionPresentation({vmOpcodeWorkspace:document,vmAnalysisDocument:analysis,
    vmFindings:findings,selectedVmFindingId:finding.findingId}).label,label);
}
"""
    subprocess.run(["node"], input=model + presentation + exercise, text=True,
                   capture_output=True, check=True, timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--broker", required=True)
    parser.add_argument("--analyzer")
    args = parser.parse_args()
    ids = {
        "session": 101,
        "navigation": 102,
        "frame": 103,
        "invocation": 104,
        "finding": 105,
        "investigation": 106,
        "interpreter-artifact": 107,
        "bytecode-artifact": 108,
    }
    common = [item for key, value in ids.items() for item in (f"--{key}-id", str(value))]
    repository = Path(__file__).resolve().parents[1]
    references_root = repository / "tools/fixtures/native-vm-dispatch"
    references = json.loads((references_root / "references.json").read_text())
    assert references["program_manifest_sha256"] == hashlib.sha256(
        (repository / "protocol/owned-vm-programs-v1.json").read_bytes()
    ).hexdigest()
    for fixture in ("register", "stack"):
        reference = next(row for row in references["sources"] if row["fixture"] == fixture)
        source = (references_root / reference["path"]).read_bytes()
        digest = hashlib.sha256(source).hexdigest()
        assert reference["sha256"] == digest
        command = [args.binary, "--emit-dispatch-events-v1", "--fixture", fixture, *common]
        produced = subprocess.run(command, capture_output=True, check=True, timeout=10)
        assert not produced.stderr
        with tempfile.TemporaryDirectory(prefix="reb-owned-dispatch-") as root:
            store = Path(root) / "events.jsonl"
            broker = subprocess.run(
                [args.broker, "--store", str(store)],
                input=produced.stdout,
                capture_output=True,
                check=True,
                timeout=10,
            )
            assert b"accepted=10" in broker.stderr, broker.stderr
            events = [json.loads(line) for line in store.read_text().splitlines()]
            if args.analyzer:
                artifacts = Path(root) / "artifacts"
                (artifacts / "blobs").mkdir(parents=True)
                (artifacts / "blobs" / f"{digest}.bin").write_bytes(source)
                artifact = {"protocol_version": 1, "artifact_id": "107", "session_id": "101",
                            "navigation_id": "102", "frame_id": "103", "parent_artifact_id": "0",
                            "creator_event_id": "0", "execution_context_id": "1",
                            "capture_origin": "dynamic_javascript", "kind": "javascript",
                            "url": f"fixture://declared-native-reference/{fixture}.js", "mime_type": "text/javascript",
                            "byte_size": len(source), "sha256": digest, "sensitive": False,
                            "content_path": f"blobs/{digest}.bin"}
                (artifacts / "manifest.jsonl").write_text(json.dumps(artifact) + "\n")
                subprocess.run([args.analyzer, "--artifacts", str(artifacts), "--events", str(store)],
                               capture_output=True, check=True, timeout=30)
                document = json.loads((artifacts / "analysis/vm-opcode-workspace-v2.json").read_text())
                assert document["contract_version"] == 2
                workspace = document["workspaces"][0]
                assert workspace["source_artifact_sha256"] == digest
                assert workspace["sample_count"] == 9 and len(workspace["samples"]) == 9
                assert {row["opcode"]: row["sample_count"] for row in workspace["handlers"]} == {
                    1: 2, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1}
                assert all(row["state"] == "observed" for row in workspace["handlers"])
                assert all(row["instruction_pointer_units"] == "instruction-index" for row in workspace["samples"])
                assert all(row["invocation_id"] == "104" for row in workspace["samples"])
                assert workspace["coverage"]["characterized_bytes"] == 0
                assert not workspace["coverage"]["complete"]
                check_artifact_scoped_ui(repository, args.analyzer, artifacts, store, artifact)
        assert len(events) == 10
        marker, *samples = events
        assert marker["type"] == "vm_finding" and marker["sequence_number"] == "1"
        marker_bytes = bytes.fromhex(marker["payload"])
        assert marker_bytes[4:8] == bytes([3, 0, 1, 4])
        assert struct.unpack_from("<QQQQ", marker_bytes, 24) == (105, 106, 104, 108)
        assert marker_bytes[72:72 + len(f"owned-{fixture}-v1")] == f"owned-{fixture}-v1".encode()
        for index, event in enumerate(samples):
            assert event["type"] == "vm_dispatch_sample"
            assert event["category"] == "vm"
            assert event["sequence_number"] == str(index + 2)
            assert event["parent_event_id"] == "1"
            assert event["artifact_id"] == "107"
            assert event["session_id"] == "101"
            assert event["navigation_id"] == "102"
            assert event["frame_id"] == "103"
            assert event["process_id"] == marker["process_id"] > 0
            data = bytes.fromhex(event["payload"])
            assert len(data) == 128 and event["payload_size"] == 128
            assert struct.unpack_from("<HH", data) == (1, 128)
            assert struct.unpack_from("<IIII", data, 4) == (
                [0, 1, 2, 3, 4, 5, 6, 8, 10][index],
                [1, 1, 2, 3, 4, 5, 6, 7, 8][index],
                [1, 1, 2, 3, 4, 5, 6, 7, 8][index],
                index,
            )
            assert struct.unpack_from("<QQQQ", data, 24) == (105, 106, 107, 108)
            assert data[20:24] == bytes(4) and data[56] == 0 and data[58:] == bytes(70)
            assert data[57] == [1, 1, 2, 1, 1, 2, 1, 2, 0][index]
        host_command = [*command]
        host_command[1] = "--emit-host-dispatch-events-v1"
        produced = subprocess.run(host_command, capture_output=True, check=True, timeout=10)
        assert not produced.stderr
        with tempfile.TemporaryDirectory(prefix="reb-owned-host-") as temporary:
            root = Path(temporary)
            store = root / "events.jsonl"
            subprocess.run([args.broker, "--store", str(store)], input=produced.stdout,
                           capture_output=True, check=True, timeout=10)
            host_events = [json.loads(line) for line in store.read_text().splitlines()]
            assert len(host_events) == 11
            host = next(event for event in host_events if event["category"] == "runtime")
            assert bytes.fromhex(host["payload"]) == b"owned.monotonic_clock.after_instruction"
            assert host["type"] == "api_call" and host["sequence_number"] == "5"
            assert host["parent_event_id"] == "4"
            sample = next(event for event in host_events if event["sequence_number"] == "4")
            assert struct.unpack_from("<I", bytes.fromhex(sample["payload"]), 4)[0] == 2
            assert host["process_id"] == sample["process_id"]
            if args.analyzer:
                artifacts = root / "artifacts"
                (artifacts / "blobs").mkdir(parents=True)
                (artifacts / "blobs" / f"{digest}.bin").write_bytes(source)
                (artifacts / "manifest.jsonl").write_text(json.dumps(artifact) + "\n")
                def analyze(records):
                    store.write_text("".join(json.dumps(event) + "\n" for event in records))
                    subprocess.run([args.analyzer, "--artifacts", str(artifacts), "--events", str(store)],
                                   capture_output=True, check=True, timeout=30)
                    document = json.loads((artifacts / "analysis/vm-host-links-v1.json").read_text())
                    workspace = json.loads((artifacts / "analysis/vm-opcode-workspace-v2.json").read_text())
                    assert document["workspace_document_digest"] == workspace["document_digest"]
                    assert "payload" not in json.dumps(document)
                    return document["workspaces"][0]
                link = analyze(host_events)["links"][0]
                assert link["state"] == "observed" and link["guest_position"]["instruction_pointer"] == 2
                assert link["guest_position"]["instruction_pointer_units"] == "instruction-index"
                assert link["host_event"]["sequence_number"] == "5"
                assert link["guest_position"]["sample_event"]["sequence_number"] == "4"
                without_samples = [event for event in host_events if event["type"] != "vm_dispatch_sample"]
                missing = analyze(without_samples)
                assert missing["links"][0]["guest_position"] is None
                assert "dispatch-samples-unavailable" in missing["omissions"]
                unproven = dict(host, parent_event_id="1")
                records = [unproven if event is host else event for event in host_events]
                assert analyze(records)["links"][0]["state"] == "correlated"
                assert analyze([*host_events, unproven])["links"] == []
        for invalid in (
            command[:-1], command + ["--session-id", "101"],
            command[:3] + ["unknown"] + command[4:],
            command[:-1] + ["0"], command[:-1] + ["01"],
            command[:-1] + ["18446744073709551616"],
            command[:6] + ["--session-id", "102"] + command[8:],
        ):
            rejected = subprocess.run(invalid, capture_output=True, check=False, timeout=10)
            assert rejected.returncode == 2 and not rejected.stdout, invalid
    print("Owned register/stack dispatch export: all 18 instructions and two real owned-clock calls stored by the broker")
    if args.analyzer:
        print("Actual analyzer UI selection: identical source findings retain separate session modes, samples and snapshot joins")


if __name__ == "__main__":
    main()
