#!/usr/bin/env python3
"""Write a deterministic long-session evidence store from authored data only.

The store under OUT holds events.jsonl, origin-trace.jsonl and artifacts/. Its
first records are an early Wasm module, the runtime read that starts an early
request, and that request's renderer and browser records, joined by stored
Origin Trace edges. Every later record is newer traffic, runtime reads and
JavaScript artifacts, so a reader that sees only a newest window, a first page
or a fixed count of rows loses the early ones. Serve it with
`origin-trace-backend --store OUT/events.jsonl --trace-store
OUT/origin-trace.jsonl --artifacts OUT/artifacts` or open it in Origin Trace.

The defaults (200,000 requests, 300,000 artifacts) write about 450 MB of
events. No captured data is read and nothing is sent.
"""
import argparse
import hashlib
import json
import os
import sys

# The smallest module that exports one function returning 42.
WASM = bytes.fromhex("0061736d01000000010501600001" "7f030201000a06010400412a0b")


def compact(record):
    return json.dumps(record, separators=(",", ":")) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("out", help="an empty or absent directory")
    parser.add_argument("--requests", type=int, default=200_000)
    parser.add_argument("--artifacts", type=int, default=300_000)
    args = parser.parse_args()
    if os.path.exists(args.out) and os.listdir(args.out):
        sys.exit(f"{args.out} is not empty; choose a new directory")
    blobs = os.path.join(args.out, "artifacts", "blobs")
    os.makedirs(blobs, exist_ok=True)

    def blob(content):
        digest = hashlib.sha256(content).hexdigest()
        path = os.path.join(blobs, f"{digest}.bin")
        if not os.path.exists(path):
            with open(path, "wb") as handle:
                handle.write(content)
        return digest

    def artifact(identifier, kind, url, mime, content):
        digest = blob(content)
        return {
            "protocol_version": 1, "artifact_id": str(identifier), "session_id": "1",
            "navigation_id": "1", "frame_id": "1", "parent_artifact_id": "0",
            "creator_event_id": "0", "kind": kind, "url": url, "mime_type": mime,
            "byte_size": len(content), "sha256": digest, "sensitive": False,
            "content_path": f"blobs/{digest}.bin",
        }

    with open(os.path.join(args.out, "artifacts", "manifest.jsonl"), "w") as manifest:
        manifest.write(compact(artifact(1, "wasm", "https://early.test/module.wasm", "application/wasm", WASM)))
        for index in range(args.artifacts):
            # 64 distinct bodies keep the blob directory small.
            content = f"console.log({index % 64});\n".encode()
            manifest.write(compact(artifact(index + 2, "javascript", f"https://cdn.later.test/chunk-{index}.js",
                                            "text/javascript", content)))

    base = {
        "protocol_version": 3, "session_id": "1", "navigation_id": "1", "frame_id": "1",
        "artifact_id": "0", "tab_id": 1, "category": "network", "payload_encoding": "hex",
        "parent_event_id": "0", "request_id": "0", "browser_context_id_high": "1", "browser_context_id_low": "2",
        "initiator_request_id": 0, "initiator_process_id": 0, "status_code": 0, "error_code": 0,
        "resource_type": 13, "flags": 0, "payload_truncated": False,
        "encoded_data_length": "0", "decoded_body_length": "0",
    }
    # Process 100 is the browser, 200 the renderer; each stream is contiguous.
    sequence = {100: 0, 200: 0}
    clock = [1_000_000]

    def event(process, kind, text, **fields):
        sequence[process] += 1
        clock[0] += 1000
        payload = text.encode().hex()
        record = dict(base, process_id=process, thread_id=process + 1,
                      sequence_number=str(sequence[process]), monotonic_time_ns=str(clock[0]),
                      type=kind, payload=payload, payload_size=len(payload) // 2)
        record.update(fields)
        return record

    with open(os.path.join(args.out, "events.jsonl"), "w") as events, \
            open(os.path.join(args.out, "origin-trace.jsonl"), "w") as trace:
        def write(record):
            events.write(compact(record))
            return record

        def edge(relation, source, target, request="0"):
            trace.write(compact({
                "protocol_version": 1, "session_id": "1",
                "from_process_id": source["process_id"], "from_sequence_number": source["sequence_number"],
                "to_process_id": target["process_id"], "to_sequence_number": target["sequence_number"],
                "relation": relation, "confidence": "observed", "request_id": request, "artifact_id": "0",
            }))

        source = write(event(200, "property_read", "navigator.userAgent", category="runtime"))
        initiated = write(event(200, "request_initiated", "GET early.test", request_id="1",
                                parent_event_id=source["sequence_number"]))
        started = write(event(100, "request_started", "GET early.test", request_id="1",
                              initiator_process_id=200, initiator_request_id=1))
        write(event(100, "response_started", "application/wasm; protocol=h2", request_id="1", status_code=200))
        write(event(100, "request_completed", "completed", request_id="1", status_code=200,
                    encoded_data_length="44", decoded_body_length="44"))
        edge("parent_event", initiated, source)
        edge("request_initiator", started, initiated, "1")

        for index in range(2, args.requests + 2):
            host = f"api-{index % 997}.later.test"
            request = str(index)
            write(event(100, "request_started", f"GET {host}", request_id=request))
            write(event(100, "response_started", "application/json; protocol=h2", request_id=request, status_code=200))
            write(event(100, "request_completed", "completed", request_id=request, status_code=200,
                        encoded_data_length=str(1000 + index % 5000), decoded_body_length=str(2000 + index % 5000)))
            if index % 4 == 0:
                write(event(200, "property_read", "document.cookie", category="runtime"))


if __name__ == "__main__":
    main()
