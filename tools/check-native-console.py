#!/usr/bin/env python3
"""Exercise the real C++ console transport; --browser also exercises Blink/V8.

The fake browser mode is an explicitly synthetic wire fixture for HTTP/UI tests,
not evidence that the browser overlay compiled or executed JavaScript.
"""

import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

MAGIC = 0x43424552
REQUEST = struct.Struct("<IHHQQII")
RESPONSE = struct.Struct("<IHHQHHIII")
HELLO = struct.Struct("<IHHQ32s16s")
TARGET = struct.Struct("<QHHI256sHH128s512sI")


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise EOFError("native peer disconnected")
        data.extend(chunk)
    return bytes(data)


def connect(path):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(10)
    deadline = time.monotonic() + 5
    while True:
        try:
            stream.connect(str(path))
            return stream
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() >= deadline:
                stream.close()
                raise
            time.sleep(0.02)


def response(stream, request, kind, payload=b"", status=0, count=0, flags=0):
    stream.sendall(RESPONSE.pack(MAGIC, 2, status, request, kind, flags, count, len(payload), 0) + payload)


def fnv1a(text):
    value = 0xcbf29ce484222325
    for byte in text.encode():
        value = ((value ^ byte) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


class DocumentStart:
    """Synthetic mirror of the browser-process registry: bounded, non-draining.

    It never compiles or runs JavaScript. It exists so the owner's wire
    admission, cursor, drop counting and refusal paths are exercised by the
    real C++ transport and the real HTTP API.
    """

    CAPACITY = 128
    PAGE = 32

    def __init__(self, permitted):
        self.permitted = permitted
        self.generation = 0
        self.next_script = 1
        self.next_sequence = 1
        self.scripts = []
        self.output = []
        self.dropped = 0

    def record(self, script, kind, text):
        if len(self.output) >= self.CAPACITY:
            self.output.pop(0)
            self.dropped += 1
        self.output.append({
            "sequence": str(self.next_sequence), "record": kind,
            "provenance": "console-document-start-script", "script_id": script["script_id"],
            "document_id": "7", "frame_id": "99", "top_frame": script["rule"]["frame"] == "top",
            "time": 1700000000000.0, "truncated": False, "text": text,
        })
        self.next_sequence += 1
        script["records"] += 1
        if kind == "injected":
            script["injected_documents"] += 1
        if kind == "refused":
            script["refused"] += 1

    def refusal(self, text):
        # Mirror the browser: report what is still armed, without the output
        # page a reader already has.
        state = self.state(0)
        state.pop("output", None)
        state["status"] = "error"
        state["text"] = text
        return state

    def arm(self, scripts):
        if not isinstance(scripts, list) or not 1 <= len(scripts) <= 4:
            return self.refusal("Arm 1 to 4 document-start scripts")
        prepared = []
        total = 0
        for entry in scripts:
            if not isinstance(entry, dict) or entry.get("frame") not in {"top", "child"}:
                return self.refusal("A document-start rule matches frame top or child")
            source = entry.get("source") or ""
            total += len(source.encode())
            if not source or len(source.encode()) > 4096 or total > 8192:
                return self.refusal("Document-start snippet exceeds its source limit")
            rule = {"origin": entry["origin"], "frame": entry["frame"]}
            if entry.get("path_prefix"):
                rule["path_prefix"] = entry["path_prefix"]
            prepared.append({"script_id": str(self.next_script), "rule": rule,
                             "source_bytes": len(source.encode()), "digest": fnv1a(source),
                             "records": 0, "injected_documents": 0, "refused": 0, "source": source})
            self.next_script += 1
        self.scripts = prepared
        self.generation += 1
        self.output = []
        self.dropped = 0
        # A matching new document would run each armed script exactly once.
        for script in self.scripts:
            self.record(script, "injected", "Snippet ran before this document's own scripts")
            if "__flood__" in script["source"]:
                for index in range(200):
                    self.record(script, "report", f"flood-{index}")
            else:
                self.record(script, "report", "kinds=string:12 return=4 digest=0f0f")
        return self.state(0)

    def clear(self):
        # A synthetic stand-in for a clear the browser could not apply, so the
        # owner's unconfirmed-removal path runs through the real C++ relay.
        if any("__refuse_clear__" in script["source"] for script in self.scripts):
            return self.refusal("Synthetic browser kept the armed set")
        self.generation += 1
        self.scripts = []
        self.output = []
        self.dropped = 0
        return self.state(0)

    def state(self, after):
        page = [record for record in self.output if int(record["sequence"]) > after][:self.PAGE]
        return {
            "status": "ok", "contract_version": 3, "permitted": self.permitted,
            "generation": str(self.generation), "renderer_processes": 1,
            "pending_renderer_processes": 0,
            "scripts": [{key: value for key, value in script.items() if key != "source"}
                        for script in self.scripts],
            "output": {
                "records": page, "next_sequence": str(self.next_sequence),
                "oldest_sequence": self.output[0]["sequence"] if self.output else "0",
                "retained": len(self.output), "dropped": self.dropped,
                "unattributed": 0, "stale": 0,
            },
        }

    def command(self, source):
        try:
            command = json.loads(source)
        except json.JSONDecodeError:
            return self.refusal("Malformed document-start command")
        if not self.permitted:
            return {"status": "unavailable", "permitted": False, "scripts": [],
                    "text": "This browser session does not permit document-start scripts"}
        operation = command.get("operation")
        if operation == "arm":
            return self.arm(command.get("scripts"))
        if operation == "clear":
            return self.clear()
        if operation == "state":
            cursor = command.get("after")
            if not isinstance(cursor, str) or not cursor.isdigit():
                return self.refusal("state takes a decimal after cursor")
            return self.state(int(cursor))
        return self.refusal("Unknown document-start operation")


def fake_browser(arguments):
    flags = dict(argument[2:].split("=", 1) for argument in arguments if argument.startswith("--") and "=" in argument)
    assert not any("remote-debugging" in argument for argument in arguments)
    # The switch alone permits the experiment; it arms nothing by itself.
    document_start = DocumentStart("--reb-native-console-document-start" in arguments)
    live = "--reb-native-console-live-binding" in arguments
    token_path = Path(flags["reb-native-console-token-file"])
    assert token_path.stat().st_mode & 0o777 == 0o600
    assert token_path.parent.stat().st_mode & 0o777 == 0o700
    assert Path(flags["user-data-dir"]) == token_path.parent / "profile"
    (token_path.parent / "fixture-pid").write_text(f"{os.getpid()} {os.getppid()}")
    stream = connect(flags["reb-native-console-socket"])
    stream.sendall(HELLO.pack(0x52454249, 1, 64, int(flags["reb-native-console-session-id"]), bytes.fromhex(token_path.read_text().strip()), bytes(16)))
    stream.settimeout(None)
    origin = b"http://127.0.0.1:fixture"
    target_id = 0
    handles = {}
    pending_handles = set()
    logs = []
    next_handle = 0
    last = None
    try:
        while True:
            magic, version, operation, request, target, size, reserved = REQUEST.unpack(exact(stream, 32))
            assert magic == MAGIC and version == 2 and reserved == 0 and size <= (65536 if operation == 3 else 8192)
            source = exact(stream, size).decode()
            if operation == 1:
                # A live capture document keeps its identity across listings; a
                # disposable fixture renumbers so stale-target paths are reachable.
                if not (live and target_id):
                    target_id += 1
                response(stream, request, 10, TARGET.pack(target_id, len(origin), 2, 0, origin, 27, 29, b"Synthetic transport fixture", b"http://127.0.0.1:fixture/page", 0), count=1,
                         flags=2 if document_start.permitted else 0)
            elif operation == 4:
                # No target: the armed set belongs to the session, so it can
                # never be pinned to or satisfied by a stale document.
                assert target == 0
                response(stream, request, 12, json.dumps(document_start.command(source)).encode())
            elif target != target_id:
                response(stream, request, 0, b"Selected document changed", status=2)
            elif operation == 3:
                command = json.loads(source)
                op = command["operation"]
                value = {"status": "ok"}
                if op == "evaluate":
                    expression = command["source"]
                    if expression == "while (true) {}":
                        response(stream, request, 0, b"fixture execution timeout", status=5)
                        continue
                    elif expression == "__malformed_native_reply__":
                        stream.sendall(RESPONSE.pack(MAGIC, 2, 0, request, 11, 0, 0, 0xFFFFFFFF, 0))
                        continue
                    elif expression.startswith("throw "):
                        value = {"status": "exception", "text": "Error: fixture exception", "location": {"url": "reb-console", "line": 1, "column": 7}, "stack": [{"url": "reb-console", "line": 1, "column": 7}]}
                    else:
                        kind, text = "string", expression
                        if expression == "window.fixture + 1":
                            kind, text = "number", "42"
                        elif expression == "console.log(\"hello\")":
                            kind, text = "undefined", "undefined"
                            logs.append({"text": "hello", "url": "reb-console", "line": 1, "level": "info", "time": 1, "stack": "", "truncated": False})
                        elif expression.startswith("await ") or expression == "new Promise(() => {})":
                            kind, text = "promise", "Promise {<pending>}"
                        elif expression == "window.previewObject":
                            kind, text = "object", "Object"
                        elif expression == "document.body":
                            kind, text = "object", "<BODY>"
                        elif expression == "document.querySelector":
                            kind, text = "function", "ƒ querySelector(…)"
                        elif expression == "$_" and last:
                            kind, text = last["type"], last["text"]
                        preview = {"type": kind, "text": text, "truncated": False}
                        if kind in ["object", "function", "promise"]:
                            next_handle += 1
                            preview["handle"] = str(next_handle)
                            handles[str(next_handle)] = preview
                            if expression == "new Promise(() => {})":
                                pending_handles.add(str(next_handle))
                        if kind == "function":
                            preview["location"] = {"url": "https://checkout.acme.test/assets/cart.js", "line": 1, "column": 1}
                        value["value"] = preview
                        last = preview
                elif op == "poll":
                    value.update(messages=logs.copy(), dropped=0)
                    logs.clear()
                elif op == "traffic":
                    value.update(events=[{"event_id": "1", "document_id": str(target), "resource_id": "81", "after_request_id": "2", "origin": "http://127.0.0.1", "method": "GET", "status": 200, "network_error": 0, "cached": False, "time": 1, "operation": "resource_load_complete"}], dropped=0)
                elif op == "clear":
                    handles.clear()
                    logs.clear()
                    last = None
                elif op == "complete":
                    entries = ["fixture", "previewObject"] if not command["path"] else ["value", "toString"]
                    value["items"] = [{"name": name, "kind": "function" if name == "toString" else "property"} for name in entries if name.startswith(command["prefix"])]
                elif op == "last":
                    value["value"] = last
                elif command.get("handle") not in handles:
                    value = {"status": "error", "text": "Value expired, was released, or belongs to another document"}
                elif op == "inspect":
                    properties = [{"name": "value", "accessor": True, "value": {"type": "accessor", "text": "[Getter / Setter]", "truncated": False}}, {"name": "fixture", "value": {"type": "number", "text": "41", "truncated": False}}] if command["offset"] == 0 else []
                    value.update(properties=properties, more=False, offset=2)
                elif op == "await" and command["handle"] in pending_handles:
                    value["status"] = "pending"
                elif op == "await":
                    value["value"] = {"type": "number", "text": "42", "truncated": False}
                elif op in ["release", "cancel"]:
                    handles.pop(command["handle"])
                    value["text"] = "Value released"
                elif op == "store":
                    value["text"] = "window.temp1"
                elif op == "source":
                    value["text"] = "function querySelector(selector) { /* synthetic fixture */ }"
                elif op == "listeners":
                    value.update(properties=[], more=False, offset=0, truncated=False)
                elif op in ["monitor", "unmonitor"]:
                    value["text"] = "Synthetic event monitor response"
                response(stream, request, 11, json.dumps(value).encode())
            elif source == "__malformed_native_reply__":
                stream.sendall(RESPONSE.pack(MAGIC, 2, 0, request, 4, 0, 0, 0xFFFFFFFF, 0))
            elif source.startswith("throw "):
                response(stream, request, 0, b"fixture exception", status=4)
            elif source == "while (true) {}":
                response(stream, request, 0, b"fixture execution timeout", status=5)
            elif source == "window.fixture + 1":
                response(stream, request, 3, b"42")
            else:
                response(stream, request, 4, source.encode()[:8192])
    except (EOFError, BrokenPipeError, ConnectionResetError):
        pass
    finally:
        stream.close()
    return 0


def kill_browser_group(process):
    try:
        os.killpg(process.pid, 9)
    except ProcessLookupError:
        pass
    except PermissionError:
        # macOS returns EPERM for a group containing only an unreaped zombie.
        # Reap that child, but preserve permission failures for a live peer.
        if process.poll() is None:
            raise


@contextlib.contextmanager
def bridge(binary, browser=None, binary_mode=True, document_start=False):
    with tempfile.TemporaryDirectory(prefix="reb-console-check.", dir="/tmp") as directory:
        # Chromium canonicalizes aliases such as /tmp on macOS. Keep the
        # explicitly owned socket, token and profile under that same root.
        root = Path(directory).resolve()
        token = root / "token"
        token.write_text(secrets.token_hex(32) + "\n")
        token.chmod(0o600)
        command = [str(binary), "--socket", str(root / "console.sock"), "--token-file", str(token), "--session", "1"]
        if binary_mode:
            command.append("--bridge")
        console = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        browser_arguments = ["--reb-native-console", f"--reb-native-console-socket={root / 'console.sock'}", f"--reb-native-console-token-file={token}", "--reb-native-console-session-id=1", f"--user-data-dir={root / 'profile'}", "--no-first-run", "--no-default-browser-check", "--use-mock-keychain", "--password-store=basic"]
        if document_start:
            browser_arguments.append("--reb-native-console-document-start")
        child = None
        try:
            if browser:
                browser_arguments.append(browser[1])
                child = subprocess.Popen([browser[0], *browser_arguments], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            else:
                # An unauthenticated peer must not consume the console session.
                with connect(root / "console.sock") as bad:
                    bad.sendall(HELLO.pack(0x52454249, 1, 64, 1, bytes(32), bytes(16)))
                child = subprocess.Popen([sys.executable, __file__, *browser_arguments], start_new_session=True)
            console.native_browser = child
            yield console
        finally:
            for process in [console, child]:
                if process:
                    # Only a real browser owns a process tree. The synthetic
                    # peer is one process that can be mid-exit as the console
                    # closes, when macOS refuses killpg with EPERM before the
                    # exit is visible to poll().
                    if process is child and browser:
                        kill_browser_group(process)
                    process.kill()
                    process.wait(timeout=5)
            if console.stdin:
                console.stdin.close()
            if console.stdout:
                console.stdout.close()
            if console.stderr:
                console.stderr.close()


def exchange(process, request, operation=1, target=0, source=""):
    encoded = source.encode()
    process.stdin.write(REQUEST.pack(MAGIC, 2, operation, request, target, len(encoded), 0) + encoded)
    process.stdin.flush()
    header = process.stdout.read(32)
    assert len(header) == 32, "C++ bridge closed before a response"
    fields = RESPONSE.unpack(header)
    assert fields[:2] == (MAGIC, 2) and fields[3] == request and fields[8] == 0
    payload = process.stdout.read(fields[7])
    assert len(payload) == fields[7]
    return fields, payload


class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        content = b"<!doctype html><title>Native console fixture</title><script>window.fixture=41;window.previewCalls=0;window.previewObject={get value(){window.previewCalls++;return 1},toString(){window.previewCalls++;return 'unsafe'}};</script><h1>Native console fixture</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *_args):
        pass


def wait_unreaped(pid, timeout=5):
    """Return once pid has exited, leaving it unreaped like waitid(WNOWAIT)."""
    if hasattr(os, "waitid"):
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
        return
    # macOS Python before 3.13 has no waitid; ps reports the zombie as Z.
    deadline = time.monotonic() + timeout
    while not subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                             text=True).stdout.strip().startswith("Z"):
        assert time.monotonic() < deadline, "Exited fixture never became a zombie"
        time.sleep(0.01)


def check(binary, browser):
    # Keep an exited group leader unreaped, exactly as a peer can be when
    # the console closes its socket before bridge() tears the fixture down.
    with subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True) as exited:
        wait_unreaped(exited.pid)
        kill_browser_group(exited)
        assert exited.wait(timeout=5) == 0, "Exited browser fixture was not reaped"
    for flag in ["--version", "-v", "-V"]:
        assert subprocess.check_output([binary, flag]) == b"2\n"
    invalid = subprocess.run([binary, "--unexpected"], capture_output=True)
    assert invalid.returncode == 2 and b"USAGE" in invalid.stdout
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    try:
        with bridge(binary, (browser, url) if browser else None) as process:
            request = 0
            def run(operation=1, target=0, source=""):
                nonlocal request
                request += 1
                return exchange(process, request, operation, target, source)
            deadline = time.monotonic() + 15
            while True:
                header, payload = run()
                if header[6]:
                    break
                assert time.monotonic() < deadline, "HTTP fixture never became an eligible frame"
                time.sleep(0.1)
            target = TARGET.unpack(payload[:TARGET.size])[0]
            header, payload = run(2, target, "window.fixture + 1")
            assert header[2] == 0 and header[4] == 3 and payload == b"42"
            header, _ = run(2, target, "throw 'fixture'")
            assert header[2] == 4
            header, _ = run(2, target, "while (true) {}")
            assert header[2] == 5
            header, payload = run(2, target, "window.fixture + 1")
            assert header[2] == 0 and payload == b"42", "Execution did not recover after timeout"
            if browser:
                header, _ = run(2, target, "window.previewObject")
                assert header[4] == 8
                _, payload = run(2, target, "window.previewCalls")
                assert payload == b"0", "Preview invoked page code"
                header, payload = run(2, target, "'雪'.repeat(8192)")
                assert header[5] == 1 and len(payload) <= 8192
                payload.decode("utf-8", errors="strict")
                def runtime(operation, **fields):
                    header, data = run(3, target, json.dumps({"operation": operation, **fields}))
                    assert header[4] == 11 and header[2] == 0, (header, data)
                    return json.loads(data)
                logged = runtime("evaluate", source='console.log("hello")')
                assert logged["value"]["type"] == "undefined", logged
                assert any(message["text"] == "hello" for message in runtime("poll")["messages"])
                obj = runtime("evaluate", source="window.previewObject")["value"]
                properties = runtime("inspect", handle=obj["handle"], offset=0)["properties"]
                assert next(p for p in properties if p["name"] == "value")["accessor"]
                assert runtime("evaluate", source="window.previewCalls")["value"]["text"] == "0"
                runtime("evaluate", source="let consoleLexical = {method() {return 1}}")
                assert any(item["name"] == "consoleLexical" for item in runtime("complete", path=[], prefix="consoleLex" )["items"])
                assert any(item["name"] == "method" for item in runtime("complete", path=["consoleLexical"], prefix="met")["items"])
                # Engine REPL promises are distinct from promises returned by
                # user code. Top-level await may settle before the reply.
                awaited = runtime("evaluate", source="await Promise.resolve(42)")["value"]
                if awaited["type"] == "promise":
                    awaited = runtime("await", handle=awaited["handle"])["value"]
                assert awaited["type"] == "number" and awaited["text"] == "42", awaited
                deferred = runtime("evaluate", source="await new Promise(resolve => setTimeout(() => resolve(43), 500))")["value"]
                assert deferred["type"] == "promise", deferred
                assert runtime("await", handle=deferred["handle"])["status"] == "pending"
                assert runtime("store", handle=deferred["handle"])["status"] == "error"
                last_deferred = runtime("last")["value"]
                deadline = time.monotonic() + 5
                while True:
                    settled = runtime("await", handle=last_deferred["handle"])
                    if settled["status"] != "pending":
                        break
                    assert time.monotonic() < deadline, settled
                    time.sleep(.05)
                assert settled["status"] == "ok" and settled["value"]["text"] == "43", settled
                promise = runtime("evaluate", source="Promise.resolve(42)")["value"]
                assert promise["type"] == "promise", promise
                assert runtime("await", handle=promise["handle"])["value"]["text"] == "42"
                # An object that resembles the engine wrapper remains user
                # evidence, including its property descriptor and getter.
                fake = runtime("evaluate", source="Promise.resolve({get ['.repl_result']() { window.previewCalls++; return 99 }})")["value"]
                fake_result = runtime("await", handle=fake["handle"])["value"]
                assert fake_result["type"] == "object", fake_result
                assert runtime("inspect", handle=fake_result["handle"], offset=0)["properties"][0]["accessor"]
                assert runtime("evaluate", source="window.previewCalls")["value"]["text"] == "0"
                runtime("release", handle=obj["handle"])
                assert runtime("inspect", handle=obj["handle"], offset=0)["status"] == "error"
                stored = runtime("store", handle=promise["handle"])["text"]
                assert stored.startswith("window.temp")
                assert runtime("evaluate", source=stored)["value"]["type"] == "promise"
                function = runtime("evaluate", source="function consoleSample(a) {return a}; consoleSample")["value"]
                assert "consoleSample" in runtime("source", handle=function["handle"])["text"]
                dom = runtime("evaluate", source="document.body")["value"]
                runtime("evaluate", source="document.body.addEventListener('click', function fixtureClick() {})")
                assert any(prop["name"].startswith("click") and prop["value"]["type"] == "function" for prop in runtime("listeners", handle=dom["handle"])["properties"])
                runtime("monitor", handle=dom["handle"])
                runtime("evaluate", source="document.body.click()")
                assert any(message["text"] == "event: click" for message in runtime("poll")["messages"])
                # Standalone unmonitorEvents reevaluates the Element and gets a
                # new handle. Monitoring follows native node identity, not IDs.
                same_dom = runtime("evaluate", source="document.body")["value"]
                runtime("unmonitor", handle=same_dom["handle"])
                runtime("evaluate", source="document.body.click()")
                assert not any(message["text"] == "event: click" for message in runtime("poll")["messages"])
                pending = runtime("evaluate", source="new Promise(() => {})")["value"]
                assert runtime("await", handle=pending["handle"])["status"] == "pending"
                runtime("cancel", handle=pending["handle"])
                assert runtime("await", handle=pending["handle"])["status"] == "error"
                typed = runtime("evaluate", source="new Uint8Array(65537)")["value"]
                typed_properties = runtime("inspect", handle=typed["handle"], offset=65520)
                assert typed_properties.get("truncated"), typed_properties
                assert typed_properties["status"] == "ok" and len(typed_properties["properties"]) == 16
                assert all(prop["value"]["type"] == "number" and prop["value"]["text"] == "0" for prop in typed_properties["properties"])
                proxy = runtime("evaluate", source="new Proxy(new Uint8Array(4), {getOwnPropertyDescriptor() { window.previewCalls++; return undefined }})")["value"]
                assert runtime("inspect", handle=proxy["handle"], offset=0)["status"] == "error"
                assert runtime("evaluate", source="window.previewCalls")["value"]["text"] == "0"
                runtime("evaluate", source="for (let i=0;i<40;i++) console.log('queue-' + i)")
                messages = runtime("poll")
                assert len(messages["messages"]) <= 32 and messages["dropped"] > 0
                # JSON escaping must be charged before enqueue. This batch fit
                # the old 32 KiB raw-text budget but exceeded the 64 KiB reply,
                # losing all logs after poll had already reset its drop count.
                runtime("evaluate", source="for (let i=0;i<16;i++) console.log(String.fromCharCode(1).repeat(2048))")
                messages = runtime("poll")
                assert messages["status"] == "ok" and messages["messages"]
                assert len(messages["messages"]) + messages["dropped"] == 16
                assert messages["dropped"] > 0
                assert all(message["text"] == "\x01" * 2048 for message in messages["messages"])
                assert runtime("poll")["dropped"] == 0
                runtime("evaluate", source="fetch('/console-resource')")
                deadline = time.monotonic() + 5
                while True:
                    activity = runtime("traffic")
                    if activity["events"]:
                        break
                    assert time.monotonic() < deadline, "No browser resource completion metadata"
                    time.sleep(.05)
                assert all(event["document_id"] == str(target) and event["operation"] == "resource_load_complete" for event in activity["events"])
                assert runtime("evaluate", source="throw new Error('console failure')")["status"] == "exception"
                runtime("clear")
                run(2, target, "location.href = '/next'; 1")
                time.sleep(0.3)
            else:
                run()
            header, _ = run(2, target, "window.fixture + 1")
            assert header[2] == 2, "Stale selection was reused"
            if browser:
                process.stdin.close()
                assert process.wait(timeout=5) == 0
                process.native_browser.wait(timeout=10)
        with bridge(binary) as process:
            # A browser session without the switch must leave the capability
            # bit clear, so the owner never sends operation 4 to it.
            header, _ = exchange(process, 1)
            assert header[5] & 2 == 0, "A session without the switch advertised document-start support"
        with bridge(binary, document_start=True) as process:
            request = 0
            def run(operation=1, target=0, source=""):
                nonlocal request
                request += 1
                return exchange(process, request, operation, target, source)
            header, _ = run()
            assert header[5] & 2 == 2, "A permitted session did not advertise document-start support"
            def document_start(**command):
                header, payload = run(4, 0, json.dumps(command))
                assert header[4] == 12 and header[2] == 0, (header, payload)
                return json.loads(payload)
            idle = document_start(operation="state", after="0")
            assert idle["status"] == "ok" and idle["scripts"] == [] and idle["permitted"]
            armed = document_start(operation="arm", scripts=[
                {"origin": "http://127.0.0.1:8080", "frame": "top", "path_prefix": "/lab/",
                 "source": "report('kinds=string:12');"}])
            assert armed["status"] == "ok" and len(armed["scripts"]) == 1, armed
            assert armed["scripts"][0]["rule"] == {"origin": "http://127.0.0.1:8080", "frame": "top", "path_prefix": "/lab/"}
            records = armed["output"]["records"]
            assert [record["record"] for record in records] == ["injected", "report"], records
            assert all(record["provenance"] == "console-document-start-script" for record in records)
            # Reads never drain: the same cursor repeats, a later cursor advances.
            assert document_start(operation="state", after="0")["output"]["records"] == records
            assert document_start(operation="state", after=records[-1]["sequence"])["output"]["records"] == []
            # Each refusal leaves the previously armed set exactly as it was.
            for refused in [
                {"operation": "arm", "scripts": []},
                {"operation": "arm", "scripts": [{"origin": "https://a.test", "frame": "any", "source": "1"}]},
                {"operation": "arm", "scripts": [{"origin": "https://a.test", "frame": "top", "source": "a" * 4097}]},
                {"operation": "unknown"},
                {"operation": "state", "after": "not-a-number"},
            ]:
                refusal = document_start(**refused)
                assert refusal["status"] == "error", refused
                assert refusal["scripts"] == armed["scripts"], refused
                assert "output" not in refusal, "a refusal must not re-send records"
            assert document_start(operation="state", after="0")["scripts"] == armed["scripts"]
            # A bounded ring drops the oldest records with a visible count.
            flooded = document_start(operation="arm", scripts=[
                {"origin": "https://a.test", "frame": "child", "source": "report('__flood__');"}])
            assert flooded["output"]["dropped"] > 0, flooded["output"]
            assert flooded["output"]["retained"] <= 128
            assert len(flooded["output"]["records"]) <= 32
            cleared = document_start(operation="clear")
            assert cleared["status"] == "ok" and cleared["scripts"] == []
            assert cleared["output"]["records"] == [] and cleared["output"]["dropped"] == 0
            # Operation 4 is session-scoped: a target makes it malformed, so a
            # stale document can never satisfy or block the armed set.
            process.stdin.write(REQUEST.pack(MAGIC, 2, 4, request + 1, 1, 2, 0) + b"{}")
            process.stdin.flush()
            assert process.wait(timeout=5) == 1, "A document-start request with a target was accepted"
        with bridge(binary) as process:
            _, targets = exchange(process, 1)
            target = TARGET.unpack(targets)[0]
            process.stdin.write(REQUEST.pack(MAGIC, 2, 2, 2, target, 8193, 0))
            process.stdin.flush()
            assert process.wait(timeout=5) == 1, "Oversized input was accepted"
        with bridge(binary) as process:
            _, targets = exchange(process, 1)
            target = TARGET.unpack(targets)[0]
            malformed = b"__malformed_native_reply__"
            process.stdin.write(REQUEST.pack(MAGIC, 2, 2, 2, target, len(malformed), 0) + malformed)
            process.stdin.flush()
            assert process.wait(timeout=7) == 1, "Oversized peer response was accepted"
        with bridge(binary, binary_mode=False) as process:
            output, _ = process.communicate(b":use 1\nwindow.fixture + 1\nthrow 'fixture'\n:quit\n", timeout=10)
            assert process.returncode == 1 and b"42" in output and b"EXCEPTION" in output, "Scripted errors must exit nonzero"
        with bridge(binary, binary_mode=False) as process:
            process.communicate(b":unknown\n:quit\n", timeout=10)
            assert process.returncode == 2, "Invalid stdin commands must exit with a usage error"
        print("PASS native console version/usage, authentication, actual C++ pipe/socket handoff, malformed lengths, stale selection, exception/timeout responses")
        print("PASS document-start capability advertisement, session-scoped operation 4, non-draining cursor, bounded ring drops, refusals that preserve the armed set")
        print("PASS real Blink/V8 execution, timeout recovery, preview isolation and Unicode bounds" if browser else "NOT RUN browser overlay compilation and actual Blink/V8 execution; supply --browser after rebuilding Brave")
    finally:
        server.shutdown()
        server.server_close()


def check_backend(binary, backend):
    # Exercise the real public API, Rust manager and native C++ relay. Only the
    # final browser peer is synthetic. Keep every fixture store private.
    with tempfile.TemporaryDirectory(prefix="reb-console-http.", dir="/tmp") as directory:
        root = Path(directory)
        endpoint = root / "endpoint"
        live_directory = root / ("long-capture-path-" * 4) / ("session-evidence-" * 4)
        live_directory.mkdir(parents=True, mode=0o700)
        assert len(str(live_directory / "console.sock").encode()) > 108
        command = [backend, "--port", "0", "--endpoint-file", str(endpoint),
                   "--native-console", binary, "--brave-binary", str(Path(__file__).resolve()),
                   "--native-console-live-directory", str(live_directory)]
        for flag in ["store", "trace-store", "signal-store", "artifacts", "api-collection", "local-analyst"]:
            command += [f"--{flag}", str(root / flag)]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        live_peer = None
        live_transport = None
        def call(action=None, status=200, headers=None, path=None):
            data = json.dumps(action).encode() if action is not None else None
            route = path or ("/api/native-console/actions" if data else "/api/native-console")
            request = urllib.request.Request(url + route, data=data,
                                             headers={"Content-Type": "application/json", **(headers or {})})
            try:
                result = urllib.request.urlopen(request, timeout=40)
            except urllib.error.HTTPError as error:
                result = error
            with result:
                assert result.status == status, (result.status, result.read())
                return json.load(result)

        def read_document_start(after="0", status=200):
            return call(status=status, path=f"/api/native-console/document-start?after_sequence={after}")
        try:
            deadline = time.monotonic() + 15
            while not endpoint.exists():
                assert process.poll() is None, "Backend exited before publishing its endpoint"
                assert time.monotonic() < deadline
                time.sleep(0.02)
            url = endpoint.read_text().strip()
            binding = live_directory / "binding"
            assert binding.is_file(), "Long capture path prevented the live Console binding"
            live_id, live_socket, live_token = binding.read_text().splitlines()
            live_transport = Path(live_socket).parent
            assert len(live_socket.encode()) < 104 and Path(live_socket).is_socket()
            assert live_transport.stat().st_mode & 0o777 == 0o700
            assert Path(live_token).stat().st_mode & 0o777 == 0o600
            # A capture launched with REB_CONSOLE_DOCUMENT_START=1: its registry
            # outlives every Console connection, exactly like the real browser's.
            live_peer = subprocess.Popen([
                sys.executable, __file__, "--reb-native-console",
                "--reb-native-console-live-binding", "--reb-native-console-document-start",
                f"--reb-native-console-socket={live_socket}",
                f"--reb-native-console-token-file={live_token}",
                f"--reb-native-console-session-id={live_id}",
                f"--user-data-dir={live_transport / 'profile'}",
            ])
            state = call()
            assert state["available"] and state["state"] == "idle"
            assert state["live_available"] and state["targets"], "Live bridge did not authenticate"
            # A read with no session reports which gate is missing and starts
            # nothing: no process, profile or armed set may appear.
            idle = read_document_start()
            assert idle["state"] == "idle" and idle["session_id"] is None
            assert idle["document_start"]["permitted"] is False
            assert idle["document_start"]["scripts"] == []
            assert idle["limits"]["scripts"] == 4 and idle["limits"]["execution_millis"] == 50
            # Out-of-scope contexts are stated rather than silently skipped.
            contexts = {entry["context"] for entry in idle["unsupported"]}
            assert {"service_worker", "dedicated_worker", "isolated_world", "already_open_document"} <= contexts
            assert call()["state"] == "idle", "A document-start read started a session"
            read_document_start(after="01", status=400)
            call(status=400, path="/api/native-console/document-start?unexpected=1")
            call({"action": "start", "url": "http://127.0.0.1/fixture"}, 403, {"Origin": "https://example.invalid"})
            call({"action": "start", "url": "file:///tmp/fixture"}, 400)
            call({"action": "start", "url": "http://user:secret@127.0.0.1/"}, 400)
            value = call({"action": "start", "url": "http://127.0.0.1/fixture"})
            session = value["session_id"]
            target = value["targets"][0]["id"]
            base = {"action": "evaluate", "session_id": session, "target_id": target}
            # Disabled control: a session started without the opt-in advertises
            # no support, so arming fails closed and nothing is relaunched.
            assert value.get("document_start_supported") is False, value
            disabled = read_document_start()
            assert disabled["document_start"]["permitted"] is False
            assert disabled["document_start"]["status"] == "unavailable"
            assert "REB_CONSOLE_DOCUMENT_START" in disabled["document_start"]["message"]
            armed_request = {"action": "arm_document_start", "session_id": session,
                             "confirm_document_start": True,
                             "scripts": [{"origin": "http://127.0.0.1:8080", "frame": "top",
                                          "source": "report('x');"}]}
            call(armed_request, 503)
            # Clearing a session that never permitted the experiment reports
            # that instead of sending an operation this browser would reject.
            unavailable = call({"action": "clear_document_start", "session_id": session})
            assert unavailable["document_start"]["status"] == "unavailable"
            assert call()["state"] == "ready", "A refused arm retired the session"
            assert call({**base, "source": "window.fixture + 1"})["text"] == "42"
            call({**base, "session_id": "1", "source": "1"}, 409)
            call({**base, "source": "雪" * 2731}, 400)
            call({**base, "source": "a\0b"}, 400)
            call({**base, "target_id": "01", "source": "1"}, 400)
            call({**base, "target_id": "18446744073709551616", "source": "1"}, 400)
            failure = call({**base, "source": "throw 'fixture'"})
            assert failure["status"] == "exception" and failure["code"] == "application_failed"
            assert failure["details"] == {}
            failure = call({**base, "source": "while (true) {}"})
            assert failure["status"] == "timeout" and failure["code"] == "command_outcome_unknown"
            assert failure["details"] == {"phase": "command_exchange", "cause": "timeout"}
            assert call({**base, "source": "window.fixture + 1"})["text"] == "42"
            runtime = {"action": "runtime", "session_id": session, "target_id": target}
            def command(operation, **fields):
                result = call({**runtime, "command": {"operation": operation, **fields}})
                if result["runtime"]["status"] in {"error", "exception", "rejected"}:
                    assert result["code"] == "application_failed" and result["details"] == {}
                else:
                    assert "code" not in result and "details" not in result
                return result["runtime"]
            assert command("evaluate", source="window.fixture + 1")["value"]["text"] == "42"
            assert command("evaluate", source='console.log("hello")')["value"]["type"] == "undefined"
            assert command("poll")["messages"][0]["text"] == "hello"
            assert command("poll")["messages"] == []
            obj = command("evaluate", source="window.previewObject")["value"]
            assert command("inspect", handle=obj["handle"], offset=0)["properties"][0]["accessor"]
            assert command("complete", path=[], prefix="fix")["items"][0]["name"] == "fixture"
            assert command("store", handle=obj["handle"])["text"] == "window.temp1"
            command("release", handle=obj["handle"])
            assert command("inspect", handle=obj["handle"], offset=0)["status"] == "error"
            promise = command("evaluate", source="await Promise.resolve(42)")["value"]
            assert command("await", handle=promise["handle"])["value"]["text"] == "42"
            command("cancel", handle=promise["handle"])
            assert command("await", handle=promise["handle"])["status"] == "error"
            for invalid in [{"operation": "complete", "path": "window", "prefix": ""}, {"operation": "complete", "path": ["a"] * 9, "prefix": ""}, {"operation": "inspect", "handle": "01", "offset": 0}, {"operation": "inspect", "handle": "1", "offset": -1}, {"operation": "poll", "source": "1"}]:
                call({**runtime, "command": invalid}, 400)
            activity = command("traffic")
            assert activity["events"][0]["document_id"] == target and activity["dropped"] == 0
            fn = command("evaluate", source="document.querySelector")["value"]
            assert "synthetic fixture" in command("source", handle=fn["handle"])["text"]
            dom = command("evaluate", source="document.body")["value"]
            assert command("listeners", handle=dom["handle"])["properties"] == []
            command("monitor", handle=dom["handle"])
            command("unmonitor", handle=dom["handle"])
            waiting = command("evaluate", source="new Promise(() => {})")["value"]
            assert command("await", handle=waiting["handle"])["status"] == "pending"
            command("cancel", handle=waiting["handle"])
            assert command("await", handle=waiting["handle"])["status"] == "error"
            command("clear")
            call({"action": "targets", "session_id": session})
            failure = call({**base, "source": "1"})
            assert failure["status"] == "stale_target" and failure["code"] == "target_unavailable"
            assert failure["details"] == {}
            # Locate only our authenticated synthetic child; verify both the
            # browser process and private session directory disappear on Stop.
            def owned_directories():
                result = []
                for path in Path("/tmp").glob("reb-console.*/fixture-pid"):
                    try:
                        identity = path.read_text().split()
                    except FileNotFoundError:
                        continue
                    if len(identity) == 2 and identity[1] == str(process.pid):
                        result.append(path.parent)
                return result
            owned = owned_directories()
            assert len(owned) == 1, "Synthetic browser ownership could not be established"
            call({"action": "stop", "session_id": "1"}, 409)
            call({"action": "stop", "session_id": session})
            assert all(not p.exists() for p in owned), "Disposable console profile survived Stop"
            assert call()["state"] == "idle"
            value = call({"action": "start", "url": "http://127.0.0.1/fixture"})
            failure = call({"action": "evaluate", "session_id": value["session_id"], "target_id": value["targets"][0]["id"],
                            "source": "__malformed_native_reply__"}, 500)
            assert failure["code"] == "command_outcome_unknown"
            assert failure["details"] == {"phase": "command_exchange", "cause": "transport_failure"}
            assert call()["state"] == "idle", "Malformed native response did not retire the session"
            assert not owned_directories(), "Failed console session leaked its profile"
            # Document-start enabled: the same public API, Rust manager and C++
            # bridge, with the browser session permitted at launch.
            value = call({"action": "start", "url": "http://127.0.0.1/fixture", "document_start": True})
            session = value["session_id"]
            assert value.get("document_start_supported") is True, value
            ready = read_document_start()
            assert ready["document_start"]["permitted"] is True
            assert ready["document_start"]["scripts"] == []
            assert ready["document_start"]["pending_renderer_processes"] == 0
            armed = call({"action": "arm_document_start", "session_id": session,
                          "confirm_document_start": True,
                          "scripts": [{"origin": "http://127.0.0.1:8080", "frame": "child",
                                       "path_prefix": "/lab/", "source": "report('kinds=string:12');"}]})
            assert armed["contract_version"] == 3 and armed["document_start"]["status"] == "ok"
            assert armed["document_start"]["scripts"][0]["rule"]["frame"] == "child"
            records = armed["document_start"]["output"]["records"]
            assert [record["record"] for record in records] == ["injected", "report"]
            assert all(record["provenance"] == "console-document-start-script" for record in records)
            # A cursor read is non-draining and never fabricates a record.
            assert read_document_start()["document_start"]["output"]["records"] == records
            assert read_document_start(after=records[-1]["sequence"])["document_start"]["output"]["records"] == []
            # Consent and rule shape are enforced before the wire.
            for refused in [
                {"confirm_document_start": False},
                {"confirm_document_start": None},
                {"scripts": []},
                {"scripts": [{"origin": "fixture.test", "frame": "top", "source": "1"}]},
                {"scripts": [{"origin": "https://Fixture.test", "frame": "top", "source": "1"}]},
                {"scripts": [{"origin": "https://fixture.test/", "frame": "top", "source": "1"}]},
                {"scripts": [{"origin": "https://*.fixture.test", "frame": "top", "source": "1"}]},
                {"scripts": [{"origin": "https://fixture.test", "frame": "any", "source": "1"}]},
                {"scripts": [{"origin": "https://fixture.test", "frame": "top", "source": ""}]},
                {"scripts": [{"origin": "https://fixture.test", "frame": "top", "source": "a" * 4097}]},
                {"scripts": [{"origin": "https://fixture.test", "frame": "top", "path_prefix": "lab", "source": "1"}]},
                {"scripts": [{"origin": "https://fixture.test", "frame": "top", "source": "1", "extra": 1}]},
                {"scripts": [{"origin": "https://fixture.test", "frame": "top", "source": "a" * 4096}] * 3},
            ]:
                call({"action": "arm_document_start", "session_id": session,
                      "confirm_document_start": True,
                      "scripts": [{"origin": "http://127.0.0.1:8080", "frame": "top", "source": "report(1);"}],
                      **refused}, 400)
            preserved = read_document_start()["document_start"]
            assert preserved["scripts"] == armed["document_start"]["scripts"], "A refusal changed the armed set"
            cleared = call({"action": "clear_document_start", "session_id": session})
            assert cleared["document_start"]["status"] == "ok" and cleared["document_start"]["scripts"] == []
            assert read_document_start()["document_start"]["output"]["records"] == []
            call({"action": "arm_document_start", "session_id": "1", "confirm_document_start": True,
                  "scripts": [{"origin": "http://127.0.0.1:8080", "frame": "top", "source": "report(1);"}]}, 409)
            call({"action": "stop", "session_id": session})
            print("PASS document-start HTTP surface: disabled control, launch-time permission, consent and rule refusals that preserve the armed set, non-draining cursor reads and clearing")

            # Live capture: the browser's armed set outlives each Console
            # connection, so Disconnect must clear it before reporting idle.
            def connect_live():
                listing = call()
                assert listing["live_available"] and listing["targets"], listing
                return call({"action": "connect_live", "binding_id": listing["binding_id"],
                             "target_id": listing["targets"][0]["id"], "confirm_live": True})["session_id"]
            live_session = connect_live()
            live_rule = {"origin": "http://127.0.0.1:8080", "frame": "top", "source": "report('kinds=string:12');"}
            armed = call({"action": "arm_document_start", "session_id": live_session,
                          "confirm_document_start": True, "scripts": [live_rule]})
            assert armed["document_start"]["status"] == "ok" and len(armed["document_start"]["scripts"]) == 1
            assert call({"action": "stop", "session_id": live_session})["state"] == "idle"
            assert read_document_start()["document_start"]["status"] == "idle"
            live_session = connect_live()
            reconnected = read_document_start()["document_start"]
            assert reconnected["scripts"] == [] and reconnected["output"]["records"] == [], \
                "Disconnect left document-start scripts armed in the capture browser"
            # A clear the browser does not confirm fails the Disconnect and is
            # reported as unconfirmed, never as an idle experiment.
            call({"action": "arm_document_start", "session_id": live_session, "confirm_document_start": True,
                  "scripts": [{**live_rule, "source": "report('__refuse_clear__');"}]})
            refused = call({"action": "stop", "session_id": live_session}, 409)
            assert "did not confirm" in refused["error"], refused
            unconfirmed = read_document_start()
            assert unconfirmed["state"] == "idle" and unconfirmed["document_start"]["status"] == "unconfirmed"
            assert "Restart the capture" in unconfirmed["document_start"]["message"]
            assert call()["live_available"] is False, "An unconfirmed clear handed the live binding back"
            print("PASS live Disconnect clears and confirms armed document-start scripts, and an unconfirmed clear is never reported idle")
            print("PASS public HTTP -> Rust session -> actual C++ bridge -> synthetic browser; locality, UTF-8 limits, identity guards, timeout recovery, malformed peer retirement and profile disposal")
        finally:
            process.terminate()
            process.wait(timeout=10)
            if live_peer:
                live_peer.wait(timeout=10)
            if process.stderr:
                process.stderr.close()
        assert live_transport is not None and not live_transport.exists(), "Live Console transport survived backend shutdown"
        assert live_directory.is_dir() and binding.is_file(), "Stopping Console removed capture-owned evidence"
        print("PASS long live capture paths use an authenticated private short socket directory; shutdown removes transport and preserves capture-owned files")


def main():
    if "--reb-native-console" in sys.argv:
        return fake_browser(sys.argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/reb-console")
    parser.add_argument("--backend", help="Also exercise the public HTTP API with the synthetic browser peer")
    parser.add_argument("--browser", help="Rebuilt custom Brave executable; enables actual renderer execution checks")
    arguments = parser.parse_args()
    binary = str(Path(arguments.binary).resolve())
    check(binary, arguments.browser)
    if arguments.backend:
        check_backend(binary, str(Path(arguments.backend).resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
