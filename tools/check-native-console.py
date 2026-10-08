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


def fake_browser(arguments):
    flags = dict(argument[2:].split("=", 1) for argument in arguments if argument.startswith("--") and "=" in argument)
    assert not any("remote-debugging" in argument for argument in arguments)
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
                target_id += 1
                response(stream, request, 10, TARGET.pack(target_id, len(origin), 2, 0, origin, 27, 29, b"Synthetic transport fixture", b"http://127.0.0.1:fixture/page", 0), count=1)
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


@contextlib.contextmanager
def bridge(binary, browser=None, binary_mode=True):
    with tempfile.TemporaryDirectory(prefix="reb-console-check.", dir="/tmp") as directory:
        root = Path(directory)
        token = root / "token"
        token.write_text(secrets.token_hex(32) + "\n")
        token.chmod(0o600)
        command = [str(binary), "--socket", str(root / "console.sock"), "--token-file", str(token), "--session", "1"]
        if binary_mode:
            command.append("--bridge")
        console = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        browser_arguments = ["--reb-native-console", f"--reb-native-console-socket={root / 'console.sock'}", f"--reb-native-console-token-file={token}", "--reb-native-console-session-id=1", f"--user-data-dir={root / 'profile'}", "--no-first-run", "--no-default-browser-check", "--use-mock-keychain", "--password-store=basic"]
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
                    if process is child:
                        try:
                            os.killpg(process.pid, 9)
                        except ProcessLookupError:
                            pass
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


def check(binary, browser):
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
                assert runtime("evaluate", source='console.log("hello")')["value"]["type"] == "undefined"
                assert any(message["text"] == "hello" for message in runtime("poll")["messages"])
                obj = runtime("evaluate", source="window.previewObject")["value"]
                properties = runtime("inspect", handle=obj["handle"], offset=0)["properties"]
                assert next(p for p in properties if p["name"] == "value")["accessor"]
                assert runtime("evaluate", source="window.previewCalls")["value"]["text"] == "0"
                runtime("evaluate", source="let consoleLexical = {method() {return 1}}")
                assert any(item["name"] == "consoleLexical" for item in runtime("complete", path=[], prefix="consoleLex" )["items"])
                assert any(item["name"] == "method" for item in runtime("complete", path=["consoleLexical"], prefix="met")["items"])
                promise = runtime("evaluate", source="await Promise.resolve(42)")["value"]
                assert runtime("await", handle=promise["handle"])["value"]["text"] == "42"
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
                assert runtime("inspect", handle=typed["handle"], offset=65520)["truncated"]
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
        command = [backend, "--port", "0", "--endpoint-file", str(endpoint),
                   "--native-console", binary, "--brave-binary", str(Path(__file__).resolve())]
        for flag in ["store", "trace-store", "signal-store", "artifacts", "api-collection", "local-analyst"]:
            command += [f"--{flag}", str(root / flag)]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        def call(action=None, status=200, headers=None):
            data = json.dumps(action).encode() if action is not None else None
            request = urllib.request.Request(url + ("/api/native-console/actions" if data else "/api/native-console"), data=data,
                                             headers={"Content-Type": "application/json", **(headers or {})})
            try:
                result = urllib.request.urlopen(request, timeout=40)
            except urllib.error.HTTPError as error:
                result = error
            with result:
                assert result.status == status, (result.status, result.read())
                return json.load(result)
        try:
            deadline = time.monotonic() + 15
            while not endpoint.exists():
                assert process.poll() is None, "Backend exited before publishing its endpoint"
                assert time.monotonic() < deadline
                time.sleep(0.02)
            url = endpoint.read_text().strip()
            state = call()
            assert state["available"] and state["state"] == "idle"
            call({"action": "start", "url": "http://127.0.0.1/fixture"}, 403, {"Origin": "https://example.invalid"})
            call({"action": "start", "url": "file:///tmp/fixture"}, 400)
            call({"action": "start", "url": "http://user:secret@127.0.0.1/"}, 400)
            value = call({"action": "start", "url": "http://127.0.0.1/fixture"})
            session = value["session_id"]
            target = value["targets"][0]["id"]
            base = {"action": "evaluate", "session_id": session, "target_id": target}
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
            print("PASS public HTTP -> Rust session -> actual C++ bridge -> synthetic browser; locality, UTF-8 limits, identity guards, timeout recovery, malformed peer retirement and profile disposal")
        finally:
            process.terminate()
            process.wait(timeout=10)
            if process.stderr:
                process.stderr.close()


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
