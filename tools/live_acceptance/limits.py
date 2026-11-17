"""#436: long URLs, large and read request bodies, and 40 parallel scripts are kept whole."""

from __future__ import annotations

from live_acceptance.evidence import find_rows, for_row, members
from live_acceptance.fixture import Fixture, Request, cors, html_response, payload, redirect, text_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#436"
NAME = "limits"
SCRIPTS = 40
BODY_LIMIT = 16 * 1024 * 1024
# ERR_ALPN_NEGOTIATION_FAILED: the stream body needs HTTP/2 or QUIC and the fixture offers HTTP/1.1.
STREAM_REFUSED = -122
CHUNKED_DATA_PIPE = 4
LARGE_BODY = 17 * 1024 * 1024
GRAPHQL_FIELDS = 760

INDEX = document("limits", f"""<script>
function bytes(length, seed) {{
  const out = new Uint8Array(length);
  let x = seed >>> 0 || 1;
  for (let i = 0; i < length; i++) {{
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    out[i] = x & 255;
  }}
  return out;
}}
(async () => {{
  await REB.run('limits:graphql', async () => {{
    const fields = Array.from({{length: {GRAPHQL_FIELDS}}}, (_, i) => 'field' + i).join(' ');
    const query = 'query RebLiveAcceptance {{ node(id: "reb") {{ ' + fields + ' }} }}';
    const url = '/limits/graphql?query=' + encodeURIComponent(query);
    await fetch(url);
    return url.length;
  }});
  await REB.run('limits:json', async () => {{
    const items = Array.from({{length: 42000}}, (_, i) => ({{i, v: 'value-' + i + '-' + 'x'.repeat(100)}}));
    const body = JSON.stringify({{items}});
    await fetch('/limits/json', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body}});
    return body.length;
  }});
  await REB.run('limits:multipart', async () => {{
    const form = new FormData();
    form.append('note', 'multipart with a file');
    form.append('upload', new File([bytes(262144, 7)], 'reb-upload.bin', {{type: 'application/octet-stream'}}));
    await fetch('/limits/multipart', {{method: 'POST', body: form}});
  }});
  await REB.run('limits:blob', () => fetch('/limits/blob', {{method: 'POST', body: new Blob([bytes(131072, 11)])}}));
  // Chromium sends a stream body only over HTTP/2 or QUIC, which this plain
  // HTTP fixture cannot negotiate, so the browser refuses it before sending.
  await REB.run('limits:stream', async () => {{
    const parts = [bytes(65536, 21), bytes(65536, 22), bytes(1000, 23)];
    const body = new ReadableStream({{start(controller) {{
      for (const part of parts) controller.enqueue(part);
      controller.close();
    }}}});
    try {{
      await fetch('/limits/stream', {{method: 'POST', body, duplex: 'half'}});
      return 'sent';
    }} catch (error) {{
      return 'refused: ' + error.message;
    }}
  }});
  await REB.run('limits:redirected-post', () => fetch('/limits/post-307', {{
    method: 'POST', body: 'redirected post body ' + 'y'.repeat(2000),
  }}));
  await REB.run('limits:large', () => fetch('/limits/large', {{method: 'POST', body: bytes({LARGE_BODY}, 31)}}));
  await REB.run('limits:password', async () => {{
    const sink = document.createElement('iframe');
    sink.name = 'password-sink';
    document.body.append(sink);
    const form = document.createElement('form');
    form.method = 'post';
    form.action = '/limits/password';
    form.target = 'password-sink';
    form.innerHTML = '<input name=user value=reb><input type=password name=secret value=not-a-real-password>';
    document.body.append(form);
    const loaded = new Promise(resolve => sink.addEventListener('load', resolve, {{once: true}}));
    form.submit();
    await loaded;
  }});
  await REB.run('limits:scripts', () => Promise.all(Array.from({{length: {SCRIPTS}}}, (_, i) =>
    new Promise((resolve, reject) => {{
      const script = document.createElement('script');
      script.src = '/limits/script?i=' + i;
      script.onload = resolve;
      script.onerror = () => reject(new Error('script ' + i + ' failed'));
      document.head.append(script);
    }}))));
}})();
</script>""")

RESULTS = ["limits:graphql", "limits:json", "limits:multipart", "limits:blob", "limits:stream",
           "limits:redirected-post", "limits:large", "limits:password", "limits:scripts"]


def script_source(index: int) -> str:
    return f"globalThis.rebParallelScript{index} = '{payload(f'script{index}', 2048).hex()}';\n"


def _received(request: Request):
    return text_response(f"received {len(request.body)} bytes\n", "text/plain", cors(request))


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/limits/index.html", INDEX)
    for path in ("/limits/graphql", "/limits/json", "/limits/multipart", "/limits/blob", "/limits/stream",
                 "/limits/post-307-target", "/limits/large"):
        fx.route(path, _received)
    fx.route("/limits/post-307", lambda _r: redirect("/limits/post-307-target", 307))
    fx.route("/limits/password", lambda _r: html_response("<p>password form received</p>"))
    fx.route("/limits/script", lambda r: text_response(script_source(int(r.query.get("i", "0"))), "text/javascript"))


def drive(run: Run) -> None:
    run.open("/limits/index.html")
    run.wait(ISSUE, RESULTS, 180)


def body_record(run: Run, target: str, problems: list[str], label: str):
    rows = find_rows(run.rows(), target=target)
    if len(rows) != 1:
        problems.append(f"{label}: {len(rows)} rows")
        return None
    bodies = for_row(run.records()[0], rows[0])
    if len(bodies) != 1:
        problems.append(f"{label}: {len(bodies)} request_body records")
        return None
    return bodies[0]


def body_kept(run: Run, target: str, expected: bytes, problems: list[str], label: str,
              read: bool | None = None) -> None:
    record = body_record(run, target, problems, label)
    if record is None:
        return
    if record.state != "captured" or record.captured_length != len(expected):
        problems.append(f"{label}: state {record.state}, {record.captured_length} of {len(expected)} bytes")
        return
    if read is not None and record.read != read:
        problems.append(f"{label}: read flag {record.read}, expected {read}")
    if run.api.content(record.artifact_id) != expected:
        problems.append(f"{label}: the artifact bytes differ from what the server received")


def received(run: Run, path: str) -> bytes | None:
    found = run.fixture.receipts(path)
    return found[0].request.body if len(found) == 1 else None


def verify(run: Run) -> None:
    report, fx = run.report, run.fixture
    failed = [(name, run.result(name)[1]) for name in RESULTS if not run.result(name)[0]]

    problems: list[str] = []
    graphql = fx.receipts("/limits/graphql")
    rows = find_rows(run.rows(), prefix="/limits/graphql?query=")
    if len(graphql) != 1 or len(rows) != 1:
        problems.append(f"{len(rows)} rows and {len(graphql)} receipts for the GraphQL GET")
    else:
        target = graphql[0].request.target
        if len(target) < 8000:
            problems.append(f"the URL is only {len(target)} bytes")
        if not rows[0].get("url_truncated") or rows[0].get("target_length") != len(target):
            problems.append(f"row url_truncated {rows[0].get('url_truncated')} target_length "
                            f"{rows[0].get('target_length')}, the server got {len(target)}")
        targets = for_row(run.records()[1], rows[0])
        retained = [t for t in targets if t.retention == "retained"]
        if not retained:
            problems.append(f"request_target retention {[t.retention for t in targets]}")
        elif run.api.content(retained[0].artifact_id) != target.encode("latin-1"):
            problems.append("the request_target artifact differs from the URL the server received")
    report.check(ISSUE, "8 KB GraphQL GET URL", problems, "the whole path and query is retained")

    problems = []
    for path, label, read in (("/limits/json", "5 MiB JSON POST", False), ("/limits/multipart", "multipart with a file", True),
                              ("/limits/blob", "Blob upload", True)):
        body = received(run, path)
        if body is None:
            ok, error = run.result(label_name(path))
            problems.append(f"{label}: the server got {len(fx.receipts(path))} requests; page: {error if not ok else 'ok'}")
            continue
        if path == "/limits/json" and len(body) < 5 * 1024 * 1024:
            problems.append(f"{label}: only {len(body)} bytes")
        body_kept(run, path, body, problems, label, read)
    report.check(ISSUE, "5 MiB JSON, multipart and Blob bodies", problems,
                 "each kept with the exact bytes the server received")

    problems = []
    if fx.receipts("/limits/stream"):
        problems.append(f"the server got {len(fx.receipts('/limits/stream'))} stream-body requests over HTTP/1.1")
    record = body_record(run, "/limits/stream", problems, "stream-body fetch")
    if record is not None:
        seen = (record.kind, record.state, record.captured_length, record.sha256)
        if seen != (CHUNKED_DATA_PIPE, "not_captured_read_incomplete", 0, None):
            problems.append(f"kind {record.kind} state {record.state} captured {record.captured_length} "
                            f"digest {'present' if record.sha256 else 'absent'}")
        keys = {(m["process_id"], m["request_id"]) for row in find_rows(run.rows(), target="/limits/stream")
                for m in members(row)}
        codes = [e.get("error_code") for e in run.api.events("request_failed")
                 if (e["process_id"], e["request_id"]) in keys]
        if codes != [STREAM_REFUSED]:
            problems.append(f"request_failed error codes {codes}, expected [{STREAM_REFUSED}]")
    report.check(ISSUE, "stream-body fetch over HTTP/1.1", problems,
                 "Chromium refuses it unsent; the chunked body is recorded unread, with no bytes and no digest")

    problems = []
    hops = [received(run, "/limits/post-307"), received(run, "/limits/post-307-target")]
    if None in hops or hops[0] != hops[1]:
        problems.append("the server did not receive the same body at both hops")
    else:
        rows = find_rows(run.rows(), target="/limits/post-307") + find_rows(run.rows(), target="/limits/post-307-target")
        target = rows[0]["target"] if rows else "/limits/post-307"
        body_kept(run, target, hops[0], problems, "307 POST redirect")
    report.check(ISSUE, "307 POST redirect", problems, "one request body record keeps the re-sent body")

    problems = []
    large = received(run, "/limits/large")
    record = body_record(run, "/limits/large", problems, "17 MiB POST") if large is not None else None
    if large is None:
        problems.append("the server did not receive the 17 MiB POST")
    elif record is not None:
        if (record.state, record.body_length, record.captured_length) != ("captured_truncated", len(large), BODY_LIMIT):
            problems.append(f"state {record.state} length {record.body_length} captured {record.captured_length}")
        elif run.api.content(record.artifact_id) != large[:BODY_LIMIT]:
            problems.append("the kept 16 MiB differ from the first 16 MiB the server received")
    report.check(ISSUE, "body above 16 MiB", problems, "the first 16 MiB are kept and the whole length is recorded")

    problems = []
    record = body_record(run, "/limits/password", problems, "password form")
    if record is not None and (record.state != "not_captured_credential_form" or record.sha256):
        problems.append(f"state {record.state}, digest {'present' if record.sha256 else 'absent'}")
    report.check(ISSUE, "password form post", problems, "not_captured_credential_form, no bytes and no digest")

    problems = []
    scripts = {a["sha256"] for a in run.api.artifacts(kind="javascript")}
    for index in range(SCRIPTS):
        target = f"/limits/script?i={index}"
        rows = find_rows(run.rows(), target=target)
        cases = [(row.get("response_body") or {}).get("case") for row in rows]
        served = [r for r in fx.receipts("/limits/script") if r.request.query.get("i") == str(index)]
        if cases != ["source_artifact"] or len(served) != 1:
            problems.append(f"{target}: cases {cases}, {len(served)} receipts")
        elif served[0].decoded_sha256 not in scripts:
            problems.append(f"{target}: no javascript artifact with the served digest")
    report.check(ISSUE, f"{SCRIPTS} parallel scripts", problems, f"all {SCRIPTS} sources retained")

    for name, error in failed:
        report.failed(ISSUE, f"page step {name}", str(error))

    report.manual(ISSUE, "file chosen from disk and a file changed after it was attached",
                  "a file input needs a file chooser. In the content session open a page with "
                  "<input type=file> on the fixture origin, choose a file, POST it as multipart and compare "
                  "get_events request_body (read flag, captured) and its artifact with the file; then attach a "
                  "file, change it on disk before sending, and check not_captured_read_incomplete")
    report.manual(ISSUE, "stream-body fetch over HTTP/2",
                  "Chromium sends a ReadableStream body only over HTTP/2 or QUIC, which the loopback fixture "
                  "cannot serve. On an owned HTTPS endpoint that negotiates h2, POST a ReadableStream body with "
                  "duplex 'half' and compare get_events request_body (kind 4, read flag, captured) and its "
                  "artifact with the bytes the server received")
    report.manual("#428 #436", "browser memory bound",
                  "watch the browser's memory with Instruments or Activity Monitor during this page: it stays "
                  "within the 32 MiB in-flight pool plus the browser's baseline; record how it was measured")


def label_name(path: str) -> str:
    return {"/limits/json": "limits:json", "/limits/multipart": "limits:multipart", "/limits/blob": "limits:blob"}[path]
