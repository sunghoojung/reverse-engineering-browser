"""#428: response bodies kept with exact bytes and digest, or a visible reason."""

from __future__ import annotations

import gzip
import json
import time

from live_acceptance.binary import png, wav
from live_acceptance.evidence import find_rows, members
from live_acceptance.fixture import (Fixture, Gate, Pause, Request, Response, bytes_response,
                                     payload, redirect, sha256, text_response)
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#428"
NAME = "bodies"
PARALLEL = 50
BURST = 256 * 1024
RESPONSE_REDIRECTED = 8
ETAG = '"reb-etag-1"'


def text_body(name: str, size: int) -> str:
    line = f"{name} body line {{:06d}} " + "abcdefghijklmnopqrstuvwxyz0123456789" + "\n"
    out, index = [], 0
    while sum(map(len, out)) < size:
        out.append(line.format(index))
        index += 1
    return "".join(out)[:size]


JSON_BODY = json.dumps({"case": "json", "items": [{"i": i, "v": payload(f"json{i}", 24).hex()}
                                                 for i in range(400)]}).encode()
HTML_BODY = document("html body", "<p>" + text_body("html", 16000) + "</p>").encode()
IMAGE = png(64, 64, "bodies")
# Bytes no sanitizer accepts as a font: the browser still fetches them whole as
# a font load, which is what the capture keeps.
FONT = payload("bodies-font", 4096)
AUDIO = wav(8000, "bodies")
GZIP_TEXT = text_body("gzip", 64 * 1024).encode()
BROTLI_TEXT = text_body("brotli", 64 * 1024).encode()
CHUNKS = [payload(f"chunk{index}", 16 * 1024) for index in range(5)]
EVENTS = [f"id: {index}\ndata: event {index} {payload(f'sse{index}', 32).hex()}\n\n".encode()
          for index in range(10)]
EVENTS.append(b"event: end\ndata: done\n\n")

INDEX = document("bodies", """<script>
const read = (url, init) => fetch(url, init).then(async response => {
  const bytes = await response.arrayBuffer();
  return {status: response.status, length: bytes.byteLength, sha256: await REB.digest(bytes)};
});
async function stream() {
  const events = new EventSource('/bodies/sse?r=1');
  return await new Promise((resolve, reject) => {
    const seen = [];
    events.onmessage = event => seen.push(event.data);
    events.addEventListener('end', () => { events.close(); resolve(seen.length); });
    events.onerror = () => { events.close(); reject(new Error('event stream failed')); };
  });
}
async function activated(registration) {
  const worker = registration.installing || registration.waiting || registration.active;
  while (worker.state !== 'activated') {
    await new Promise(resolve => worker.addEventListener('statechange', resolve, {once: true}));
  }
}
function frame(src) {
  const element = document.createElement('iframe');
  element.src = src;
  document.body.append(element);
}
(async () => {
  await REB.run('bodies:json', () => read('/bodies/json?r=1'));
  await REB.run('bodies:html', () => read('/bodies/html?r=1'));
  await REB.run('bodies:image-fetch', () => read('/bodies/image.png?r=fetch'));
  await REB.run('bodies:image-element', () => {
    const image = new Image();
    image.src = '/bodies/image.png?r=element';
    return image.decode().then(() => image.naturalWidth);
  });
  await REB.run('bodies:font', async () => {
    const face = new FontFace('RebFont', 'url(/bodies/font.woff2?r=1)');
    try {
      await face.load();
      return 'loaded';
    } catch (error) {
      return 'rejected: ' + error.message;
    }
  });
  await REB.run('bodies:audio', () => new Promise((resolve, reject) => {
    const audio = document.createElement('audio');
    audio.preload = 'auto';
    audio.onloadeddata = () => resolve(audio.duration);
    audio.onerror = () => reject(new Error('audio failed: ' + (audio.error && audio.error.code)));
    audio.src = '/bodies/audio.wav?r=1';
    document.body.append(audio);
  }));
  await REB.run('bodies:gzip', () => read('/bodies/gzip?r=1'));
  if (BROTLI) await REB.run('bodies:brotli', () => read('/bodies/brotli?r=1'));
  await REB.run('bodies:chunked', () => read('/bodies/chunked?r=1'));
  await REB.run('bodies:sse', stream);
  await REB.run('bodies:redirect', () => read('/bodies/redirect?r=1'));
  await REB.run('bodies:etag-first', () => read('/bodies/etag?r=1'));
  // The HTTP cache revalidates its own copy and gives the page that 200; a 304
  // reaches the page only for a conditional request the page makes itself.
  await REB.run('bodies:etag-revalidated', () => read('/bodies/etag?r=1', {cache: 'no-cache'}));
  await REB.run('bodies:etag-conditional', () => read('/bodies/etag?r=2',
    {cache: 'no-store', headers: {'If-None-Match': ETAG}}));
  await REB.run('bodies:parallel', () => Promise.all(
    Array.from({length: PARALLEL}, (_, i) => read('/bodies/parallel?i=' + i))));
  await REB.run('bodies:download', async () => {
    const link = document.createElement('a');
    link.href = '/bodies/abort-download?r=1';
    link.download = 'reb-live-acceptance-aborted.bin';
    document.body.append(link);
    link.click();
  });
  await REB.run('bodies:sw', async () => {
    const registration = await navigator.serviceWorker.register('/bodies/sw/sw.js', {scope: '/bodies/sw/'});
    await activated(registration);
    frame('/bodies/sw/client.html?r=1');
    frame('/bodies/sw/preload.html?r=1');
  });
})();
</script>""")

SERVICE_WORKER = """self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil((async () => {
  await self.registration.navigationPreload.enable();
  await clients.claim();
})()));
self.addEventListener('fetch', event => {
  const path = new URL(event.request.url).pathname;
  if (path === '/bodies/sw/synthetic') {
    event.respondWith(new Response('a body the service worker built\\n', {headers: {'Content-Type': 'text/plain'}}));
  } else if (event.request.mode === 'navigate' && path === '/bodies/sw/preload.html') {
    event.respondWith((async () => (await event.preloadResponse) || fetch(event.request))());
  }
});
"""

CLIENT = document("controlled", """<script>
REB.run('bodies:sw-answer', async () => {
  if (!navigator.serviceWorker.controller) throw new Error('this frame is not controlled');
  return await fetch('/bodies/sw/synthetic?r=1').then(response => response.text());
});
</script>""")

PRELOAD = document("preloaded", "<script>REB.beacon('bodies:preload', {controlled: "
                                "!!navigator.serviceWorker.controller});</script>").encode()

BURST_PAGE = document("burst", f"""<script>
REB.run('bodies:burst', async () => {{
  const response = await fetch('/bodies/burst?r=1');
  const reader = response.body.getReader();
  let total = 0, reported = false;
  for (;;) {{
    const {{done, value}} = await reader.read();
    if (done) return total;
    total += value.length;
    if (!reported && total >= {BURST}) {{
      reported = true;
      REB.beacon('bodies:burst-open', total);
    }}
  }}
}});
</script>""")


def _etag(request: Request) -> Response:
    headers = [("ETag", ETAG), ("Cache-Control", "no-cache"), ("Content-Type", "text/plain")]
    if request.header("If-None-Match") == ETAG:
        return Response(304, headers)
    return Response(200, headers, text_body("etag", 8000).encode())


def install(fx: Fixture, options: Options) -> None:
    index = (INDEX.replace("BROTLI", "true" if options.brotli else "false").replace("PARALLEL", str(PARALLEL))
             .replace("ETAG", json.dumps(ETAG)))
    fx.page("/bodies/index.html", index)
    fx.route("/bodies/json", lambda _r: bytes_response(JSON_BODY, "application/json"))
    fx.route("/bodies/html", lambda _r: bytes_response(HTML_BODY, "text/html; charset=utf-8"))
    fx.route("/bodies/image.png", lambda _r: bytes_response(IMAGE, "image/png"))
    fx.route("/bodies/font.woff2", lambda _r: bytes_response(FONT, "font/woff2"))
    fx.route("/bodies/audio.wav", lambda _r: bytes_response(AUDIO, "audio/wav"))
    fx.route("/bodies/gzip", lambda _r: Response(200, [("Content-Type", "text/plain"), ("Content-Encoding", "gzip"),
                                                       ("Cache-Control", "no-store")],
                                                 gzip.compress(GZIP_TEXT, mtime=0), decoded=GZIP_TEXT))
    if options.brotli:
        encoded = options.brotli(BROTLI_TEXT)
        fx.route("/bodies/brotli", lambda _r: Response(200, [("Content-Type", "text/plain"), ("Content-Encoding", "br"),
                                                             ("Cache-Control", "no-store")], encoded,
                                                       decoded=BROTLI_TEXT))
    fx.route("/bodies/chunked", lambda _r: Response(200, [("Content-Type", "application/octet-stream"),
                                                          ("Cache-Control", "no-store")],
                                                    chunks=[part for chunk in CHUNKS for part in (chunk, Pause(0.2))]))
    fx.route("/bodies/sse", lambda _r: Response(200, [("Content-Type", "text/event-stream"),
                                                      ("Cache-Control", "no-store")],
                                                chunks=[b"retry: 3600000\n\n",
                                                        *[part for event in EVENTS for part in (event, Pause(0.3))]]))
    fx.route("/bodies/redirect", lambda r: redirect(f"/bodies/redirect-target?r={r.query.get('r', '')}"))
    fx.route("/bodies/redirect-target", lambda _r: bytes_response(JSON_BODY[:4000], "text/plain"))
    fx.route("/bodies/etag", _etag)
    fx.route("/bodies/parallel", lambda r: bytes_response(
        payload(f"parallel{r.query.get('i')}", 32 * 1024), "application/octet-stream"))
    fx.route("/bodies/abort-download", lambda _r: Response(
        200, [("Content-Type", "application/octet-stream"), ("Cache-Control", "no-store"),
              ("Content-Disposition", 'attachment; filename="reb-live-acceptance-aborted.bin"')],
        payload("aborted-download", 1024 * 1024), abort_after=64 * 1024))
    fx.script("/bodies/sw/sw.js", SERVICE_WORKER)
    fx.page("/bodies/sw/client.html", CLIENT)
    fx.route("/bodies/sw/preload.html", lambda _r: bytes_response(PRELOAD, "text/html; charset=utf-8"))
    fx.route("/bodies/sw/synthetic", lambda _r: text_response("network copy\n", "text/plain"))
    fx.page("/bodies/burst.html", BURST_PAGE)
    fx.route("/bodies/burst", lambda _r: Response(200, [("Content-Type", "application/octet-stream"),
                                                        ("Cache-Control", "no-store")],
                                                  chunks=[payload("burst", BURST), Gate("bodies:burst-release", 90),
                                                          payload("burst-tail", 4096)]))


class State:
    partial: dict | None = None


STATE = State()


def drive(run: Run) -> None:
    STATE.partial = None
    names = ["bodies:json", "bodies:html", "bodies:image-fetch", "bodies:image-element", "bodies:font",
             "bodies:audio", "bodies:gzip",
             "bodies:chunked", "bodies:sse", "bodies:redirect", "bodies:etag-first", "bodies:etag-revalidated",
             "bodies:etag-conditional", "bodies:parallel", "bodies:download", "bodies:sw", "bodies:sw-answer", "bodies:preload"]
    if run.options.brotli:
        names.append("bodies:brotli")
    run.open("/bodies/index.html")
    run.wait(ISSUE, names, 90)
    run.fixture.wait_receipts(lambda r: r.request.path == "/bodies/abort-download" and r.completed is False
                              and r.aborted, 1, 20)

    # A burst followed by silence: the body is read while it is still open.
    run.open("/bodies/burst.html")
    if run.wait(ISSUE, ["bodies:burst-open"], 30):
        time.sleep(5)
        rows = find_rows(run.rows(refresh=True), target="/bodies/burst?r=1")
        STATE.partial = rows[0]["response_body"] if rows else None
    run.fixture.release("bodies:burst-release")
    run.wait(ISSUE, ["bodies:burst"], 30)
    time.sleep(1)


def kept(run: Run, target: str, expected: bytes, problems: list[str], label: str | None = None,
         case: str = "captured") -> None:
    """The row's body has this case and its artifact holds exactly these bytes."""
    label = label or target
    rows = find_rows(run.rows(), target=target)
    if len(rows) != 1:
        problems.append(f"{label}: {len(rows)} rows")
        return
    body = rows[0].get("response_body") or {}
    if body.get("case") != case:
        problems.append(f"{label}: case {body.get('case')}, expected {case}")
        return
    if body.get("sha256") != sha256(expected) or body.get("body_length") != str(len(expected)):
        problems.append(f"{label}: {body.get('body_length')} bytes {str(body.get('sha256'))[:12]}, "
                        f"the server sent {len(expected)} bytes {sha256(expected)[:12]}")
        return
    if run.api.content(body["artifact_id"]) != expected:
        problems.append(f"{label}: the artifact bytes differ from the server's")


def case_of(run: Run, target: str) -> list[str]:
    return [(row.get("response_body") or {}).get("case") for row in find_rows(run.rows(), target=target)]


def verify(run: Run) -> None:
    report, fx = run.report, run.fixture
    problems: list[str] = []
    kept(run, "/bodies/json?r=1", JSON_BODY, problems, "JSON")
    kept(run, "/bodies/html?r=1", HTML_BODY, problems, "HTML")
    kept(run, "/bodies/image.png?r=fetch", IMAGE, problems, "fetched image")
    report.check(ISSUE, "JSON, HTML and image bodies", problems, "each kept with the server's bytes and digest")

    problems = []
    kept(run, "/bodies/image.png?r=element", IMAGE, problems, "image element")
    kept(run, "/bodies/font.woff2?r=1", FONT, problems, "web font")
    kept(run, "/bodies/audio.wav?r=1", AUDIO, problems, "audio element")
    report.check(ISSUE, "image element, web font and audio element", problems,
                 "each kept with the server's bytes and digest; content sessions keep media and fonts")

    problems = []
    kept(run, "/bodies/gzip?r=1", GZIP_TEXT, problems, "gzip")
    report.check(ISSUE, "gzip body", problems, "the decoded bytes are kept")
    if run.options.brotli:
        problems = []
        kept(run, "/bodies/brotli?r=1", BROTLI_TEXT, problems, "brotli")
        report.check(ISSUE, "brotli body", problems, f"the decoded bytes are kept (encoded with {run.options.brotli_source})")
    else:
        report.skipped(ISSUE, "brotli body", run.options.brotli_source + "; install one and rerun")

    problems = []
    kept(run, "/bodies/chunked?r=1", b"".join(CHUNKS), problems, "chunked")
    sse = fx.receipts("/bodies/sse")
    if len(sse) != 1:
        problems.append(f"the event stream was requested {len(sse)} times")
    else:
        # The page closes the stream at its end event, as EventSource clients do, so the
        # body ends cancelled with every byte the server sent kept.
        kept(run, "/bodies/sse?r=1", sse[0].decoded_body, problems, "event stream", "cancelled")
    report.check(ISSUE, "chunked and streamed bodies", problems,
                 "a chunked body kept whole, and an event stream the page closed kept as sent and cancelled")

    problems = []
    rows = [row for target in ("/bodies/redirect?r=1", "/bodies/redirect-target?r=1")
            for row in find_rows(run.rows(), target=target)]
    rows = list({row["id"]: row for row in rows}.values())
    if len(rows) != 1:
        problems.append(f"{len(rows)} rows for the redirect")
    else:
        kept(run, rows[0]["target"], JSON_BODY[:4000], problems, "redirect target")
        states = set()
        for member in members(rows[0]):
            for event in run.api.events("response_body", process_id=member["process_id"],
                                        request_id=member["request_id"]):
                states.add(bytes.fromhex(event["payload"])[4])
        if RESPONSE_REDIRECTED not in states:
            problems.append(f"no redirected (8) response_body record for the hop; states {sorted(states)}")
    report.check(ISSUE, "redirect", problems, "the hop carries redirected and the target body is kept")

    problems = []
    served = [(r.request.query.get("r"), r.status) for r in fx.receipts("/bodies/etag")]
    if served != [("1", 200), ("1", 304), ("2", 304)]:
        problems.append(f"the server answered {served}, expected 200 and 304 for r=1, then 304 for r=2")
    bodies = [row.get("response_body") or {} for row in find_rows(run.rows(), target="/bodies/etag?r=1")]
    if [(b.get("case"), b.get("shared")) for b in bodies] != [("captured", False), ("captured", True)] or \
            len({b.get("sha256") for b in bodies}) != 1:
        problems.append(f"the cache revalidation is {[(b.get('case'), b.get('shared')) for b in bodies]}, "
                        "expected the first body captured, then shared by the cached 200")
    conditional = case_of(run, "/bodies/etag?r=2")
    if conditional != ["not_modified"]:
        problems.append(f"the page's own conditional request is {conditional}, expected not_modified")
    report.check(ISSUE, "304", problems,
                 "a 304 the page receives carries not_modified; a cache revalidation keeps the cached body")

    problems = []
    aborted = [r for r in fx.receipts("/bodies/abort-download") if r.aborted]
    cases = case_of(run, "/bodies/abort-download?r=1")
    if not aborted:
        problems.append("the server never cut the download")
    if len(cases) != 1 or cases[0] not in ("aborted", "cancelled", "interrupted"):
        problems.append(f"the cut download is {cases}, expected aborted")
    else:
        body = find_rows(run.rows(), target="/bodies/abort-download?r=1")[0]["response_body"]
        if body.get("artifact_id") and aborted:
            got = run.api.content(body["artifact_id"])
            if got != aborted[0].decoded_body[:len(got)]:
                problems.append("the bytes kept of the cut download differ from what the server sent")
    report.check(ISSUE, "aborted download", problems, f"carries {cases[0] if cases else None}")

    problems = []
    answer = case_of(run, "/bodies/sw/synthetic?r=1")
    if answer != ["service_worker"]:
        problems.append(f"the worker-built answer is {answer}, expected service_worker")
    ok, value = run.result("bodies:sw-answer")
    if not ok:
        problems.append(f"the controlled frame failed: {value}")
    report.check(ISSUE, "service worker answer", problems, "carries service_worker")

    problems = []
    preloads = [r for r in fx.receipts("/bodies/sw/preload.html") if r.request.header("Service-Worker-Navigation-Preload")]
    if not preloads:
        problems.append("the server saw no navigation preload request")
    else:
        kept(run, "/bodies/sw/preload.html?r=1", PRELOAD, problems, "preload navigation")
    reported = fx.beacon("bodies:preload")
    if not (isinstance(reported, dict) and reported.get("controlled")):
        problems.append(f"the preloaded page was not controlled: {reported}")
    report.check(ISSUE, "navigation answered from preloadResponse", problems,
                 "the preload request's row keeps the body the worker answered with")

    problems = []
    for index in range(PARALLEL):
        kept(run, f"/bodies/parallel?i={index}", payload(f"parallel{index}", 32 * 1024), problems)
    report.check(ISSUE, f"{PARALLEL} parallel responses", problems, f"all {PARALLEL} kept with exact bytes")

    problems = []
    whole = payload("burst", BURST) + payload("burst-tail", 4096)
    partial = STATE.partial
    if not partial or partial.get("case") != "partial":
        problems.append(f"during the silence the body was {partial and partial.get('case')}, expected partial")
    else:
        length = int(partial.get("captured_length") or 0)
        if not 0 < length <= BURST or partial.get("sha256") != sha256(whole[:length]):
            problems.append(f"the partial snapshot holds {length} bytes that are not the burst's first bytes")
    kept(run, "/bodies/burst?r=1", whole, problems, "the burst after the silence")
    report.check(ISSUE, "burst then silence", problems,
                 f"a snapshot of {partial and partial.get('captured_length')} bytes during the silence, then the whole body")
