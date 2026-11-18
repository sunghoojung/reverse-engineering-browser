"""#425: every request lands on its tab, and none is unresolved."""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlsplit

from live_acceptance.binary import png
from live_acceptance.evidence import find_rows, row_tabs
from live_acceptance.fixture import (Fixture, Request, bytes_response, cors, html_response, redirect,
                                     text_response)
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#425"
NAME = "tabs"
MANY_TABS = 30
LINK_REGISTRANT, LINK_LAST_CLIENTS, LINK_CLIENTS = 5, 4, 3

INDEX = document("tabs", """<link rel=stylesheet href="/tabs/style.css?r=parser">
<script src="/tabs/parser.js?r=parser"></script>
<img src="/tabs/pixel.png?r=parser">
<script>
REB.run('tabs:index', async () => {
  await fetch('/tabs/fetch?r=1');
  await new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '/tabs/xhr?r=1');
    xhr.onload = resolve;
    xhr.onerror = reject;
    xhr.send();
  });
  const frame = document.createElement('iframe');
  frame.src = '/tabs/slow-frame?r=1';
  document.body.append(frame);
  await REB.sleep(300);
  frame.remove();
  const worker = new Worker('/tabs/worker.js?r=1');
  await new Promise(resolve => { worker.onmessage = resolve; });
  await fetch('/tabs/redirect?n=2&r=fetch');
  const link = document.createElement('a');
  link.href = '/tabs/download?r=1';
  link.download = 'reb-live-acceptance-download.txt';
  document.body.append(link);
  link.click();
  await REB.sleep(1500);
});
</script>""")

WORKER = """fetch('/tabs/worker-fetch?r=1').then(() => {
  const nested = new Worker('/tabs/nested.js?r=1');
  nested.onmessage = () => postMessage('done');
});
"""
NESTED = "fetch('/tabs/nested-fetch?r=1').then(() => postMessage('done'));\n"
SHARED = """let clients = 0;
onconnect = event => {
  clients += 1;
  const port = event.ports[0];
  fetch('/tabs/shared-fetch?c=' + clients).then(() => port.postMessage(clients));
};
"""


def shared_page(tab: str) -> str:
    return document(f"shared {tab}", f"""<script>
REB.run('tabs:shared-{tab}', () => new Promise(resolve => {{
  const worker = new SharedWorker('/tabs/shared.js?r=1');
  worker.port.onmessage = event => resolve(event.data);
  worker.port.start();
}}));
</script>""")


UNLOAD = document("unload", """<script>
addEventListener('pagehide', () => {
  navigator.sendBeacon('/tabs/unload-beacon?r=1', 'bye');
  fetch('/tabs/unload-keepalive?r=1', {method: 'POST', body: 'bye', keepalive: true});
});
REB.beacon('tabs:unload-ready').then(() => setTimeout(() => { location.href = '/tabs/after-unload.html'; }, 500));
</script>""")

SERVICE_WORKER = """importScripts('/tabs/sw/import.js?r=1');
self.addEventListener('install', event => {
  event.waitUntil(caches.open('reb-tabs').then(cache => cache.addAll(['/tabs/sw/cached?r=1']))
    .then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => event.waitUntil(clients.claim()));
self.addEventListener('fetch', event => {
  const path = new URL(event.request.url).pathname;
  if (path === '/tabs/sw/respond-fetch') event.respondWith(fetch(event.request));
  else if (path === '/tabs/sw/cached') event.respondWith(caches.match(event.request));
});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function controlled(count) {
  for (let i = 0; i < 150; i++) {
    const list = await clients.matchAll();
    if (list.length >= count) return list;
    await sleep(200);
  }
  return clients.matchAll();
}
self.addEventListener('message', event => {
  if (event.data === 'fetch-after-close') {
    event.waitUntil(sleep(3000).then(() => fetch('/tabs/sw/after-close?r=1')));
  } else if (event.data && event.data.all) {
    // n counts every client; seen names the many-tab frames among them.
    event.waitUntil(controlled(event.data.all).then(list => fetch('/tabs/sw/all-clients?n=' + list.length + '&seen=' +
      list.map(client => new URL(client.url).searchParams.get('i')).filter(i => i !== null).join(','))));
  }
});
"""

REGISTER = document("service worker registrant", """<script>
async function activated(registration) {
  const worker = registration.installing || registration.waiting || registration.active;
  while (worker.state !== 'activated') {
    await new Promise(resolve => worker.addEventListener('statechange', resolve, {once: true}));
  }
}
REB.run('tabs:sw-ready', async () => {
  const registration = await navigator.serviceWorker.register('/tabs/sw/sw.js', {scope: '/tabs/sw/'});
  await activated(registration);
  const frame = document.createElement('iframe');
  frame.src = '/tabs/sw/client.html?r=1';
  document.body.append(frame);
  await REB.wait('tabs:sw-client-done', 60);
  frame.remove();
});
</script>""")

CLIENT = document("controlled client", """<script>
REB.run('tabs:sw-client', async () => {
  if (!navigator.serviceWorker.controller) throw new Error('this frame is not controlled');
  await fetch('/tabs/sw/passthrough?r=1');
  await fetch('/tabs/sw/respond-fetch?r=1');
  return await fetch('/tabs/sw/cached?r=1').then(response => response.text());
}).then(() => REB.beacon('tabs:sw-client-reported'));
</script>""")

POPUP = document("popup opener", """<button id=open style="font-size:32px;padding:24px">Open the controlled popup</button>
<script>
document.getElementById('open').addEventListener('click', () => {
  window.open('/tabs/sw/last.html?r=popup', '_blank', 'popup,width=480,height=360');
});
REB.beacon('tabs:popup-ready');
</script>""")


def last_client(mode: str) -> str:
    leave = ("setTimeout(() => window.close(), 300);" if mode == "popup"
             else "setTimeout(() => { location.href = '/tabs/after-sw.html'; }, 300);")
    return document("last client", f"""<script>
REB.run('tabs:last-client-{mode}', async () => {{
  if (!navigator.serviceWorker.controller) throw new Error('this page is not controlled');
  navigator.serviceWorker.controller.postMessage('fetch-after-close');
}}).then(() => {{ {leave} }});
</script>""")


def many_page(index: int) -> str:
    return document(f"tab {index}", f'<iframe src="/tabs/sw/many-frame.html?i={index}"></iframe>')


def many_frame(request: Request) -> str:
    index = int(request.query.get("i", "0"))
    # The driver releases all-open once every frame reported, so the last one waits after its report.
    tail = (f""".then(() => REB.wait('tabs:all-open', 120))
  .then(() => navigator.serviceWorker.controller.postMessage({{all: {MANY_TABS}}}))"""
            if index == MANY_TABS - 1 else "")
    return document(f"frame {index}", f"""<script>
REB.run('tabs:many-{index}', async () => {{
  if (!navigator.serviceWorker.controller) throw new Error('this frame is not controlled');
}}){tail};
</script>""")


SPECULATION = document("speculation rules", """<script type="speculationrules">
{"prefetch": [{"source": "list", "urls": ["/tabs/prefetch-target.html?r=1"]}],
 "prerender": [{"source": "list", "urls": ["/tabs/prerender-target.html?r=1"]}]}
</script>
<script>
REB.beacon('tabs:speculation-ready');
setTimeout(() => { location.href = '/tabs/prerender-target.html?r=1'; }, 4000);
</script>""")

PRERENDERED = document("prerender target", """<script>
const report = () => REB.beacon('tabs:prerender', {
  activationStart: performance.getEntriesByType('navigation')[0].activationStart,
});
if (document.prerendering) document.addEventListener('prerenderingchange', report, {once: true});
else report();
</script>""")


def _redirect(request: Request):
    hops = int(request.query.get("n", "0"))
    token = request.query.get("r", "")
    if hops > 0:
        return redirect(f"/tabs/redirect?n={hops - 1}&r={token}")
    if token == "nav":
        return html_response(document("redirected", "<script>REB.beacon('tabs:redirect-nav');</script>"))
    return text_response("redirect chain end\n", "text/plain")


def _slow_frame(_request: Request):
    time.sleep(1.5)
    return html_response("<p>slow frame</p>")


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/tabs/index.html", INDEX)
    fx.route("/tabs/style.css", lambda _r: text_response("body { margin: 8px }\n", "text/css"))
    fx.route("/tabs/pixel.png", lambda _r: bytes_response(png(1, 1, "tabs"), "image/png"))
    fx.script("/tabs/parser.js", "REB.beacon('tabs:parser-script');\n")
    fx.script("/tabs/worker.js", WORKER)
    fx.script("/tabs/nested.js", NESTED)
    fx.script("/tabs/shared.js", SHARED)
    fx.script("/tabs/sw/sw.js", SERVICE_WORKER)
    fx.script("/tabs/sw/import.js", "self.importedScript = true;\n")
    fx.page("/tabs/shared-a.html", shared_page("a"))
    fx.page("/tabs/shared-b.html", shared_page("b"))
    fx.page("/tabs/unload.html", UNLOAD)
    fx.page("/tabs/after-unload.html", document("after unload", "<script>REB.beacon('tabs:after-unload');</script>"))
    fx.page("/tabs/sw-register.html", REGISTER)
    fx.page("/tabs/sw/client.html", CLIENT)
    fx.page("/tabs/sw-popup.html", POPUP)
    fx.route("/tabs/sw/last.html", lambda r: html_response(last_client(r.query.get("r", "nav"))))
    fx.page("/tabs/after-sw.html", document("after", "<script>REB.beacon('tabs:after-sw');</script>"))
    fx.route("/tabs/many.html", lambda r: html_response(many_page(int(r.query.get("i", "0")))))
    fx.route("/tabs/sw/many-frame.html", lambda r: html_response(many_frame(r)))
    fx.page("/tabs/speculation.html", SPECULATION)
    fx.page("/tabs/prefetch-target.html", document("prefetched", "<p>prefetched</p>"))
    fx.page("/tabs/prerender-target.html", PRERENDERED)
    fx.route("/tabs/redirect", _redirect)
    fx.route("/tabs/slow-frame", _slow_frame)
    fx.route("/tabs/download", lambda _r: bytes_response(
        b"REB live acceptance download\n", "text/plain",
        [("Content-Disposition", 'attachment; filename="reb-live-acceptance-download.txt"')]))
    for path in ("/tabs/fetch", "/tabs/xhr", "/tabs/worker-fetch", "/tabs/nested-fetch",
                 "/tabs/shared-fetch", "/tabs/unload-beacon", "/tabs/unload-keepalive",
                 "/tabs/sw/passthrough", "/tabs/sw/respond-fetch", "/tabs/sw/cached",
                 "/tabs/sw/after-close", "/tabs/sw/all-clients"):
        fx.route(path, lambda r: text_response(f"{r.path}\n", "text/plain", cors(r)))


def drive(run: Run) -> None:
    fx = run.fixture
    run.open("/tabs/index.html")
    run.wait(ISSUE, ["tabs:index", "tabs:parser-script"], 60)
    run.open("/tabs/shared-a.html")
    run.wait(ISSUE, ["tabs:shared-a"], 30)
    run.open("/tabs/shared-b.html")
    run.wait(ISSUE, ["tabs:shared-b"], 30)
    run.open("/tabs/unload.html")
    run.wait(ISSUE, ["tabs:after-unload"], 30)
    run.open("/tabs/sw-register.html")
    if run.wait(ISSUE, ["tabs:sw-client-reported"], 60):
        fx.release("tabs:sw-client-done")
    run.wait(ISSUE, ["tabs:sw-ready"], 30)

    # A tab a page opened with a trusted click can close itself; one the
    # backend opened cannot, so the fallback leaves the scope instead.
    run.open("/tabs/sw-popup.html")
    run.wait(ISSUE, ["tabs:popup-ready"], 30)
    time.sleep(1)
    if run.click(ISSUE, "window.open", role="button", name="Open the controlled popup"):
        run.wait(ISSUE, ["tabs:last-client-popup"], 30)
    else:
        run.open("/tabs/sw/last.html?r=nav")
        run.wait(ISSUE, ["tabs:last-client-nav", "tabs:after-sw"], 30)
    fx.wait_receipts(lambda r: r.request.path == "/tabs/sw/after-close", 1, 20)

    run.open("/tabs/speculation.html")
    run.wait(ISSUE, ["tabs:speculation-ready"], 30)
    fx.wait_beacons(["tabs:prerender"], 20)
    run.open("/tabs/redirect?n=2&r=nav")
    run.wait(ISSUE, ["tabs:redirect-nav"], 30)

    for index in range(MANY_TABS):
        run.open(f"/tabs/many.html?i={index}")
    run.wait(ISSUE, [f"tabs:many-{index}" for index in range(MANY_TABS)], 120)
    fx.release("tabs:all-open")
    fx.wait_receipts(lambda r: r.request.path == "/tabs/sw/all-clients", 1, 60)


def _on_tab(run: Run, problems: list[str], target: str, tab: str | None, link: int | None = None,
            prefix: bool = False) -> int:
    rows = find_rows(run.rows(), prefix=target) if prefix else find_rows(run.rows(), target=target)
    if not rows:
        problems.append(f"no row for {target}")
        return 0
    if tab is None:
        problems.append(f"the tab of {target} is unknown: its document has no row with a tab")
        return 0
    for row in rows:
        if tab not in row_tabs(row):
            problems.append(f"{target} is on {sorted(row_tabs(row)) or row.get('tab_reason')}, not tab {tab}")
        elif link is not None and (row.get("tab_link") or {}).get("kind") != link:
            problems.append(f"{target} tab_link {row.get('tab_link')}, expected kind {link}")
    return len(rows)


def verify(run: Run) -> None:
    fx, report, rows = run.fixture, run.report, run.rows()
    summary = run.api.summary()
    tabs = summary.get("request_tabs", {})
    unresolved = tabs.get("unresolved")
    report.check(ISSUE, "zero unresolved", [] if unresolved == "0" else [
        f"request_tabs.unresolved {unresolved}: {tabs.get('unresolved_reasons')} "
        f"{tabs.get('unresolved_requests')}"], f"get_session_summary request_tabs.unresolved 0 of {tabs.get('rows')} rows")

    index = run.tab_of("/tabs/index.html")
    problems: list[str] = []
    for target in ("/tabs/style.css?r=parser", "/tabs/parser.js?r=parser", "/tabs/pixel.png?r=parser",
                   "/tabs/fetch?r=1", "/tabs/xhr?r=1"):
        _on_tab(run, problems, target, index)
    report.check(ISSUE, "parser, fetch and XHR loads", problems, f"5 loads on tab {index}")

    problems = []
    _on_tab(run, problems, "/tabs/slow-frame?r=1", index)
    receipt = fx.receipts("/tabs/slow-frame")
    if not receipt:
        problems.append("the removed iframe's request never reached the server")
    report.check(ISSUE, "removed iframe", problems, f"the request of an iframe removed in flight is on tab {index}")

    problems = []
    for target in ("/tabs/worker.js?r=1", "/tabs/worker-fetch?r=1", "/tabs/nested.js?r=1", "/tabs/nested-fetch?r=1"):
        _on_tab(run, problems, target, index)
    report.check(ISSUE, "dedicated and nested workers", problems, f"worker and nested worker loads on tab {index}")

    tab_a, tab_b = run.tab_of("/tabs/shared-a.html"), run.tab_of("/tabs/shared-b.html")
    problems = []
    _on_tab(run, problems, "/tabs/shared-fetch?c=1", tab_a)
    _on_tab(run, problems, "/tabs/shared-fetch?c=2", tab_a)
    _on_tab(run, problems, "/tabs/shared-fetch?c=2", tab_b)
    if tab_a and tab_a == tab_b:
        problems.append(f"both shared worker pages report tab {tab_a}")
    report.check(ISSUE, "shared worker, one then two tabs", problems,
                 f"the one-client fetch is on tab {tab_a}; the two-client fetch is on {tab_a} and {tab_b}")

    unload = run.tab_of("/tabs/unload.html")
    problems = []
    _on_tab(run, problems, "/tabs/unload-beacon?r=1", unload)
    _on_tab(run, problems, "/tabs/unload-keepalive?r=1", unload)
    report.check(ISSUE, "sendBeacon and keepalive at unload", problems, f"both on tab {unload}")

    registrant = run.tab_of("/tabs/sw-register.html")
    problems = []
    # The register job's own fetches come first. Later ones are the update checks a navigation in
    # scope starts, which link to the version's tabs when no page asked (native-network-v3.md).
    updates = 0
    for target in ("/tabs/sw/sw.js", "/tabs/sw/import.js?r=1"):
        found = find_rows(rows, target=target)
        if not found:
            problems.append(f"no row for {target}")
            continue
        if registrant not in row_tabs(found[0]):
            problems.append(f"{target} registration fetch is on {sorted(row_tabs(found[0]))}, not tab {registrant}")
        for row in found[1:]:
            link = row.get("tab_link") or {}
            if not (row_tabs(row) and link.get("complete") and link.get("kind") in (LINK_CLIENTS, LINK_LAST_CLIENTS,
                                                                                 LINK_REGISTRANT)):
                problems.append(f"{target} update check on {sorted(row_tabs(row))} with tab_link {link}")
            updates += 1
    installs = [row for row in find_rows(rows, target="/tabs/sw/cached?r=1") if row.get("initiator") != "script"
                and (row.get("tab_link") or {}).get("kind") == LINK_REGISTRANT]
    if not installs:
        problems.append("no install-time cache.addAll row linked to its registrant (tab_link kind 5)")
    for target in ("/tabs/sw/passthrough?r=1", "/tabs/sw/respond-fetch?r=1", "/tabs/sw/cached?r=1"):
        _on_tab(run, problems, target, registrant)
    ok, value = run.result("tabs:sw-client")
    if not ok:
        problems.append(f"the controlled frame failed: {value}")
    report.check(ISSUE, "service worker install, passthrough, respondWith(fetch()) and cache", problems,
                 f"registration, imports, cache.addAll and the controlled frame's loads are on tab {registrant}; "
                 f"{updates} later update-check fetches link to the version's tabs")

    popup = fx.beacon("tabs:last-client-popup") is not None
    last_target = "/tabs/sw/last.html?r=popup" if popup else "/tabs/sw/last.html?r=nav"
    last_tab = run.tab_of(last_target)
    problems = []
    if not fx.receipts("/tabs/sw/after-close"):
        problems.append("the service worker's fetch after its last client left never reached the server")
    else:
        _on_tab(run, problems, "/tabs/sw/after-close?r=1", last_tab, LINK_LAST_CLIENTS)
    how = "its last tab closed itself" if popup else "its last client navigated out of scope"
    report.check(ISSUE, "service worker fetch after its last tab", problems,
                 f"{how}; the fetch links to tab {last_tab} as its last client")
    if popup:
        opener = run.tab_of("/tabs/sw-popup.html")
        problems = []
        if not last_tab or last_tab == opener:
            problems.append(f"the window.open document is on tab {last_tab}, the opener is {opener}")
        report.check(ISSUE, "window.open first document", problems,
                     f"the popup's first document is on its own tab {last_tab}")
    else:
        report.manual(ISSUE, "window.open first document and a closed last tab",
                      f"a trusted click is unavailable ({run.click_unavailable or 'click failed'}). Grant macOS "
                      "Accessibility to the app that runs reb-api and rerun, or start the content session, open "
                      f"{run.url('/tabs/sw-register.html')}, then {run.url('/tabs/sw-popup.html')}, click "
                      "'Open the controlled popup', and check that get_requests shows /tabs/sw/last.html?r=popup "
                      "on a new tab and /tabs/sw/after-close?r=1 on that tab with tab_link kind 4")

    many = [run.tab_of(f"/tabs/many.html?i={index}") for index in range(MANY_TABS)]
    problems = []
    if None in many or len(set(many)) != MANY_TABS:
        problems.append(f"the {MANY_TABS} client tabs are not {MANY_TABS} distinct tabs: {many}")
    found = find_rows(rows, prefix="/tabs/sw/all-clients?")
    if not found:
        problems.append("no row for the fetch a service worker made with 30 controlled tabs")
    unseen: list[int] = []
    for row in found:
        # Capture must link the tabs of the frames the worker saw as clients.
        # Every frame reported itself controlled, but on a loaded machine the
        # worker once saw 21 of 30 after 30 s: a fixture premise, kept apart.
        seen_text = parse_qs(urlsplit(row.get("target") or "").query).get("seen", [""])[0]
        seen = {int(index) for index in seen_text.split(",") if index.isdigit() and int(index) < MANY_TABS}
        unseen = sorted(set(range(MANY_TABS)) - seen)
        missing = {many[index] for index in seen if many[index]} - row_tabs(row)
        if missing:
            problems.append(f"{row.get('target')} is missing tabs {sorted(missing)}; tab_link {row.get('tab_link')}")
        if (row.get("tab_link") or {}).get("kind") != LINK_CLIENTS:
            problems.append(f"tab_link {row.get('tab_link')}, expected kind {LINK_CLIENTS}")
    if unseen and not problems:
        report.skipped(ISSUE, f"service worker with {MANY_TABS} tabs",
                       f"the worker saw only {MANY_TABS - len(unseen)} of the {MANY_TABS} frames as clients when it "
                       f"fetched (not frames {unseen}), though each reported itself controlled. Its fetch links to "
                       "the tabs of the frames it saw. Rerun with --only tabs")
    else:
        report.check(ISSUE, f"service worker with {MANY_TABS} tabs", problems,
                     f"its fetch links to all {MANY_TABS} client tabs")

    speculation = run.tab_of("/tabs/speculation.html")
    prefetched = [r for r in fx.receipts("/tabs/prefetch-target.html") if "prefetch" in (r.request.header("Sec-Purpose") or "")]
    prerendered = [r for r in fx.receipts("/tabs/prerender-target.html") if "prerender" in (r.request.header("Sec-Purpose") or "")]
    if not prefetched and not prerendered:
        report.manual(ISSUE, "speculation-rules prefetch and prerender",
                      "the server saw no request with Sec-Purpose prefetch or prerender, so this Brave did not "
                      "preload (Brave turns Preload pages off by default). Start the content session, enable "
                      "brave://settings/performance 'Preload pages', open "
                      f"{run.url('/tabs/speculation.html')} and check that get_requests shows "
                      "/tabs/prefetch-target.html?r=1 and /tabs/prerender-target.html?r=1 on that tab")
    else:
        problems = []
        if prefetched:
            _on_tab(run, problems, "/tabs/prefetch-target.html?r=1", speculation)
        else:
            problems.append("the prefetch never reached the server")
        if prerendered:
            _on_tab(run, problems, "/tabs/prerender-target.html?r=1", speculation)
            activation = fx.beacon("tabs:prerender")
            if not (isinstance(activation, dict) and activation.get("activationStart", 0) > 0):
                problems.append(f"the prerender did not activate: {activation}")
        else:
            problems.append("the prerender never reached the server")
        report.check(ISSUE, "speculation-rules prefetch and prerender", problems,
                     f"prefetch and the activated prerender are on tab {speculation}")

    problems = []
    redirected = [row for row in rows if (row.get("target") or "").startswith("/tabs/redirect?") and "r=nav" in row["target"]]
    if not redirected:
        problems.append("no row for the redirect chain navigation")
    for row in redirected:
        if not row_tabs(row):
            problems.append(f"{row.get('target')} has no tab: {row.get('tab_reason')}")
    for row in [row for row in rows if (row.get("target") or "").startswith("/tabs/redirect?") and "r=fetch" in row["target"]]:
        if index not in row_tabs(row):
            problems.append(f"the fetch redirect chain {row.get('target')} is not on tab {index}")
    report.check(ISSUE, "redirect chains", problems, "a navigation and a fetch through two redirects are on their tabs")

    problems = []
    downloads = find_rows(rows, target="/tabs/download?r=1")
    if not fx.receipts("/tabs/download"):
        problems.append("the download never reached the server")
    _on_tab(run, problems, "/tabs/download?r=1", index)
    report.check(ISSUE, "download", problems, f"the download is on tab {index}")
    if downloads:
        run.notes.append("the #425 download may have saved reb-live-acceptance-download.txt to the "
                         "research profile's download folder (macOS default: ~/Downloads)")
