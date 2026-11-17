"""#427: request and response headers equal what the echo server saw and sent."""

from __future__ import annotations

from collections import Counter

from live_acceptance.evidence import find_rows, parse_header_block, per_request
from live_acceptance.fixture import Fixture, Receipt, Request, Response, payload, redirect
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#427"
NAME = "headers"
LARGE_HEADERS, LARGE_VALUE = 52, 4000
LARGE_BLOCK_MIN = 200 * 1024
HOPS = ("/headers/hop1", "/headers/hop2", "/headers/final")

INDEX = document("headers", """<script>
REB.run('headers:redirects', () => fetch('/headers/hop1?r=1', {
  headers: {'X-Reb-Probe': 'one', 'X-Reb-Probe-List': 'a, b'},
}).then(response => response.text()));
REB.run('headers:large', () => fetch('/headers/large?r=1')
  .then(response => response.headers.get('X-Reb-Large-00').length));
</script>""")


def large_headers() -> list[tuple[str, str]]:
    return [(f"X-Reb-Large-{index:02d}", payload(f"large-header-{index}", LARGE_VALUE // 2).hex())
            for index in range(LARGE_HEADERS)]


def _hop(request: Request) -> Response:
    token = request.query.get("r", "")
    common = [("X-Reb-Multi", "first"), ("X-Reb-Multi", "second")]
    if request.path == "/headers/hop1":
        return redirect(f"/headers/hop2?r={token}", 302,
                        [*common, ("X-Reb-Hop", "1"), ("Set-Cookie", "hdr_hop1=one; Path=/")])
    if request.path == "/headers/hop2":
        return redirect(f"/headers/final?r={token}", 307,
                        [*common, ("X-Reb-Hop", "2"), ("Set-Cookie", "hdr_hop2=two; Path=/")])
    body = "\n".join(f"{name}: {value}" for name, value in request.headers).encode()
    return Response(200, [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store"),
                          *common, ("X-Reb-Hop", "final")], body)


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/headers/index.html", INDEX)
    for path in HOPS:
        fx.route(path, _hop)
    fx.route("/headers/large", lambda _r: Response(
        200, [("Content-Type", "text/plain"), ("Cache-Control", "no-store"), *large_headers()], b"large\n"))


def drive(run: Run) -> None:
    run.open("/headers/index.html")
    run.wait(ISSUE, ["headers:redirects", "headers:large"], 60)


def compare(recorded: list[tuple[str, str]], served: list[tuple[str, str]]) -> list[str]:
    """Differences between two header lists: names without case, values exact."""
    def key(pairs):
        return Counter((name.lower(), value.strip(" \t")) for name, value in pairs)

    have, want = key(recorded), key(served)
    problems = [f"missing {name}: {value[:60]}" for (name, value), n in (want - have).items() for _ in range(n)]
    problems += [f"extra {name}: {value[:60]}" for (name, value), n in (have - want).items() for _ in range(n)]
    return problems


def block_headers(run: Run, block: dict) -> tuple[list[tuple[str, str]] | None, str]:
    """A captured block's exact lines, from its artifact, with credential values."""
    if block.get("state") not in ("captured", "captured_shared"):
        return None, f"state {block.get('state')}"
    if block.get("artifact") != "verified":
        return None, f"artifact {block.get('artifact')}"
    return parse_header_block(run.api.content(block["artifact_id"])), ""


def network_block(blocks: list[dict]) -> dict | None:
    return next((b for b in blocks if b.get("source") == "network"), None)


def check_hop(run: Run, label: str, hop: dict, receipt: Receipt, problems: list[str]) -> None:
    if hop.get("network_block_missing"):
        problems.append(f"{label}: network block missing ({hop['network_block_missing']})")
    for side, blocks, served in (("request", hop.get("request", []), receipt.request.headers),
                                 ("response", hop.get("response", []), receipt.response_headers)):
        block = network_block(blocks)
        if block is None:
            problems.append(f"{label} {side}: no network block, sources {[b.get('source') for b in blocks]}")
            continue
        headers, why = block_headers(run, block)
        if headers is None:
            problems.append(f"{label} {side}: {why}")
            continue
        problems += [f"{label} {side}: {p}" for p in compare(headers, served)]
        listed = [entry.get("name", "").lower() for entry in block.get("headers", [])]
        if listed != [name.lower() for name, _ in headers]:
            problems.append(f"{label} {side}: the headers list does not follow its artifact")
        if side == "response" and block.get("status_code") != receipt.status:
            problems.append(f"{label}: status {block.get('status_code')}, the server sent {receipt.status}")


def verify(run: Run) -> None:
    report, rows = run.report, run.rows()
    receipts = [run.fixture.receipts(path) for path in HOPS]
    problems: list[str] = []
    if any(len(found) != 1 for found in receipts):
        problems.append(f"the server saw {[len(found) for found in receipts]} requests for the three hops")
    chain = [row for path in HOPS for row in find_rows(rows, target=f"{path}?r=1")]
    chain = list({row["id"]: row for row in chain}.values())
    if len(chain) != 1:
        problems.append(f"{len(chain)} rows for the redirect chain, expected one")
    elif not problems:
        hops = sorted(per_request(run.api, "/api/request-headers", chain[0]).get("hops", []),
                      key=lambda hop: hop.get("hop", 0))
        if len(hops) != len(HOPS):
            problems.append(f"{len(hops)} hops recorded, the server saw {len(HOPS)}")
        for index, (hop, found) in enumerate(zip(hops, receipts)):
            check_hop(run, f"hop {index}", hop, found[0], problems)
    report.check(ISSUE, "headers across two redirect hops", problems,
                 "request and response header blocks of all three hops equal the server's, credential values included")

    problems = []
    large = find_rows(rows, target="/headers/large?r=1")
    served = run.fixture.receipts("/headers/large")
    if len(large) != 1 or len(served) != 1:
        problems.append(f"{len(large)} rows and {len(served)} receipts for /headers/large")
    else:
        hops = per_request(run.api, "/api/request-headers", large[0]).get("hops", [])
        block = network_block(hops[0].get("response", [])) if hops else None
        if block is None:
            problems.append("no network response block")
        else:
            if block.get("block_bytes", 0) < LARGE_BLOCK_MIN:
                problems.append(f"block_bytes {block.get('block_bytes')} below {LARGE_BLOCK_MIN}")
            headers, why = block_headers(run, block)
            if headers is None:
                problems.append(why)
            else:
                problems += compare(headers, served[0].response_headers)
    report.check(ISSUE, "200 KiB response header block", problems,
                 f"a {served[0].head_bytes if served else 0}-byte response head is kept whole")

    report.manual(ISSUE, "DevTools shows the same headers",
                  f"in the content session open DevTools on {run.url('/headers/index.html')}, reload, and in "
                  "Network compare /headers/hop1?r=1 (all hops) and /headers/large?r=1 with get_request_headers: "
                  "the same request and response headers, no 'Provisional headers' warning, and the same view "
                  "as a stock Brave of the same version without capture")
