"""#429: request call stacks, frame for frame against the fixture's own source."""

from __future__ import annotations

from live_acceptance.binary import wasm_import_caller
from live_acceptance.evidence import find_rows, request_stack
from live_acceptance.fixture import Fixture, bytes_response, cors, html_response, text_response
from live_acceptance.pages import document, line_of
from live_acceptance.run import Options, Run

ISSUE = "#429"
NAME = "stacks"
WRAPPERS = 148          # target + 148 wrappers + the top level = 150 frames
RECURSION = 4998        # dive(0..4998) + the top level = 5,000 frames
FRAME_LIMIT, HALF = 1024, 512
REPEATS = 10

DEEP = f"""// 150 frames: one target, {WRAPPERS} framework-style wrappers and the top level.
function wrap(next) {{
  return function wrapper() {{
    return next();
  }};
}}
let call = function target() {{
  return fetch('/stacks/deep?r=1');
}};
for (let i = 0; i < {WRAPPERS}; i++) call = wrap(call);
call();
"""
RECURSIVE = f"""// 5,000 frames deep at the fetch.
function dive(depth) {{
  if (depth === 0) return fetch('/stacks/recursion?r=1');
  return dive(depth - 1);
}}
dive({RECURSION});
"""
NETWORK = "// a network script\nfetch('/stacks/network?r=1');\n"
EVAL_SOURCE = "fetch('/stacks/eval?r=1');"
WASM = """REB.run('stacks:wasm', async () => {
  const imports = {env: {f: () => { fetch('/stacks/wasm?r=1'); }}};
  const {instance} = await WebAssembly.instantiateStreaming(fetch('/stacks/import.wasm'), imports);
  instance.exports.run();
});
"""
AWAITS = """async function innerAwait() {
  await REB.sleep(5);
  return fetch('/stacks/await?r=1');
}
async function middleAwait() {
  await innerAwait();
}
async function outerAwait() {
  await middleAwait();
}
REB.run('stacks:await', () => outerAwait());
"""
REPEAT = f"""function repeatedSite(i) {{
  return fetch('/stacks/repeat?i=' + i);
}}
for (let i = 0; i < {REPEATS}; i++) repeatedSite(i);
REB.beacon('stacks:repeat');
"""
INDEX = document("stacks", f"""<script src="/stacks/deep.js"></script>
<script src="/stacks/recursion.js"></script>
<script src="/stacks/network.js"></script>
<script>
fetch('/stacks/inline?r=1');
eval({EVAL_SOURCE!r});
REB.beacon('stacks:inline');
</script>
<script src="/stacks/wasm.js"></script>
<script src="/stacks/await.js"></script>
<script src="/stacks/repeat.js"></script>""")


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/stacks/index.html", INDEX)
    for path, source in (("/stacks/deep.js", DEEP), ("/stacks/recursion.js", RECURSIVE),
                         ("/stacks/network.js", NETWORK), ("/stacks/wasm.js", WASM),
                         ("/stacks/await.js", AWAITS), ("/stacks/repeat.js", REPEAT)):
        fx.script(path, source)
    fx.route("/stacks/import.wasm", lambda _r: bytes_response(wasm_import_caller(), "application/wasm"))
    for path in ("/stacks/deep", "/stacks/recursion", "/stacks/network", "/stacks/inline", "/stacks/eval",
                 "/stacks/wasm", "/stacks/await", "/stacks/repeat"):
        fx.route(path, lambda r: text_response("ok\n", "text/plain", cors(r)))
    fx.route("/stacks/blank.html", lambda _r: html_response("<p>blank</p>"))


def drive(run: Run) -> None:
    run.open("/stacks/index.html")
    run.wait(ISSUE, ["stacks:inline", "stacks:wasm", "stacks:await", "stacks:repeat"], 60)


def expected_deep() -> list[tuple[str, int]]:
    """Every frame of the 150-frame stack, innermost first: (script, line)."""
    return ([("/stacks/deep.js", line_of(DEEP, "return fetch("))]
            + [("/stacks/deep.js", line_of(DEEP, "return next();"))] * WRAPPERS
            + [("/stacks/deep.js", line_of(DEEP, "call();\n"))])


def expected_recursion() -> list[tuple[str, int]]:
    """Every frame of the 5,000-deep stack, innermost first."""
    return ([("/stacks/recursion.js", line_of(RECURSIVE, "return fetch("))]
            + [("/stacks/recursion.js", line_of(RECURSIVE, "return dive("))] * RECURSION
            + [("/stacks/recursion.js", line_of(RECURSIVE, f"dive({RECURSION});"))])


def kept_frames(frames: list) -> list:
    """What a 1,024-frame walk keeps: the innermost and the outermost 512."""
    return frames if len(frames) <= FRAME_LIMIT else frames[:HALF] + frames[-HALF:]


def expected_await_lines() -> list[int]:
    """The lines of the two awaiting callers, innermost first."""
    return [line_of(AWAITS, "await innerAwait();"), line_of(AWAITS, "await middleAwait();")]


def stack_for(run: Run, target: str, problems: list[str]) -> dict | None:
    rows = find_rows(run.rows(), target=target)
    if len(rows) != 1:
        problems.append(f"{target}: {len(rows)} rows")
        return None
    stack = request_stack(run.api, rows[0])
    if stack.get("status") != "recorded":
        problems.append(f"{target}: stack {stack.get('status')} {stack.get('error', '')}".strip())
        return None
    if stack.get("state") != "captured":
        problems.append(f"{target}: stack state {stack.get('state')}")
    return stack


def frame_at(frame: dict, url_suffix: str, line: int) -> str | None:
    resolution = frame.get("resolution") or {}
    if resolution.get("status") != "resolved":
        return f"frame {frame.get('index')} is {resolution.get('status')} {resolution.get('reason', '')}".strip()
    if not (resolution.get("url") or "").endswith(url_suffix) or resolution.get("line") != line:
        return (f"frame {frame.get('index')} resolves to {resolution.get('url')}:{resolution.get('line')}, "
                f"expected {url_suffix}:{line}")
    return None


def check_frames(frames: list[dict], expected: list[tuple[str, int]], problems: list[str], label: str) -> None:
    if len(frames) != len(expected):
        problems.append(f"{label}: {len(frames)} frames, expected {len(expected)}")
    for frame, (url, line) in zip(frames, expected):
        wrong = frame_at(frame, url, line)
        if wrong:
            problems.append(f"{label}: {wrong}")
            return


def verify(run: Run) -> None:
    report = run.report

    problems: list[str] = []
    stack = stack_for(run, "/stacks/deep?r=1", problems)
    if stack:
        if (stack.get("total_depth"), stack.get("recorded"), stack.get("omitted")) != (150, 150, 0):
            problems.append(f"depth {stack.get('total_depth')}, recorded {stack.get('recorded')}, "
                            f"omitted {stack.get('omitted')}; expected 150, 150, 0")
        check_frames(stack.get("frames", []), expected_deep(), problems, "150 frames")
    report.check(ISSUE, "150-frame stack through wrappers", problems,
                 "all 150 frames recorded, each at its source line")

    problems = []
    stack = stack_for(run, "/stacks/recursion?r=1", problems)
    total = RECURSION + 2
    if stack:
        if (stack.get("total_depth"), stack.get("recorded"), stack.get("omitted")) != (total, FRAME_LIMIT, total - FRAME_LIMIT):
            problems.append(f"depth {stack.get('total_depth')}, recorded {stack.get('recorded')}, omitted "
                            f"{stack.get('omitted')}; expected {total}, {FRAME_LIMIT}, {total - FRAME_LIMIT}")
        if stack.get("omitted_after_index") != HALF - 1:
            problems.append(f"omitted_after_index {stack.get('omitted_after_index')}, expected {HALF - 1}")
        check_frames(stack.get("frames", []), kept_frames(expected_recursion()), problems, "recursion")
    report.check(ISSUE, "5,000-deep recursion", problems,
                 f"{FRAME_LIMIT} frames kept (the innermost and outermost {HALF}) and {total - FRAME_LIMIT} omitted of {total}")

    problems = []
    origins = {}
    for target, url, line, eval_frame in (
            ("/stacks/inline?r=1", "/stacks/index.html", line_of(INDEX, "fetch('/stacks/inline"), False),
            ("/stacks/eval?r=1", "", 1, True),
            ("/stacks/network?r=1", "/stacks/network.js", line_of(NETWORK, "fetch("), False)):
        stack = stack_for(run, target, problems)
        if not stack or not stack.get("frames"):
            continue
        top = stack["frames"][0]
        if bool(top.get("eval")) != eval_frame:
            problems.append(f"{target}: frame eval {top.get('eval')}")
        wrong = frame_at(top, url, line) if url else None
        resolution = top.get("resolution") or {}
        if wrong:
            problems.append(f"{target}: {wrong}")
        elif resolution.get("status") != "resolved":
            problems.append(f"{target}: frame {resolution}")
        else:
            artifact = run.api.artifact(resolution["artifact_id"]) or {}
            origins[target] = artifact.get("capture_origin")
        if eval_frame and len(stack["frames"]) > 1:
            wrong = frame_at(stack["frames"][1], "/stacks/index.html", line_of(INDEX, "eval("))
            if wrong:
                problems.append(f"{target} caller: {wrong}")
    report.check(ISSUE, "inline, eval and network script frames resolve", problems,
                 f"each resolves to its file and line; source artifacts {origins}")

    problems = []
    stack = stack_for(run, "/stacks/wasm?r=1", problems)
    if stack:
        frames = stack.get("frames", [])
        kinds = [frame.get("kind") for frame in frames]
        if stack.get("wasm_frames", 0) < 2 or kinds[1:3] != ["wasm", "wasm"]:
            problems.append(f"wasm_frames {stack.get('wasm_frames')}, frame kinds {kinds[:4]}")
        else:
            names = [(frame.get("resolution") or {}).get("function_name") for frame in frames[1:3]]
            indexes = [frame.get("function_index") for frame in frames[1:3]]
            if indexes != [1, 2]:
                problems.append(f"Wasm frames name functions {indexes} {names}, expected 1 (reb_inner) and 2 (reb_run)")
        wrong = frame_at(frames[0], "/stacks/wasm.js", line_of(WASM, "fetch('/stacks/wasm")) if frames else "no frames"
        if wrong:
            problems.append(wrong)
    ok, value = run.result("stacks:wasm")
    if not ok:
        problems.append(f"the Wasm page failed: {value}")
    report.check(ISSUE, "fetch from a Wasm import", problems, "the import's JS frame, then reb_inner and reb_run")

    problems = []
    stack = stack_for(run, "/stacks/await?r=1", problems)
    if stack:
        awaits = [frame for frame in stack.get("frames", []) if frame.get("kind") == "await"]
        lines = [(frame.get("resolution") or {}).get("line") for frame in awaits]
        want = expected_await_lines()
        if stack.get("async_frames", 0) < 2 or lines[:2] != want:
            problems.append(f"async_frames {stack.get('async_frames')}, await frames at lines {lines}, expected {want}")
        if not any(segment.get("kind") == "microtask" and segment.get("promise_stacks_on")
                   for segment in stack.get("task_segments", [])):
            problems.append("no microtask segment with promise stacks on: "
                            f"{[(s.get('kind'), s.get('promise_stacks_on')) for s in stack.get('task_segments', [])]}")
    report.check(ISSUE, "await chain", problems, "the awaiting callers show as async frames")

    problems = []
    digests = []
    for index in range(REPEATS):
        stack = stack_for(run, f"/stacks/repeat?i={index}", problems)
        if stack:
            digests.append(stack.get("digest"))
    if len(set(digests)) != 1 or None in digests:
        problems.append(f"{len(set(digests))} distinct digests over {len(digests)} stacks")
    else:
        stored = run.api.artifacts(kind="stack", sha256=digests[0])
        if len(stored) != 1:
            problems.append(f"{len(stored)} stack artifacts carry the shared digest, expected one")
    report.check(ISSUE, "one call site's stack sent once", problems,
                 f"{REPEATS} requests share one digest and one stack artifact")

    report.manual(ISSUE, "stacks match DevTools frame for frame",
                  f"in the content session open DevTools on {run.url('/stacks/index.html')}, reload, and in "
                  "Network compare the Initiator stack of /stacks/deep?r=1 (and the async part of /stacks/await?r=1) "
                  "with get_request_stack: the same functions, files, lines and columns, frame for frame")
    report.manual(ISSUE, "stack walk cost",
                  "measure p50 and p99 stack walk time per request with a profiler (Instruments) on this page, and "
                  "record how it was measured; the inactive path is one atomic load")
