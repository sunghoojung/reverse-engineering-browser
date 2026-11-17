"""The release-notes baseline: Wasm dispatch, a Canvas readback and fingerprint reads."""

from __future__ import annotations

import base64

from live_acceptance.binary import wasm_dispatch
from live_acceptance.fixture import Fixture, bytes_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "release notes"
NAME = "baseline"
PICKS = [1, 20, 10, 20]

INDEX = document("baseline", """<script>
REB.run('baseline', async () => {
  const {instance} = await WebAssembly.instantiateStreaming(fetch('/baseline/dispatch.wasm'));
  const picks = [0, 1, 2, 3].map(i => instance.exports.pick(i));
  const canvas = document.createElement('canvas');
  canvas.width = 64;
  canvas.height = 32;
  const context = canvas.getContext('2d');
  context.fillStyle = '#c33';
  context.fillRect(0, 0, 64, 32);
  context.fillStyle = '#fff';
  context.fillText('REB', 4, 20);
  const image = canvas.toDataURL();
  const surfaces = [navigator.userAgent, navigator.hardwareConcurrency, screen.width, navigator.languages.join()];
  return {picks, image, surfaces: surfaces.length};
});
</script>""")


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/baseline/index.html", INDEX)
    fx.route("/baseline/dispatch.wasm", lambda _r: bytes_response(wasm_dispatch(), "application/wasm"))


def drive(run: Run) -> None:
    run.open("/baseline/index.html")
    run.wait(ISSUE, ["baseline"], 60)


def verify(run: Run) -> None:
    report = run.report
    ok, value = run.result("baseline")
    if not ok:
        report.failed(ISSUE, "baseline page", str(value))
        return
    problems: list[str] = []
    if value.get("picks") != PICKS:
        problems.append(f"pick() returned {value.get('picks')}, expected {PICKS}")
    dispatch = run.api.events("wasm_dispatch_observation")
    indirect = run.api.events("wasm_indirect_observation")
    if not dispatch or not indirect:
        problems.append(f"{len(dispatch)} br_table and {len(indirect)} call_indirect observations")
    report.check(ISSUE, "Wasm br_table and call_indirect", problems,
                 f"{len(dispatch)} br_table and {len(indirect)} call_indirect observations")

    problems = []
    image = str(value.get("image", ""))
    decoded = base64.b64decode(image.partition(",")[2] or "")
    images = run.api.artifacts(kind="canvas_data_url")
    if not images:
        problems.append("no canvas_data_url artifact")
    elif not any(run.api.content(artifact["artifact_id"]) in (image.encode(), decoded) for artifact in images):
        problems.append(f"none of {len(images)} canvas_data_url artifacts holds the page's toDataURL image")
    report.check(ISSUE, "Canvas readback image", problems, "the toDataURL image is kept byte for byte")

    problems = []
    surfaces = run.api.events("property_read,api_call")
    categories = sorted({event.get("category") for event in surfaces})
    if "navigator" not in categories or "canvas" not in categories:
        problems.append(f"fingerprint reads in categories {categories}, expected navigator and canvas")
    report.check(ISSUE, "network and fingerprint surfaces", problems,
                 f"{len(surfaces)} fingerprint reads in {categories}")
