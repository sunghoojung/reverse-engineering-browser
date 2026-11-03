# Document-start Console scripts

An agent or researcher registers a small JavaScript snippet plus an explicit
match rule. The native Console runs that snippet in the page main world of
every **new matching document**, before that document's own scripts, and the
snippet's bounded output is read back through the loopback HTTP API.

[Native Console v3](../../protocol/native-console-v3.md) is the contract:
limits, wire layout, refusals and the live-browser acceptance list.
[`SAFETY.md`](../../SAFETY.md) owns the authorization policy that governs
arming this at all. Use it only on a system you own or are explicitly
authorized to test.

## When this is the right tool

Use it when the thing you need to see happens **before** you could evaluate
anything by hand: a page defining a global, installing a handler, reading a
value during parse, or running once at startup. An explicit console command
always arrives too late for those.

Use the explicit console instead when the page is already loaded and you want
to inspect or change it once. Use native capture when you need evidence: a
document-start snippet is page JavaScript, not capture, and never becomes
evidence.

## Enable it

Three independent gates must all be satisfied. None implies the others, and
nothing is relaunched to obtain one.

1. A browser built from the pinned revisions with the v3 overlay. Without it
   the browser never advertises support and arming fails closed.
2. Permission for that browser session:
   - disposable (the default): send `document_start: true` with the Console
     `start` action, or check **Permit document-start scripts in the next
     disposable session** in the Console settings before connecting;
   - live capture: launch it with `REB_CONSOLE_DOCUMENT_START=1`. A capture
     already running without it cannot be upgraded.
3. An explicit confirmed arm. Clearing the set, disconnecting, ending the
   session, or session expiry removes it.

The switch alone arms nothing. A permitted session with no armed script runs no
snippet, and document creation costs one check.

## The local synthetic page

Everything below uses the repository-authored fixture in
[`tools/fixtures/console-document-start/`](../../tools/fixtures/console-document-start/).
`synthetic-transform.html` defines one plain function on `window` and calls it
with authored values; `synthetic-transform-child.html` is a child frame. No
third-party site, service or vendor code is involved.

Serve it from a local HTTP server and use that server's exact origin:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 \
  --directory tools/fixtures/console-document-start
```

For a cross-origin child frame, serve the same directory from a second port and
open
`http://127.0.0.1:8080/synthetic-transform.html?child=http://127.0.0.1:8081/synthetic-transform-child.html`.
`127.0.0.1:8080` and `127.0.0.1:8081` are different origins, so the child gets
its own renderer process, and a `child` rule must name the child's own origin.

## Arm the example snippet

[`observe-synthetic-transform.js`](../../tools/fixtures/console-document-start/observe-synthetic-transform.js)
is the example. It installs a configurable accessor on `window` before the
page's inline script runs, so it observes the page's own assignment of
`window.syntheticTransform`, then logs only argument kinds and lengths, the
return length, and a digest:

```js
report(
  `call=${calls} args=${args.map(shape).join(',')} return=${shape(result)}` +
    (typeof result === 'string' ? ` digest=${digest(result)}` : ''),
);
```

It never logs a raw string, so it cannot leak a token, cookie, credential or
body even if the observed function handled one. Keep that property in anything
you write. `report` accepts a string, number, boolean or bigint; a string over
512 UTF-8 bytes is kept as a visibly truncated prefix, and any other argument
produces a `refused` record instead.

Arm it against the exact origin, for top frames, under the fixture's path:

```sh
python3 - <<'PY'
import json, urllib.request
from pathlib import Path

endpoint = Path.home() / ".config/origin-trace/reb-api.endpoint"
url = endpoint.read_text().strip()
session = json.load(urllib.request.urlopen(url + "/api/native-console"))["session_id"]
body = json.dumps({
    "action": "arm_document_start",
    "session_id": session,
    "confirm_document_start": True,
    "scripts": [{
        "origin": "http://127.0.0.1:8080",
        "frame": "top",
        "path_prefix": "/synthetic-transform.html",
        "source": Path("tools/fixtures/console-document-start/"
                       "observe-synthetic-transform.js").read_text(),
    }],
}).encode()
request = urllib.request.Request(url + "/api/native-console/actions", data=body,
                                 headers={"Content-Type": "application/json"})
print(json.dumps(json.load(urllib.request.urlopen(request)), indent=2))
PY
```

Then reload the page and read the output:

```sh
curl -s "$(cat ~/.config/origin-trace/reb-api.endpoint)/api/native-console/document-start?after_sequence=0"
```

Through `reb-api mcp`, the same surfaces are the `get_native_console_document_start`,
`native_console_action` and `get_native_console` tools. All three exchange a
request with the browser process, so they are classified as effectful and stay
hidden unless `--allow-effects` is set. That flag is not authorization,
redaction, or permission to send captured data to a model.

## Writing a rule that cannot widen

A rule names exactly one target:

| Field | Rule |
| --- | --- |
| `origin` | One exact serialized origin, lowercase, no path, credentials, wildcard, host suffix or trailing slash. `http://127.0.0.1:8080` does not cover `127.0.0.1:8081`, `localhost:8080`, or `https://`. |
| `frame` | Exactly `top` or `child`. Arm two rules if you need both. |
| `path_prefix` | Optional literal prefix of the committed path. Absent matches every path in that origin. |

A document no declared rule covers is never injected. There is no pattern, no
wildcard, no host suffix, and no URL guessing.

## What to expect, and what to check

- **Only new documents.** A document already open when you arm is never
  retroactively injected. Reload it.
- **Renderer readiness.** `pending_renderer_processes` is zero once every live
  renderer holds the current generation. Reload after it reaches zero; a
  positive value is a readiness gap, not a lost record.
- **Reads do not drain.** Pass the last `sequence` you saw as
  `after_sequence`. A failed or slow read cannot lose a record; the bounded
  ring reports `dropped` when it evicts one.
- **Output is page JavaScript.** Every record carries provenance
  `console-document-start-script`, is snippet-authored untrusted text, and is
  never evidence, never correlated, and never exported automatically.
- **Clearing really stops it.** After `clear_document_start`, a `report`
  function the page retained becomes an inert no-op. Work the snippet already
  scheduled in the page is not rolled back.
- **Disconnecting a live capture clears it too.** The capture browser outlives
  each Console connection, so Disconnect clears an armed set and waits for the
  browser to confirm it. If that cannot be confirmed, Disconnect fails and the
  state reads `unconfirmed`, not idle: restart the capture before relying on new
  documents running nothing.

## Limits worth remembering

Four scripts, 4096 bytes each and 8192 per set; 64 records per document then
one refusal notice; a 128-record ring with a visible drop count; 32 records per
read; a 50 ms synchronous injection budget; and a lifetime of at most one hour,
bounded by the Console session.

A snippet runs with the page's full main-world authority. The `(function(report)
{ … })` wrapper exists to supply `report`; it is not a sandbox. A page can see
what a snippet defines and what it does.

## Verify a change

```sh
make native-tests                                   # rule, codec and wire admission
make native-console-check                           # real C++ transport and HTTP API
node tools/check-native-console-document-start.mjs  # the shipped panel
```

None of these prove Blink, V8 or the pinned browser. After rebuilding the
matching browser, backend and packaged assets, run the acceptance list in
[Native Console v3](../../protocol/native-console-v3.md): the disabled control,
a non-matching frame, a matching child frame, refresh and a new document, the
limits and gap counters, lifetime, and the packaged macOS app.
