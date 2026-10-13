# Traffic capture runtime QA

Use the synthetic fixture to test the actual Traffic export controls in native
WebKit and browser development. It serves the real UI through the app's existing
loopback `--ui-url` option. No real capture, account, personal browser profile,
or external site is needed. All credentials and values below are synthetic.

This fixture tests authored UI snapshots and clipboard/download behavior. It
does not establish CDP collection, body retrieval scheduling, backend clipping,
real reconnections, or native Brave probes. Those require their own tests. The
native route here is live HTTP WebKit, not custom `reb://` stored-evidence mode.

## Build and start

Record the exact source revision and dirty status, macOS version/architecture,
Node version and app origin. Follow the full gate in [AGENTS.md](../../AGENTS.md).
For native QA, build and verify the intended app:

```sh
make app-build
codesign --verify --deep --strict "build/Origin Trace.app"
```

The package check requires `ORIGIN_TRACE_TEST_BROWSER` to name an already
installed supported Chrome/Chromium executable; it uses a disposable profile.
For example, on a Mac with Chrome already installed:

```sh
export ORIGIN_TRACE_TEST_BROWSER="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
node tools/check-origin-trace-package.mjs
node tools/check-origin-trace-native-close.mjs
```

The fixture's contract and loopback checks run in `make javascript-check`:

```sh
node tools/check-traffic-capture-qa.mjs
```

From the repository root, start the fixture with the packaged UI assets:

```sh
REB_QA_ASSET_DIR="$PWD/build/Origin Trace.app/Contents/Resources/research-ui" \
  node tools/traffic-capture-qa.mjs serve "$PWD"
```

It prints a random `http://127.0.0.1:PORT/` URL and the exact native launch
command. Run that command in another terminal. It disables automatic live
sessions. Each served public asset must byte-match the current source before
the server starts. No bundle or source file is changed. Without
`REB_QA_ASSET_DIR`, the fixture serves source-tree assets for browser QA.

Keep the fixture terminal open: it accepts `baseline`, `epoch`, `instance`,
`target`, `truncated`, `states`, `clear`, `off`, `disconnect`, `malformed`, and
`quit`. It listens only on IPv4 loopback, requires the exact loopback Host,
rejects non-GET requests, serves only declared public UI assets, and has no HTTP
mutation route. It never starts a browser, fetches captured URLs, exports data
or accesses the OS clipboard. Stop with `quit` or Ctrl+C.

Open Requests/Traffic and select `synthetic-json`. Broker-unavailable/Network
only disclosure is expected because the synthetic fixture has no native broker.
Other workspaces are intentionally unavailable. Do not start Live capture from
this fixture.

## Exact Copy checks

Copy replaces the system clipboard and may participate in existing OS clipboard
sync. If native Copy is unsupported or denied, record that limitation and leave
permissions unchanged. Both native Save actions must remain disabled.

Select **Export capture → Copy raw capture**, then save the explicitly copied
synthetic clipboard text to a new local file:

```sh
QA_OUT="$(mktemp -d -t reb-traffic-runtime-qa)"
pbpaste > "$QA_OUT/json.raw.json"
REB_QA_EXPECT_MODE=raw node tools/traffic-capture-qa.mjs verify \
  "$QA_OUT/json.raw.json" synthetic-json
```

The verifier checks the entire retained record against an independent oracle.
Baseline raw values are:

- URL, document URL and initiator source: `https://synthetic-user:synthetic-pass@example.test/path?token=synthetic-query#synthetic-fragment`
- Authorization: `Bearer synthetic-auth`; Cookie: `synthetic-cookie`
- Proxy-Authorization: `synthetic-proxy`; X-Custom-Token: `synthetic-custom`
- Set-Cookie: `synthetic-response-cookie`
- Target title: `Synthetic title`; error: `Synthetic diagnostic text`
- JSON body: `{"password":"synthetic-json","n":9007199254740993,"dup":1,"dup":2}`
- Response base64: `AP8BAgM=`; decoded bytes: `00 ff 01 02 03`
- Coverage dropped: `7`; limits: `1000 / 131072 / 128 / 65536`

Select **Copy redacted copy**, paste to a different file, and verify:

```sh
pbpaste > "$QA_OUT/json.redacted.json"
REB_QA_EXPECT_MODE=redacted_copy node tools/traffic-capture-qa.mjs verify \
  "$QA_OUT/json.redacted.json" synthetic-json
```

Expected redaction: URLs become `https://example.test/path`; every header value,
target title and error text become `<redacted>`; bodies become `redacted` with
empty text/base64 and reason `Body content omitted from this explicitly redacted copy.`
IDs, timing, method, status, truncation flags and retention/drop disclosure stay
unchanged. The warning states that paths, header names and other metadata may
still contain secrets. This is best-effort, not universal sanitization.

Copy raw again to a new file and verify it, proving explicit redaction did not
mutate retained values. Request/Response views must still show raw values.
Selection, refresh and menu opening must not trigger Copy or Save automatically.

Repeat both modes for `synthetic-form` and `synthetic-plain`. The form body is
exactly `token=synthetic-form&token=second+value`. The plain body is a BOM, `雪`,
CRLF, and `<script>synthetic-plain</script>`; it must remain inert. The oracle
checks newline/BOM preservation, duplicate JSON keys, large-number spelling and
binary bytes without reparsing the body JSON.

## Interrupted state, ownership and truncation

Type a fixture command, wait for the normal UI refresh, then inspect:

1. `disconnect`: debugger HTTP 503 must preserve the last valid readable record
   and show capture unavailable. Explicit Copy of retained evidence may remain
   available. `baseline` recovers with a complete validated response.
2. `malformed`: invalid state cannot replace prior evidence. `baseline` must
   recover without automatic export.
3. With a completed Copy notice visible on `synthetic-json`, type `epoch`.
   Instance/request IDs and start times are reused, but epoch changes to 2.
   Old notice/menu retires. New body is `{"owner":"synthetic-epoch"}`.
   Verify a new copy with final arguments `synthetic-json epoch`.
4. `instance`: new backend instance, same request IDs/times, epoch 1. Body is
   `{"owner":"synthetic-instance"}`; verify with variant `instance`.
   `target` changes target ID and body to `{"owner":"synthetic-target"}`;
   use All tabs if the old filter hides the row. Old notices must retire.
5. `clear`: window becomes empty, drop count becomes 8, selection/export
   disappears. `baseline` restores identical IDs; old Copy status cannot return.
6. `off`: content capture is disabled and no CDP record/export remains.
7. `states`: select `synthetic-missing`, `synthetic-loading`, `synthetic-error`
   and `synthetic-empty`. Raw keeps states/reasons. Redacted keeps these states
   and flags, clears body fields and supplies the explicit-omission reason.
   Verify with the selected ID and variant `states`.
8. `truncated`: select `synthetic-truncated`. Expect URL/document 65,536 bytes,
   method 32 ASCII `M`s, header value 2,730 `雪`s (8,190 UTF-8 bytes), request
   body 131,072 ASCII `x`s, initiator source 8,192 ASCII bytes. Both header flags,
   request body flag and URL/document/method/source flags are true. Inspect
   visible truncation labels; verify both modes with
   `synthetic-truncated truncated`. Redaction must preserve limitation flags.

Use fresh filenames for every case. Expected mode and fixture variant are
explicit verifier inputs, not inferred from the exported file.

### Pending operations

`node tools/check-traffic-capture.mjs` deterministically holds Copy completion,
repeats clicks, and changes selection/backend instance/epoch or evicts/restores
an identical request. It checks a single initiated write and suppression of
stale status. That is DOM-model evidence, not native clipboard evidence.

On the Mac, also change selection immediately after Copy and check that success
is not attributed to another selection. If Copy finishes too quickly to establish
the race, record the native pending case as **not established**. Do not replace
`navigator.clipboard` and call it a native pass. A clipboard failure must show
`Export failed. The captured record is unchanged.` without false success.
An already initiated OS clipboard write cannot be recalled; selection changes
suppress its notice, not the write itself.

The separate backend regression is:

```sh
cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml \
  retired_body_completion_cannot_populate_reconnected_same_id
```

`make check` additionally covers raw preservation, capture-off, retention/drop
counts, malformed headers, bounded prefixes and body encodings. This authored
UI fixture does not inject a delayed response into a real CDP process.

## Keyboard, layout and browser Save

Test a wide native window and its narrowest supported size. Record actual
window dimensions. Check Tab/activation, visible focus, Escape returning focus
to the menu summary, reopen/selection change, readable long values, truncation
labels, menu bounds and independent pane scrolling. Fixture markup must remain
inert. Native Save is disabled because no verified native download path exists;
successful Copy does not prove Save.

For browser-development Save, open the fixture URL in an installed browser and
check 1440×900, 760×560 and 360×740. Explicitly save each mode and verify the
completed files with the same oracle. Expected names are
`selected.reb-traffic.raw.json` and `selected.reb-traffic.redacted.json`;
browser duplicate-name suffixes are normal. `Download requested` is not proof
of a completed file. Do not weaken security or override the browser sandbox.

## Evidence and artifacts

Record source/app revision, platform, command exit statuses, scenario results,
exact-file verifier output, wide/narrow screenshots, clipboard denial/race
limitations, and untested cases. Clearly label native, rendered-browser,
backend, DOM-model and authored-fixture evidence separately.

CI app previews are pre-archived with the release workflow's `ditto` recipe
before upload to preserve bundle permissions. After downloading the outer CI
artifact, extract the enclosed `Origin-Trace-macos-preview.zip` with `ditto`,
then verify the app's deep strict signature again. The preview is short-lived,
ad-hoc signed, and not a notarized public distribution. Release publication,
Developer ID/notarization, and full pinned-Brave compilation are separate gates.
