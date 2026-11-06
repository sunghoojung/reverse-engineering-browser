# Origin Trace HTTP API

[`openapi.json`](openapi.json) describes the Rust loopback backend in
`apps/origin-trace-backend`, including the [native console](native-console-v2.md)
state and action routes.
It is OpenAPI 3.1 with JSON Schema 2020-12. Stable `operationId` values drive the
included Rust CLI. The routes and stored evidence contracts are unchanged by
the implementation migration.

## Start and call it

From the repository root, `make ui` starts browser development on port 7319.
For an explicitly managed server and machine-readable endpoint discovery:

```sh
apps/origin-trace-backend/target/debug/origin-trace-backend --port 0 --endpoint-file /tmp/reb-api-endpoint
```

Use the printed URL or the endpoint file for **that server**. Live/native
sessions use ephemeral ports and their own endpoint files. Do not assume the
installed app uses port 7319 or start a competing server over its stores.
The endpoint file contains a URL, not an authentication token.

The CLI embeds this specification for operation IDs, routes,
parameters and request-body limits. It requires an explicit local server URL or
endpoint file, so it will not silently target an installed app session:

```sh
apps/origin-trace-backend/target/debug/reb-api list
apps/origin-trace-backend/target/debug/reb-api spec > origin-trace-openapi.json
apps/origin-trace-backend/target/debug/reb-api describe capture_action
apps/origin-trace-backend/target/debug/reb-api describe vm_debugger_action --action step
apps/origin-trace-backend/target/debug/reb-api call get_events \
  --endpoint-file /tmp/reb-api-endpoint --param limit=50 --show-headers
printf '%s' '{"action":"stop"}' | apps/origin-trace-backend/target/debug/reb-api call capture_action \
  --endpoint-file /tmp/reb-api-endpoint --body-file -
apps/origin-trace-backend/target/debug/reb-api call get_artifact_content \
  --endpoint-file /tmp/reb-api-endpoint --param artifact_id=1 \
  --param offset=0 --param limit=2097152 --output artifact-chunk.bin --show-headers
```

Immutable JavaScript lexical facts are available as `get_source_facts`:
`reb-api call get_source_facts --endpoint-file /tmp/reb-api-endpoint
--param session_id=1 --param artifact_id=2`. Both identifiers must match the
stored artifact; no live/URL/derived-source fallback is supported. The optional
`region_start_byte`/`region_end_byte` pair narrows analysis to the innermost
callable body containing that original byte range, so a bundle that reaches a
whole-program budget can still produce facts for one callable. See
[JavaScript source facts v1](javascript-source-facts-v1.md) for exact-byte ranges,
limits, `coverage.analyzed_range`, and partial/unavailable coverage semantics.

`spec` prints the complete embedded OpenAPI document for validators and client
generators without contacting a server. `describe` is an operation-detail
document rather than a complete OpenAPI document. It includes the referenced
component schemas, so every local `$ref`
resolves within its JSON output. `--action NAME` narrows a multiplexed request
to that action and its mapped success response when an action-result mapping
exists. The operation's body-size limit and other extensions remain visible.
Action descriptions also expose `x-reb-selected-action-execution` alongside the
unchanged operation-level `x-reb-execution` common guards. Read both together.

`call` accepts repeated `--param NAME=VALUE` for the operation's documented
path, query and header parameters, including `If-None-Match`. POST bodies come
from a JSON object file or stdin, not a command-line JSON argument. The CLI
preflights parameter names, required values, object bodies and encoded body
size; the server remains authoritative for schema and runtime validation.
Successful JSON is printed to stdout without a wrapper. A 304 produces no
stdout body; `--show-headers` prints status, ETag and other response headers to
stderr. HTTP errors exit nonzero and show the server's error text. Binary
content requires `--output PATH` (or explicit `--output -` for stdout), and a
file path is never overwritten. JSON also accepts optional `--output`; file
publication uses a synced mode-0600 temporary and atomic no-clobber persistence.
Exported evidence packages must validate before publication. The CLI does not provide additional permissions
on its own.

## OpenAPI MCP projection

The same-machine wrapper defaults to `~/.config/origin-trace/reb-api.endpoint`
and `--require-live`; live launchers publish it, not idle/demo backends. Each
MCP reconnect resolves the file anew. The current connection fails closed if
the file changes or a live backend's `Health.instance_id` changes, rather than
retargeting pending calls. MCP sends `X-REB-Expected-Instance` with the startup
health identity on tool requests; the backend rejects a nonmatching or duplicate
supplied precondition with HTTP 409 `state_conflict` before body processing or
dispatch. Existing API clients that omit the header remain supported.
A backend holds the endpoint file it published until it exits, so an endpoint
file that no running backend holds is stale, as a killed backend leaves it, and
MCP refuses it before any request.
This closes replacement at the same port between health and action. It is not
an authentication token, permission grant, or a document-generation selector;
existing action-specific target/document ownership checks remain required. A
legacy backend without a health identity cannot use `--require-live`.
Live mode requires `capture_mode=live` and `broker_connected=true` (the native
capture broker is connected) before advertising tools and before valid tool
dispatch. The retired `debugger_state` field is always `unavailable` and is not
consulted.
Diagnostics name the loopback endpoint and allowlisted states, never the health
body's evidence paths. Explicit stored-evidence connections can omit the live
requirement. See [connection and restart behavior](../docs/development/local-coding-agents.md#select-the-endpoint).

`x-reb-mcp` in this specification is the only MCP contract. `reb-api mcp` reads
that extension and serves operation IDs as stdio tools. It does not add an HTTP
route. The single tool that is not an operation, `start_live_session`, is
declared in `x-reb-mcp.session_start`; see
[live session control](#live-session-control). A client supplies the same loopback root as `call`, through `--base-url`
or `--endpoint-file`.

```sh
reb-api mcp --endpoint-file /tmp/reb-api-endpoint
reb-api mcp --session-dir /absolute/path/to/one-selected-session
reb-api mcp --endpoint-file /tmp/reb-api-endpoint --allow-effects
```

Pass exactly one of `--base-url`, `--endpoint-file`, or `--session-dir`.
`--session-dir` reads `research-ui.endpoint` from that directory and does not
search for a newer session. A native UI URL that includes a query is rejected
and is not echoed. Before the server reads stdio, it requests `/api/health` on
the selected loopback root and exits unless the JSON `status` is `ok`. The
health document names local store paths, so it is not printed. This check is
reachability. It does not identify a capture or authorize a tool call.
[`scripts/reb-api-mcp.sh`](../scripts/reb-api-mcp.sh) is the client launcher.
It execs this command and does not add a server. Cursor, Codex, Claude Code,
Grok Bot, and T3 Code settings are in the
[local coding-agent guide](../docs/development/local-coding-agents.md).

The default tool list is the read-only projection used by `list --json`.
`--allow-effects` also lists the other operations. The flag does not authorize
a target, redact a response, or permit sending captured data to a model
provider. Binary success bodies are refused before a request, because the
projection sets `binary_inline` to false. JSON whose raw bytes or pretty text
exceed `inline_json_limit_bytes` is not inlined and is not truncated. The tool
returns `mcp_projection: structural_summary`: short scalars, collection sizes,
and low-cardinality histograms for object arrays longer than eight items.
Strings longer than `summary_string_chars` are replaced with character and byte
counts. Fields that carry source, bytecode, derived text, or disassembly
(`original_source`, `representation`, `text`, `body`, `raw`, `value`, and the
other content names in the adapter) are omitted even when short. The summary is
not the OpenAPI response document.

Each tool `inputSchema` is a closed JSON Schema. Component `$ref` values are
inlined, and OpenAPI extension keywords are omitted, so a client does not need
the components object. The server checks arguments against that schema before a
request. A missing required parameter or object body is a tool error and sends
no request. An unknown tool name, or a tool left out of the default list, is
JSON-RPC error `-32602` and sends no request.

A matching `If-None-Match` is a successful tool result,
`{"http_status":304,"etag":"..."}`, not an error and not a response body. The
`etag` is included only when that response header is non-empty, at most 256
bytes, and free of control characters. Successful JSON still returns the
response document itself, without response headers.

The server speaks newline-delimited JSON-RPC 2.0 and rejects batches
(`batching` is false). One message may not exceed `message_limit_bytes`
(32 MiB); a longer line is a parse error and is not echoed. It accepts protocol
versions `2024-11-05`, `2025-03-26`, and `2025-06-18`. `initialize` is required
before other requests. `ping` may come first. A second `initialize` is
rejected. The `notifications/initialized` notification is accepted and does not
receive a response, because this server does not send requests. Logs stay on
stderr. Captured content returned by a tool is untrusted data, not
instructions.

Each tool description is the operation summary, its description, its
execution notes and, for a multiplexed body, every `action` with its fields,
for example `connect_live(binding_id, confirm_live=true, target_id)`. A field
fixed to `true` is a confirmation the researcher gives, not a default. An
unknown argument is named in the refusal; its value is not echoed.

An operation with `x-reb-wait-parameter` waits on the server for up to that
many milliseconds. The client adds that wait to its own `--timeout`, so the
timeout still bounds transport time. An operation with `x-reb-filter-echo`
returns that key whenever it applied a filter. If a filtered call comes back
without it, the backend predates filtered reads and returned unfiltered
records; the tool reports an error and discards that result rather than let an
agent read it as filtered. `reb-api call` applies both rules.

`readOnlyHint` follows the read-only projection. `destructiveHint` is true when
the operation is not `kind: operation`, when `effects` is not an array, or when
any direct or state-dependent effect is something other than `analysis`.
`openWorldHint` is false: calls stay on the configured loopback root.

```sh
REB_API=$(cat /tmp/reb-api-endpoint)
curl --fail-with-body "$REB_API/api/health"
curl --fail-with-body "$REB_API/api/events?limit=50"
curl --fail-with-body --json '{"action":"stop"}' "$REB_API/api/capture/actions"
```

The last call stops capture. A server without configured live services still
exposes stored-evidence operations and returns explicit unavailable state or 409
for live controls. Every retired `/api/debugger` route returns 410
`debugger_unavailable`.

Health, events, session context, session summary and capture action results
report `capture_state`, the live capture lifecycle: `running`,
`stop_requested`, `stopped`, `ended`, `lost`, or `not_live` for idle and demo
backends. A broker counts as running while it holds the lock on its event store
guard, which the kernel releases even when the broker is killed; a socket file
alone is never a broker. `ended` means it shut down on its own and removed its
socket; `lost` means it left the socket behind. `broker_connected` keeps its
per-surface reading: health and events report false only for a live backend
whose broker is not running, while session context and summary report true only
while a live broker runs. `capture_action` `stop` signals only a running broker
whose `--broker-pid` still names the process it named at backend startup;
otherwise it returns 409 `dependency_unavailable` and signals nothing. A stop
that times out returns 408 `timeout` after the signal was delivered and stays
`stop_requested`; repeating it signals again, and stop after `stopped`
succeeds. `clear` empties the trace and signal stores before the event store.

`curl --json` sends the required Content-Length; streaming/chunked request bodies
are unsupported. Action bodies must be JSON objects within the per-operation
`x-max-body-bytes` limit. The server does not enforce Content-Type, but clients
should send `application/json`.

Conditional GET operations list `If-None-Match` and a bodyless 304 response.
Artifact content uses `offset` and `limit` query arguments and always returns
200 on success, including partial chunks. Advance using actual byte count and
`X-Artifact-Total-Bytes`; `X-Artifact-Truncated` is the string `true` when bytes
remain and `false` at the end. An offset equal to the total returns an empty
chunk; a negative, malformed, or beyond-end offset returns 400.
Artifact lookup or full-content verification can return a JSON 408 when its
five-second manifest or thirty-second verification deadline expires.
This is not HTTP Range/206 pagination. Unfiltered events and artifacts are a
bounded recent tail. [Filtered reads](#filtered-and-paged-reads) add byte
cursors for paging. Neither is a stable exhaustive export.

## Local coding-agent discovery and observational calls

`reb-api list --json` is an offline, versioned discovery document. It returns
`format: reb-api-discovery-v1`, the embedded `execution_policy`, and `operations`
ordered by operation ID. Every entry has `operation_id`, `method`, `path`,
`summary`, `execution` (the operation's complete advisory metadata), and a
boolean `read_only_eligible`. The default tab-separated `list` remains unchanged.
This describes the CLI build, not a live server's identity, version or abilities.
`describe` remains the source of parameter, request, response and action schemas.

`reb-api call OPERATION --read-only` rejects an ineligible operation before
reading the endpoint file or request body, opening the output file, or dispatching
HTTP. Eligibility requires the supported execution policy, metadata valid under
`RebExecutionMetadata`, `kind: operation`, effects limited to `analysis` (or no
effects), and empty `state_dependent_effects`, `uncertainties` and `confirmations`.
Missing, malformed, unsupported and action-dependent metadata fails closed.
The discovery flag uses this same predicate. There is no method-based shortcut:
inert evidence comparison POSTs qualify, but VM cache GETs, source-helper GETs,
native session retirement and live browser controls do not.

The flag is opt-in; existing unguarded calls and raw-local responses are unchanged.
It is an accident-prevention aid, not a sandbox, approval, capture redaction or
proof of complete effect accounting. It does not stop independent background
capture or incidental local transport, and explicit CLI `--output` file writes
still work. The API remains unauthenticated and loopback-only. Guard rejection
exits 2 without a request; other response handling and exit codes are unchanged.
No operation is automatically retried.

A local agent can transmit returned values to its model provider. Establish the
user-approved provider, session and data categories before reading captures into
agent context; even structural paths and identifiers can be sensitive. Use the
[local coding-agent guide](../docs/development/local-coding-agents.md) and shared
repo skill for exact session selection, capture-as-untrusted-data handling,
offline client scaffolding and explicit approval before effects. Neither the
skill nor the guard authorizes sharing or configures the user's agent account.

## Observed website API catalog

Retired. `GET /api/network/catalog` (`get_api_observation_catalog`) derived
endpoint shapes from retained CDP Traffic bodies. It was removed with CDP:
native network records carry the method and host, plus bounded path and header
prefixes in sensitive mode, and no bodies to infer shapes from. The route
returns 404 and the operation is absent from the contract. The
[historical v1 contract](api-observation-catalog-v1.md) describes the removed
response.

## Exact request trace selection

`get_origin_trace` accepts optional `session_id` in addition to `request_id` and
its existing paired `root_process_id` / `root_sequence_number` selectors. Send all
four for an exact retained request event:

```sh
reb-api call get_origin_trace --endpoint-file /tmp/reb-api-endpoint \
  --param session_id=7 --param request_id=91 \
  --param root_process_id=42 --param root_sequence_number=3
```

Session IDs are nonzero canonical uint64 decimal strings. The UI forwards the
selected row's exact session identity; unsafe numeric identities and ambiguous
rows are rejected before fetching. Existing unambiguous calls without a session
continue to work. Multiple retained matches, including the same process/sequence
in different sessions, return the existing `ambiguous` status and
`ambiguous_request` gap with no steps. This intentionally replaces the previous
misleading `empty` result for a reused process/sequence pair. Lifecycle preference
never chooses between different sessions. Missing exact matches remain `empty`,
without falling back to another session or event. Session selection participates
in the ETag. The v1 response shape, stored evidence and capture policy are unchanged.

## Compact session context

`GET /api/session/context` (`get_session_context`) is the compact first read for
a connected agent. It returns bounded current session discovery without fetching
source or bytecode. It includes `live_admission`, the same process-lifetime
`instance_id` as `/api/health` (also sent as `X-REB-Expected-Instance`), endpoint,
capture mode, `capture_options`, and a retained Wasm artifact inventory (16
entries from a 256 KiB manifest tail). Use this route's own ETag for
conditional reads. No target/session join is inferred from URL or timing.

`capture_options` labels what this session's launcher passed to Brave, for
every live session (agent, app or `make live`): `request_content`,
`canvas_images`, `document_start` (`permitted` or `not_permitted`; whether
this Brave honors it is `document_start_supported` in `get_native_console`),
and `js_invocation` with `state` (`not_armed`, `armed`, `browser_unsupported`
or `unreadable`), `count` and `digests`. `run-live-session.sh` passes the
backend `--session-request-content`, `--session-canvas-images` and
`--session-document-start`; they grant and enable nothing. Idle and demo
backends report `source: not_live` with everything off. Site labels and
source URLs stay in `get_js_invocation_sites`.

CDP was removed. Version 1 keeps its debugger fields with fixed retirement
values so existing clients still parse it: `debugger_state` is `unavailable`,
`target` is null, `wasm_scripts` is empty, `generation`, `capture_epoch` and
`target_document_epoch` are 0, and `debugger_etag` is `"debugger-0"`.

Titles are omitted, HTTP(S) URL labels contain only origins, and conventional
Wasm hex labels are retained. Source, headers, bodies, socket URLs and diagnostics
are absent. Identifiers/origins remain potentially sensitive metadata. Direct
HTTP reports `allow_effects: null`; MCP annotates its own flag without granting
authorization. See the [agent context recipe](../docs/development/local-coding-agents.md#start-with-compact-session-context)
for field omissions and coverage limits.

## Live session control

`POST /api/session/actions` (`session_action`) drives the live session this
backend belongs to. Both actions refuse with 409 `idle_backend` unless
`capture_mode` is `live`.

- `{"action":"open_url","url":"https://..."}` hands an HTTP(S) URL without
  credentials to the session's running capture browser, which opens it in a
  new tab. It uses Chromium's same-profile relay: the backend runs its
  `--brave-binary` with the session's `--brave-profile` and the URL. It
  refuses with 409 `native_capture_unavailable` unless `capture_state` is
  `running`, and with 409 `target_unavailable` when no live
  process holds the profile's `SingletonLock`. The relay carries proxy and
  resolver switches that the running browser ignores but that leave a relay
  with no network if it ever starts a browser of its own; such a relay is
  stopped after 10 seconds and reported. A running broker proves only that the
  broker runs, so the response reports `capture_observed`: true once a new
  record reaches the session's store within 10 seconds. False means nothing
  was recorded, for example because the configured browser is not a capture
  build. It never runs page JavaScript.
- `{"action":"reset_wasm_sample_budgets"}` increments the session's Wasm
  sample-budget reset file. The capture browser restarts both sample indexes
  at 0 without closing the profile or replacing the capture configuration.
  It needs recording capture, `--wasm-budget-reset-file`, and a live process
  holding the profile, and otherwise returns 409. The browser applies the new
  generation on its writer wake, about 250ms later. A rebuilt Brave is
  required before a live browser honors the file. The response is
  `{"ok":true,"action":"reset_wasm_sample_budgets","generation":N}`.
- `{"action":"end","confirm":true}` replies, then about 300 ms later sends
  SIGTERM to the backend's `--launcher-pid`, which must be its parent. The
  launcher closes the capture browser and stops every helper, including the
  backend. Stored evidence stays on disk.

- `list_inputs`, `click`, `type`, `press` and `scroll` send trusted input to
  the session's page on macOS. The backend finds the capture browser by the
  process holding its profile lock and reads the page through the browser's
  accessibility tree, which it turns on with `AXManualAccessibility`; that
  tree spans cross-origin frames. The page is the tab's largest HTTP(S) web
  area, never DevTools, a side panel or a `chrome://` or `brave://` page.
  `list_inputs` returns up to 200 controls with a short `role`, an accessible
  `name` of at most 120 characters, a viewport rectangle in points, `visible`
  (the center lies inside every enclosing frame), `frame_depth` and `checked`.
  Names are page text; field values are not read directly, but a name can
  include label text that embeds one. `click` takes `x` and `y` in viewport
  points or a `role` and case-insensitive `name` matching exactly one visible
  control (or `nth`), plus `count`; there is no right click, because a context
  menu reaches browser features. `type` takes up to 200 characters without
  line breaks, `press` one named key, and `scroll` `dx` and `dy`. Each input
  action brings the capture browser to the front and moves the pointer along a
  short eased path. Just before a click or scroll, a hit test must find this
  browser's page under the point, and the named control for a named click.
  Before every key, the keyboard focus must be inside the page, so keys never
  reach the address bar, a browser dialog or a menu; only Escape is allowed
  anywhere in the browser. The frameworks are loaded at run time, only in the
  backend process, never in its sandboxed analysis workers. They
  refuse with 409 `dependency_unavailable` when macOS has not granted
  Accessibility to the app that started the session, or off macOS; with 409
  `target_unavailable` when there is no window, page, focus or match; and
  with 503 `resource_limit` when another session holds the machine-wide input
  lock for 15 seconds. Like `open_url`, they require recording capture.

`run-live-session.sh` passes `--brave-binary`, `--brave-profile` and
`--launcher-pid` to the backend it starts. A backend started any other way
returns 409 `dependency_unavailable` for these actions.

`reb-api session start` and the MCP tool `start_live_session` take the
`LiveSessionStart` options: `url`, `wasm_dispatch`, `wasm_call_indirect`,
`guest_adapter`, `js_dispatch_sites`, `quiet`, `category_mask`,
`duration_seconds`, `localhost_only`, `canvas_images`, `request_content`,
`document_start`, `js_invocation_sites`, `js_invocation_saved_sites`,
`js_invocation_digests`, `confirm_sensitive_capture`,
`publish_canonical_endpoint`, `brave_binary`, `timeout_seconds`,
`wasm_samples_per_function`, `wasm_samples_per_indirect_site`,
`wasm_function_allow`, `wasm_function_deny` and `wasm_module_allowlist`.
The Wasm budget options require `wasm_dispatch` or `wasm_call_indirect` and
do not raise the 16-record cap. Every
capture switch is off unless named; an inherited capture switch, site file,
browser profile or embedded-session variable is ignored, so an inherited
`REB_CAPTURE_REQUEST_CONTENT`, `REB_CONSOLE_DOCUMENT_START`,
`REB_NATIVE_JS_INVOCATION_SITES` or `REB_NATIVE_JS_INVOCATION_DIGESTS` never
reaches an agent session.

| Option | Launcher switch | Rule |
| --- | --- | --- |
| `request_content` | `REB_CAPTURE_REQUEST_CONTENT=1` | Sensitive: needs `confirm_sensitive_capture` and category bits 256 and 1024. Without it, request body length, type and digest are still recorded, but no path, query or body bytes. |
| `document_start` | `REB_CONSOLE_DOCUMENT_START=1` | Permits document-start Console scripts in this capture browser. Arms nothing: a rule still needs a live Console connection and a confirmed `arm_document_start`. |
| `js_invocation_sites` | `REB_NATIVE_JS_INVOCATION_SITES` | Absolute path of a `native-js-invocation-sites-v1` file. Checked, then armed from a private copy under the agent session directory. Needs category bit 512. |
| `js_invocation_saved_sites` | `REB_NATIVE_JS_INVOCATION_SITES` | Arms the agent sessions' own saved set, `~/.config/origin-trace/agent-sessions/js-invocation-sites-v1.json`, which `js_invocation_site_action` edits in an agent session. Never the app's set. Refused when empty. Not with `js_invocation_sites`. |
| `js_invocation_digests` | `REB_NATIVE_JS_INVOCATION_DIGESTS=1` | Sensitive: needs named sites and `confirm_sensitive_capture`. |
| `canvas_images` | `REB_CAPTURE_CANVAS_IMAGES=1` | Sensitive: needs `confirm_sensitive_capture`. |
| `wasm_samples_per_function` | `REB_NATIVE_WASM_SAMPLES_PER_FUNCTION` | 1..16 retained samples of each function on each Wasm stream. Needs `wasm_dispatch` or `wasm_call_indirect`. |
| `wasm_samples_per_indirect_site` | `REB_NATIVE_WASM_SAMPLES_PER_INDIRECT_SITE` | 1..16 retained `call_indirect` samples of each caller and module offset. |
| `wasm_function_allow` | `REB_NATIVE_WASM_FUNCTION_ALLOW` | Up to 32 function indexes. Other functions do not consume either sample index. Deny wins. |
| `wasm_function_deny` | `REB_NATIVE_WASM_FUNCTION_DENY` | Up to 32 function indexes to exclude. |
| `wasm_module_allowlist` | `REB_NATIVE_WASM_MODULE_ALLOWLIST` | Up to 8 SHA-256 digests, written to a private file. Other modules do not advance either sample index. |

An agent sets `confirm_sensitive_capture` only on the researcher's
authorization for that content and target. Named invocation sites are strict:
`REB_NATIVE_JS_INVOCATION_IF_SUPPORTED` is removed, so a Brave without
invocation capture refuses the start instead of silently dropping the sites.
The start result's `options` (and `js_invocation_sites_armed`), the first
line of the launch log (`Agent session options: {...}`) and the session
context's `capture_options` show what the session runs with. A launcher
refusal that names an environment switch also names the option to change.
Operator
settings such as helper binary paths, `REB_LIVE_SESSION_ROOT`, `REB_ORIGIN_TRACE_APP` and
`REB_OPEN_COMMAND` still apply. They run the launcher that belongs with the
`reb-api` build (`Contents/Resources/run-live-session.sh` in the app,
`scripts/run-live-session.sh` in a checkout, or `REB_LIVE_SESSION_SCRIPT`)
detached in its own process group, wait for its ready line and a live health
report, then optionally open `url`, retrying for up to 20 seconds while the
browser is still taking its profile, and return `capture_observed`. The
session keeps running after the caller exits until it is ended, Brave is
closed, or capture expires; if the MCP server is stopped during a start, close
that session's Brave window. A launcher failure line is returned as the error
after the launcher's own cleanup; a timeout stops the launcher and then its
process group. By
default the session publishes its endpoint only to a private file, so it does
not replace the canonical endpoint other connections use. The session uses the
mock Keychain, since an agent cannot answer a Keychain prompt. The CLI prints
the session directory, endpoint file and launch log; the MCP result omits
them and shows the home folder in launcher errors as `~`.

`reb-api mcp --allow-session-start` requires `--allow-effects`. It lists
`start_live_session` and `session_action` (the operations named in
`x-reb-mcp.session_start.operations`, hidden otherwise) and starts even when
its endpoint is missing or not live. `session_action` is accepted only for a
session this connection started; a connection bound to the researcher's
session gets a refusal without a request. Starting again first ends the
session this connection started. Under `--require-live`, `session_action`
`end` stays available when capture has expired or stopped.
Until a session is bound, every operation tool refuses without a request. A
successful start rebinds the connection to that session's own
`research-ui.endpoint` and exact `instance_id`; this is the only retargeting,
and any other endpoint or instance change still retires the connection. After
a successful `session_action` `end`, the connection is unbound again (or, without
`--allow-session-start`, retired).

### Native Console for agents

The Console reaches any frame of the capture browser through the same tools
as the panel; nothing about it is MCP-specific. `get_native_console` lists the
capture browser's HTTP(S) documents with `binding_id`. Each target has `id`
(execution identity only within that binding), `frame` (`top` or `child`),
`origin`, `url` and `label` (display only), and for a child frame
`top_relation` and `out_of_process`. The browser's target record carries no
parent frame and no renderer process, so these two are derived: the child's
origin is compared with every listed top-level document. `same_origin`,
`same_site` (equal host or IP address, any port), and `cross_site` (another
scheme, an IP against a name, or names whose last two labels differ) are
decided without the public suffix list; two names that share their last two
labels, tops that disagree, or an opaque origin are `undetermined`.
`out_of_process` is true for `cross_site`, which Chromium's full site isolation
runs in its own renderer process, false for `same_origin`, and null otherwise.
After connecting, `location.ancestorOrigins` in the frame confirms its parents.

`native_console_action` `connect_live` with `binding_id`, `target_id` and
`confirm_live: true` selects one document, cross-site children included, and
returns a fresh `session_id`. `evaluate` and `runtime` run only in that
document. While connected, the listing's `selection` is `selected`, `none`, or
`stale` with the `target_id` that navigated, reloaded or was removed; that
state lasts until `stop` or the next `connect_live`. A command for any other
`target_id`, or for a stale selection, returns HTTP 200 with
`status: stale_target`, `code: target_unavailable` and text that names the next
step, and nothing is sent to the browser. A second `connect_live` while one is
open, a stale `session_id` and a stale `binding_id` are 409 refusals that say
what to read or send next. Document-start rules for a child frame name that
frame's exact origin with `frame: child`; see
[Native Console v3](native-console-v3.md).

## Session summary

`GET /api/session/summary` (`get_session_summary`) answers "did this capture
work?" in one read. It reports capture state, event counts by category and
type, first and last event time, up to 16 sessions, the 32 busiest frames with
their top event types, gap counts with named gap reasons, artifact counts by
kind with the 32 newest artifact identities and digests, and `checks`. Each
check has a `code`, a `severity` of `info` or `warning`, and a plain message:

| Code | Meaning |
| --- | --- |
| `capture_not_live` | Idle or demo backend; stored evidence only. |
| `capture_stopped` | Native capture was stopped in this session. |
| `broker_disconnected` | Live capture whose broker is gone; nothing new arrives. |
| `artifact_receiver_disconnected` | New scripts and Wasm modules are not stored. |
| `no_events` | The store is empty. |
| `wasm_without_artifacts` | Wasm compiled, but no Wasm module was stored. |
| `artifact_capture_failed` | Some artifact bodies were not stored. |
| `queue_drops` | Records lost to a full queue, beyond named gap markers. |
| `sequence_gaps` | Sequence numbers missing inside the scanned events. |
| `named_gap` | A producer named why it stopped, with `category`, `reason` and `count`. A reason containing `budget` or `limit` means a sampling budget filled. A Wasm reason ending in `filtered` is a sample-policy exclusion: that execution was not sampled and did not take a slot. |
| `bounded_scope` | Only the newest 64 MiB of events were summarized. |

The summary scans the same newest 64 MiB as the polling window and the newest
64 MiB of the manifest. It contains counts, identifiers and origin or
`wasm://wasm/<hex>` labels only: no payloads, URL paths or queries, source or
bodies. Identifiers and origins can still be sensitive. It has its own ETag.

## Saved JavaScript invocation sites

The Origin Trace app keeps one saved set of at most 8
[native JavaScript invocation sites](native-js-invocation-v1.md#site-file)
and arms it in the next capture it starts. These routes name, save and list
those sites; none of them changes the open page or a running capture.

- `GET /api/js-invocation-sites/resolve` (`resolve_js_invocation_site`) takes
  an exact `session_id` and `artifact_id` and exactly one of `name` (a dotted
  name such as `window.hsw`, `hsw` or `a.b.c`) or `byte_offset` (a UTF-8 offset
  in the artifact bytes, BOM included). It returns one
  `reb-js-invocation-site-resolution-v1` document: `status: resolved` with the
  exact site entry, or `status: refused` with a `reason` and at most 32
  candidates, each with its byte offset, line, column, kind, binding and a
  short context line. It saves nothing.
- `GET /api/js-invocation-sites` (`get_js_invocation_sites`) returns the saved
  set with each site's label, source URL and session, whether this session
  retained the saved script version (`retained.state`: `matches`,
  `other_version` or `not_retained`), and what this session's launcher armed
  (`session.state`: `not_armed`, `armed`, `browser_unsupported` or
  `unreadable`, with `digests`).
- `POST /api/js-invocation-sites/actions` (`js_invocation_site_action`) takes
  `add` (the resolve inputs and an optional `label`), `remove`
  (`source_sha256` and `anchor_offset`) or `clear` with `confirm: true`. `add`
  resolves the artifact again on the server and never accepts a site from the
  caller. A refused resolution returns HTTP 200 with `added: false` and the
  resolution; a duplicate `(source_sha256, anchor_offset)` or a ninth site is
  a 409. Every action returns the updated set.

A name matches only syntax that binds it: an assignment to that identifier or
member chain (`a.b`, `a["b"]`), a `var`, `let` or `const` initializer, a
`function NAME(` declaration, or an object-literal `NAME: function(` property
or `NAME(` method, including chained assignments and properties of an object
bound to a name. `window.`, `self.` and `globalThis.` are one prefix, because
in a document's main world they are the same global object and invocation
capture never arms a worker. A bare name also matches that global property;
a prefixed name matches a top-level `var` or function declaration of a
classic script but never a local or a module declaration. Strings, templates
and comments never match, because the analysis worker reads its bounded
tree-sitter syntax tree, not text. A local variable named `window` is not told
apart from the global object, so every refusal lists candidates with context.
Zero matches list definitions whose name has the same final segment
(`candidate_relation: same_final_name`).

A position selects the innermost function whose definition contains it,
counting the head that binds it (`window.hsw=`, `var hsw=`, `hsw:`) as part of
that function. Refusals carry a reason: `no_match`, `ambiguous`,
`unsupported_function` (a bare-parameter or `async` arrow, whose anchor is not
a `(`, a generator or a class constructor), `no_function` (top-level code),
`class_initializer` (a field initializer or static block) and
`source_unavailable` (the bounded parse refused the source). The site key is
computed in the backend exactly as `tools/native-js-invocation-site.py`
computes it; both check `tools/fixtures/native-js-invocation/site-cases.json`.

The saved set is the exact `native-js-invocation-sites-v1` file at
`--js-invocation-site-store` (the app passes
`~/Library/Application Support/Origin Trace/js-invocation-sites-v1.json`;
`make live` and `make ui` use `build/sessions/js-invocation-sites-v1.json`;
agent-started sessions use their own
`~/.config/origin-trace/agent-sessions/js-invocation-sites-v1.json`, which a
later `start_live_session` with `js_invocation_saved_sites` arms)
plus a `js-invocation-sites-v1.labels.json` sidecar with each label, source URL
and session, which the browser never reads. Both are written atomically with
user-only permissions. An empty set has no site file. The list and resolve
routes are read-only; resolve runs the analysis worker, so like
`get_source_facts` it is listed only with `--allow-effects`, as is the action
route.

## Error reasons and uncertain outcomes

JSON error responses retain their existing HTTP status and human `error` text,
and add `code` and bounded `details`. `ErrorCode` and `ErrorDetails` in the
OpenAPI document own these fields. Precise reasons are assigned only where the
source establishes the failure; legacy cases may use `unspecified` or a coarse
reason. A request-body timeout is before action dispatch. Interrupted command
writes, missing/malformed replies, or workspace directory-sync failure after
publication can have `command_outcome_unknown`; this never proves no effect or
authorizes a retry. Dynamic failure reasons do not
replace the [advisory effects and common guards](#execution-metadata).

Invalid action bodies return schema-derived `allowed_actions` and, where
unambiguous, `missing_fields` inside details. Submitted values are not echoed.
`idle_backend` is an idle process. `native_capture_unavailable` means a live
backend whose native capture broker is not connected.
`live_admission` on session context uses the same distinction and adds
`not_live_capture` for demo and other non-live modes. The retired debugger
actions and their `x-reb-requires-live-target` annotations were removed with
them. A disconnected capture
broker cannot report a newly requested stop as successful
(`dependency_unavailable`). `--require-live` MCP connections refuse other tools
with `idle_backend`, `native_capture_unavailable`, or `state_conflict` before
dispatch. `get_session_context` remains readable on that connection until the
endpoint file or instance identity changes, which retires the connection
instead of retargeting the call.

Analyst, JWT Decoder and native Console application failures can remain HTTP
200. Inspect their existing `ok`, `outcome`, `status` or `runtime.status` fields
as well as their added reason. Success results are unchanged.

For structured CLI errors, `reb-api call ... --json-errors` prints a bounded
JSON object on stderr with the observed `http_status`, allowlisted `code` and
`details`, a human `error` capped at 512 UTF-8 bytes, and `error_truncated`.
Default stderr and successful stdout remain unchanged. Completed non-2xx
responses exit 1; body-read/size failures after non-2xx headers produce a fixed
safe JSON diagnostic and keep exit 2. Preflight/connection failures before
headers retain ordinary CLI diagnostics and exit 2, with no invented status.
The flag conflicts with `--show-headers`; neither headers nor arbitrary body
fields are included. HTTP 200 application failures still use stdout and exit 0.
Response reads remain capped at 64 MiB; commands are never automatically retried.

## Analysis definitions and reviewed sources

`GET /api/analysis/catalog` (`reb-api call get_analysis_catalog --base-url URL`)
returns the embedded current VM profile and digest, every structural/static/runtime
rule ID and weight, and reviewed source IDs, primary URLs, revisions, applicability,
limitations, and reuse status. `reb-api describe get_analysis_catalog` works
offline and includes the complete response schema and advisory execution metadata.
The closed response has at most 64 rules and 32 source records; a regression gate
keeps the actual embedded response below 128 KiB. It takes no parameters and needs
no evidence store, browser, worker, or network source access.

Match a generated document's producer ID/version to `current_producer` and its
`profile_digest` to `current_profile_digest` before using these definitions.
Build identity is not recorded, so matching metadata does not prove the same binary. Older v1 profile shapes remain accepted by their existing
schema, but historical definitions are not included or revalidated. Static relevance
weights were not included in that historical profile projection; the catalog exposes
them without changing existing analysis identity. Neither value alone is a full analyzer identity.
`catalog_digest` is SHA-256 of canonical sorted-key JSON excluding itself, using the
existing VM canonicalization. It changes with source/definition metadata while the
analysis profile identity stays unchanged. Neither digest nor score proves source
authenticity, accuracy, causality, or semantic equivalence.

Sources are inert metadata; this endpoint does not fetch URLs, read evidence, run
source, or write the VM cache. The [analysis catalog guide](../docs/product/analysis-catalog-v1.md)
explains evidence levels and compatibility.

## HTTP Traffic capture coverage

Retired. The shared HTTP ledger described here lived in `GET /api/debugger`
and its CDP connection, both removed. Native network evidence arrives as broker
events in [`get_events`](#native-event-window-and-summary-scope) and the
[native Traffic to VM selection](#exact-native-traffic-to-vm-selection) below.

## Exact retained Traffic request

Retired. `GET /api/network/request` (`get_network_request`) returned one
retained CDP Traffic record as `reb-network-request-v1`. Nothing produces those
records any more, so the route returns 404 and the operation is absent from
the contract. Offline client export tools still accept previously saved
`reb-network-request-v1` files.

## Authentication and locality

There is **no bearer token, API key, login, or OAuth scheme** on this HTTP API.
`security: []` is deliberate, not missing configuration. Every `/api/` request and
every POST checks the exact listening port in `Host` and permits only
`127.0.0.1`, `localhost`, or `::1`. `Sec-Fetch-Site: cross-site` is rejected.
If supplied, `Origin` must be HTTP with a local hostname and matching port,
without credentials, parameters, query or fragment, and with empty or `/` path.
A CLI can omit Origin. These are local request checks, not user identity or
remote-access authentication. The default bind is 127.0.0.1; the local-only
rule is defined in [`SAFETY.md`](../SAFETY.md).
The client rejects redirects, so a response cannot send a request to a
different host or local service.

The native broker's socket token belongs to a **different transport**. The
macOS `WKURLSchemeHandler`, C++/Unix sockets, worker stdin/stdout
protocols and static UI assets are not OpenAPI HTTP endpoints. Native custom
scheme behavior is not guaranteed to match the Rust backend in every detail.

## Contract coverage and known gaps

The specification describes current HTTP API routes, query parameters,
body-size ceilings, conditional responses and known application errors. Trace,
request-signal and VM schemas are embedded from their versioned protocol files
so the OpenAPI document is portable. Update embedded schemas whenever their
versioned source changes.
The VM HTTP response additionally allows its actual optional `selection` field.

The action routes are multiplexed, not invented REST resources:

- Capture has exact stop and confirmed-clear shapes. Clear requires capture to
  be stopped and does not remove artifact files.
- Decoder has four discriminated actions and result schemas. JWT `ok=false`
  may be an HTTP 200 result, so inspect application outcomes.
- Collection and Analyst replacement share the
  [cooperative writer lease](workspace-writer-lease-v1.md), use optimistic
  `expected_generation` and full documents. Stale generations return 409. Tree integrity, uniqueness,
  forbidden headers and aggregate UTF-8 limits remain runtime validations.
  Replacement responses do not include an ETag; read the workspace to obtain
  its current conditional-GET validator.
- Analyst execution requires the current saved JavaScript script and explicit
  confirmation; sensitive selected artifact data needs additional confirmation.

Known behavior worth preserving in clients:

- Invalid events/artifacts `limit`, VM `request_id`, or artifact offset/limit
  parsing returns 400. Valid signed `limit` values clamp to the operation's
  bounds; offsets and identifiers must be canonical unsigned decimals.
- At the application handler, malformed JSON, non-object bodies, invalid body
  lengths and unsupported chunked bodies return JSON 400 errors. A body read
  exceeding five seconds returns 408. Transport-level HTTP framing failures
  may be rejected before the application handler and have no JSON guarantee.
- Unknown API paths return JSON 404; unsupported methods return JSON 405.
  Every application response includes `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff`. HEAD is not an equivalent of API GET.
- GET VM analysis may write its local analysis cache. No rate-limit, pagination
  cursor, idempotency key, cancellation API for every operation, or remote auth
  exists. A connection failure or process crash has no guaranteed JSON body.
- Some size constraints are UTF-8 bytes, not characters. `x-max-utf8-bytes`
  describes those checks without misusing JSON Schema `maxLength`.

## CLI usage guidance

Use the OpenAPI operation IDs as CLI commands and pass the actual `action`
discriminator for multiplexed commands. Preserve decimal-string 64-bit IDs.
Accept whole request objects from files/stdin so quoting and nested JSON remain
predictable. Keep transport errors separate from structured `{error}` responses
and successful HTTP responses containing an application failure. Do not blindly
retry mutations after a timeout or dropped connection.

## Execution metadata

All HTTP operations and all 23 top-level request action variants carry version 1
`x-reb-execution` metadata. It is a source-owned,
static advisory catalog. It does not grant permission, verify target ownership,
report current availability, replace server validation, or prove that an action
has no additional effects. In particular, no confirmation field means only that
the current handler has no such field. Native evaluation still requires
appropriate researcher authorization under [SAFETY.md](../SAFETY.md).

One root `x-reb-execution-policy` owns the common `version: 1`, `advisory: true`,
`automatic_retry: never`, and `idempotence: unproven` rules. The CLI copies this
policy into every description and fails if it is missing or unsupported.
The `x-reb-execution-schema` reference on each operation points to the embedded
`RebExecutionMetadata` JSON Schema. The CLI includes this schema in offline
descriptions. Individual execution entries have these fields:

- `kind` is `operation`, `action`, or `action-dependent`. An action-dependent
  operation has `effects: null`; clients must resolve the exact request action.
  Missing entries, unknown actions, unsupported versions, and explicit
  `uncertainties` must never turn into a read-only or safe default.
- `effects` lists possible direct effects, not effects guaranteed to occur on
  every successful request. `state_dependent_effects` lists additional effect
  sets with human-readable `when` conditions. Both lists matter. Their absence
  is not a proof of harmlessness or a comprehensive browser/OS sandbox claim.
- `uncertainties` identifies areas needing further inspection. The native
  `runtime` action, for example, has a second `command.operation` discriminator;
  those nested commands are not individually effect-audited in this version.
- `prerequisites` contains stable descriptive `id` values and human-readable
  `condition` text. They describe relevant availability/ownership checks, not
  an executable capability evaluator or every request-validation constraint.
  The request schema and referenced handlers remain authoritative. Common
  operation and action-specific prerequisites apply together.
- `confirmations` lists exact request `field` names, `value: true`, and a
  JSON Schema 2020-12 `when` predicate over the entire request. `{}` means
  unconditional. For example, unsigned JWT creation needs
  `allow_unsigned_confirmed=true` when `algorithm` is `none`; selected-field
  capture needs `confirmed=true` when `enabled` is true. Analyst execution also
  needs `confirmed_sensitive=true` when the selected artifact is sensitive.
  Ordinary requiredness and boolean types remain in the request schema.
- `notes` supplies the effect scope and caveats. `sources` gives repository
  `path` and Rust `symbol` pointers for auditing, without fragile line numbers.

The common policy deliberately confers no retry permission. It is conservative
client guidance, not a claim that every operation is non-idempotent. A timeout,
failed cancellation, or dropped connection can leave effects in flight; do not
infer rollback or a no-op.

The effect vocabulary is deliberately separate from HTTP method and success:

- `analysis`: interprets or transforms supplied/captured data
- `local-state-write`: changes retained backend/session state, including caches,
  counters, watches, definitions, or result records; excludes incidental locks
  and temporary response allocations
- `filesystem-write`: creates, replaces, truncates, or removes local files or
  directories, including analysis caches and temporary snapshots/profiles
- `browser-control`: sends browser/debugger commands or changes its attachment,
  execution, instrumentation, or native bridge state; a source-fetch command
  can have this label even without page mutation
- `disposable-target-mutation`: changes an owned experiment/native-console
  target, context, page, or its instrumentation; the label is not proof that
  arbitrary downstream page code stays within any authorization boundary
- `live-target-mutation`: changes the exact captured document explicitly selected
  and authorized for live Console commands; this is not a disposable context
  or a read-only evaluation guarantee
- `code-execution`: evaluates expressions, executes supplied scripts or helper
  JavaScript, or enables subsequent target execution; static parsing/decoding
  alone is `analysis`
- `network-access`: possible target/external HTTP(S) requests or requests caused
  by page code, navigation, reload, or replay; ordinary local API, CDP, socket,
  and helper transport is excluded, so this is not a network-isolation claim
- `process-launch` / `process-stop`: starts or terminates owned helpers,
  transports, browser processes, or capture services
- `data-discard`: removes or replaces retained data, definitions, results,
  browser state, or files; it does not mean every removal is permanent
- `sensitive-capture`: explicitly changes selected-value capture that may
  process sensitive request content; the label is not a complete privacy review

Effects include later work explicitly enabled by an action. Independently running capture and
unrelated background refresh are not attributed to an evidence GET. Browser
internals, target code, partial failures, and raced state can introduce effects
that static metadata cannot establish. Check the uncertainty and condition text.

Important distinctions captured by the catalog:

- VM GET can write its analysis cache. Native-console GET can retire an expired
  or poisoned session, stop processes, and delete its temporary profile.
- Capture clear truncates stored records after capture stops, while leaving
  artifact files. Workspace replacements and clear-history actions discard
  data even when they do not touch the live target.

`describe --action` fails explicitly if the chosen action lacks supported
metadata. It retains the operation extension and adds the selected entry under
`x-reb-selected-action-execution`; it does not overwrite locality, body limits,
or common prerequisites. `call` and backend dispatch do not consult this catalog
for authorization or retry, and this change adds no runtime capabilities.

## Maintain and validate

Run `make lint`, `make check`, `make e2e`, `make sanitize`, and `git diff --check`
as the repository handoff gate. The HTTP tests validate actual response bodies,
statuses, declared headers, conditional responses and artifact chunks against
the embedded specification, including invalid-input cases. These local tests
do not establish live browser or native-app coverage. Run
`apps/origin-trace-backend/target/debug/reb-api list` to confirm the client loads
the contract. Validate the document with an OpenAPI 3.1-capable tool.
When changing the server, update the spec in the same change. Never update a
schema to claim an endpoint or authorization mechanism that is not implemented.

## Inert evidence package validation

`POST /api/evidence/packages/validate` (`validate_evidence_package`) accepts a
bounded supplied package directly. It returns `valid`, `invalid`, or
`unsupported` validation data with `origin: untrusted_input` and
`authenticity: not_established`; HTTP 200 alone does not imply validity.
Duplicate JSON keys are rejected before HTTP or CLI materialization. See
[Evidence Package v1](evidence-package-v1.md) for the closed metadata schema,
canonical serialization/digest, limits, safe issues, and provenance boundaries.
No source store or artifact content is accessed, and no export is implied.


## Guarded evidence package export

`POST /api/evidence/packages/export` (`export_evidence_package`) reads an exact
bounded event/artifact selection from the configured local stores. It requires
updated producer guard files and stopped relevant writers, fully scans requested
sources, verifies complete selected blobs, and emits closed metadata with honest
coverage and unknown historical provenance. Empty selection reads no sources.
No capture control, raw content export, helper execution or automatic retry is
included. Source/guard aliases and unsafe store permissions fail closed.

Use `reb-api call export_evidence_package --body-file selection.json --output
selected.reb-evidence.json` with the usual endpoint option. See
[Evidence Package v1](evidence-package-v1.md#selected-stopped-store-export) for
request shape, safe persistence, exact limits, lease compatibility and stable
error reasons. Backend event clear now also requires matching exclusive guards
for all existing configured outputs; legacy unguarded clear returns 503.

## Native event window and summary scope

`GET /api/events?limit=5000` returns `count`/`events` for the newest general
window and `network_events` for a separate newest network-lifecycle window.
Each array is capped by the requested limit (maximum 5,000); ordering is file
arrival order, not numeric sequence order. Network selection includes
`request_initiated`, `request_started`, `request_redirected`, `response_started`,
`response_completed`, `request_completed`, and `request_failed` with category
`network`. General event churn cannot displace this second window within the
scan budget. Neither array promises a complete request lifecycle.

The reader scans at most the newest 67,108,864 bytes, plus one boundary byte.
`event_window` reports `scan_start` and `scan_end` as canonical unsigned byte
offsets (end exclusive), `scan_limit`, and separate `events_limited` and
`network_events_limited` flags. A cut-through record prefix is omitted, not
parsed as a new record. `scope: "store"` means the scan starts at byte zero;
`"bounded_tail"` excludes an older prefix, even if fewer than 5,000 rows remain.

`sequence_gaps` and `queue_drops` are canonical unsigned decimal strings over
validated records in this declared scope. They are not session totals.
Sequence gaps count absent IDs between the minimum and maximum observed sequence
within each session/process in the stated scope. Late ACK-delayed arrivals close
holes; duplicates do not create gaps. Unknown prefixes and tails are not counted.
The native broker retains bounded missing intervals independently of its event
ring; `sequence_tracking_evictions` reports lost tracking coverage when that
budget is exhausted, rather than freezing speculative losses.
A canonical positive unsigned decimal gap-marker payload contributes its value
to queue drops, otherwise the marker weighs one. Drop totals may overlap gaps.
The respective `_saturated` flags distinguish clamping at u64 maximum.

Malformed or incomplete JSON in the scanned records fails the refresh; the UI
retains its last valid data. A complete final record without a newline is valid.
The cache verifies exact overlap/boundary bytes and file identity before reuse.
The Rust endpoint and the Swift stored-evidence reader both support this
contract, including the separate network window, scan coverage, and saturated
gap and drop totals. A response that omits the fields is still accepted, and
the UI then resets old summaries and labels fallback counts as
visible-window-only.

### Filtered and paged reads

Any filter or cursor parameter turns `GET /api/events` into a filtered read
that bypasses the polling cache. The unfiltered window above is unchanged.
Filters combine with AND and compare stored fields exactly:

- `type` and `category`: comma-separated lowercase names, at most 16;
- `session_id`, `navigation_id`, `frame_id`, `tab_id`, `process_id`,
  `artifact_id`, `request_id`, `parent_event_id`: canonical decimal integers;
- `since_ns` (inclusive) and `until_ns` (exclusive) on `monotonic_time_ns`.

Without a cursor the read starts at the last complete record and returns the
newest `limit` matches in file order. `before=OFFSET` continues backward and
`after=OFFSET` reads forward from a record boundary. Each response adds `query`
with the applied `filters`, `direction`, `returned`, `store_end`, `limited`,
`budget_exhausted`, `next_before` (null at the start of the store) and
`next_after`. A page stops at `limit` matches or after 64 MiB of records, so
pass the cursor on to continue. A record without its newline is still being
written and is not returned until it is complete. `event_window.scope` is
`bounded_range` unless the read covered the whole store. Gap fields describe
only the scanned range. `network_events` is empty: select network records with
`category=network`.

Cursors are byte offsets of record boundaries in this backend's store. An offset
past the end or inside a record returns 400. They do not survive a clear or a
different store. An unknown query parameter returns 400 on the filtered and the
unfiltered route, so a misspelled filter cannot return unfiltered records.

`GET /api/artifacts` takes `kind`, `artifact_id`, `session_id`,
`navigation_id`, `frame_id`, `execution_context_id`, `sha256` and `host`
(case-insensitive URL host), with the same `after` and `before` cursors over
`manifest.jsonl`. Records keep the public fields of the unfiltered route, and
a duplicate artifact ID inside the scanned range still fails the read. Wasm
modules usually have a `wasm://wasm/<hex>` URL, so select them with `kind=wasm`
or `frame_id`, not `host`.

The Rust backend serves these reads. The native stored-evidence `reb://` reader
serves only the unfiltered window.

### Waiting for events

`GET /api/events/wait` (`wait_for_events`) takes the same filters, `after`,
`limit` (default 100) and `timeout_ms` (1 to 60,000, default 10,000). It
returns as soon as a complete record after the cursor matches, in the filtered
`get_events` shape plus `wait` with `timed_out`, `timeout_ms` and `waited_ms`.
Without `after` it waits only for records written after the call starts. On a
timeout it returns no events and `query.next_after`, which is the `after` for
the next wait. `event_window` covers every byte read while waiting. The server
checks the store length every 200 ms and holds no reader between checks. At
most eight waits run at once; a ninth returns 503 `resource_limit`. Waiting
changes nothing in the browser or the stores.

## Exact native Traffic to VM selection

`GET /api/analysis/vm` without selectors remains session analysis. A request
selection must supply all four nonzero canonical fields: `request_id`,
`session_id`, `root_process_id` (32-bit), and `root_sequence_number` (64-bit).
Incomplete, malformed, or repeated selectors return 400. The selector and ETag
include the complete native root, never just a reused numeric request ID.

Selected results require `exact_request_links`: a unique native
`request_started` root, a same-process/session `response_started`, and a retained
successful `artifact_captured` event whose `parent_event_id` equals the
manifest's `creator_event_id`. Request/frame/navigation metadata must agree;
root and response browser-context tokens must agree. The response sequence is
producer-owned, not a URL, timing, same-frame, or content-hash match. Identical
redelivery is idempotent, conflicting identities and multiple roots/captures
remain unlinked, and arrival order is not interpreted as causal order. Network
artifacts have no JavaScript execution-context or trustworthy document-generation
identity; neither is inferred. The exact request and creator event instances
bound this narrower body-capture relation.

The response labels selection semantics `exact-captured-response-body` and keeps
the evidence references. This proves that the analyzed bytes were captured from
that native response, not that the source ran, dispatched a guest VM, or caused
an outgoing request. Native redirects are one chain-level request, not an exact
CDP redirect-hop claim. Mixed hypotheses, generated source, allocating-script
snapshots, missing ACK/creator records, and historical captures without the new
parent link are excluded from exact selection. `related_request_ids` remains
legacy correlated context for unfiltered analysis and is never an exact filter.

Host/method/time correlations and incomplete roots stay in Traffic with an
explanation. Use the VM workspace navigation explicitly for unfiltered session
analysis. A rebuilt, matched Brave is required to produce the new capture-parent
link.
