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
stored artifact; no live/URL/derived-source fallback is supported. See
[JavaScript source facts v1](javascript-source-facts-v1.md) for exact-byte ranges,
limits, and partial/unavailable coverage semantics.

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
route. A client supplies the same loopback root as `call`, through `--base-url`
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
This is not HTTP Range/206 pagination. Events and artifacts expose a bounded
recent tail, not a cursor or stable exhaustive export.

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
capture mode, and a retained Wasm artifact inventory (16 entries from a 256 KiB
manifest tail). Use this route's own ETag for conditional reads. No
target/session join is inferred from URL or timing.

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
