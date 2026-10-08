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
apps/origin-trace-backend/target/debug/reb-api describe debugger_action
apps/origin-trace-backend/target/debug/reb-api describe debugger_action --action add_automation_recipe
apps/origin-trace-backend/target/debug/reb-api call get_events \
  --endpoint-file /tmp/reb-api-endpoint --param limit=50 --show-headers
printf '%s' '{"action":"pause"}' | apps/origin-trace-backend/target/debug/reb-api call debugger_action \
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

```sh
REB_API=$(cat /tmp/reb-api-endpoint)
curl --fail-with-body "$REB_API/api/health"
curl --fail-with-body "$REB_API/api/events?limit=50"
curl --fail-with-body "$REB_API/api/debugger"
curl --fail-with-body --json '{"action":"pause"}' "$REB_API/api/debugger/actions"
```

The last call needs a connected debugger and changes its execution state.
A server without configured live services still exposes stored-evidence
operations and returns explicit unavailable state or 409 for live controls.
`curl --json` sends the required Content-Length; streaming/chunked request bodies
are unsupported. Action bodies must be JSON objects within the per-operation
`x-max-body-bytes` limit. The server does not enforce Content-Type, but clients
should send `application/json`.

Conditional GET operations list `If-None-Match` and a bodyless 304 response.
Debugger long polling accepts `wait_ms=0..25000`; it waits only when the supplied
ETag matches the current generation. Set client timeouts above the chosen wait.
Artifact content uses `offset` and `limit` query arguments and always returns
200 on success, including partial chunks. Advance using actual byte count and
`X-Artifact-Total-Bytes`; `X-Artifact-Truncated` is the string `true` when bytes
remain and `false` at the end. An offset equal to the total returns an empty
chunk; a negative, malformed, or beyond-end offset returns 400.
Artifact lookup or full-content verification can return a JSON 408 when its
five-second manifest or thirty-second verification deadline expires.
This is not HTTP Range/206 pagination. Events and artifacts expose a bounded
recent tail, not a cursor or stable exhaustive export.

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
macOS `WKURLSchemeHandler`, C++/Unix sockets, CDP WebSockets, worker stdin/stdout
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
- Debugger enumerates all 59 current actions with source-backed request fields,
  types, requiredness, defaults and bounded values, including automation,
  repeater, interception, object search and mutation. Six variants retain
  `x-schema-completeness: partial` for complex constraints: interception rule
  normalization, recursive mutation-value budgets, JSON-inside-string shape
  parsing in the two object searches, and legacy condition/expression fallback
  in breakpoint creation/update. These are modeling limits, not unknown endpoints.
  `x-unmodeled-constraints` identifies each residual check. All 59 actions map
  to one of 17 closed response envelopes; nested experiment, search-row and
  CDP-dependent state records remain partially typed with source pointers.

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
- Current debugger dispatch rejects every action except disarm while Runtime
  Hooks is active, **including request-value comparison**. This conflicts with
  the UI enabling Compare while armed. CLI clients must disarm first until the
  dispatcher is corrected; this change documents rather than alters behavior.
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

All 25 operations and all 74 top-level request action variants, including the 59
debugger actions, carry version 1 `x-reb-execution` metadata. It is a source-owned,
static advisory catalog. It does not grant permission, verify target ownership,
report current availability, replace server validation, or prove that an action
has no additional effects. In particular, no confirmation field means only that
the current handler has no such field. Native evaluation and Repeater still
require appropriate researcher authorization under [SAFETY.md](../SAFETY.md).

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

Effects include work explicitly enabled by an action, such as automatic recipes
or saved watches evaluated on later pauses. Independently running capture and
unrelated background refresh are not attributed to an evidence GET. Browser
internals, target code, partial failures, and raced state can introduce effects
that static metadata cannot establish. Check the uncertainty and condition text.

Important distinctions captured by the catalog:

- VM GET can write its analysis cache. Native-console GET can retire an expired
  or poisoned session, stop processes, and delete its temporary profile.
- Heap searches/comparisons capture fresh temporary files and run a helper.
  Live-object search and watch evaluation execute JavaScript. Adding a watch
  enables its automatic evaluation on a later pause.
- Configuring interception immediately arms browser rules. Automation
  cancel/disarm can reload a page, causing more code and requests to run.
- Capture clear truncates stored records after capture stops, while leaving
  artifact files. Workspace replacements and clear-history actions discard
  data even when they do not touch the live target.
- Debugger action narrowing preserves the common dispatcher guards. Runtime
  Hooks currently blocks every action except disarm while active, including
  field comparison. A cancellation lock exemption does not bypass other owners.

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

### Debugger action response envelopes

Every successful debugger response has `ok: true` and `generation`. The following
additional fields depend on the requested action; responses are not full snapshots.
Nested state models remain extensible where noted. `x-action-results` in the spec
is the machine-readable action-to-schema map.

- `pause`, `resume`, `step_over`, `step_into`, `step_out`, `restart_frame`, `remove_breakpoint`, `set_breakpoints_active`, `set_pause_on_exceptions`, `add_watch`, `remove_watch`, `evaluate_watches`, `set_xhr_breakpoint`, `remove_xhr_breakpoint`, `set_event_breakpoint`, `remove_event_breakpoint`, `select_target`, `clear_memory_origin_trace`, `clear_heap_diff_baseline`, `clear_console`: no additional fields.

- `set_breakpoint`, `update_breakpoint`: `breakpoint`.

- `search_live_objects`: `search`.

- `search_heap_snapshot`: `snapshot`.

- `start_memory_origin_trace`, `stop_memory_origin_trace`: `trace`.

- `set_action_scope`, `close_experiment_page`: `action_scope`.

- `create_request_interception_experiment`, `dispose_request_interception_experiment`: `action_scope`, `automation_recipes`, `experiment`, `object_experiment`, `repeater`, `runtime_hooks`.

- `create_experiment_page`: `action_scope`, `target_id`.

- `navigate_object_experiment`, `search_object_experiment`, `mutate_object_experiment`: `object_experiment`.

- `add_runtime_hook`, `remove_runtime_hook`, `arm_runtime_hooks`, `disarm_runtime_hooks`, `clear_runtime_hook_hits`, `configure_runtime_field_test`, `compare_runtime_field_test`: `runtime_hooks`.

- `add_automation_recipe`, `update_automation_recipe`: `automation_recipes`, `recipe`.

- `remove_automation_recipe`, `arm_automation_recipes`, `disarm_automation_recipes`, `cancel_automation_recipe`, `clear_automation_runs`: `automation_recipes`.

- `run_automation_recipe`: `automation_recipes`, `run`, `runs`.

- `configure_request_interception`, `run_request_interception`, `clear_request_interception_result`: `experiment`.

- `configure_repeater_variables`, `run_repeater_request`, `cancel_repeater_request`, `compare_repeater_history`, `clear_repeater_history`: `repeater`.

- `capture_heap_diff_baseline`: `baseline`.

- `compare_heap_diff`: `diff`.

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
