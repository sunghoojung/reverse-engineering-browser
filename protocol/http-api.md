# Origin Trace HTTP API

[`openapi.json`](openapi.json) describes the **existing Python loopback server**
in `apps/research-ui/server.py`: 14 GET operations and five POST action
operations. It is OpenAPI 3.1, uses JSON Schema 2020-12, and is JSON rather than
YAML so existing Python tooling can read it without a parser dependency.
Stable `operationId` values drive the included Python CLI. No new server
endpoint or authentication system is introduced. The existing server and new
client remain Python; adding Go or Rust would not improve this small
local-client boundary.

## Start and call it

From the repository root, `make ui` starts browser development on port 7319.
For an explicitly managed server and machine-readable endpoint discovery:

```sh
python3 apps/research-ui/server.py --port 0 --endpoint-file /tmp/reb-api-endpoint
```

Use the printed URL or the endpoint file for **that server**. Live/native
sessions use ephemeral ports and their own endpoint files. Do not assume the
installed app uses port 7319 or start a competing server over its stores.
The endpoint file contains a URL, not an authentication token.

The dependency-free CLI reads this specification for operation IDs, routes,
parameters and request-body limits. It requires an explicit local server URL or
endpoint file, so it will not silently target an installed app session:

```sh
python3 apps/research-ui/api_cli.py list
python3 apps/research-ui/api_cli.py describe debugger_action
python3 apps/research-ui/api_cli.py call get_events \
  --endpoint-file /tmp/reb-api-endpoint --param limit=50 --show-headers
printf '%s' '{"action":"pause"}' | python3 apps/research-ui/api_cli.py call debugger_action \
  --endpoint-file /tmp/reb-api-endpoint --body-file -
python3 apps/research-ui/api_cli.py call get_artifact_content \
  --endpoint-file /tmp/reb-api-endpoint --param artifact_id=1 \
  --param offset=0 --param limit=2097152 --output artifact-chunk.bin --show-headers
```

`call` accepts repeated `--param NAME=VALUE` for the operation's documented
path, query and header parameters, including `If-None-Match`. POST bodies come
from a JSON object file or stdin, not a command-line JSON argument. The CLI
preflights parameter names, required values, object bodies and encoded body
size; the server remains authoritative for schema and runtime validation.
Successful JSON is printed to stdout without a wrapper. A 304 produces no
stdout body; `--show-headers` prints status, ETag and other response headers to
stderr. HTTP errors exit nonzero and show the server's error text. Binary
content requires `--output PATH` (or explicit `--output -` for stdout), and a
file path is never overwritten. The importable `api_client.py` uses the same
operation IDs. It does not provide additional permissions on its own.

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
`X-Artifact-Total-Bytes`; `X-Artifact-Truncated` indicates remaining data.
This is not HTTP Range/206 pagination. Events and artifacts expose a bounded
recent tail, not a cursor or stable exhaustive export.

## Authentication and locality

There is **no bearer token, API key, login, or OAuth scheme** on this HTTP API.
`security: []` is deliberate, not missing configuration. Every `/api/` GET and
every POST checks the exact listening port in `Host` and permits only
`127.0.0.1`, `localhost`, or `::1`. `Sec-Fetch-Site: cross-site` is rejected.
If supplied, `Origin` must be HTTP with a local hostname and matching port,
without credentials, parameters, query or fragment, and with empty or `/` path.
A CLI can omit Origin. These are local request checks, not user identity or
remote-access authentication. The default bind is 127.0.0.1; do not expose it
remotely as if it had credential-based access control.
The client rejects redirects, so a response cannot send a request to a
different host or local service.

The native broker's socket token belongs to a **different transport**. The
macOS `WKURLSchemeHandler`, C++/Unix sockets, CDP WebSockets, worker stdin/stdout
protocols and static UI assets are not OpenAPI HTTP endpoints. Native custom
scheme behavior is not guaranteed to match the Python server in every detail.

## Contract coverage and known gaps

All current HTTP API routes, documented query parameters, body-size ceilings,
conditional responses and caught error statuses are represented. Trace,
request-signal and VM schemas are embedded from their versioned protocol files
so the OpenAPI document is portable. Update embedded schemas whenever their
versioned source changes.
The VM HTTP response additionally allows its actual optional `selection` field.

The action routes are multiplexed, not invented REST resources:

- Capture has exact stop and confirmed-clear shapes. Clear requires capture to
  be stopped and does not remove artifact files.
- Decoder has four discriminated actions and result schemas. JWT `ok=false`
  may be an HTTP 200 result, so inspect application outcomes.
- Collection and Analyst replacement use optimistic `expected_generation` and
  full documents. Stale generations return 409. Tree integrity, uniqueness,
  forbidden headers and aggregate UTF-8 limits remain runtime validations.
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
  parsing currently returns 500, not 400. Several numeric limits clamp values.
- Malformed decoder JSON envelopes or invalid Content-Length can escape its
  exception handler and close the connection without a structured response.
  Deobfuscation also has uncaught filesystem/manifest errors. No synthetic
  status is promised for these gaps.
- Unknown GET paths fall back to static-file handling, often an HTML 404;
  unknown POST paths return a JSON 404. Unsupported methods use the inherited
  HTTP handler behavior, not an API-wide JSON error envelope. HEAD is not a
  documented equivalent of API GET.
- Current debugger dispatch rejects every action except disarm while Runtime
  Hooks is active, **including request-value comparison**. This conflicts with
  the UI enabling Compare while armed. CLI clients must disarm first until the
  dispatcher is corrected; this change documents rather than alters behavior.
- GET VM analysis may write its local analysis cache. No rate-limit, pagination
  cursor, idempotency key, cancellation API for every operation, or remote auth
  exists. Unknown exceptions have no guaranteed JSON contract.
- Some size constraints are UTF-8 bytes, not characters. `x-max-utf8-bytes`
  describes those checks without misusing JSON Schema `maxLength`.

## CLI usage guidance

Use the OpenAPI operation IDs as CLI commands and pass the actual `action`
discriminator for multiplexed commands. Preserve decimal-string 64-bit IDs.
Accept whole request objects from files/stdin so quoting and nested JSON remain
predictable. Keep transport errors separate from structured `{error}` responses
and successful HTTP responses containing an application failure. Do not blindly
retry mutations after a timeout or dropped connection.

## Maintain and validate

Run `make lint`, `make check`, and `make e2e` as the repository handoff
gate. Run `python3 apps/research-ui/api_cli.py list` to confirm the client
loads the contract. Validate the document with an OpenAPI 3.1-capable tool.
When changing the server, update the spec in the same change. Never update a
schema to claim an endpoint or authorization mechanism that is not implemented.

### Debugger action response envelopes

Every successful debugger response has `ok: true` and `generation`. The following
additional fields depend on the requested action; responses are not full snapshots.
Nested state models remain extensible where noted. `x-action-results` in the spec
is the machine-readable action-to-schema map.

- `pause`, `resume`, `step_over`, `step_into`, `step_out`, `restart_frame`, `remove_breakpoint`, `set_breakpoints_active`, `set_pause_on_exceptions`, `add_watch`, `remove_watch`, `evaluate_watches`, `set_xhr_breakpoint`, `remove_xhr_breakpoint`, `set_event_breakpoint`, `remove_event_breakpoint`, `select_target`, `stop_memory_origin_trace`, `clear_memory_origin_trace`, `clear_request_interception_result`, `clear_heap_diff_baseline`, `clear_console`: no additional fields.

- `set_breakpoint`, `update_breakpoint`: `breakpoint`.

- `search_live_objects`: `search`.

- `search_heap_snapshot`: `snapshot`.

- `start_memory_origin_trace`: `trace`.

- `set_action_scope`, `close_experiment_page`: `action_scope`.

- `create_request_interception_experiment`, `dispose_request_interception_experiment`: `action_scope`, `automation_recipes`, `experiment`, `object_experiment`, `repeater`, `runtime_hooks`.

- `create_experiment_page`: `action_scope`, `target_id`.

- `navigate_object_experiment`, `search_object_experiment`, `mutate_object_experiment`: `object_experiment`.

- `add_runtime_hook`, `remove_runtime_hook`, `arm_runtime_hooks`, `disarm_runtime_hooks`, `clear_runtime_hook_hits`, `configure_runtime_field_test`, `compare_runtime_field_test`: `runtime_hooks`.

- `add_automation_recipe`, `update_automation_recipe`: `automation_recipes`, `recipe`.

- `remove_automation_recipe`, `arm_automation_recipes`, `disarm_automation_recipes`, `cancel_automation_recipe`, `clear_automation_runs`: `automation_recipes`.

- `run_automation_recipe`: `automation_recipes`, `run`, `runs`.

- `configure_request_interception`, `run_request_interception`: `experiment`.

- `configure_repeater_variables`, `run_repeater_request`, `cancel_repeater_request`, `compare_repeater_history`, `clear_repeater_history`: `repeater`.

- `capture_heap_diff_baseline`: `baseline`.

- `compare_heap_diff`: `diff`.
