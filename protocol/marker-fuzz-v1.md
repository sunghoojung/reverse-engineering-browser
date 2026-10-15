# Literal marker fuzz workflow v1

This opt-in CLI workflow previews explicitly authored marker substitutions and
executes reviewed cases sequentially through the existing disposable Repeater.
It is a real bounded runner, not just a planner. It does not discover targets,
import credentials, ship a payload catalog, interpret payloads as scripts, or
probe anything when preparing a plan. Follow [SAFETY.md](../SAFETY.md).

## Prepare and review

Create a disposable Experiment in Origin Trace. Read its current target ID,
`network.instance_id`, `request_interception.experiment_id`, and `repeater.session_id` from the local
`GET /api/debugger` response or `reb-api call get_debugger --read-only`. Explicitly
set interception to **Continue** and keep the primary page selected. Compose a
local file with this exact shape (the target below is illustrative, not usable):

```json
{
  "format": "reb-marker-fuzz-input-v1",
  "source_id": "my-authored-loopback-request",
  "scope": {"instance_id": "COPY_CURRENT_INSTANCE", "target_id": "COPY_CURRENT_TARGET", "experiment_id": 1, "session_id": 1},
  "request": {
    "url": "http://127.0.0.1:8000/echo?q=REB_MARKER",
    "method": "GET", "headers": {"accept": "*/*"}, "body": ""
  },
  "marker": {"field": "query", "literal": "REB_MARKER"},
  "payloads": ["", "snow 雪 & next=1", "{{literal}}"],
  "limits": {"interval_ms": 250, "request_timeout_ms": 1000, "deadline_ms": 5000, "max_request_bytes": 65536}
}
```

```sh
node tools/prepare-marker-fuzz.mjs --input authored.json
node tools/prepare-marker-fuzz.mjs --input authored.json --output reviewed-plan.json
```

The first command prints every resolved request and payload for review, along
with source/request/case SHA-256 identities, the selected marker byte range,
aggregate authored-field bytes, and the plan SHA-256. Neither command accesses
the backend or target. The second saves identical plan data privately without
replacing an existing path. Review the actual plan contents, exact origin,
method, payloads, limits and target authorization before arming its digest.

Inputs/plans are regular, unchanged UTF-8 JSON files at most 256 KiB; symlink
files/parent directories, duplicate keys and invalid Unicode are refused. A
source ID is an authored label, not a claim of captured evidence or ownership.
`source_sha256` hashes the entire input's canonical JSON; `request_sha256`
hashes canonical `{body,headers,method,url}`. Canonical JSON sorts object keys,
preserves arrays and string values, omits whitespace, and uses ordinary JSON
string escaping. Formatting the input differently does not change its identity.
The plan digest hashes all plan fields except `plan_sha256`. The runner rebuilds
and compares the entire plan, so altered cases, budgets or identity are refused.

### Marker semantics

- Select `body` or `query` and one ASCII `[A-Za-z0-9_-]+` literal, 1–64 bytes.
- The selected body or complete URL must contain exactly one literal occurrence.
  Missing, duplicated or overlapping occurrences are rejected. There is no
  escape syntax or implicit decoding; `%52EB_MARKER` does not match `REB_MARKER`.
- Body mode replaces precisely that UTF-8 substring, preserving every other
  byte. Payloads including `{{literal}}` remain literal; Repeater variables are
  not evaluated in marker mode.
- Query mode requires the literal to be inside a query value after its `=`.
  It substitutes only that substring. Payload UTF-8 is percent-encoded, with
  only RFC 3986 unreserved characters left literal; spaces become `%20`, never
  `+`. Existing query bytes, duplicate query keys and all unselected bytes stay
  unchanged. A marker in a name/path/host or multiple values is rejected.
- `marker_range` contains half-open UTF-8 byte offsets in the original selected
  body or full URL. For `雪😀:REB_MARKER:end`, the range is `[8,18)`.

## Explicit execution

```sh
node tools/run-marker-fuzz.mjs --plan reviewed-plan.json \
  --arm REVIEWED_PLAN_SHA256 --base-url http://127.0.0.1:8765 \
  --report new-report.json
```

The base URL must be an explicit HTTP literal-loopback backend origin (`127.0.0.1`
or `[::1]`), with no credentials, path, query or fragment. The CLI uses Node's
HTTP transport directly; it does not use a proxy, cookie jar or automatic
redirect/retry. The target request may use the exact explicitly reviewed HTTP(S)
origin. The tool does not verify target ownership. Testing this feature uses
only authored loopback fixtures.

There are 1–16 cases, each payload at most 2 KiB UTF-8. Only GET, HEAD and POST
are supported; GET/HEAD bodies are rejected. Request URLs must already be
canonical ASCII HTTP(S), without userinfo or even an empty fragment. Headers
are limited to lowercase `accept: */*` and `content-type: text/plain; charset=utf-8`.
These avoid custom credential headers and application-request preflights.
No cookie or authentication data is imported; browser fetch uses
`credentials: "omit"`, `redirect: "error"`, `cache: "no-store"`, and
`referrerPolicy: "no-referrer"`. Payloads cannot change origin or method.

The CLI uses a monotonic clock for sequential execution with at least 250–5000 ms between dispatch
attempts, a 1000–60000 ms whole-run deadline, and a 1–65536 byte aggregate budget.
Each case's URL + method + body + header name/value UTF-8 bytes must fit 8192
bytes. This is an authored-field budget, not a measurement of TLS, browser-added
headers or transport overhead. One request timeout is 100–5000 ms and is reduced
to the remaining deadline. Browser response reads retain at most 8192 body bytes
and 2048 total header bytes per case; truncation is explicit. Full network byte
counts cannot be bounded by retained response-prefix limits.

Before every case, the runner rechecks the exact backend instance, target, experiment and Repeater
session, idle Repeater and Continue interception. Unexpected history activity
between cases stops the run. The backend independently checks the per-case
scope, literal request digest, canonical origin/method, header/size/timeout
limits and deadline, and rechecks scope plus exact active execution after the CDP writer queue,
immediately before command bytes are sent. Controller installation and guarded
cancellation use the same admission boundary. The browser runner
also checks expiry before fetch. Aggregate count, spacing and total request-byte
budgets belong to the CLI; the single-case API does not persist or enforce a
multi-case budget across independently invoked requests.

Ctrl-C/SIGTERM stops scheduling immediately. When an acknowledged execution is
active, one guarded cancellation request identifies backend instance, target, experiment, session,
execution ID, plan digest and case index. A newer replacement execution is never
cancelled. Cancellation can be requested but unconfirmed; it does not prove the
server did not receive or process the request. Deadline handling likewise stops
scheduling and attempts guarded cancellation. A pending local API call is bounded
to two seconds; a cancellation acknowledgment can take another two seconds.
No signal handler or tool can guarantee cancellation after SIGKILL/process loss.
API replies require bounded strict UTF-8 JSON without duplicate keys, a JSON
content type and no unsupported content encoding; malformed evidence fields
are never copied into reports.

An HTTP error status such as 404 is a completed response and permits the next
case. Network/redirect error, timeout, cancellation, changed scope or malformed,
missing or uncertain acknowledgment stops all remaining cases. Unknown outcomes
are never retried. Inspect the exact Repeater history before deciding what to do
next. If the process dies, Repeater's bounded per-case timeout still applies;
the remaining cases were never queued in the backend.

## Reports and API extension

`reb-marker-fuzz-report-v1` is printed to stdout and optionally saved to a new
private file. It contains plan/source/scope identity and one record per attempted
case: case/request/payload hashes, exact execution ID when acknowledged, terminal
state or explicit unknown, status, duration, body hash, truncation flags and
cancellation confirmation level. `attempted_cases` counts conservative backend
dispatch attempts, including uncertain ones; `confirmed_executions` counts exact
acknowledged execution IDs. `not_attempted_cases` never implies an uncertain
attempt was unsent. An existing report path fails before execution; a later
filesystem failure still leaves the report on stdout.

The report deliberately contains no request/response payload text or header
values. It is not guaranteed nonsensitive: source labels, target identities and
hashes can be identifying. Plans contain authored payloads and requests; raw
bounded responses remain potentially private ephemeral Repeater evidence.
Nothing is automatically published or exported. Review all artifacts before
sharing. The ordinary Repeater history can evict old entries; missing evidence
stops the runner rather than substituting another case.

The existing `run_repeater_request` action accepts optional `marker_fuzz` with
version, plan digest, case index/count, exact backend instance/target/experiment/session,
origin/method, request digest and absolute expiry. Accepted metadata accompanies
both active execution and retained history. `cancel_repeater_request` accepts
optional `expected_execution` with the complete tuple above. Without these
extensions, ordinary Repeater substitution, limits and redirect behavior remain
unchanged. The CLI is the supported batch surface; no new GUI fuzzer/editor,
background scheduler, automatic retry, durable job manager or exploit library
is provided.

## Verification

`node tools/check-marker-fuzz.mjs` covers pure planning, UTF-8/percent-encoding,
limits, duplicate/absent/overlapping markers, changed plans, private/no-overwrite
files, explicit CLI arming and reporting, stale/unknown/cancel/deadline handling,
spacing and the production fetch function against authored loopback routes.
Rust unit tests cover strict per-case scope/digest/header/budget validation and
the full cancellation tuple. `make backend-e2e` additionally runs real-CDP cases
via `tools/marker-fuzz-integration.mjs`, including literal payloads, exact scoped
results, rejected stale scope/replacement cancel, actual cancellation and
redirect refusal. Missing toolchains must be reported, not replaced by a claim
that fixture/model tests established backend or native acceptance.

Response limits apply separately to the raw stream prefix and retained UTF-8 text (8 KiB each). Invalid UTF-8 replacement decoding can expand text; marker mode truncates that text at a complete code point and marks `body_truncated`. The response digest covers the exact retained text, not raw wire bytes. Ordinary Repeater decoding is unchanged.
