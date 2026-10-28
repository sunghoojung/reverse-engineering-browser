# Literal marker fuzz workflow v1

This offline-only CLI previews explicitly authored marker substitutions.
Browser execution and the CDP/Repeater runner have been removed; no fallback
or native execution replacement is provided. It does not discover targets,
import credentials, ship a payload catalog, interpret payloads as scripts, or
probe anything when preparing a plan. Follow [SAFETY.md](../SAFETY.md).

## Prepare and review

Compose a local file with this exact shape. Scope fields are retained as authored
v1 metadata for plan compatibility; they do not bind to a live browser or prove
capture or authorization.

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
method, payloads and limits. The digest validates offline integrity, not execution authorization.

Inputs/plans are regular, unchanged UTF-8 JSON files at most 256 KiB; symlink
files/parent directories, duplicate keys and invalid Unicode are refused. A
source ID is an authored label, not a claim of captured evidence or ownership.
`source_sha256` hashes the entire input's canonical JSON; `request_sha256`
hashes canonical `{body,headers,method,url}`. Canonical JSON sorts object keys,
preserves arrays and string values, omits whitespace, and uses ordinary JSON
string escaping. Formatting the input differently does not change its identity.
The plan digest hashes all plan fields except `plan_sha256`. The offline `validatePlan` helper rebuilds
and compares the entire plan, so altered cases, budgets or identity are refused.

### Marker semantics

- Select `body` or `query` and one ASCII `[A-Za-z0-9_-]+` literal, 1–64 bytes.
- The selected body or complete URL must contain exactly one literal occurrence.
  Missing, duplicated or overlapping occurrences are rejected. There is no
  escape syntax or implicit decoding; `%52EB_MARKER` does not match `REB_MARKER`.
- Body mode replaces precisely that UTF-8 substring, preserving every other
  byte. Payloads including `{{literal}}` remain literal; variables are not evaluated.
- Query mode requires the literal to be inside a query value after its `=`.
  It substitutes only that substring. Payload UTF-8 is percent-encoded, with
  only RFC 3986 unreserved characters left literal; spaces become `%20`, never
  `+`. Existing query bytes, duplicate query keys and all unselected bytes stay
  unchanged. A marker in a name/path/host or multiple values is rejected.
- `marker_range` contains half-open UTF-8 byte offsets in the original selected
  body or full URL. For `雪😀:REB_MARKER:end`, the range is `[8,18)`.

## Offline bounds

There are 1–16 cases, each payload at most 2 KiB UTF-8. Only GET, HEAD and POST
are accepted as authored request descriptions; GET/HEAD bodies are rejected.
URLs must be canonical ASCII HTTP(S), without credentials or fragments. Headers
are limited to lowercase `accept: */*` and `content-type: text/plain; charset=utf-8`.
Payloads cannot change origin or method. Each authored request is at most 8 KiB,
and the aggregate request-byte budget is 1–65536 bytes. Historical timing fields
retain v1 validation bounds (250–5000 ms interval, 100–5000 ms timeout,
1000–60000 ms deadline) but schedule no work and promise no live enforcement.

## Removed execution

`tools/run-marker-fuzz.mjs` exits nonzero immediately, including when supplied a
valid plan digest and backend URL. It reads no plan, writes no report, contacts
no backend, and launches no browser. There is no executable API helper, repeater
runner, or browser integration test in this workflow. Do not use historical
scope fields as evidence that a live experiment exists.

Plans contain authored payloads and requests; labels and hashes can also be
identifying. Nothing is automatically published. Review artifacts before sharing.

## Verification

`node tools/check-marker-fuzz.mjs` covers exact literal/query/UTF-8 plans,
percent-encoding, limits, duplicate/absent/overlapping markers, changed plans,
private/no-overwrite files, symlink and duplicate-key refusal, plus CLI refusal
under network, file-read and subprocess tripwires. These checks establish offline
planning and removal behavior, not native browser acceptance.
