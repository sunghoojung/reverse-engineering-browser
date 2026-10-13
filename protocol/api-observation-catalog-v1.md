# API observation catalog v1

`GET /api/network/catalog` is an explicit, read-only interpretation of the
existing ephemeral CDP Traffic ledger. It does not enable capture, fetch data,
send requests, save templates, modify raw values, or introduce MCP. Its OpenAPI
operation ID is `get_api_observation_catalog`. The response is
`reb-api-observation-catalog-v1`; the closed schema lives in
[openapi.json](openapi.json). Requests take no query parameters.

## Endpoint and evidence identity

The catalog groups the newest 64 retained requests by exact method, normalized
HTTP(S) origin, and observed path spelling. An absent path becomes `/`.
Percent-encoding and dot segments in paths remain distinct; IDs are never
replaced with guessed REST parameters. Non-HTTP(S), truncated, malformed,
over-budget, or unidentifiable records increase `coverage.skipped_records`.
There is no host, path, time, or method fallback for a missing source.

Each observation carries the exact public CDP request ID, target ID, and
`started_monotonic_ms`. Its enclosing coverage carries backend `instance_id`
and `capture_epoch`; clients must match all five before linking to a current
Traffic record. `debugger_generation` identifies the captured state version.
These are ephemeral CDP identities, not native event or stored-artifact IDs.
A later poll, reconnect, or eviction can make the source unavailable. Observations
within a group are newest first; groups are sorted by method, origin, and path.

Each observation lists form-decoded query parameter names, lowercase request
and response header names, observed response status, request lifecycle state,
and independent request/response JSON shapes. Names are deduplicated and sorted. Malformed percent escapes or non-UTF-8 query
names are omitted explicitly rather than replaced with invented characters.
`omitted` / `header_names_omitted` count rejected name occurrences, not unique
unseen parameters. `headers_truncated` separately preserves upstream loss.
No parameter values, header values, raw body values, URL credentials or fragments
are copied into this structural view. The MIME field contains only a validated,
normalized media type without Content-Type parameters; malformed types become
an empty string. Paths, names, and identifiers can still
contain sensitive data. Review before sharing; this is not a secrecy guarantee.
The original local Traffic ledger and UI remain unchanged.

## Shapes and unknowns

An `observed` shape covers one complete retained UTF-8 text body with an
`application/json` or `application/*+json` media type. Typed path segments keep
object property names distinct from array elements, including literal `*`, empty,
slash-containing, and dot-containing keys. Matching array element paths collect
observed types and occurrence counts. Root type, node count, and observed maximum
depth describe that body alone. This is not JSON Schema, an inferred service
contract, or a claim about required/optional fields or unobserved array members.

Bodies that are missing, loading, empty, failed, truncated, base64, non-JSON,
malformed, or over budget have `status: unavailable`, `shape: null`, and an
explicit reason. The original body state is retained separately. Duplicate
object keys, including escaped equivalents, are rejected. The streaming parser
discards scalar values and detects resource limits while traversing. No partial
shape is represented as complete. A valid observed shape says nothing about
upstream wire completeness, authentication needs, or future API responses.

## Bounds and coverage

- Newest 64 of the existing at-most-1,000 retained requests; no stable pagination
- 8,192-byte URLs, 8,192-byte request IDs, 4,096-byte target IDs
- 32 KiB of complete text per body side; no base64 decoding
- 64 names per surface and 256 UTF-8 bytes per name
- 2,048 shape value nodes, depth 16, 64 distinct non-root paths
- 16 KiB summed serialized shape paths; 4 MiB maximum response

The `limits` object exposes inference limits. Catalog window exclusions,
capture evictions, invalid records, name omissions, header truncation, and body
unknowns stay separate; they are not added to invent an exhaustive loss count.
Capture-off and empty/unconnected states remain explicit. Inference occurs on
the backend's existing bounded blocking pool after a bounded projection releases
the debugger state lock. No new probe or network hot-path work is added.

## Local client consumption

Use the endpoint file belonging to the intended live session:

```sh
reb-api describe get_api_observation_catalog
reb-api call get_api_observation_catalog --endpoint-file /tmp/reb-api-endpoint \
  --output observed-api.json
```

`--output` is explicit and uses the CLI's existing private, no-overwrite file
publication. The catalog may contain private paths or names. It is not suitable
for automatic repository publication.

A local client can list observed operations without issuing target requests:

```python
import json

with open("observed-api.json", encoding="utf-8") as source:
    catalog = json.load(source)
assert catalog["format"] == "reb-api-observation-catalog-v1"
for endpoint in catalog["endpoints"]:
    print(endpoint["method"], endpoint["origin"], endpoint["path"])
    for observation in endpoint["observations"]:
        body = observation["response"]["body"]
        print(observation["source"]["request_id"], body["status"], body["reason"])
```

This first slice supplies observations for a human-reviewed API consumer. It
does not generate an authenticated SDK, infer credentials, validate replay, or
make authorization decisions. The source-pinned adaptation and MIT notice are
in [third_party/rea](../third_party/rea/README.md). Project policy remains in
[SAFETY.md](../SAFETY.md).
