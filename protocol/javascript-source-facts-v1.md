# JavaScript source facts v1

`GET /api/source-facts?session_id=SESSION&artifact_id=ARTIFACT` returns
`schema: reb-javascript-source-facts-v1` from the existing Rust/Oxc worker. The
OpenAPI operation is `get_source_facts`, available through the existing generic
CLI:

```sh
reb-api describe get_source_facts
reb-api call get_source_facts --endpoint-file /tmp/reb-api-endpoint \
  --param session_id=1 --param artifact_id=2
```

Both canonical unsigned decimal identifiers are required. The manifest must
select exactly one artifact, and its stored session must match. Artifact IDs
are globally unique under the current storage contract; duplicate IDs make the
manifest invalid. The artifact contract does not carry a process ID, so this
API neither accepts nor invents one. Live script IDs, URLs, displayed text,
pretty-printed or derived representations, and extra parameters are rejected.
There is no fallback source selection.

Only immutable captured artifacts with `kind: javascript` are accepted. The
entire blob must pass the existing content size and SHA256 checks before strict
UTF-8 decoding and analysis. Input is at most 4 MiB; prefixes and replacement
characters are never substituted. Empty JavaScript is valid input. The result's
`source` is the public artifact record, including session/artifact,
navigation/frame/execution context, capture origin, exact SHA256 and byte size.
`source_bytes` must equal that verified byte size. A direct worker rejection of
an oversized request retains its actual source length up to the JSON framing
cap; HTTP rejects that input before invoking the worker. Original bytes are never
modified. Facts are not persisted or added to captured evidence automatically.

## Worker boundary and bounds

The request is one JSON line: `{"operation":"source_facts","source":"..."}`.
It uses the existing worker executable, process lock and process-group cleanup.
The adapter clears the worker environment, allows five seconds, caps stdout at
32 MiB and stderr at 64 KiB. No JavaScript is executed. No model, network,
browser-control or new parser path participates.

The worker response and HTTP response share the fields below; only HTTP adds
`source`. IDs are independent unsigned integer namespaces per fact array,
local to these exact source bytes. They must never be joined across different
source identities. The adapter checks the schema, source length, identifier
uniqueness, references, acyclic parent-before-child ownership, source containment
and unique local order slots before returning the result. Operation kinds,
targets, receivers and details have closed bounded schemas; unknown worker
shapes are rejected rather than forwarded.

- `profile: lexical-effects-v1`, `offset_unit: utf-8-byte`
- `scopes`: `id`, nullable `parent_id`, `range`, `kind`
- `bindings`: `id`, `scope_id`, `name`, declaration `range`, `kind`
- `callables`: `id`, `scope_id`, `range`, `body_range`, `kind`, `async`, `generator`
- `regions`: `id`, nullable `parent_id` and `callable_id`, `range`, `kind`,
  `entry_order`
- `operations`: `id`, `region_id`, `order`, `range`, `kind`, heterogeneous
  `detail` with lexical reference targets and effect evidence

All ranges are half-open `{start,end}` offsets into original UTF-8 bytes,
including detail fields ending in `_range`. Neither UTF-16 indices nor rewritten
text offsets are accepted. A target with `kind: binding` names local
`binding_ids`; unresolved and ambiguous targets are explicit. Property targets
carry object/key ranges and computed-key information rather than asserting a
runtime object identity. These records describe lexical structure and effects,
not a control-flow proof, executed trace, or value-flow graph. A `callable-body`
region is deferred until its callable executes. `entry_order`
and operation `order` describe structural local order conditional on region entry
and normal completion. They never form a global execution trace or CFG and do
not flatten conditional arms, short-circuit operands or repeated loop work into
unconditional execution. Every call target remains unknown, even when its callee
identifier resolves to a lexical binding. Binding resolution is neither a
reaching-definition proof nor proof that temporal-dead-zone checks succeed.
Optional chains, try/finally, classes and complex iteration remain omitted with
explicit frontiers rather than invented effects.

`limits` reports `max_source_bytes: 4194304`, `max_ast_nodes: 32768`,
`max_facts: 16384`, `max_frontiers: 256`, `max_binding_candidates: 64`,
`preflight_depth: 128` and
`preflight_nodes: 500000`. The fact limit is the total across all five arrays.
The bounded lexical preflight and Oxc parser use the same inert-source path as
the existing worker. Frontier records and diagnostics are bounded separately.

## Coverage and failures

Always inspect both `ok` and `coverage`, even after HTTP 200.

- `complete`: complete within the declared lexical profile only; never a claim
  of complete JavaScript behavior or runtime/cross-artifact resolution
- `partial`: available facts coexist with explicitly unknown frontiers or a
  reached budget; `ok` remains true
- `unavailable`: the source could not be safely parsed/analyzed; `ok` is false
  and all fact arrays are empty

`coverage.truncated` identifies budget loss. `coverage.diagnostics` contains
bounded messages, and `coverage.frontiers` contains `{range,reason}` records.
Declaration-table exhaustion returns empty facts and partial/truncated coverage,
rather than incorrectly resolving references against an incomplete scope table.
Unknown or unsupported effects remain frontiers; their absence from supported
facts must not be interpreted as proof that an effect cannot occur.

Invalid or duplicate parameters, a non-JavaScript artifact, invalid UTF-8, or an
oversized source return 400. Missing artifacts or session mismatch return 404.
A manifest lookup or worker deadline returns 408; a busy shared worker returns
409. Worker output overflow returns 422. Abnormal worker exit or malformed
response returns 502, and an unavailable executable returns 503. Corrupt content,
ambiguous manifests or local I/O errors return 500. These errors never trigger
automatic retries or analysis of a different source.

## Supported profile and next boundaries

Simple lexical declarations and parameters, closures, lexical shadowing,
forward `var` references and named functions retain distinct source identities.
Duplicate declarations are ambiguity sets rather than a guessed winner. More
than 64 candidates produce an unresolved target and truncated coverage; the
candidate list is never copied unboundedly into each reference.
Implicit `arguments`, external names, direct-eval/with environments, non-simple
parameter environments and block-function ambiguity remain explicit unknowns.
The parser pair admits syntax; this profile is not a complete ECMAScript early
error or environment-instantiation validator. Lexical identity never proves a
value is initialized, an access will succeed, or a called binding still holds
the originally declared function.

Supported expression facts distinguish reference formation from value reads
and writes, computed object/key/RHS order, eager left-to-right argument regions,
method versus detached receivers, compound and logical assignments, and prefix
new versus postfix old expression results. Update writes explicitly store the
new value in either case. Super references remain unsupported rather than
being mislabeled as ordinary method receivers. Conditional arms and loop test/body/update
regions remain nested. Implicit getters, proxies, coercions, spread iteration,
unknown calls and abrupt completion have named frontiers. Optional chains,
try/catch/finally, switch selection/fallthrough, classes, destructuring effects,
and async/generator execution are deliberately not flattened into eager facts.
Original literal/template ranges retain all bytes for subsequent inspection.

This increment has no bundle recognizer or module dependency graph. D16 must
establish connected loader/container bindings and occurrence-level dependency
proofs before assigning virtual module owners; callback containers alone are
insufficient. D19 can consume those owners and these original binding/effect
ranges later, but numeric module IDs or source-local fact IDs cannot establish
cross-build identity. Neither extension needs another parser or execution
engine.

## Browser presentation

Sources **Facts** is an explicit consumer of this exact contract. It accepts only
the selected captured JavaScript identity, pages at most 100 facts, labels
unknown/truncated coverage, and navigates half-open UTF-8 ranges only after
verifying the complete original bytes through the existing artifact chunk API.
The browser and native live workspace share the Rust HTTP adapter. The native
stored-evidence `reb://` scheme explicitly reports unavailable and disables the
action; it does not duplicate or weaken validation. See the
[Sources operating guide](../apps/research-ui/README.md#captured-javascript-facts).
