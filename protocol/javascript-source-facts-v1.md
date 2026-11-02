# JavaScript source facts v1

`GET /api/source-facts?session_id=SESSION&artifact_id=ARTIFACT` returns
`schema: reb-javascript-source-facts-v1` from the existing Rust/Oxc worker. The
OpenAPI operation is `get_source_facts`, available through the existing generic
CLI:

```sh
reb-api describe get_source_facts
reb-api call get_source_facts --endpoint-file /tmp/reb-api-endpoint \
  --param session_id=1 --param artifact_id=2
reb-api call get_source_facts --endpoint-file /tmp/reb-api-endpoint \
  --param session_id=1 --param artifact_id=2 \
  --param region_start_byte=1048576 --param region_end_byte=1048576
```

Both canonical unsigned decimal identifiers are required. The manifest must
select exactly one artifact, and its stored session must match. Artifact IDs
are globally unique under the current storage contract; duplicate IDs make the
manifest invalid. The artifact contract does not carry a process ID, so this
API neither accepts nor invents one. Live script IDs, URLs, displayed text,
pretty-printed or derived representations, and extra parameters are rejected.
There is no fallback source selection.

`region_start_byte` and `region_end_byte` are the only optional parameters and
the only way to narrow analysis. They are canonical unsigned decimals, must
appear together, and must form a half-open range of original UTF-8 bytes inside
the verified source at Unicode scalar boundaries; equal offsets address one
cursor. A half pair, a reversed range, an offset past the verified byte size and
an offset inside a multi-byte scalar are all rejected. The range selects no
bytes by itself. The analysis unit is the innermost callable body containing it,
resolved inside the parse of the complete source, because a byte slice has no
meaning on its own: its scope chain, strictness and syntactic position come from
the bytes around it. A range no callable body contains analyzes the whole
program rather than a fragment of one.

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

The request is one JSON line: `{"operation":"source_facts","source":"..."}`,
carrying an optional `"region":{"start":N,"end":M}` with exactly the requested
offsets. The worker re-admits that range against the source it was given.
It uses the existing worker executable, process lock and process-group cleanup.
The adapter clears the worker environment, allows five seconds, caps stdout at
32 MiB and stderr at 64 KiB. No JavaScript is executed. No model, network,
browser-control or new parser path participates.

The worker response and HTTP response share the fields below; only HTTP adds
`source`. IDs are independent unsigned integer namespaces per fact array,
local to these exact source bytes. They must never be joined across different
source identities. The adapter checks the schema, source length, identifier
uniqueness, references, acyclic parent-before-child ownership, source containment
and unique local order slots before returning the result. It also checks the
declared coverage against the request it made: an unscoped request must report
the whole source as analyzed, a scoped one must report a range containing what
was asked, and a range narrower than the source can never carry `complete`
status. Operation kinds,
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

`limits` reports `max_source_bytes: 4194304`, `max_ast_nodes: 262144`,
`max_facts: 16384`, `max_frontiers: 256`, `max_binding_candidates: 64`,
`preflight_depth: 128`, `preflight_nodes: 2097152` and
`preflight_parse_heap_bytes: 402653184`. The fact limit is the total across all
five arrays.
The node budget counts only the nodes inside the analyzed range, and it stays
fixed rather than caller-supplied so two reports of the same bytes cannot
disagree about what was admitted. It sits below the preflight node bound that
already admitted the source, so on a large bundle the fact budget, not the node
budget, is normally reached first; a region is the answer to either. The bounded
lexical preflight and Oxc parser use the same inert-source path as the existing
worker. Frontier records and diagnostics are bounded separately.

`preflight_nodes` is the shared admission bound in front of this operation, and
it is one tree-sitter node per two bytes of `max_source_bytes`. The grammar
cannot exceed two nodes per byte, so any source up to 1,048,576 bytes is
admitted whatever its shape; above that, admission depends on density, and real
minifier output measures about 1.09 nodes per byte. A dense bundle of roughly
1.9 MB is therefore the practical admission ceiling, and `max_source_bytes`
stays unreachable for the densest code. Admission is a function of the supplied
bytes alone: the traversal behind this bound is limited by node count and tree
depth, never by elapsed time, so the same artifact is admitted or refused
identically on a fast and a slow machine. Only the tree-sitter parse keeps a
wall-clock backstop, and it is sized so that it cannot refuse a source this
node bound admits.

`preflight_parse_heap_bytes` is the one admission bound enforced *during* the
parse rather than after it. The depth and node bounds read a finished tree, so
on their own a source they refuse is built and paid for first: a 4 MiB source of
nested sequence expressions reached 2,011.7 MiB of transient tree and was then
refused for its depth. This limit caps the bytes tree-sitter asks its allocator
for and stops the parse from inside the progress callback when the cap is
crossed, which held the same source to 441.2 MiB. It is 192 bytes of parser heap
per node `preflight_nodes` admits, measured against a densest admissible tree
that needs 136 and real minifier output that needs 118. Like the node bound it
is a function of the supplied bytes: allocation sizes and their order follow the
grammar and the source, so an optimized and an unoptimized worker report the
same verdict, the same diagnostic and the same peak. What it narrows is stated
rather than hidden: shapes that hold several parser stack versions at once cost
about 325 bytes of heap per node, so one larger than roughly 1.2 MB is now
refused here instead of admitted by node count, and a deeply nested source above
roughly 690 KB reports this limit rather than `preflight_depth`. A refusal is
reported as `coverage.status: "unavailable"` with the preflight diagnostic and no
facts; being admitted says nothing about coverage, and a bundle large enough to
need admission headroom normally still reaches a whole-program budget and needs
a region.

## Coverage and failures

Always inspect both `ok` and `coverage`, even after HTTP 200.

- `analyzed_range`: the original bytes these facts cover. It is the whole
  program unless a requested region resolved to one enclosing callable body, it
  always contains the requested region, and it is reported even when the budget
  produced no facts at all
- `complete`: complete within the declared lexical profile only; never a claim
  of complete JavaScript behavior or runtime/cross-artifact resolution
- `partial`: available facts coexist with explicitly unknown frontiers or a
  reached budget; `ok` remains true
- `unavailable`: the source could not be safely parsed/analyzed; `ok` is false
  and all fact arrays are empty

`coverage.truncated` identifies budget loss. Region scoping is a narrower
question, not budget loss, so it never sets `truncated`; it is reported as
`partial` status, a narrower `analyzed_range`, a diagnostic, and
`outside-analyzed-region` frontiers over the skipped prefix and suffix.
`coverage.diagnostics` contains bounded messages, and `coverage.frontiers`
contains `{range,reason}` records. Declaration-table exhaustion returns empty
facts and partial/truncated coverage, rather than incorrectly resolving
references against an incomplete scope table. A reached budget also names the
narrower request that can still produce facts, and still reports the range it
attempted. Unknown or unsupported effects remain frontiers; their absence from
supported facts must not be interpreted as proof that an effect cannot occur.

A scoped report keeps resolutions honest by refusing them. Only scopes whose
syntax was analyzed in full own a closed declaration table. The selected
callable body and everything nested inside it qualify, so its parameters,
locals and closures resolve exactly. Every enclosing scope owns syntax this
report skipped, so a name that leaves the selected body is `unresolved` with
resolution `outside-analyzed-region` instead of a candidate set that a skipped
sibling could have changed. That reason deliberately does not distinguish a
declaration in the skipped part of the file from a genuine global: unscoped
analysis separates those as `external-or-implicit`, and a region trades that
distinction away. Local order values rank the facts a report emitted; under a
region they do not imply a position among siblings it never analyzed.

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
Under a region, a skipped `with` or direct `eval` cannot silently weaken a
resolution either: it could only add bindings to a scope the report already
declared open, and such scopes never resolve a name.
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

Sources **Facts** is an explicit consumer of this exact contract. It requests
the whole artifact and never a region, so its coverage line is never a scoped
claim. It accepts only
the selected captured JavaScript identity, pages at most 100 facts, labels
unknown/truncated coverage, and navigates half-open UTF-8 ranges only after
verifying the complete original bytes through the existing artifact chunk API.
The Bindings explorer joins only admitted top-level operation targets to local
binding IDs within the same report. Exact lexical bindings, ambiguous declaration
candidates, unresolved names and property targets remain distinct. Read/write/call
filters are projections of static operations, never runtime/dataflow claims or
occurrence counts. Successful reanalysis resets selected report-local IDs;
changing the view retires pending original-range navigation. This adds no wire
fields, backend operations, persisted index or execution.
The browser and native live workspace share the Rust HTTP adapter. The native
stored-evidence `reb://` scheme explicitly reports unavailable and disables the
action; it does not duplicate or weaken validation. See the
[Sources operating guide](../apps/research-ui/README.md#captured-javascript-facts).
