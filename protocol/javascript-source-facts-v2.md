# JavaScript source facts v2

`GET /api/source-facts?session_id=SESSION&artifact_id=ARTIFACT` analyzes one
whole captured JavaScript artifact of any size with the existing Rust/Oxc
worker and returns `schema: reb-javascript-source-facts-v2`: the report's
coverage and the number of rows in each table. `GET /api/source-facts/rows`
reads those rows one page at a time, with optional filters. The OpenAPI
operations are `get_source_facts` and `list_source_fact_rows`, available
through the existing generic CLI:

```sh
reb-api describe get_source_facts
reb-api call get_source_facts --endpoint-file /tmp/reb-api-endpoint \
  --param session_id=1 --param artifact_id=2
reb-api call list_source_fact_rows --endpoint-file /tmp/reb-api-endpoint \
  --param session_id=1 --param artifact_id=2 --param table=bindings \
  --param name=decode
reb-api call get_source_facts --endpoint-file /tmp/reb-api-endpoint \
  --param session_id=1 --param artifact_id=2 \
  --param region_start_byte=1048576 --param region_end_byte=1048576
```

v2 removes every size and budget bound of v1. v1 refused sources over 4 MiB,
stopped at 262,144 AST nodes, 16,384 facts, 256 frontiers and 64 binding
candidates, refused dense or deep sources in a tree-sitter preflight, and gave
the worker five seconds and 32 MiB of output. A real 6 to 9 MB bundle hit
those bounds at once. v2 analyzes the whole artifact, reports every fact, and
has no deadline. Because a whole report of a large bundle holds about a
million rows, it is no longer one response: the summary says how many rows
each table holds, and the rows route pages through them. `limits` and
`coverage.truncated` are gone, and so is the `binding-candidate-limit` reason.

## Request

Both canonical unsigned decimal identifiers are required. The manifest must
select exactly one artifact, and its stored session must match. Artifact IDs
are globally unique under the current storage contract; duplicate IDs make the
manifest invalid. The artifact contract does not carry a process ID, so this
API neither accepts nor invents one. Live script IDs, URLs, displayed text,
pretty-printed or derived representations, and extra parameters are rejected.
There is no fallback source selection.

`region_start_byte` and `region_end_byte` are the only optional analysis
parameters and the only way to narrow analysis. They are canonical unsigned
decimals, must appear together, and must form a half-open range of original
UTF-8 bytes inside the verified source at Unicode scalar boundaries; equal
offsets address one cursor. A half pair, a reversed range, an offset past the
verified byte size and an offset inside a multi-byte scalar are all rejected.
The range selects no bytes by itself. The analysis unit is the innermost
callable body containing it, resolved inside the parse of the complete source,
because a byte slice has no meaning on its own: its scope chain, strictness and
syntactic position come from the bytes around it. A range no callable body
contains analyzes the whole program rather than a fragment of one. A region is
a narrower question, never a way around a limit.

Only immutable captured artifacts with `kind: javascript` are accepted. The
entire blob must pass the existing content size and SHA-256 checks before strict
UTF-8 decoding and analysis; prefixes and replacement characters are never
substituted. Empty JavaScript is valid input. The result's `source` is the
public artifact record, including session/artifact, navigation/frame/execution
context, capture origin, exact SHA-256 and byte size. `source_bytes` must equal
that verified byte size. Original bytes are never modified. Facts are not
persisted or added to captured evidence.

## Rows

`list_source_fact_rows` takes the same `session_id`, `artifact_id` and optional
region, plus:

- `table`: `scopes`, `bindings`, `callables`, `regions`, `operations` or
  `frontiers`
- `offset` (default 0) and `limit` (1 to 1,000, default 100) select the page;
  `total` counts every row the filter selects, not only the page
- `binding_id` and `kind` filter operations: those whose admitted lexical
  target names that binding, exact or as one of several duplicate-declaration
  candidates, and those of one operation kind
- `name` and `candidates_of` filter bindings: names containing the text,
  ignoring case, and the declarations one ambiguous operation names

A filter on the wrong table, a `binding_id` past the binding table and a
`candidates_of` that is not an ambiguous operation are 400. The response,
`schema: reb-javascript-source-fact-rows-v2`, echoes `table`, `offset` and
`filter`, carries the `source` identity and `analyzed_range`, and lists
`rows`. A page of operations also carries `bindings`: the declaration each
exact target names, and the filter's own binding, so a page is readable
without reading the binding table first.

## Worker boundary and admission

The request is one JSON line: `{"operation":"source_facts","source":"..."}`,
carrying an optional `"region":{"start":N,"end":M}` with exactly the requested
offsets. The worker re-admits that range against the source it was given. It
uses the existing worker executable, process queue and process-group cleanup.
The adapter clears the worker environment and caps stderr at 64 KiB. Stdout is
read in full, with no deadline. No JavaScript is executed. No model, network,
browser-control or new parser path participates.

The worker writes its report with every row as compact JSON, straight to its
output. The adapter admits it row by row against borrowed text, so it never
builds a second tree of the whole report: each row is checked against its
OpenAPI component, then recorded as a byte span of the worker's own text with
the indexes the filters need. A 9 MB bundle produced 1.1 million rows (218 MB
of JSON) and was admitted in 1.6 s at a 627 MB peak.

Admission checks the schema, source length, that every ID is its row's
position, references, acyclic parent-before-child ownership, source
containment and unique local order slots. It also checks the declared coverage
against the request it made: an unscoped request must report the whole source
as analyzed, a scoped one must report a range containing what was asked, and a
range narrower than the source can never carry `complete` status. Operation
kinds, targets, receivers and details have closed schemas; unknown worker
shapes are rejected rather than forwarded.

IDs are independent unsigned integer namespaces per table, local to these exact
source bytes and region. The same bytes always produce the same IDs, so a page
read after the report was rebuilt still matches. They must never be joined
across different source identities.

- `profile: lexical-effects-v1`, `offset_unit: utf-8-byte`
- `scopes`: `id`, nullable `parent_id`, `range`, `kind`
- `bindings`: `id`, `scope_id`, `name`, declaration `range`, `kind`
- `callables`: `id`, `scope_id`, `range`, `body_range`, `kind`, `async`, `generator`
- `regions`: `id`, nullable `parent_id` and `callable_id`, `range`, `kind`,
  `entry_order`
- `operations`: `id`, `region_id`, `order`, `range`, `kind`, heterogeneous
  `detail` with lexical reference targets and effect evidence
- `frontiers`: `range`, `reason`

All ranges are half-open `{start,end}` offsets into original UTF-8 bytes,
including detail fields ending in `_range`. Neither UTF-16 indices nor rewritten
text offsets are accepted. A target with `kind: binding` names local
`binding_ids`; unresolved and ambiguous targets are explicit. Property targets
carry object/key ranges and computed-key information rather than asserting a
runtime object identity. These records describe lexical structure and effects,
not a control-flow proof, executed trace, or value-flow graph. A `callable-body`
region is deferred until its callable executes. `entry_order` and operation
`order` describe structural local order conditional on region entry and normal
completion. They never form a global execution trace or CFG and do not flatten
conditional arms, short-circuit operands or repeated loop work into
unconditional execution. Every call target remains unknown, even when its
callee identifier resolves to a lexical binding. Binding resolution is neither
a reaching-definition proof nor proof that temporal-dead-zone checks succeed.
Optional chains, try/finally, classes and complex iteration remain omitted with
explicit frontiers rather than invented effects.

## Cost, cancellation and caching

- The worker's parser stack is sized from the source's lexical nesting before
  it parses, so deep nesting is analyzed instead of overflowing a fixed stack
  or being refused.
- Memory grows with the report. Measured peaks: 627 MB for a 9.3 MB bundle and
  its 1.1 million rows; the worker itself holds the Oxc tree and its rows.
- Analyses and deobfuscation share one worker queue and run in arrival order.
  There is no deadline: an analysis runs until it finishes or its request goes
  away. A request that goes away stops its queued wait, kills its worker
  process group, or stops admission at the next batch of rows, and answers 499
  if it is still listening.
- Admitted reports are kept in memory by source SHA-256 and region: at most 4,
  within a sixteenth of the machine's memory ceiling, always keeping the newest
  whatever its size. A summary or page whose report was evicted rebuilds it,
  which yields identical rows. Every request still reads and verifies the whole
  blob, so a changed artifact is never answered from the cache. `cached` says
  whether the summary reused a report.

## Coverage and failures

Always inspect both `ok` and `coverage`, even after HTTP 200.

- `analyzed_range`: the original bytes these facts cover. It is the whole
  program unless a requested region resolved to one enclosing callable body, and
  it always contains the requested region
- `complete`: complete within the declared lexical profile only; never a claim
  of complete JavaScript behavior or runtime/cross-artifact resolution
- `partial`: available facts coexist with explicitly unknown frontiers; `ok`
  remains true
- `unavailable`: the source could not be parsed; `ok` is false and every table
  but `frontiers` is empty

Region scoping is reported as `partial` status, a narrower `analyzed_range`, a
diagnostic, and `outside-analyzed-region` frontiers over the skipped prefix and
suffix. `coverage.diagnostics` contains worker messages, and the `frontiers`
table contains `{range,reason}` records. Unknown or unsupported effects remain
frontiers; their absence from supported facts must not be interpreted as proof
that an effect cannot occur.

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

Invalid or duplicate parameters, a non-JavaScript artifact or invalid UTF-8
return 400. Missing artifacts or session mismatch return 404. A request that
went away returns 499. Abnormal worker exit or malformed response returns 502,
and an unavailable executable returns 503. Corrupt content, ambiguous manifests
or local I/O errors return 500. These errors never trigger automatic retries or
analysis of a different source.

## Supported profile and next boundaries

Simple lexical declarations and parameters, closures, lexical shadowing,
forward `var` references and named functions retain distinct source identities.
Duplicate declarations are ambiguity sets rather than a guessed winner, and
every declaration of the name stays a candidate. Implicit `arguments`, external
names, direct-eval/with environments, non-simple parameter environments and
block-function ambiguity remain explicit unknowns. Under a region, a skipped
`with` or direct `eval` cannot silently weaken a resolution either: it could
only add bindings to a scope the report already declared open, and such scopes
never resolve a name. The parser admits syntax; this profile is not a complete
ECMAScript early error or environment-instantiation validator. Lexical identity
never proves a value is initialized, an access will succeed, or a called binding
still holds the originally declared function.

Supported expression facts distinguish reference formation from value reads
and writes, computed object/key/RHS order, eager left-to-right argument regions,
method versus detached receivers, compound and logical assignments, and prefix
new versus postfix old expression results. Update writes explicitly store the
new value in either case. Super references remain unsupported rather than
being mislabeled as ordinary method receivers. Conditional arms and loop
test/body/update regions remain nested. Implicit getters, proxies, coercions,
spread iteration, unknown calls and abrupt completion have named frontiers.
Optional chains, try/catch/finally, switch selection/fallthrough, classes,
destructuring effects, and async/generator execution are deliberately not
flattened into eager facts. Original literal/template ranges retain all bytes
for subsequent inspection.

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
claim. It accepts only the selected captured JavaScript identity, shows elapsed
time while the analysis runs with a Cancel that stops it, and reads 100 rows at
a time. Unknown coverage stays labeled, and half-open UTF-8 ranges are navigated
only after verifying the complete original bytes through the existing artifact
chunk API. The Bindings explorer asks the rows route for the operations whose
admitted target names a binding, for declarations by name, and for one
operation's candidates; it never joins names itself. Exact lexical bindings,
ambiguous declaration candidates, unresolved names and property targets remain
distinct. Read/write/call filters are projections of static operations, never
runtime/dataflow claims or occurrence counts. Successful reanalysis resets
selected report-local IDs; changing the view retires pending original-range
navigation and the older page read. The browser and native live workspace share
the Rust HTTP adapter. The native stored-evidence `reb://` scheme explicitly
reports unavailable and disables the action; it does not duplicate or weaken
validation. See the
[Sources operating guide](../apps/research-ui/README.md#captured-javascript-facts).
