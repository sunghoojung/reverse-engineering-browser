# Lane ED, wave55 section-scoped `inspect_wasm`

**API, provider and contract change landed; no browser attestation.**
`inspect_wasm` (`GET /api/wasm`) now accepts an optional `sections` filter, and
the function section now produces its own rows. Together those make the
export-to-type chain and the tables the binary format places after the code
section reachable inside the unchanged 8,192-row budget. `coverage` declares
what each document covers, and a filtered document is never `decoded`.

The repository gate proves the mechanism through the loopback HTTP route, the
response contract, and the packaged CLI provider. No Brave toolchain exists on
this machine, so nothing here is attested inside a running browser or against
live capture.

## What was unreachable

Lane DV measured `inspect_wasm` against an OT-witnessed module and found 7,856
of 8,192 rows spent on code-section instructions for roughly 25 of about 1,200
functions. Two separate things were unreachable, and they need different fixes.

**The func-to-type mapping was never a row.** The function section (ID 3) holds
one type index per defined function. The old provider read it into
`function_types` and emitted nothing, so the only place a function's declared
type appeared was the `function` header row inside the code section. With ~25
of ~1,200 bodies decoded, an export naming function 900 had no reachable type,
regardless of how the budget was spent.

**Sections after the code section were unreachable at any budget.** The format
orders data (ID 11) and trailing custom sections after code (ID 10). Once
instruction rows exhaust the budget mid-code, traversal stops, so an unfiltered
document can never name a data segment or the `name` custom section of a large
module. Raising `max_rows` moves that line but does not remove it, and it makes
every response larger for every caller.

So the fix is two parts: a `declaration` row makes the static mapping a fact in
its own right, and the filter decides where the budget is spent.

## The request shape

`sections` is one comma separated value of section names, the same names section
rows already print: `custom`, `type`, `import`, `function`, `table`, `memory`,
`global`, `export`, `start`, `element`, `code`, `data`, `data_count`, `tag`.
The vocabulary and the row labels are the same array in the provider, so a label
and the filter that selects it cannot drift apart.

A scalar comma separated string rather than a repeated parameter, because the
`reb-api mcp` projection sends each tool argument as a single string, number or
boolean. An array parameter could not be called through the only MCP surface
this repository has.

Measured on the test fixture: 40 declared functions, 251 instructions per body,
with data and trailing custom sections present.

| Request | Rows | Instructions | Reaches |
| --- | --- | --- | --- |
| whole module | 8,192 | 8,110 | type, import, function, export; code truncated at body 33 |
| `type,import,function,export` | 51 | 0 | the full export-to-type chain |
| `data,custom` | 9 | 0 | the segments and the custom section |

Every row of that table is `partial`. The second one is the point:
`"last" - Func 40` resolves through `func 40 declares type 1` to
`type 1: () -> (i32)` in 51 rows, with no function body decoded.

The unfiltered run also reports `defined_functions: 33` against the filtered
runs' `40`, because an unfiltered traversal stops inside the code section while a
request that excludes `code` still walks the section's framing to its end. The
count has always meant "bodies this traversal enumerated"; excluding the section
makes it more accurate, not less.

## How coverage stays honest

A request narrows which sections produce rows. It never narrows the traversal.
Section framing, the imported-function count, the function declarations behind
every function index, and the function/code count agreement check all run
exactly as they do unfiltered, so a filtered document's function indexes and
counts mean the same thing they always did. Section rows are kept for every
section, including excluded ones, so a filtered document still names the bytes
it did not decode.

`coverage` then carries four claims, all recorded while walking the bytes rather
than derived from the request:

- `requested_sections` is the scope the response used, or `null` for the whole
  module. This is the field a caller checks against the filter it sent. A route
  that ignores `sections` answers `null`, which cannot be mistaken for a
  filtered answer.
- `analyzed_sections` is present, requested and decoded to the end.
- `excluded_sections` is present but not selected. Its contents were never read.
- `truncated_sections` is requested and present but not completely covered.
  Every traversal limit funnels through one `Rows::stop`, so a section that was
  stopped is removed from `analyzed_sections` instead of being reported twice.
- `section_map_complete` says whether traversal reached the module end. Only
  then do the three lists name every section in the bytes, so only then does a
  requested section missing from all three mean the module does not have one.

Two further rules keep the status field from over-claiming:

- A filtered document always carries an omission naming the requested sections,
  which makes its status `partial` by construction, even when the filter
  happened to exclude nothing present in the bytes. Over-conservative, in the
  direction that cannot mislead.
- An excluded section is never read, so its entries and function bodies are
  never validated. A filtered `200` is not evidence that those bytes are well
  formed. A malformed body that an unfiltered request reports as `422` is simply
  not looked at when `code` is excluded. `excluded_sections` is the only honest
  statement available about it, and the OpenAPI notes say so.

`defined_functions` still counts the code-section bodies the traversal
enumerated from the section's own framing, which stays accurate when bodies are
not decoded. `instructions` counts decoded instructions only, so an excluded
code section reports zero rather than claiming none exist.

## What an excluded section still costs

A request narrows rows, not traversal, so an excluded section is still walked.
Two walks are not row-budget gated, and both stay bounded:

- Imports are always counted, because a defined function's index continues the
  imported range. A 1.9 MB module of 480,000 minimal function imports with
  `sections=export` returns in 0.44 s in a debug build, including process
  start, manifest read and the SHA-256 of the whole blob. The same module
  unfiltered returns in 0.16 s but truncates at 8,190 imports and reports
  `imported_functions: 8190`; the filtered answer reads further and reports
  480,000. Reading more of the module while emitting fewer rows is the trade.
- Code bodies are enumerated from the section's framing. That count cannot
  exceed `MAX_ROWS`, because a module declaring more functions than that stops
  at the declaration limit before the code section is reached.

## Default-path effect

`declaration` rows are emitted whenever the function section is in scope, which
includes every unfiltered request. For a module with N defined functions that
moves N rows out of the instruction budget. On the DV-shaped module that is
about 1,200 of 8,192 rows, taking instruction coverage from roughly 25 bodies to
roughly 21 while making all ~1,200 func-to-type pairs reachable. Emitting the
rows only under an explicit filter was rejected: the same section request must
produce the same rows whether or not other sections were also asked for.

## Not done here

- The native `reb://app/api/wasm` route ignores unknown query parameters, so it
  answers for the whole module when sent `sections`. It is detectable, because
  `coverage.requested_sections` comes back `null`, and the protocol document
  says to compare it. Making that route reject the parameter is a Swift change
  and pulls in the packaged-app gate, which has no Xcode on this machine.
- The Origin Trace UI still requests whole-module inspection on both the browser
  and native paths. It renders `status` and `omissions`, so a filtered document
  would display as partial with its requested sections named, but it does not
  send `sections` and `isWasmInspection` does not yet check `coverage`.
- Per-function scoping is still missing. `sections=code` restores the original
  problem, because instruction rows for 1,200 bodies cannot fit any budget.
  A function-index request is the next step for reading one body's instructions
  out of a large module; `declaration` rows make choosing which body to ask for
  possible without it.
- Request-body retention is untouched. DV #3 is a parent and policy question.
