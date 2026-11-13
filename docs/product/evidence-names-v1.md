# Evidence names v1

Researcher names label retained evidence with the researcher's own
interpretation, the way a disassembler lets you rename `handler 0` to
`push_const`. A name is not evidence. It never replaces, hides or edits a
captured value: Origin Trace shows it beside the raw identifier, which stays
visible. Names are not an evidence package, finding, replay recipe or capture
setting. See [SAFETY.md](../../SAFETY.md).

## Scope

Four kinds of retained item can be named:

- a retained Traffic request;
- a captured source artifact shown in Sources;
- a VM handler row of one finding's opcode workspace (handler listing, Symbol
  Tree and Selected handler);
- a WebAssembly function, keyed by its module's SHA-256 and function index, so
  the name follows identical module bytes across sessions (contract:
  [Wasm function names v1](../../protocol/wasm-function-names-v1.md)).

## Persistence

Names live in one ordinary Local Analyst file in the Analyst root folder:
`Evidence names.reb-names.json`, `kind: scratchpad`, `language: json`. This is
the same permission-restricted, atomic, generation-checked library the
[investigation notebook](../../protocol/investigation-notebook-v1.md) uses, read and written
through the existing `GET /api/local-analyst` and
`POST /api/local-analyst/actions` (`replace_local_analyst_workspace`) routes. No
backend route is added. Browser storage is not used, so names survive a relaunch
of the packaged app, whose web view keeps no website data. The file is created on
the first saved name and is visible and editable as JSON in Analyst. The runner
accepts only `analyst-script` files, so the names document cannot run.

The file is library-wide: it holds names for every session and profile that used
this library. A name for an identity absent from the current evidence is kept
but not shown.

## Closed document

A names document contains exactly:

- `document_kind: "reb-evidence-names"`
- `contract_version: 1` or `2`
- `scope: "local-analyst-library"`
- `requests`: request entries
- `artifacts`: artifact entries
- `vm_programs`: at most 64 program groups
- `wasm_modules` (version 2 only): at most 64 module groups

Version 1 has exactly the first six members and stays readable. Writers keep
writing version 1 while no Wasm function name exists and write version 2, with
`wasm_modules`, once one does.

Every entry carries exactly its identity fields (below) and a `name`. Unknown
members, duplicate object members (including escaped duplicates), duplicate
identities and duplicate program groups are rejected. A program group has a
nonempty `handlers` array; clearing its last name removes the group.

## Identities

Identity is exact and never derived from a label, URL, file name or handler
label. Each kind reuses the fields the investigation navigation and notebook
already use. Session, artifact, sequence and request identifiers are nonzero
canonical decimal u64 strings; the process identifier is a nonzero decimal u32
string.

- **Request**: `origin`, `session`, `process`, `sequence`, `request`. The
  session, process and sequence are those of the request's root event (the
  browser `request_started`, else the renderer `request_initiated`, else any
  event with a nonzero request ID) and `request` is its request ID: the
  investigation navigation's `captured-request` identity. `origin` is `live` or
  `demo`. Requests carry no content hash, so the origin keeps a deterministic
  demo identifier from naming a live request that happens to share its numbers.
- **Artifact**: `session`, `artifact`, `sha256` (64 lowercase hex characters) and
  `bytes` (the original byte size): the notebook's `captured-artifact` identity.
  Other bytes under the same URL or file name are a different artifact.
- **VM handler**: a program group holds `finding` (the opcode workspace's
  24-hex-character finding ID) and the source artifact identity (`session`,
  `artifact`, `sha256`, `bytes`); each handler entry holds `handler` (the
  listing key: `opcode:handler_index:source_offset`, or `span:offset:size` for a
  shared dispatch row) and `start`/`end`, the handler's half-open source byte
  range. The source artifact must be the workspace's interpreter artifact, with
  the workspace's SHA-256, and its artifact ID must be unique in the catalog.
- **Wasm function**: a module group holds `sha256` (64 lowercase hex
  characters); each function entry holds `function`, the index in the module's
  full index space, imports included. Every artifact with those bytes shares
  the name by design, so no uniqueness rule applies.

A name is shown, and an item can be renamed, only when exactly one retained
record has its identity. Requests also need a unique Traffic row ID and artifacts
a unique artifact ID, because those views select by that key. Missing, changed
and ambiguous items show no name; nothing is substituted.

## Bounds and validation

- A name is plain single-line text of 1 to 80 characters (Unicode code points)
  with no surrounding whitespace. Control characters (C0, DEL and C1), zero-width
  and invisible format characters, bidirectional marks, overrides and isolates,
  line and paragraph separators, the byte-order mark and unpaired surrogates are
  refused. Names sit beside raw identifiers and must not reorder or mimic them;
  the UI also renders them bidi-isolated.
- The input is trimmed. An empty result clears the name.
- At most 500 names per document.
- The compact serialized document is at most 32 KiB (32,768 UTF-8 bytes), the
  Analyst per-file limit. Request and artifact entries spend most of that on
  identity, so with live identifiers and short names the byte bound is reached
  first, at roughly 240 request names or 180 artifact names. Handler names share
  their program's identity and reach the count bound at about 480 to 500. Mixed
  documents fall in between. Parsing is bounded to 16 levels and 25,000 values.
- The shared library keeps its 64-file and 512-KiB content limits.

Every refusal is explicit and happens before a write; nothing is truncated or
dropped. A malformed or unsupported names file, or more than one candidate (a
`.reb-names.json` suffix or valid names content), shows no names and is never
overwritten or repaired. Ordinary JSON files are not adopted by file name alone.

## Concurrency

Every save starts from a fresh read of the library and replaces exactly one
generation; the shared [writer lease](../../protocol/workspace-writer-lease-v1.md) and the
generation check refuse a stale replacement with HTTP 409. In addition, the
editor remembers the name it opened with. If the saved name for that identity
changed in the meantime, nothing is written: the editor shows the newer name and
the researcher confirms again or cancels. Other names and other Analyst files in
the newer generation are preserved.

A refused, cancelled, timed-out or malformed write is never retried
automatically. Its outcome stays unconfirmed until the next save rereads the
library; if that read shows the name already committed, nothing is written again.
Save receipts must match the submitted generation, files and folder metadata, as
for the notebook. The names reader owns its own loaded generation and does not
change Analyst editor drafts. When the Analyst editor admits a newer library
generation, names follow it without another request.

## What is never stored

The document stores identity fields and researcher-authored names only. It never
stores a URL, method, header, body, source text, byte range content, event
payload, console output, cookie, credential, profile, capture setting or
permission. Names themselves may contain private interpretation; they stay local
and are never uploaded. Wasm function names are the one kind that reaches an
agent: the Wasm reads join them as `analyst_name` at every `reb-api mcp`
permission level, so an agent the researcher connects sends them to its model
provider. Request, source and handler names are not joined into any read.

## Interface

Rename sits in the Traffic request header (pencil), the Sources toolbar and the
VM Selected handler pane. F2 renames the focused or selected request, source
(tree row or tab) or handler (listing or Symbol Tree row), except in text fields
and modal dialogs. The inline editor saves on Enter, cancels on Escape or when
focus leaves it, and clears on an empty name. Names appear as proportional
italic text in the researcher-name color: first in the Traffic row's name cell
and request header, in the Sources tree and file tab, and in the VM listing,
Symbol Tree and Selected handler. Traffic search and the handler filter match
names too. Names are always inserted as text.

Wasm functions are renamed from Sources Inspect (the pencil on a function,
import, declaration or start row), the Graph (**Rename** in its toolbar, and F2
on the graph or a highlighted row of the **Functions** list) and a Flow graph
Wasm card (**Rename** in Details, or F2 on the graph with the card selected).
F2 on a call row renames its callee. The name follows the decoded listing, the
Graph title, the function list (whose filter matches it), Flow cards and
Details, Initiator frames and cross-reference rows. `wasm_function_names.js`
owns these surfaces; Wasm names are not listed in the palette. The open UI
polls the library on its 2 s tick with the last ETag, which the backend
answers with 304 from one `stat` while nothing changed, so names an agent saves
appear without a reload. A save from Flow Details returns focus to the redrawn
Rename button or the canvas.

When the command palette is present, the module registers a `Names` provider
(`id: "evidence-names"`) through `globalThis.RebCommandPalette.addProvider`,
whether the palette loads before or after it; without a palette this is a no-op.
`RebEvidenceNames.paletteProvider()` hands the same provider to a palette that
prefers to pull it. Searching matches names and the raw detail. A result opens
the exact current item through the UI's own paths: live requests through the
investigation navigation, demo requests as a row click, sources by exact artifact
identity and handlers through their Symbol Tree entry. Absent or ambiguous items
are not listed.

## Acceptance

`node tools/check-evidence-names.mjs` runs in the `make lint` JavaScript gate.
It runs the shipped module and the names section of `app.js` and covers identity
exactness (same label, other identity gets no name), demo/live separation, the
closed document and its exact bounds, discovery, the Analyst round trip,
preservation of unrelated files and names, per-name conflicts, stale-generation
refusal without retry, lost receipts, clearing, refusals before any write,
hostile names rendered as text, the editor's keyboard handling, F2 routing and the
palette provider. `make e2e` adds
`node tools/check-evidence-names.mjs --persistence <origin-trace-backend>`, which
saves through the real Rust route, checks the user-only file mode, restarts the
process, reloads the name and confirms stale-generation refusal.
