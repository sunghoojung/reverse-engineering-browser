# Investigation notebook v1

The notebook stores researcher-authored names and notes beside exact retained
references. It is not an evidence package, capture archive, authenticated finding,
replay recipe, or restored runtime session. Original evidence remains owned by
its existing store and readers. See [SAFETY.md](../SAFETY.md).

## Persistence and scope

**Notebook** in the application toolbar opens an explicit local library view.
**Create notebook** saves a new ordinary Local Analyst file with
`kind: scratchpad`, `language: json` and a `.reb-notebook.json` suffix in the
Analyst root folder. Existing scripts, scratchpads and folders are preserved.
The existing runner accepts only `analyst-script` files: a notebook cannot run.
Saved notebooks remain visible and editable as JSON in Analyst.

This is the existing permission-restricted, atomic, generation-checked Analyst
library, not browser localStorage. It is library-wide and can contain research
from several sessions/profiles. The dialog discloses this scope before saving.
Opening it does not select a profile or make a reference valid for a live page.
The [shared writer lease](workspace-writer-lease-v1.md) serializes native Swift and
Rust process replacements. A stale library generation rejects replacement; no automatic conflict merge,
retry, profile switch, capture change, or permission restoration occurs.

The notebook controller owns a separate loaded library generation. It never
installs asynchronous results into the Analyst editor or changes its drafts.
An Analyst save based on an older generation conflicts rather than overwriting
new notebook data. A changed/deleted file under the same numeric ID is likewise
protected by the generation and selected file owner. Cancellation retires UI
ownership, not a committed disk write: a cancelled, timed-out, refused or malformed
POST leaves its outcome unconfirmed and prevents another write until a successful
explicit reload. Draft notes remain visible. No action executes saved code.

## Closed document

A notebook contains exactly:

- `document_kind: "reb-investigation-notebook"`
- `contract_version: 1`
- `scope: "local-analyst-library"`
- `next_pin_id`: positive safe integer, greater than every retained pin ID
- `pins`: at most 64 entries

Each pin has exactly `id`, `name`, `note`, and `reference`. IDs are unique positive
safe integers. Names are nonempty, trimmed text of at most 80 UTF-8 bytes; names
can repeat, because they are labels rather than identities. Notes contain at most
2,048 UTF-8 bytes and are explicitly marked as researcher interpretation. Control
characters other than tab, newline and carriage return, invalid Unicode and
unknown document fields are rejected. JSON input rejects duplicate object members,
including escaped duplicates. Parsing bounds are 16 levels and 25,000 values.
The serialized document is at most 32 KiB. The shared library retains its existing
64-file, 512-KiB content and 1-MiB envelope limits.

A malformed or unsupported notebook is still an inert scratchpad. This view does
not overwrite or repair it. Ordinary JSON files are not adopted by filename alone;
a suffix only makes a malformed notebook discoverable with an explicit warning.
Deletion is an explicit two-step action and removes only the selected notebook
scratchpad or selected pin. It never deletes captured evidence.

## References and verification

Captured artifacts have exactly `type: "captured-artifact"`, `session`,
`artifact`, `sha256`, `bytes` and `range`. Session/artifact identifiers are nonzero
canonical decimal u64 strings. SHA-256 is 64 lowercase hex characters and original
byte size is a nonnegative safe integer. Range is null or exactly `{start,end}`:
a nonempty half-open original UTF-8 byte interval within the original size.
Only ranges already revealed through the verified JavaScript Facts reader can be
created by the UI. Pin opening uses the same guarded Sources adapter and the
existing original-byte verification. It never treats pretty/derived offsets as
original offsets. Artifacts whose ID is reused across sessions remain ambiguous
because the current Sources selector is artifact-ID based. Uniqueness checks
cover the admitted artifact window, including entries beyond the first 500.

Native events have exactly `type: "captured-event"`, `session`, `process`,
`sequence` and `fingerprint`. Session/sequence are nonzero canonical decimal u64
strings; process is a nonzero decimal u32 string. Only existing admitted protocol
2/3 non-gap observations can be pinned. The full event's supported fields must
be present with their existing types; unknown extension keys are rejected rather
than ignored. Fingerprints include the original payload, flags, outcome, timing,
context, relationship and other admitted fields, but persist only the digest.

The fingerprint is SHA-256 of UTF-8 bytes of the domain
`REB\0notebook-event\0v1\0` followed by compact `JSON.stringify` of the full
supported event object with keys sorted lexicographically. All supported fields
are scalar strings, safe integers or booleans under the existing event validator.
Optional context fields remain optional and their absence affects the digest;
no values or strings are normalized. The canonical event is bounded to 4 KiB.
This profile is not the evidence-package semantic identity profile and makes no
authenticity or complete-capture claim.

Duplicate scoped event IDs fail before digest matching, even if one duplicate
has matching bytes. Replacements during SHA-256 work, between the promise result
and its receiver, and before navigation are rechecked against the same complete
canonical record. Verification tokens are ephemeral. The notebook stores no event
payload, URL, request header/body, source text, console output, result, cookie,
credential, profile, capture setting or permission. Default names contain only
artifact/event IDs. User-entered names and notes may themselves contain private
information; nothing is exported or uploaded automatically.

The reader resolves only currently retained, exact identities. Missing, changed,
ambiguous and unsupported references stay visible and never substitute a URL,
filename, neighbor, new session or live request. Reopening an event preserves the
current Evidence filters and shows out-of-filter detail explicitly. A saved event
has no saved request association: displayed request relationships refer to the
current retained context and retain their existing correlation limitations.
No full-store discovery, website refetch, analysis or runtime action is added.

## Transport and UI ownership

GET and POST reuse `/api/local-analyst` and `/api/local-analyst/actions`. Responses
are bounded to 1 MiB and 65,536 transport chunks with the existing cancellation-
aware reader. The ten-second deadline includes fetch, body reads and validation.
Cancellation does not wait for a stalled producer cleanup. Save receipts must
match the submitted generation, complete file projections and folder metadata;
object-key ordering is not semantic identity. A late result cannot replace a
newer operation or steal its focus. Escape closes the modal, keeps unsaved notes
in its owner, and does not reach Sources/debugger/Console shortcuts. Explicit
Cancel edits discards only the current local editor draft.

## Acceptance

`checkNotebookCore` in `tools/check-investigation-notebook.mjs` runs through the
existing `make lint` JavaScript gate. It covers closed schemas, exact limits,
full-event fingerprints, cross-session ambiguity, asynchronous replacement,
non-executable files, unrelated library preservation, quotas, corrupt data,
receipt identity, deadlines and cancellation uncertainty.

The existing `--investigation-ui-browser` mode additionally runs real pointer,
keyboard and reload workflows through the complete product host, with a clearly
synthetic bounded HTTP library. It checks wide/760/360 layouts, original-range
reopen, event/source replacement, eviction, duplicate labels/IDs, interrupted
storage, draft retention and modal shortcut isolation. It records screenshots and
structured notebook receipts under the existing investigation UI artifact. This
fixture does not establish Rust disk persistence or native WebKit acceptance.
The unchanged actual library store has separate Rust/HTTP persistence tests.
`node tools/check-investigation-notebook.mjs --persistence /path/to/origin-trace-backend`
exercises the actual local route, user-only file permissions, process restart and
stale-generation refusal using a temporary synthetic library.
New JS assets are included in Rust serving, native scheme routing and package
copy lists; macOS app-build/signing/runtime acceptance remains a separate gate.
