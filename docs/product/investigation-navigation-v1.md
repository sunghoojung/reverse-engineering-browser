# Investigation navigation v1

## Ownership and safety

`apps/research-ui/investigation_navigation.js` owns one ephemeral Back/Forward
trail around the existing `showScreen`, `selectRequest`, `selectArtifact` and
Sources Facts byte-navigation handlers. It is not a URL router, data store or
analysis engine. There are no new backend operations, dependencies, persistent
capture/history storage, external-site fetches, automatic transforms, Run, Send,
probe enabling, target evaluation or browser navigation.

Existing controllers own form drafts, selected documents, captured bytes and
analysis results. Return history never clones drafts, captures, source text,
trace reports or DOM nodes. Zero scroll offsets are saved for known panes.
Dynamic rows use stable identity focus selectors; unsupported dynamic controls
fall back to a safe workspace control rather than an ordinal DOM position. It retains at most 24 stops total across Back and
Forward, with at most 32 scroll positions and one bounded focus selector per
stop. New navigation drops the Forward branch. Clear return history changes
only these ephemeral references. Reloading the application clears the trail.

## Exact reference types

- Captured event: session + process + sequence, lossless canonical identifiers.
- Captured request: captured event identity + native request ID.
- Captured artifact: session + artifact ID + SHA-256 + original byte size.
- Debugger request: retained UI ID + target + protocol request ID + start time.
- Original range: half-open UTF-8 byte offsets tied to the exact captured artifact.

A source or request link requires exactly one matching retained identity and
a unique ID in its existing UI selector. Actual selection handlers revalidate
the expected full identity before changing selection. A reused artifact
ID across sessions remains ambiguous because the existing Sources selector is
artifact-ID-based; this boundary refuses to guess. Source metadata and content
hash are not substituted with a filename or URL. Native trace responses must
match the selected request ID and exact root session/process/sequence. Ownership
is rechecked after fetch, including 304, and after reading the response body; a
broker refresh can replace a root without changing the visible request row ID.
Only one trace read owns a controller at a time. New reads, selection changes
and leaving Backtrace abort it. A ten-second deadline includes body reads; the
existing bounded stream reader limits the response to 1 MiB and 65,536 chunks.
Timeouts remain explicit and preserve only a still-matching prior report. Missing,
changed and ambiguous records leave the current workspace intact with a visible
explanation. A return does not reload a missing capture from a target website.

Debugger Requests can currently inherit native events through host, method and
time correlation in `requestsFromDebuggerNetwork` (`evidence_models.js`). That
is not an exact captured identity. `requestTraceRoot` excludes those projected
rows from native trace pivots; their own debugger identity remains usable for
returning to the retained Request. The existing Request signal correlation and
other analysis labels remain their original contracts.

## Working path and provenance

1. Select a captured request and open Evidence → Trace origin. The selected root
   is a captured request reference. Trace steps continue labeling recorded links,
   shared identifiers and missing predecessors independently.
2. Open retained source on a step with a source artifact. The relationship is the
   step's explicit artifact ID in the same session. It does not prove value flow.
3. Choose Facts and an Original bytes link. The existing Sources controller owns
   bounded chunk reads, SHA-256 verification, strict UTF-8/BOM decoding, range
   validation, cancellation and the original-byte display.
4. Decode range copies no more than 64 KiB of those verified bytes in Base64 input
   form. This preserves exact bytes including line endings and avoids textarea
   normalization. It does not execute a transformation. The Decoder evidence
   origin identifies session, artifact, SHA-256 and byte range. Input edits show
   a stale-origin label; Reset clears the handoff provenance.
5. Open original evidence returns through the same source identity/range boundary.
   Shared Back/Forward restores prior selected items, focus and pane position.
   A retained older request trace is reread through the existing read-only route
   before restoring its selected event. Gaps are matched by predecessor event,
   reason and diagnostic text, never their old row position. Missing selections
   remain explicit. Source byte rereads, when needed for returning to an original range, use only
   the verified local artifact route. Newer navigation retires delayed focus and
   cancels the existing Sources controller's pending result ownership. A newer
   same-workspace selection or pointer/keyboard/scroll interaction also retires
   delayed focus and byte navigation. Sources opens the exact destination before
   displaying its workspace, in original-only mode with no automatic derived
   analysis request. Explicit Deob still invokes the existing analyzer; ordinary
   Sources selection keeps its existing analysis behavior. Hidden workspaces do
   not start derived analysis.

Request inspector handoffs preserve UTF-8 of the selected displayed value, not
raw HTTP framing or JSON lexeme bytes. Field trace preserves its existing exact
string-byte snapshot (including textarea normalization handling). Both label raw
HTTP offsets unavailable. A handoff cannot overwrite a Decoder draft or active
operation without the existing operation finishing/cancelling and an explicit
replacement confirmation. Derived Decoder output is interpretation; the label
does not claim those transformations occurred in the target page.

Console uses a separate disposable browser. A location creates an inert search
panel of at most 20 retained exact-URL candidates, without switching or loading
Sources. Candidates explicitly remain unverified; choosing one opens its own
retained artifact identity and never applies the Console line offset. Console
activity links back to a retained transcript row only with matching Console
session, document and native evaluation request ID. Displayed command numbering
is separate. Missing scope reports expired output. Console activity, runtime-hook
request trails, native requests and saved Collection recipes remain distinct.

## Narrow integration boundary

- `investigationArtifactIdentity(source)` / `investigationRequestIdentity(request)`
  return a typed reference or null when the required evidence is unavailable.
- `openInvestigation({kind, identity, relation, inspectorTab?, range?})` accepts
  request, trace or artifact. Relation is explanatory text, never authority to
  invent a link. It resolves identity before calling existing safe UI handlers.
- `investigationBeforeScreen(name)` is the single shared `showScreen` hook.
- `rememberInvestigationRange(source, range)` runs only after the existing Facts
  controller has verified and revealed the original bytes.

Collection, Fingerprinting and Analyst controllers retain their own drafts and
selection models. Their exact-origin pivots should call this boundary rather
than build another history. Collection import retains the original
request identity before asynchronous refresh and recognizes a confirmed saved
recipe ID before opening the saved template. A newer selection or interaction
prevents a late copy from redirecting or stealing focus. Existing dirty drafts
are guarded by the Collection controller. Only a complete credential-free HTTP
URL and method can be copied; query and fragment are omitted. A
recipe or run is not the captured request. No capture data belongs in its saved
recipe document. Fingerprinting should pass the event's exact session/artifact
identity and preserve its own observed/correlated/unknown relationship label.

Evidence coverage, newer WASM control-flow ranges, Decoder verification and
structural VM candidates have separate reviewed feature contracts. This change
does not import those unmerged implementations or claim their new adapters.
Future integrations must preserve this identity/return boundary and use each
feature's original-byte validator, never reinterpret a pretty-printed offset.

## Verification

The existing `tools/check-origin-trace-debugger.mjs` driver runs the pure identity,
branching, bounds, fixture-admission and packaging checks from
`tools/check-investigation-navigation.mjs`. Its additive
`--investigation-ui-browser` mode uses the same real browser startup, hit-tested
pointer controls, keyboard dispatch, screenshots and failure-only diagnostics.

The original synthetic workflow covers request → trace → retained source →
verified UTF-8/BOM range → Decoder evidence → Back, selected identity and draft
preservation, keyboard Back/Forward, missing/ambiguous artifacts, foreign-session
trace rejection, interrupted delivery, unverified Console search and a stale
return after session change. It verifies that navigation made no action POST.
It also clicks Open original evidence, exercises native decline/confirm
replacement dialogs, and checks for derived-analysis requests, not just POSTs.
The fixture deliberately does not claim to validate native transformation
algorithms. The existing Decoder and Sources suites own their computational
contracts. Rendered QA and screenshot inspection on a supported host are required
before acceptance; passing pure checks is not rendered-browser evidence.

## Explicit remaining integration gaps

The supported identity-aware path in this version is captured Requests, native
Backtrace, captured Sources, verified original JavaScript ranges and Decoder
origin navigation. Collection copy has a verified source return, but generic return to Collection
keeps its current owner-managed draft and execution selection; it does not
restore historical recipe versions or run results. Generic return to Analyst,
Memory or Experiments is only a
workspace return; it does not claim historical run, heap snapshot, execution
context or result selection restoration. Those owner controllers keep drafts
and consent. Navigation does not execute or inherit consent for their actions.

Analyst run metadata is run ID + original script ID + library generation. A
selected request ID in an evidence summary is insufficient for an exact captured
event link. Artifact content_bytes is a snapshot preview length, not original
artifact byte_size. A future adapter must resolve session + artifact + hash
against a unique retained descriptor before validating original byte size. It
may not substitute the current request/source selection for the original run
snapshot.

Evidence selection/export can retain explicit native event keys while labeling
their relation to a debugger request as correlation. Exact selected keys do not
upgrade a host/method/time request association to causal evidence. An adapter
must carry that qualifier or show a retained-window context; it must not silently
select or discard records. This version does not yet implement that D12 adapter.
