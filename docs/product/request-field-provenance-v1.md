# Request Field Provenance v1

A researcher can select one complete string in Traffic's request JSON tree or
Query view and choose **Trace value**. The field view connects original request
content, request call sites, bounded source search, and the existing disposable
Request Value Test. It does not implement JavaScript taint tracking.

## Evidence semantics

- The selected field and its replay observations are observed request content.
- CDP synchronous initiator frames are observed request execution context. They
  are not proof that a function produced the selected field.
- Source search finds literal text occurrences in original attached JavaScript,
  including comments and other non-executed text. Every occurrence is correlated,
  not a recovered producer or transformation.
- A primitive string hash equal to the selected replay string, in a retained
  same-target hook hit within the preceding five seconds, is a correlated runtime
  candidate. Full string hashes are computed only while selected-value capture
  is enabled. Accessors and object graphs are never evaluated for matching.
- The existing matched baseline and synchronous return-override comparison can
  report intervention-associated. Other inputs, randomness, time, and page state
  remain possible confounders; this is not complete value-flow proof.

Original requests and disposable replay observations remain separate. A matching
method, query-free path, value type, and exact selector connects the workflows;
it does not imply that the replay recreated every original input. Capture and
return replacement keep their existing explicit confirmations.

## Workflow

1. Select a live request in Traffic. Use the request viewer's **JSON tree** option
   or **Query** tab, select a string, and choose **Trace value**.
2. Inspect observed request call sites and optionally **Find sources**.
   Selecting a source row opens original source at its UTF-16 line and column.
3. Choose **Test value**. The request method, query-free URL,
   value type, and escaped JSON Pointer or exact query name are prefilled.
4. Create a disposable context and open the replay page if needed. Confirm the
   selected-value capture and repeat the request. No hook is required.
5. Add an observation-only synchronous return hook at a candidate function,
   collect a baseline, then disarm and replace it with a confirmed return
   override before repeating the same input. Compare retained observations.
6. **Field trace** returns to the field view with replay call sites,
   equal-string candidates, comparison, and named coverage gaps.
7. Stop and erase capture or dispose the context to erase replay observations.
   Original captured request evidence is unchanged.

For an encoded string, choose **Decode value** in Field trace, apply explicit
Decoder transformations, then choose **Find sources for result**. Search uses
the complete selected step's UTF-8 output, including whitespace and an initial
BOM, rather than its display preview. Field trace retains the original captured
string above the decoded search value and an expandable operation history with
input/output byte counts. **Use original value** returns to the original search.
**Test value** continues to select the original request field.

Decoded source matches are labeled **Decoded candidate**. The transformation
chain describes researcher actions, not transformations observed in the page.
Search accepts nonempty valid UTF-8 output of at most 4 KiB and preserves the
existing target, script, source-hash, eight-source, 2 MiB, and 32-match bounds.
Binary and oversized output cannot start source search. Editing the Decoder
input or its format, resetting the chain, or choosing a different request field
invalidates this handoff. Selecting an earlier completed step searches only the
chain prefix that produced it. Pending transforms cannot be handed off. The
chain and search projection remain ephemeral UI state and add no capture path,
storage, or wire contract.
Strings containing unpaired UTF-16 surrogates cannot start a Decoder handoff
because UTF-8 conversion would change the original string. Source search checks
the loaded source identity and excludes viewer-added truncation notices.

## Bounds and compatibility

Selections require a complete string of at most 4 KiB and a selector of at most
256 UTF-8 bytes. JSON Pointer tokens escape `~` and `/`. Duplicate query names,
truncated URLs or bodies, non-string leaves, unsafe JSON tree conversions, and
response values cannot start this workflow.

Source search prioritizes request call-site scripts, examines at most eight
attached JavaScript sources in the exact selected target, analyzes at most 2 MiB,
and retains at most 32 text occurrences. Unavailable or changed sources and
limits remain visible. Links require both target/script identity and the
retained source hash, preventing reuse of a script ID after navigation from
opening different code.
Live-function hook hits identify the executing frame's script in its exact
target, which may differ from the source selected when configuring the hook.
If that script is unavailable, its source link stays unavailable.

Replay retains the existing 16-observation, 256-byte preview, 128 KiB body,
4 KiB selected-value, two-extraction-worker, and private ephemeral limits. Each
observation adds at most 16 synchronous call sites and 32 matching hook candidates
with at most 34 bounded value labels per candidate. Candidate locations survive
hook eviction as evidence snapshots. Missing original hits and unloaded sources
remain visible; no guessed source link is created.

The optional `FieldProvenance` v1 observation extension is described in
[`protocol/openapi.json`](../../protocol/openapi.json). Existing field-test v2
responses remain readable when the extension is absent. General network capture
adds optional bounded `initiator` sites using the same source identity model.
Stored native evidence and renderer capture are unchanged. Provenance rules live
in `apps/origin-trace-backend/src/provenance.rs`.
The projection runs in-process in the Rust debugger, with no additional service,
worker protocol, or production Python code. Each asynchronous extraction retains
its request-time call sites and bounded hit snapshot. Session and capture revision
checks prevent late extraction results from restoring erased evidence.

The view uses compact source rows, concise evidence labels, and expandable
coverage and observation details. Hashes and correlation identifiers remain
available without crowding the primary flow.

Serialization, encoding, hashing, encryption, asynchronous continuations,
cross-frame/worker propagation, and WASM internals are explicitly unobserved.
The page preserves the last understandable evidence on refresh failure and
inserts all captured values and source labels as inert text.

Original literal rows also offer **Test this candidate**. The
[Candidate experiment v1 bridge](candidate-experiment-v1.md) carries the original
question into existing Runtime Hooks, uniquely rebinds complete source bytes in
an explicitly chosen disposable target, and adds an observation-only return
hook. Capture, arming and later return replacement remain explicit. Unsupported
syntax, changed/ambiguous sources and stale lifetimes fail visibly.
