# Candidate experiment bridge v1

## Research question and division of work

Can one literal candidate in original live JavaScript be observed again in a
new disposable context, and does its synchronous return match the selected
request string? **Test this candidate** carries that question into the existing
Runtime Hooks workspace. It does not create another panel or claim recovered
value flow. Native C++ CDP transport carries bounded source and debugger commands;
the Rust coordinator owns disposable-target identity, the existing Rust worker
resolves source structure, and the UI keeps original evidence separate from
replay observations. No new native probe is enabled.

Research motivation, not imported code or authority for causality:

- [Nero's browser debugging workflow](https://nerodesu017.github.io/posts/2023-07-29-debugging-scripts-in-the-browser)
  demonstrates a short inspect/change/retest cycle using CDP and a separate AST
  patcher. Here, retesting remains explicit and disposable; interception and
  source rewriting are not introduced.
- [Ghostwire](https://github.com/sofianeelhor/ghostwire) combines runtime
  instrumentation with CDP for web research. Its stealth positioning does not
  establish invisibility, complete coverage or semantic equivalence for REB.
- [Forking Chromium](https://yacinesellami.com/blog/forking-chromium/) illustrates
  the native build and maintenance cost. This increment joins reviewed layers
  rather than expanding the disabled native-probe surface.

The next possible increment is an explicit baseline/intervention/reversal
(A/B/A) plan with controlled inputs and auditable observations. This version has
no orchestrator, automatic browser actions, invisible instrumentation claim or
universal causality result.

## First-time path

1. In Traffic, select an original request JSON or query string → Trace value →
   Find sources → Test this candidate on a literal occurrence.
2. A compact question strip appears beside existing Runtime Hooks. A different
   value-test draft requires replacement confirmation. Hook form drafts remain
   untouched. Both Capture and Arm confirmation are cleared.
3. Explicitly Create isolated context and Open isolated page with a URL supplied
   by the researcher. Choose Page or a discovered dedicated Worker in the strip;
   there is no automatic target choice. Navigation resets this choice/consents.
4. Bind observation hook restores the original URL/method/kind/selector setup
   after disposable creation clears old form drafts. A different current draft
   requires the existing replacement confirmation; declining preserves it and
   sends no binding action. Capture and Arm consent remain unchecked.
   It explicitly reads sources and adds one observation-only
   return definition. It neither captures selected values nor installs breakpoints.
   A bound target is locked; remove its definition before binding another candidate.
5. Explicitly confirm Capture, then confirm Arm hooks, and repeat the owned-page
   action. A **Matched baseline** requires the exact field selector/method/path,
   target, bound hook, return hit and a full primitive-string digest match in the
   existing provenance projection. Timing alone is insufficient. This remains
   correlation, not an intervention or proof of production.
6. Return to original field returns to retained original evidence without target
   navigation or a request replay. Missing original live sources remain visibly
   unavailable. Clear question releases the UI owner, not hooks/capture; use the
   existing Disarm, Stop and erase, and Dispose controls for those operations.

## Exact source boundary

The one ephemeral UI owner retains complete original live source text (at most
2 MiB), the original field reference and candidate half-open UTF-8 byte range.
`reb-live-script-utf8-v1` means SHA-256 of UTF-8 encoding of the complete
`Debugger.getScriptSource` string, with no BOM stripping, line-ending changes,
formatting, derived text, truncation notice or JSON-envelope bytes. It is not an
artifact digest or CDP `scriptParsed.hash`; those identities are not interchangeable.

The first version supports external HTTP(S) JavaScript only: zero inline start
offsets, no `hasSourceURL`, no source matching the page document URL, and no BOM,
replacement characters or lossy/unpaired-surrogate encoding. Worker script URLs
may identify the worker's document. URLs only reject unsupported representations;
they never select a replay match. These are deliberately conservative exclusions.

`bind_runtime_candidate` carries digest version, digest/byte count, range,
explicit disposable target, session ID, creation timestamp and navigation ID.
It carries no original script ID, original URL, selected field value or full source.
The backend scans **all** JavaScript in the selected disposable target: 1–64
scripts, at most 8 MiB declared and actual aggregate source text, 15 seconds total
including source reads and the worker. An unreadable/truncated source or exceeded
bound refuses binding because uniqueness is unknown. Zero matches and multiple
matches fail distinctly. Page and worker IDs never substitute for one another.

The existing worker query adds `candidate_end_byte` alongside `function_at_byte`.
Only a full range inside a string literal in a declared-synchronous function body
returns `function_location.candidate_eligible: true`. Comments, global literals,
parameter defaults, templates, async/generator functions and accessors fail
closed. A legacy worker omitting this flag is unsupported for this bridge;
ordinary function-location and deobfuscation callers remain compatible. Actual
breakable synchronous returns are resolved by existing CDP hook arming. A
non-async function can still return a Promise; it cannot provide this matched
string baseline or a supported synchronous return override.

Catalog eviction or a rejected script descriptor taints completeness until a fresh
attached lifetime; a truncated retained catalog can never establish uniqueness.
A main reconnect that retains worker debugger sessions also taints completeness
because it clears their descriptors without re-enabling those sessions. Dispose
and create a fresh context to recover; no automatic reconnect/retest is added.

Target-local catalog revisions and exact source descriptors guard source reads,
worker results, definition insertion, arming awaits/commit and hit processing.
Revision changes and catalog edits share the debugger state lock. At most nine
revision entries (one page plus eight workers) are retained; removed/reset target
revisions are never reused. Unknown ownership, registry overflow or revision
exhaustion taints completeness rather than silently evicting a fence. Global
disposable navigation, reconnect and session fences remain independent. Binding re-reads
the matched source before its definition is added; arming repeats the complete
unique-source scan and strict worker check. Selected-target catalog churn expires candidate use; unrelated Worker discovery,
parsing and title changes cannot retire a Page or another Worker's binding. The
UI scopes pending receipt ownership to the same selected-target catalog plus
global disposable lifetime. Neither layer silently rebinds.
Rollback removes newly installed points if ownership changes while arming.
**Stop waiting**, navigation, disposal, panel close, return or newer selection retires UI replies;
a retired POST acknowledgement says native completion is unknown and never
retries automatically. Original evidence can remain available after replay ends.

## Retention and verification

This adds no notebook schema, durable selected value, backend source cache,
third-party traffic or native probe. Existing field-capture retention and explicit
replacement consent remain as documented in [Request Value Test v2](request-value-test-v2.md).
The candidate guard in an ephemeral hook contains digest/range and replay ownership
metadata, not original source text or selected values. Existing definition/hit/
observation limits and disposable erasure still apply.

Worker/backend unit tests cover structural and identity admission. Controller
fixtures cover ownership, late replies and draft/consent safety. The rendered
`--candidate-bridge-ui-browser` journey uses real backend/CDP plus an owned
localhost fixture with separate Page and Worker buttons and a literal-return
function. It starts at Traffic without copied IDs, hidden setup, or direct
backend actions replacing the visible journey. Exact-head browser screenshots
and native packaging CI remain required; unit/DOM checks are not rendered proof.
