# API Collection v1

API Collection saves credential-free request templates for repeated authorized
research. It extends the pinned WireBrowser folder, request-editor, variable,
and execution-history workflow while preserving REB's local-first evidence and
isolation boundaries. Project-wide authorization and data-handling policy is
in [`SAFETY.md`](../../SAFETY.md); this document describes the collection's
credential-free request contract and local persistence behavior.

## Workflow

1. Open Collection and create folders or saved requests.
2. Define root, folder, and request variables with `{{name}}` placeholders.
3. Save the template, then create the shared disposable Request Lab context.
4. Use **Run saved request**, or the explicit **Save & Run** action when edits
   are pending, and inspect its ephemeral response and execution history.

The library, request editor, and response pane have separate jobs. Headers,
Body, and Variables are keyboard-accessible request sections. Response Body and
Headers describe the selected submitted run, including its resolved method,
URL, duration, truncation and outcome. Folder settings, run history, and storage
limits use disclosures. Narrow windows stack the authoring and result panes
inside a scrolling workspace.

Unsaved request and folder edits remain owned by their selected item. Selecting
that item again, a debugger refresh, or a failed save preserves raw text and
folder choices. Switching, creating, duplicating or deleting requires an
explicit save or discard first. Leaving the Collection workspace preserves the
current draft in panel memory; reloading the application does not persist it.
A generation conflict retains the draft for review. Request ownership includes
both ID and creation timestamp. If another window removed or replaced its owner, the last valid collection stays visible until edits are discarded
and the current store is reloaded. Known-stale owners cannot be saved or run.
Retry load is explicit. A request cannot move to a different folder while the
current folder has unsaved edits; save or discard those edits first. Creating a
folder selects that folder and clears the previous request selection.

Selection and preview never send a request. Save & Run saves exactly once before
submitting the saved snapshot; a run failure does not imply that saving failed.
Repeated submissions are disabled while that operation is pending. A context
change between variable configuration and sending stops the send. The recipe ID is reserved while variable configuration is pending, and its
creation identity is rechecked before sending. An acknowledgement is distinct
from completion: the previous response remains visible until the acknowledged
run appears in a later snapshot. That completion selects the new result only
while the request and history selection remain unchanged. New editor drafts
remain untouched; choosing another run or request cancels this automatic
selection. A late run cannot steal a newer request selection. Run history is scoped by saved request
ID and disposable context, never matched by URL to captured Traffic. New recipes
do not recycle IDs still present in ephemeral runs. History predating the
recipe’s creation is excluded if another window reused an ID. A bounded
25-entry, context-scoped in-memory ownership map also binds locally
acknowledged executions to their exact recipe creation identity. A separate
bounded 25-record dispatch ledger registers that identity before the run action
starts, so a polling result cannot be attributed to a replacement recipe while
the action acknowledgement is delayed or lost. It retains only context, recipe
identity and the prior execution ID, never request or response content. Older
history is outside that submission’s range. Once polling or acknowledgement
identifies its execution, the dispatch claim is retired and only that exact
execution keeps its owner; later runs are not claimed. Unresolved dispatches
remain protected across a lost acknowledgement, while ambiguous overlapping
incarnations stay unassigned until a specific acknowledgement resolves them.

Traffic can create a saved request, but the import copies only the method and a
URL with query and fragment removed. It never imports captured headers,
cookies, request bodies, or credentials.

## Persistence contract

The collection is one versioned `api-collection` document. Browser development
uses `build/sessions/api-collection-v1.json` by default. The native app uses
`Application Support/Origin Trace/api-collection-v1.json`. Both paths can be
overridden with `--api-collection`.

Every replacement includes the generation it read. A stale generation is
rejected with a conflict instead of overwriting another window's changes. A
successful change is written as one atomic file replacement with user-only
permissions. Existing request creation timestamps are preserved, and update
timestamps change only when request content changes.

The fixed root folder has ID `1` and the name `API Collection`. The document is
strictly validated before it replaces the last valid collection:

- at most 32 folders and 128 requests;
- at most four nested folder levels;
- unique case-insensitive sibling folder and request names;
- at most 32 variables and 32 KiB of variable text per scope;
- at most 64 headers and 16 KiB of header text per request;
- at most 64 KiB per request body and 2 MiB for the complete document;
- 100 millisecond to 30 second request timeouts;
- no cycles, missing parents, duplicate IDs, controls in names, or malformed
  timestamps.

Credential, cookie, connection, host, and transport framing headers are
rejected. Collection data is user-authored state and never enters the evidence
store.

## Scoped variables

Variables resolve in deterministic order:

```text
root folder -> ancestor folders -> selected folder -> saved request
```

Later scopes override earlier scopes by name. The resolved variable map is sent
to Repeater immediately before the saved request. Repeater then performs its
existing bounded substitution and validates the fully resolved URL, method,
headers, body, and timeout before any network request starts. `{{=name}}`
remains a literal token.

## Execution lifetime

Saved request templates persist. Executions do not. API Collection reuses the
disposable Request Lab BrowserContext and tags each Repeater history entry with
its saved request ID. The Collection UI filters the bounded 24-entry, 512 KiB
Repeater history by that ID.

Disposing the Request Lab context erases variables, active execution state,
request and response bodies, and all execution history. No API Collection run
is appended to captured evidence.

## Performance boundary

Collection parsing, validation, persistence, and rendering occur only on an
explicit cold-path user action. The native browser probe, bounded renderer
transport, event broker hot path, and dependency-free C++ event foundation are
unchanged. The UI updates only the bounded collection document and bounded
Repeater snapshot.
