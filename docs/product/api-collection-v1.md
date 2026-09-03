# API Collection v1

API Collection saves credential-free request templates for repeated authorized
research. It extends the pinned WireBrowser folder, request-editor, variable,
and execution-history workflow while preserving REB's local-first evidence and
isolation boundaries.

## Workflow

1. Open Collection and create folders or saved requests.
2. Define root, folder, and request variables with `{{name}}` placeholders.
3. Create the shared disposable Request Lab context.
4. Run the selected saved request and inspect its ephemeral execution history.

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
