# Local Analyst Workspace v1

Local Analyst Workspace provides the reusable Node Scripts and scratchpad
workflow pinned from WireBrowser commit
`77e1e48ceb4acaef0356877ee2d09391763613cc`. A researcher can organize local
files, write async JavaScript, run a saved analyst script against an immutable
snapshot of captured evidence, and inspect bounded logs and results.

The runner intentionally does not provide ambient Node.js, Puppeteer, network,
filesystem, process, module-loader, or arbitrary DevTools access. REB exposes
browser mutation and live debugger control through Object Lab, Runtime Hooks,
Automation Recipes, Repeater, and the debugger UI, where target scope and
consent remain visible. MCP remains deferred.

## Persistent local library

The versioned library is stored locally with atomic replacement and user-only
permissions. The browser development server defaults to
`build/sessions/local-analyst-workspace-v1.json`. The native application uses
`Application Support/Origin Trace/local-analyst-workspace-v1.json`.

The library supports:

- up to 32 folders with four hierarchy levels;
- up to 64 files;
- `analyst-script` JavaScript files and `scratchpad` JavaScript, JSON,
  Markdown, or plain-text files;
- 32 KiB per file and 512 KiB total content;
- unique sibling names and stable numeric identifiers; and
- generation-based replacement so stale windows cannot overwrite newer data.

Only saved `analyst-script` files can execute. Scratchpads never execute.
Variables, logs, results, and evidence snapshots are ephemeral and are never
written into the library.

## Explicit evidence snapshot

Each run requires confirmation and constructs one immutable snapshot from the
already local investigation state. The researcher chooses whether to include:

- up to 500 normalized events;
- up to 500 artifact metadata records;
- up to 1,000 Origin Trace edges;
- up to 256 request signal profiles;
- the bounded offline VM analysis document; and
- at most 64 KiB from one explicitly selected artifact.

Selected sensitive artifact bytes require a second visible confirmation. The
complete serialized snapshot is capped at 768 KiB. Truncation and included
record counts remain visible on every run. The snapshot is copied into the
runner and deeply frozen, so script mutation cannot alter stored evidence or UI
state.

## Script API

Scripts run inside an async function and receive `WB`, `Utils`, and a bounded
`console`. `Utils` aliases `WB.Node.Utils`.

`WB.Node.Utils` provides:

- `getVar(name)` for one private per-run variable snapshot;
- `safeJsonStringify(value)` with circular, BigInt, accessor, depth, entry, and
  byte bounds; and
- `iterate(value)` for arrays, typed arrays, sets, maps, and own enumerable
  data properties.

`WB.Node.Evidence` provides frozen arrays and documents through `events()`,
`artifacts()`, `traceEdges()`, `signalProfiles()`, `vmAnalysis()`,
`selectedArtifact()`, `summary()`, and `capabilities()`. Returned values are
read-only copies. Accessors from script-created values are never invoked during
result or log serialization.

## Execution isolation

Every run uses a fresh helper process. The browser development server launches
Node with a new `node:vm` context, disabled string and WebAssembly code
generation, the Node permission model, and a bounded V8 heap. The native app
launches its packaged JavaScriptCore helper with no host objects, locked
dynamic-code constructors, and operating system CPU, data, file-size, and
descriptor limits.

Neither runner exposes `process`, `require`, imports, `fetch`, sockets, DOM,
timers, filesystem APIs, or page objects. The parent terminates the complete
helper process on cancellation or timeout. No runner state survives a run.

## Bounds

| Resource | Limit |
| --- | ---: |
| Folders | 32 |
| Files | 64 |
| Folder depth | 4 |
| File content | 32 KiB |
| Total file content | 512 KiB |
| Library document | 1 MiB |
| Variables | 32 |
| Variable value | 4 KiB |
| Variable snapshot | 16 KiB |
| Evidence snapshot | 768 KiB |
| Selected artifact bytes | 64 KiB |
| Execution time | 2 seconds |
| Node old-space heap | 64 MiB |
| Runs per application session | 256 |
| Retained run records | 64 |
| Console entries | 64 |
| Console entry | 1 KiB |
| Result preview | 32 KiB |
| Runner response | 128 KiB |

Each run exposes time, source file, operation, outcome, duration, generation,
file, and run correlation identifiers. Cancellation, timeout, malformed runner
output, unavailable runtime, input truncation, history eviction, and all
included evidence counts are visible.

## Performance boundary

Local Analyst Workspace is offline cold-path analysis. Library access uses one
bounded atomic JSON document. A run copies only explicitly selected bounded
evidence, starts one disposable helper process, and retains only normalized
text previews. It does not change the C++ probe, queue, transport, protocol ABI,
broker, artifact receiver, or evidence-store hot paths.
