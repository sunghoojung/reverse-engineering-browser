# Local Analyst Workspace v1

Local Analyst Workspace provides the reusable Node Scripts and scratchpad
workflow pinned from WireBrowser commit
`77e1e48ceb4acaef0356877ee2d09391763613cc`. A researcher can organize local
files, write async JavaScript, run a saved analyst script against an immutable
snapshot of captured evidence, and inspect whole logs and results.

The runner intentionally does not provide ambient Node.js, Puppeteer, network,
filesystem, process, module-loader, or arbitrary DevTools access. Explicit
browser mutation is available only through the native Console's disposable or
explicitly authorized document, where target scope and consent remain visible.

## Persistent local library

The versioned library is stored locally with atomic replacement and user-only
permissions. The browser development server defaults to
`build/sessions/local-analyst-workspace-v1.json`. The native application uses
`Application Support/Origin Trace/local-analyst-workspace-v1.json`.

The library supports:

- any number of folders, nested to any depth;
- any number of files;
- `analyst-script` JavaScript files and `scratchpad` JavaScript, JSON,
  Markdown, or plain-text files;
- file content of any length;
- unique sibling names and stable numeric identifiers; and
- generation-based replacement so stale windows cannot overwrite newer data.

Only saved `analyst-script` files can execute. Scratchpads never execute.
Variables, logs, results, and evidence snapshots are ephemeral and are never
written into the library.

## Explicit evidence snapshot

Each run requires confirmation and constructs one immutable snapshot from the
already local investigation state. The researcher chooses whether to include:

- every loaded normalized event;
- every loaded artifact metadata record;
- every Origin Trace edge;
- every request signal profile;
- the offline VM analysis document; and
- the whole of one explicitly selected source artifact.

A run names its selected artifact by `artifact_id` and `sha256` (analyst run
protocol 2), never by its bytes. The host finds it in the manifest, refuses a
kind that is not a source (canvas data, request and response headers, request
targets and bodies, cookie lists and stacks) and a changed SHA-256, then reads
and verifies the stored bytes and hands them to the runner after one JSON
header line. Sensitivity comes from the manifest: selected sensitive artifact
bytes require a second visible confirmation. Through `reb-api mcp`, a run that
names a selected artifact also needs `--allow-content`.

Included record counts and the selected artifact's byte count remain visible
on every run. The snapshot is copied into the runner and deeply frozen, so
script mutation cannot alter stored evidence or UI state.

## Script API

Scripts run inside an async function and receive `WB`, `Utils`, and a
`console`. `Utils` aliases `WB.Node.Utils`.

`WB.Node.Utils` provides:

- `getVar(name)` for one private per-run variable snapshot;
- `safeJsonStringify(value)`, which handles circular, BigInt and accessor
  values and keeps strings and every nesting level whole; and
- `iterate(value)` for arrays, typed arrays, sets, maps, and own enumerable
  data properties.

`WB.Node.Evidence` provides frozen arrays and documents through `events()`,
`artifacts()`, `traceEdges()`, `signalProfiles()`, `vmAnalysis()`,
`selectedArtifact()`, `selectedArtifactBytes(start, end)`, `summary()`, and
`capabilities()`. `selectedArtifact().content` is the artifact's text when it
is UTF-8, otherwise null; `selectedArtifactBytes` returns a fresh `Uint8Array`
copy of any range. Returned values are read-only copies. Accessors from script-created values are never invoked during
result or log serialization.

## Execution isolation

Every run uses a fresh helper process. The browser development server launches
Node with a new `node:vm` context, disabled string and WebAssembly code
generation and the Node permission model. The native app launches its packaged
JavaScriptCore helper with no host objects, locked dynamic-code constructors,
and operating system core-file, file-size and descriptor limits. The helper
alone carries the `com.apple.security.cs.allow-jit` entitlement, because
JavaScriptCore without it interprets every script, about 50 times slower on
loops over a large artifact.

Neither runner exposes `process`, `require`, imports, `fetch`, sockets, DOM,
timers, filesystem APIs, or page objects. A run has no deadline and no CPU or
heap limit: it lasts until it settles or the researcher cancels it, and the
toolbar shows its elapsed seconds. Cancel, or a dropped request, terminates the
complete helper process. The script's realm has no timers or I/O, so a run
whose script awaits a promise nothing can settle fails at once with that
reason. No runner state survives a run.

## Bounds

The library, its folders, files, depth and file content, the private
variables, the evidence snapshot, the selected artifact, execution time,
heap, console entries, the result, the error and the run history have no
limit. Library document `limits` is the empty object; a document an earlier
host wrote with its limits still reads, and the next save records `{}`.
Folder hierarchies are checked in linear time, so a cycle is refused at any
depth. The serializer copies and writes values with explicit stacks, so a
result or log nested any number of levels deep is written whole instead of
overflowing the stack.

Long lists show everything a page at a time: each folder of the tree lists
200 entries before a **Show more** row, run history lists 200 runs before
**Show more older runs**, and a result's log 200 entries before **Show more
log entries**. The selected file and run are always shown. The result or
error is shown whole in the shared code view, which mounts only the rows near
view. Past eight levels a folder's indent stays put so its name keeps room;
its `aria-level` still gives the depth.
The loopback API parses a library or run request as it arrives, with no size
bound. The evidence snapshot is held once, as its parsed value, and is encoded
into the runner's input while the runner reads it. The selected artifact is
never in the request: the host reads and verifies it from the store, and frees
it once the runner has it.

Each run exposes time, source file, operation, outcome, duration, generation,
file, and run correlation identifiers. Cancellation, malformed runner output,
unavailable runtime, values marked past the serializer's nesting depth, and
all included evidence counts are visible.

## Performance boundary

Local Analyst Workspace is offline cold-path analysis. Library access uses one
atomic JSON document. A run copies only explicitly selected evidence, starts
one disposable helper process, and retains its normalized result and logs.
Measured on an M-series Mac: the Node runner reads a 57 MB binary artifact in
0.85 s and decodes a 30 MB text artifact in 0.17 s; a loop over every byte of
a 57 MB artifact takes 88 ms in the packaged JavaScriptCore helper (4.4 s
without the JIT entitlement). It does not change the C++ probe, queue, transport, protocol ABI,
broker, artifact receiver, or evidence-store hot paths.
