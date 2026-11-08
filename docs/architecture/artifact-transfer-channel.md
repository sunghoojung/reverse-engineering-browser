# Artifact Transfer Channel - Low-Level Design

## Purpose

JavaScript files, WebAssembly modules, source maps, and explicitly approved
response and request bodies can be much larger than a probe event. They use a dedicated
browser-process transfer channel and never enter the renderer event ring, event
broker queue, or inline event payload.

The implemented development paths are:

```text
browser-process response-body tee ----------------------+
renderer dynamic-code/WASM callback                     |
  -> one-way bounded Mojo submission                    |
  -> browser-process capture boundary ------------------+
  -> bounded artifact queue
  -> authenticated artifact socket
  -> reb-artifact-receiver
  -> durable acknowledgment
  -> immutable content-addressed blob
  -> versioned manifest record
  -> research UI artifact API
  -> Sources workspace
```

The tracked Brave integration captures JavaScript and WebAssembly responses,
accepted dynamic JavaScript source, and byte-buffer WebAssembly compilation,
module construction, and instantiation. `reb-artifact-producer` exercises the
same socket and acknowledgment contract in deterministic end-to-end fixtures.

## Ownership boundaries

- Renderer probes emit bounded `NativeProbeEvent` records through the fast
  event transport. Authorized generated-source hooks may also submit one
  bounded immutable artifact to the browser over one-way Mojo.
- Renderer probes must not open the artifact channel, write files, hash large
  buffers, or wait for artifact storage.
- The browser process owns artifact authorization, identifiers, metadata, and
  transfer scheduling.
- The artifact receiver owns byte limits, streaming validation, hashing,
  immutable storage, and manifest publication.
- The event broker continues to own normalized low-latency evidence events. It
  is not in the artifact byte path.
- The UI reads artifact metadata and bounded content windows. It never executes
  captured bytes.

An event and an artifact join through `session_id`, `navigation_id`, `frame_id`,
`artifact_id`, and `creator_event_id`. Runtime-generated artifacts additionally
carry `execution_context_id` and `capture_origin`. Unknown parent artifacts and
creator events remain zero rather than being inferred. Capture and
interpretation remain separate.

## Wire frame

Each stream item is a fixed header followed by three byte ranges:

```text
+---------------------------+ offset 0
| ArtifactHeader (128 B)    |
+---------------------------+ offset 128
| source URL (url_size)     |
+---------------------------+
| MIME type (mime_type_size)|
+---------------------------+
| original content bytes    | content_size
+---------------------------+
```

The fixed header is standard-layout and trivially copyable. Both
`include/reb/artifact.hpp` and Brave's tracked
`common/native_artifact_header.h` assert every field offset and the 128-byte
size. Native tests assert that the two definitions remain ABI-identical.

| Offset | Size | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 4 | `magic` | `0x41424552` |
| 4 | 2 | `protocol_version` | `1` |
| 6 | 2 | `header_size` | `128` |
| 8 | 2 | `kind` | JavaScript, WASM, source map, response body, Canvas data URL, bytecode buffer, guest adapter, request body, request target |
| 10 | 2 | `flags` | bit 0 marks sensitive content |
| 12 | 4 | `reserved0` | zero |
| 16 | 48 | correlation IDs | six unsigned 64-bit values |
| 64 | 8 | `content_size` | checked before content is read |
| 72 | 4 | `url_size` | 1 to 8,192 bytes |
| 76 | 4 | `mime_type_size` | 1 to 255 bytes |
| 80 | 32 | expected SHA-256 | all zero if the sender omits preverification |
| 112 | 8 | `execution_context_id` | stable renderer context ID, or zero when unavailable |
| 120 | 2 | `capture_origin` | unknown, network response, dynamic JavaScript, WASM compile/module/instantiate, Canvas, runtime typed array or allocating script, native Wasm guest, network request |
| 122 | 2 | `reserved1` | zero |
| 124 | 4 | `reserved2` | zero |

The stream uses exact native frames only between matching local builds. A
socket transport must authenticate the browser bridge before it accepts the
first frame. Unsupported versions, flags, enum values, nonzero reserved bytes,
invalid printable UTF-8 metadata, truncated ranges, and digest mismatches fail
closed.

The receiver replies with a fixed 32-byte version-1 acknowledgment containing
the artifact identifier and receive status. Accepted means the immutable blob
and manifest entry were committed. Brave emits success only after matching that
acknowledgment to the queued artifact.

## Limits and backpressure

Defaults are:

- 16 MiB per artifact;
- 32 MiB in-flight pool for response tees and request content, charged with
  the bytes a capture holds (a declared Content-Length, or one 64 KiB chunk
  that grows) and returned when the artifact writer drops the transfer, so it
  bounds bytes held rather than captures;
- 16 queued artifacts and 32 MiB of queued browser content;
- 256 MiB of immutable blobs per session store;
- 8 KiB source URL;
- 255-byte MIME type;
- 64 KiB streaming copy and hashing chunk;
- 2 MiB maximum UI content response and 20,000 rendered lines.

Canvas data URLs use the 2 MiB UI limit as their capture limit so accepted
images are always available as complete base64 content. Other artifact kinds
retain the 16 MiB transfer limit.

The receiver validates declared sizes before it allocates metadata or reads
content. Content is streamed to a temporary file while SHA-256 is computed, so
receiver memory does not scale with artifact size. A completed temporary file
is atomically renamed into the blob directory. The manifest is published only
after the blob is durable enough for the local development contract.

When a limit is exceeded, the receiver rejects the frame and increments a
visible status counter. It does not truncate original evidence. The
browser-process bridge must treat rejection as artifact-unavailable evidence
and emit a small gap or failure event through the normal event path.

After a header passes validation and matches the authenticated session, its
declared lengths are bounded. Socket mode then discards the rest of a rejected
frame, at most `max(16 MiB, configured artifact limit)` of content, before
acknowledging, so the connection stays at a frame boundary and carries the next
frame. An invalid header, a session mismatch, a truncated stream or a larger
declared body leaves the stream unsynchronized; the receiver acknowledges and
closes that connection, then keeps listening for a reconnect. The
standard-input receiver stops after any rejected frame, because without an
acknowledgment its exit status is the producer's only signal. The live session
supervisor stops the listener explicitly when the browser session ends, and the
listener path is the UI's artifact-channel health signal while the session is
running.

The browser writer's lifecycle is explicit: connected, reconnecting, lost,
stopping or idle. A rejection acknowledgment keeps the connection. A failed
connection is replaced within five attempts over about three seconds. During
those attempts, new transfers wait in the same bounded queue and capture
admission stays open. Before writing a frame, the writer replaces an idle
connection the receiver has already closed. If a send fails, the writer reads an
acknowledgment the receiver wrote before closing, so the real status is
recorded instead of an I/O error. When reconnection fails, every queued transfer
is reported as `artifact_capture_failed` with `io_error`, and the browser emits
one `artifact_channel_lost` gap. Capture admission refuses artifacts from then
on, and that gap marks where they stop.

## Storage layout

```text
artifacts/
  manifest.jsonl
  blobs/
    <lowercase-sha256>.bin
```

Blob names are derived only from the receiver-computed digest. Original bytes
are never overwritten. A manifest record contains protocol version,
correlation IDs, kind, URL, MIME type, byte size, digest, sensitive flag, and a
store-relative content path. New records also include execution context and
capture origin while the reader remains backward-compatible with older version
1 records. The UI API removes `content_path` from catalog responses and
resolves it beneath the configured store before reading.

Identical bytes may share one content-addressed blob. Artifact identifiers are
still unique and immutable. The session limit is checked conservatively before
the digest is known. Artifact count and manifest bytes are independently
bounded, and loaded identifiers are kept in a bounded in-memory index for
constant-time duplicate checks. Live stores use mode-0700 directories and
mode-0600 evidence files.

Debugger-observed in-memory WebAssembly is appended by the Origin Trace
backend in this same manifest line format. Those artifact IDs are at or above
2^32. The authenticated receiver accepts one browser connection at a time, so
the backend does not open a second artifact socket.

## Sensitive content

Project-wide authorization, capture, and privacy rules are in
[`SAFETY.md`](../../SAFETY.md). This section describes the artifact channel's
specific enforcement contract.

Response bodies, request bodies, full request targets and Canvas data URLs
require both controls:

1. the frame kind is `response_body`, `request_body`, `request_target` or
   `canvas_data_url` and its sensitive flag is set;
2. the receiver was started with `--allow-sensitive` for that authorized
   session.

The default receiver rejects all four kinds. The live launcher enables the
receiver policy only when `REB_CAPTURE_CANVAS_IMAGES=1` or
`REB_CAPTURE_REQUEST_CONTENT=1` is set. A `request_body` or `request_target`
artifact must use the `network_request` origin, name its creator record and
carry no execution context; see [Native network v2](../../protocol/native-network-v2.md). JavaScript,
WASM, and source maps cannot be mislabeled as sensitive content. Credentials,
cookies, and authorization headers are not artifact kinds and remain outside
this channel.

## UI safety

The catalog endpoint returns metadata only. The content endpoint always uses
`application/octet-stream`, `Content-Disposition: attachment`, `nosniff`, and a
sandbox content-security policy. The Sources workspace fetches at most 2 MiB,
decodes text or displays WASM as hex, and creates DOM text nodes. Captured HTML
or JavaScript never enters an HTML parsing or execution sink.

The Sources workspace follows a familiar source-browser organization: Captured
navigator, origin and directory tree, editor tabs, line numbers, open-file and
find shortcuts, a readable derived view, and a details side pane. It reads only
the immutable artifact store; there is no live script catalog, debugger or
runtime state. Wasm modules and native guest bytecode buffers display as an
inert hex view of their retained bytes.

A response body becomes a stored JavaScript artifact only when the network tee
classifies it as a script resource or a JavaScript MIME type. `application/wasm`
and the compile, module, and instantiate hooks store Wasm, often under a
synthetic `wasm://` URL, without copying the surrounding loader script. Fetch
or XHR bodies with another MIME type, and generated source that misses the
allocating-script hook, are absent from the manifest. `chrome://` script
responses can still be stored; they are browser-UI noise, not a challenge
loader. VM Lab's session-sources panel lists stored same-session artifacts and,
only when that session is in the current live evidence window, joins CDP
JavaScript scripts as correlation. It does not write those scripts into the
artifact store and does not supply a guest position.

## Failure and recovery behavior

- Partial header or metadata: reject as invalid and publish nothing.
- Partial content: remove the temporary file and publish nothing.
- SHA-256 mismatch: remove the temporary file and publish nothing.
- Duplicate artifact ID: reject without changing the original manifest entry.
- Authenticated session mismatch: reject the frame and close the connection.
- Artifact count or manifest limit: reject before publishing a manifest entry.
- Blob commit failure: report I/O failure and publish nothing.
- Manifest failure after blob commit: roll the manifest back to the last
  acknowledged record, then remove the blob this frame created. If the rollback
  fails, keep the blob, which the record may name, count it, and stop accepting
  for the rest of the run. A later maintenance pass may remove unreferenced
  blobs, but capture never guesses or rewrites provenance.
- Restart recovery: cut back a final record without its newline, which only an
  interrupted append leaves and which was never acknowledged, and report the
  removed byte count. Reject malformed, duplicate, or mixed-session manifest
  records before accepting new evidence.
- Malformed manifest: the UI retains its last valid catalog and reports the
  artifact catalog as unavailable.

## Validation

`make e2e` exercises the deterministic artifact producer and receiver path,
checks the manifest and analysis output, and validates the event store. The
native build check and compile gate cover the receiver and producer binaries.
