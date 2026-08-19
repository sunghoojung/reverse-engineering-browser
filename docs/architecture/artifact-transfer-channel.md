# Artifact Transfer Channel - Low-Level Design

## Purpose

JavaScript files, WebAssembly modules, source maps, and explicitly approved
response bodies can be much larger than a probe event. They use a dedicated
browser-process transfer channel and never enter the renderer event ring, event
broker queue, or inline event payload.

The implemented development path is:

```text
browser-process response-body tee
  -> bounded artifact queue
  -> authenticated artifact socket
  -> reb-artifact-receiver
  -> durable acknowledgment
  -> immutable content-addressed blob
  -> versioned manifest record
  -> research UI artifact API
  -> Sources workspace
```

The tracked Brave integration implements this path for JavaScript and
WebAssembly responses. `reb-artifact-producer` exercises the same socket and
acknowledgment contract in deterministic end-to-end fixtures.

## Ownership boundaries

- Renderer probes may emit only bounded `NativeProbeEvent` records through the
  fast event transport.
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
`artifact_id`, and `creator_event_id`. Capture and interpretation remain
separate.

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
| 8 | 2 | `kind` | JavaScript, WASM, source map, response body |
| 10 | 2 | `flags` | bit 0 marks sensitive response content |
| 12 | 4 | `reserved0` | zero |
| 16 | 48 | correlation IDs | six unsigned 64-bit values |
| 64 | 8 | `content_size` | checked before content is read |
| 72 | 4 | `url_size` | 1 to 8,192 bytes |
| 76 | 4 | `mime_type_size` | 1 to 255 bytes |
| 80 | 32 | expected SHA-256 | all zero if the sender omits preverification |
| 112 | 16 | `reserved1` | zero |

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
- 32 MiB of active browser capture memory;
- 16 queued artifacts and 32 MiB of queued browser content;
- 256 MiB of immutable blobs per session store;
- 8 KiB source URL;
- 255-byte MIME type;
- 64 KiB streaming copy and hashing chunk;
- 2 MiB maximum UI content response and 20,000 rendered lines.

The receiver validates declared sizes before it allocates metadata or reads
content. Content is streamed to a temporary file while SHA-256 is computed, so
receiver memory does not scale with artifact size. A completed temporary file
is atomically renamed into the blob directory. The manifest is published only
after the blob is durable enough for the local development contract.

When a limit is exceeded, the receiver rejects the frame and increments a
visible status counter. It does not truncate original evidence. The
browser-process bridge must treat rejection as artifact-unavailable evidence
and emit a small gap or failure event through the normal event path.

The standard-input receiver stops after a rejected frame because a pipe cannot
safely resynchronize after an untrusted declared length. Socket mode closes
the authenticated connection and ends the receiver process, making the failed
artifact channel visible to the live-session supervisor.

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
store-relative content path. The UI API removes `content_path` from catalog
responses and resolves it beneath the configured store before reading.

Identical bytes may share one content-addressed blob. Artifact identifiers are
still unique and immutable. The session limit is checked conservatively before
the digest is known. Artifact count and manifest bytes are independently
bounded, and loaded identifiers are kept in a bounded in-memory index for
constant-time duplicate checks. Live stores use mode-0700 directories and
mode-0600 evidence files.

## Sensitive response bodies

Response bodies require both controls:

1. the frame kind is `response_body` and its sensitive flag is set;
2. the receiver was started with `--allow-sensitive` for that authorized
   session.

The default receiver rejects all response bodies. JavaScript, WASM, and source
maps cannot be mislabeled as sensitive content. Credentials, cookies, and
authorization headers are not artifact kinds and remain outside this channel.

## UI safety

The catalog endpoint returns metadata only. The content endpoint always uses
`application/octet-stream`, `Content-Disposition: attachment`, `nosniff`, and a
sandbox content-security policy. The Sources workspace fetches at most 2 MiB,
decodes text or displays WASM as hex, and creates DOM text nodes. Captured HTML
or JavaScript never enters an HTML parsing or execution sink.

The Sources workspace follows the Chrome DevTools organization model: Page
navigator, origin and directory tree, editor tabs, line numbers, open-file and
find shortcuts, a readable derived view, and debugger side panes. Editing and
runtime debugging remain disabled because stored evidence is immutable.

## Failure and recovery behavior

- Partial header or metadata: reject as invalid and publish nothing.
- Partial content: remove the temporary file and publish nothing.
- SHA-256 mismatch: remove the temporary file and publish nothing.
- Duplicate artifact ID: reject without changing the original manifest entry.
- Authenticated session mismatch: reject the frame and close the connection.
- Artifact count or manifest limit: reject before publishing a manifest entry.
- Blob commit failure: report I/O failure and publish nothing.
- Manifest failure after blob commit: leave an unreferenced immutable blob. A
  later maintenance pass may remove unreferenced blobs, but capture never
  guesses or rewrites provenance.
- Restart recovery: reject incomplete, malformed, duplicate, or mixed-session
  manifest records before accepting new evidence.
- Malformed manifest: the UI retains its last valid catalog and reports the
  artifact catalog as unavailable.

## Validation

`tests/artifact_test.cpp` covers ABI parity, valid streaming, SHA-256, immutable
manifest publication, duplicate identifiers, per-artifact and total limits,
artifact-count and manifest limits, truncation, digest mismatch, authenticated
session binding, and sensitive-capture policy. The socket E2E test covers
authenticated acceptance, acknowledgment, permissions, hello and frame session
mismatches, and oversized rejection. The live-session E2E test launches both
receivers, produces correlated event and artifact evidence, verifies private
store permissions, and covers capture with the Artifact category disabled.
