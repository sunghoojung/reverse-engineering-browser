# Protobuf and gRPC-web wire inspection v1

Use **Decoder → Structured data** and choose **Protobuf wire inspection (no
schema)**, **gRPC-web envelope inspection**, or **gRPC-web text inspection
(chunked Base64)**. Enter bytes as hex/base64 for binary operations. For a raw
`application/grpc-web-text` body, select UTF-8 input and the text inspection
operation; its independently padded chunks are not necessarily one ordinary
base64 entity. Run is explicit, and normal Decoder history keeps original input
and completed steps intact when a later step fails.

The same operations are available in the existing bounded native worker and
local decoder API:

```sh
build/reb-decoder transform protobuf-inspect < message.bin
build/reb-decoder transform grpc-web-inspect < response.bin
build/reb-decoder transform grpc-web-text-inspect < response.txt
```

There is no server request, schema download, `.proto` code generation, captured
code execution, replay or credential use. Raw values can be private and remain
local. Existing decoder HTTP/CLI/native bridges, timeout, worker isolation,
input/output limits and source-history provenance apply unchanged.

## Protobuf report

`reb-protobuf-wire-v1` emits ordered fields without collapsing repeated field
numbers. Each entry has the input offset, key_end, end, field_number and wire_type.
Types 0, 1 and 5 have unsigned_decimal strings, preserving all 64 bits without
JavaScript rounding. Type 2 has payload_offset, length and bytes_base64. Offsets
are zero-based half-open byte positions, relative to the inspected message.

A wire type does not establish a declared protobuf type. `schema_known:false`
means signed/ZigZag/bool/enum/float/double interpretations, field names, packed
arrays, strings and nested message boundaries remain unknown. Length-delimited
bytes are not recursively guessed. Non-minimal but bounded varints remain
inspectable; this is not a canonical reserializer. Legacy groups (wire types
3/4) are explicitly unsupported. Zero/out-of-range field numbers, unknown wire
types, >64-bit or unterminated varints, short fixed values and oversized/truncated
length fields fail without partial reports.

## gRPC-web report

`reb-grpc-web-wire-v1` reads the five-byte envelope: flags plus unsigned 32-bit
big-endian payload length. Flag 0 is an uncompressed protobuf message; 0x80 is
an uncompressed ASCII trailer block. Compressed flags and reserved flags are
explicitly unsupported. JSON/thrift bodies and ordinary HTTP/2 frame parsing
are outside scope. Only complete envelopes are accepted.

Messages contain the nested protobuf wire report. Frame offset, payload_offset,
length and end refer to the binary envelope stream; text-mode offsets refer to
the decoded envelope bytes. Text mode handles complete canonical base64 quartets,
including independently padded flush chunks that split an envelope anywhere.
Whitespace, partial quartets and malformed base64 fail; input is not silently
trimmed or normalized.

Trailers preserve ordered lowercase metadata names and exact values (including
leading spaces and repeated keys). Lines are CRLF-terminated without an extra
blank terminator. Control/non-ASCII bytes, malformed keys or excessive trailers
fail. Trailers must be last; data or another trailer frame afterward is refused.
A stream with no body trailers can still be inspected and reports
trailers_present:false, since HTTP response headers are not part of these bytes.
`rpc_success_verified:false` is always explicit: a displayed grpc-status value
does not validate the RPC, server identity, response completeness or application
semantics. Binary metadata and percent-encoded grpc-message values stay inert.

## Bounds and verification

Existing limits: 1 MiB input/output, 16 explicit steps, 4 MiB retained history,
two-second bounded worker. Additional limits: 4096 fields shared across all
messages, 256 gRPC-web envelopes and 16 KiB/128 lines of trailer metadata. No
partial output is returned after any malformed or over-budget record.

`make wire-decoder-check` runs the actual native executable on authored vectors:
full uint64 range, all supported wire types, repeated fields, exact offsets,
message/trailer framing, arbitrary padded text flush boundaries, malformed and
truncated lengths, compressed flags, resource bounds and a deterministic random
corpus. The target is included in `make check` and sanitizer builds. Native app
and HTTP capability lists and the versioned OpenAPI enum are updated together.

References: [Protocol Buffers encoding](https://protobuf.dev/programming-guides/encoding/),
[gRPC-web protocol](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md).

Sanitizer builds run the same wire corpus against a test-only driver linked to
the exact decoder implementation. The production CLI's Linux128MiB address-space
limit is unchanged; it cannot accommodate ASan's virtual shadow map. Normal
`make wire-decoder-check` still runs the real production CLI. The test driver is
not packaged or exposed by the API; parser byte/output budgets remain enforced.
