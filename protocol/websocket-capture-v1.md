# WebSocket message capture v1

`GET /api/debugger` includes `network.websockets` when the backend supports this
projection. It is exposed by the existing read-only `get_debugger` operation:

```sh
reb-api call get_debugger --base-url http://127.0.0.1:PORT --read-only
```

In Origin Trace, open **Traffic → WebSockets**. Select a retained connection and
Both directions, Sent or Received. Expand a message to inspect inert UTF-8 text
or base64. Keyboard Tab reaches the connection/direction controls; native select
keys change them. No message is sent, copied, replayed or exported by opening or
filtering the panel. Existing raw debugger snapshot access remains local.

## Source and identity

The format is `reb-websocket-capture-v1`. Identity is the enclosing network
instance_id, capture_epoch and target_id, plus a monotonically assigned connection
id and message sequence. Connection records retain the CDP requestId as
protocol_request_id. Reused protocol IDs after a close receive fresh connection
identities; a duplicate creation while open is malformed. Target reconnect
resets the projection together with the existing capture epoch. Frame events
without a current connection, after close or after connection eviction increment
orphan_events. They are not joined by URL or attached to a new connection.

Observed events: webSocketCreated, webSocketHandshakeResponseReceived,
webSocketFrameSent, webSocketFrameReceived, webSocketFrameError and webSocketClosed.
Creation has no source timestamp. Handshake/close/message timestamps remain
monotonic seconds; no wall time is invented. Frame-error text is not retained;
the connection's error_count is visible. Only response handshake status is
retained; handshake headers, cookies, auth values and request details are outside
this projection. A status other than 101 is labeled handshake_observed rather
than asserting the connection opened.

CDP exposes a message-oriented observation, not complete wire framing. opcode
and mask are retained, but FIN/RSV bits and complete fragmentation boundaries are
unavailable. Opcode 1 is UTF-8 text. Other opcodes use CDP's base64 payload, with
strict canonical decoding. Continuation/control/reserved opcodes remain numeric
observations. There is no message reassembly, decompression, execution, heartbeat
response or automatic decode chain. Transport errors are observations, not proof
of server state.

## Retention and coverage

- 64 connection records; oldest eviction increments dropped_connections
- 512 message records across connections; oldest eviction increments dropped_frames
- 4096 retained payload bytes per message; UTF-8 prefixes stop at a character
  boundary, binary prefixes are re-encoded as valid base64, truncated is explicit
- Binary source strings above 65536 encoded bytes are not decoded; payload_state
  is oversized, truncated is true, payload_bytes is null and no bytes are shown
- Smaller invalid base64, missing fields, invalid opcode/mask/timestamp and
  duplicate connection creation increment malformed_events rather than coercing
- URL prefixes are at most 8192 UTF-8 bytes with url_truncated; protocol request
  identifiers use the existing 4096-byte bound

Message payload_bytes is the original decoded size only when known. Dropped,
orphan and malformed counters are saturating lifetime counters. Connection
records may be evicted before their messages: such messages remain in the raw
snapshot and their count is visible, but the panel does not attach them to a
replacement connection. The panel renders only the newest 100 matching messages
and explicitly reports this display bound separately from capture loss.

Content capture must be enabled; the disabled path stores no sockets or payloads.
Capture controls and session authorization are unchanged. Raw URLs/text/binary
payloads may contain private data or credentials, and stay in bounded local
memory like existing CDP traffic. Never share raw snapshots without review.
Opening the inspector does not enable capture. A refresh failure labels the last
snapshot, while scope changes retire selection and the prior message view.

## Validation

Rust authored-event tests cover text/binary/control payloads, close/reuse
ownership, capture disabled, retention/omission counters and payload bounds.
`node tools/check-websocket-inspection.mjs` covers model and controller states,
inert rendering, direction/selection, focus and expansion retention, epoch reset
and 100-row display bounds. `node tools/check-origin-trace-debugger.mjs
--traffic-ui-browser` also exercises the actual Traffic panel with keyboard and
hit-tested pointer actions at 1440, 600 and 360 pixel widths, producing rendered
screenshots in the existing Requests UI artifact. These are authored fixtures,
not live third-party WebSocket probes or complete wire-capture attestation.

Primary source: [CDP Network WebSocketFrame](https://chromedevtools.github.io/devtools-protocol/tot/Network/#type-WebSocketFrame).

A closed WebSocket panel is absent when no retained connections exist, preserving
the full HTTP workspace. An already open panel keeps empty/disabled status
visible until closed. New retained connections expose the inspector automatically.
