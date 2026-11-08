# Native debugger observation v1

Status: source candidate. Records compile against the portable harnesses here;
patched Brave compilation and a live run are still required.

Phase 1 of [#434](../docs/product/native-debugger-v1.md): non-pausing probes an
agent "breaks" on by waiting on a filtered `wait_for_events` cursor. Nothing
pauses, no value is read, and no debugger protocol is used.
[SAFETY.md](../SAFETY.md) governs capture.

## Arming

Rules are armed per document through the live native Console connection
(`runtime` command `watch`), pinned to that document's frame and the current
capture configuration. Navigation, a new configuration, `unwatch`, or Console
disconnect disarms them. Records need an active capture session; a disposable
Console reports `capture_inactive`.

| Rule | Bound |
| --- | --- |
| `requests`: `url_contains` (1-256 bytes) and optional `method` | 8 |
| `events`: event type names (1-27 bytes, ASCII) | 16 |
| `timers`, `csp`: on or off | - |
| `exceptions`: `uncaught` or `all` | - |
| `dom`: element handle with `attributes`, `subtree`, `removal` | 4 nodes |

Each configuration admits at most 1,024 observation records per renderer;
the next refused record leaves one `debugger_observation_budget` gap.

## Gate

Hooks check one relaxed atomic bitmask before any other work. Disarmed probes
cost that load only. Stacks use the [#429 walker](native-network-v3.md) and
need `--reb-request-stacks`; without it records carry stack state
`no_script` and a zero digest.

## Common payload

128 bytes, little endian. Bytes 0-79 are the `request_initiator_stack` stack
summary with the same states, flags and validation (offsets 24 and 28 stay
Wasm frames and distinct scripts). Bytes 80-127 are per type; unused bytes are
zero. Stacks are kind 13 `stack` artifacts with capture origin 12, shared by
digest with request stacks; the creator is the first record that named it.

## Types

All are category `runtime` (12) except type 40, which is `network` (9).

| Type | Name | Parent |
| ---: | --- | --- |
| 40 | `request_watch_match` | the `request_initiated` record; `request_id` set |
| 41 | `listener_dispatch` | 0 |
| 42 | `timer_observation` | the scheduling record for phase 2 when admitted |
| 43 | `csp_violation` | 0 |
| 44 | `exception_observation` | 0 |
| 45 | `dom_mutation` | 0 |

`request_watch_match` (80): `u8` rule slot, `u8` flags (bit 0 method matched).

`listener_dispatch` (80): `u8` rule slot, `u8` target kind (1 element,
2 document, 3 window, 4 other node, 5 other target), `u16` node type, 16-byte
listener frame (kind 1 at the function start, or zero for a native listener),
`u8` event type length, 27 bytes event type.

`timer_observation` (80): `u8` phase (1 scheduled, 2 fired), `u8` kind
(1 timeout, 2 interval), `u16` flags (bit 0 string callback), `u32` timer id,
`u32` delay ms, 16-byte callback frame.

`csp_violation` (80): `u8` directive (DevTools `CSPDirectiveName` order),
`u8` disposition (1 enforce, 2 report), `u8` host length, 45 bytes blocked
host. Never a path or query.

`exception_observation` (80): `u8` kind (1 uncaught, 2 caught by JavaScript,
3 unhandled rejection), 16-byte throw frame.

`dom_mutation` (80): `u8` kind (1 attribute, 2 subtree, 3 removal), `u8` node
slot, `u16` mutated node type, `u8` attribute name length, 32 bytes attribute
local name. Never attribute values or text.

## Validation

`tests/debugger_observation_test.cpp` checks layout parity with the overlay,
every state and malformed records; `tools/validate-evidence-store.py` and the
backend apply the same rules.
