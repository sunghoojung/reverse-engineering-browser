# Broker refusal v1

A `broker_refusal` record (event type 53) is what the event broker stores in
place of a record it refused at validation. Before it existed, a refused
record was counted only in the broker's `invalid` stat and stop line. The
store had no trace of it, so the loss showed up only indirectly: as a sequence
hole, or as children whose parent was never stored.

Only the broker writes this record. The broker refuses one that a producer
sends, with reason `type`, and the browser never sends one. This contract is
app-side: browser overlays and patches are unchanged.

The C++ definition is `include/reb/broker_refusal.hpp`. The writer and
validator are in `src/capture/event.cpp` (`EventRefusalOf`,
`MakeBrokerRefusal`, `IsValidBrokerRefusal`). The readers apply the same
rules:
- the backend's `apps/origin-trace-backend/src/broker_refusal.rs`;
- the UI's `decodeBrokerRefusal` in `apps/research-ui/evidence_models.js`;
- `valid_broker_refusal` in `tools/validate-evidence-store.py`.

A record that any reader refuses is not counted.

## What is kept

The record keeps the refusal reason, the refused header fields as read, and
the time the record arrived. It keeps no byte of the refused record's payload
or reserved bytes. Validation is part of the capture contract, so the bytes it
refused are never stored. That includes payload text a producer was not
allowed to send, such as a header block in the wrong record. The copied
header fields are integers: identifiers, sizes, enums and flags.

## Reasons

The reason is the first check that failed, in the order the broker applies
them:

| Reason | Name | The refused record |
| --- | --- | --- |
| 1 | `protocol_version` | is not event protocol version 3 |
| 2 | `header_size` | does not have a 144-byte header |
| 3 | `process_id` | claims process 4294967295, which the broker reserves for its own stream |
| 4 | `payload_size` | declares more than 128 payload bytes |
| 5 | `reserved` | has a nonzero reserved header field or reserved record byte |
| 6 | `category` | has an unknown category |
| 7 | `type` | has an unknown type, or is a `broker_refusal` |
| 8 | `flags` | has an unknown flag |
| 9 | `network_class` | has a scheme class or loader kind it cannot carry |
| 10 | `typed_payload` | failed its type's payload validator |

## Identity

For reasons 4 to 10, the refusal takes the refused record's place (identity
1, `refused`). It carries the refused record's:
- session, process, thread, sequence number and time;
- tab, navigation, frame, artifact, parent and request identifiers.

These are copied as read. The refused sequence number is therefore accounted
for, and no sequence gap is left.

For reasons 1 to 3, the refused header cannot name that place. Its layout is
unknown (reasons 1 and 2), or it claims the broker's own stream (reason 3).
The refusal then takes the broker's own stream (identity 2, `broker`):
- session as read;
- process 4294967295 and thread 0;
- the broker's next sequence number on that stream, from 1, contiguous within
  one broker run;
- the arrival time as its time;
- every other identifier 0.

The refused record's sequence number stays a sequence gap in its own stream,
and the refusal explains it.

Process 4294967295 is reserved for the broker. The widest process ID a
producer can use is 4294967294. Real process IDs never reach it.

## Category and the session policy

The refusal's category is the refused record's category when it is a known
one, else `unknown`. `unknown` is accepted only on a `broker_refusal`.

The broker applies its session policy to a refused record as it would to a
valid one. This is the disabled behaviour:
- After the session expires, nothing is stored.
- For a known category the session's mask excludes, nothing is stored.

Both still count in `invalid`. An unknown category cannot be matched against
the mask, so its refusal is always kept. Over the authenticated socket, the
broker refuses a record from another session before validation, as before.

## Record

The header is an ordinary version 3 header:
- `type` 53 and `payload_size` 128;
- `flags` 0, `scheme_class` 0 and `loader_kind` 0;
- the browser context, encoded and decoded lengths, status, error, resource
  type and initiator fields all 0;
- the reserved fields and bytes zero.

The payload is 128 bytes, version 1, little-endian:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | version, 1 |
| 2 | 2 | size, 128 |
| 4 | 2 | reason, 1 to 10 |
| 6 | 2 | identity: 1 refused, 2 broker |
| 8 | 2 | refused protocol version |
| 10 | 2 | refused header size |
| 12 | 2 | refused category |
| 14 | 2 | refused type |
| 16 | 4 | refused payload size |
| 20 | 2 | refused flags |
| 22 | 1 | refused scheme class |
| 23 | 1 | refused loader kind |
| 24 | 8 | broker monotonic time the record arrived |
| 32 | 8 | refused sequence number |
| 40 | 8 | refused monotonic time |
| 48 | 4 | refused process ID |
| 52 | 4 | refused thread ID |
| 56 | 72 | zero |

Every refused field is read at its version 3 offset and is not validated.

A reader accepts the record only when all of these hold:
- The header follows the rules above.
- The payload version is 1, its size is 128, and bytes 56 to 128 are zero.
- The reason is 1 to 10.
- The header category is the one the refused category files under.
- The reason agrees with the copied fields:
  - every check before the reason passed and the reason's own check failed,
    for protocol version, header size, process ID, payload size and category;
  - checks 5 and 7 to 10 are not compared, because the bytes they read are
    not kept.
- Identity is 2 exactly for reasons 1 to 3. The header then carries the
  broker's stream, and its time is the arrival time.
- Otherwise the header's process, thread, sequence number and time equal the
  copied ones.

## Counts

The broker's stop line adds `refusals_recorded=` after `invalid=`. `invalid`
still counts every refused record, so `refusals_recorded` is `invalid` minus
the refused records the session policy left nothing for. The exit status is
unchanged: 1 whenever a record was refused.

Each read below counts refusals by `(category, reason)` in first-seen order:
- `/api/events` (`get_events`), the filtered reads and the waiting read return
  them as `broker_refusals`;
- the session summary returns them as `events.broker_refusals`.

A filtered read sees them in its scan order, newest first. A refusal is
neither a queue drop nor a named gap.

The session summary also adds one `broker_refusal` check per pair, with
severity `error`. A producer wrote a record the broker could not accept: that
is a capture bug, and the record is lost except for its refusal.

Every read that returns events puts the decoded record beside the payload hex
as `broker_refusal`:
- `status`, `reason` and `identity`;
- `received_monotonic_time_ns`;
- the `refused` fields.

A record that fails the rules above decodes as `{"status": "invalid"}`.

Origin Trace's status bar adds a clause after the gap counts, for example
`3 records refused by the broker (reserved, type)`, marked as a loss. Signals
does not list a refusal as a signal of its category.

## Compatibility

- A store written before this contract has no refusal records.
- A reader from before it refuses type 53 as an unknown type.
- The backend's event index layout is `reb-event-index-v1/6`, so an older
  index is rebuilt.
- Evidence Package v1 accepts `broker_refusal` with the `unknown` category,
  as it accepted earlier record types.
- The refused record's numeric fields are kept, never its payload, so a
  later reader can tell what was sent without the capture having stored
  anything it refused.
