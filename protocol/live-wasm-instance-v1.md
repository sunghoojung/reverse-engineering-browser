# Live Wasm instance commands v1

Confirmed reads, writes, and calls against the one Wasm instance a command
peer is already attached to. This is not the retired
[live Wasm inspection v1](live-wasm-inspection-v1.md) contract.
`GET /api/debugger` and `POST /api/debugger/actions` still return 410
`debugger_unavailable`. `list_live_wasm_objects` and `read_live_wasm_memory`
stay retired.

The operations are `get_live_wasm` (`GET /api/live-wasm`) and
`live_wasm_action` (`POST /api/live-wasm/actions`). They follow the same
effect and confirmation catalog as the rest of the loopback API. They do not
replace [native Wasm dispatch](native-wasm-dispatch-v1.md) capture, and they
do not emit broker events.

## Named omission: `live_wasm_browser_adapter`

No current Brave or V8 patch serves this socket. Rebuilding Brave from the
pinned revisions does not make a live capture session answer these commands.
When `--live-wasm-socket` is unset, `get_live_wasm` returns
`availability: unsupported` and `reason: browser_command_unsupported`, with
null budget and counters and no attachments. A configured socket that cannot
be used returns the same availability with `reason: peer_unavailable`.
`live_wasm_action` then returns 503 `dependency_unavailable` and sends
nothing. The API does not invent a guest PC, a dispatch sample, memory
bytes, or a return value.

The peer in `apps/origin-trace-backend/src/live_wasm.rs` is the contract
implementation the tests drive. It parses one real core Wasm module and runs
a closed interpreter with no host imports. A future browser adapter has to
enter the real instance the dispatch hooks are already attached to, so those
hooks record samples. This API must not synthesize them.

## Attachment

`get_live_wasm` takes no query. The ready state names one attachment:

- `instance_id`, `document_token_high`, `document_token_low`, `document_epoch`
- named memories (`name`, `byte_length`, `shared`)
- exports (`name`, `kind` `function` or `memory`, numeric `params` and `results`)
- functions (`index`, `params`, `results`, `export` or null)

`budget` is 16, the same cap as `kNativeWasmDispatchSampleBudget`.
`dispatch_samples_used` and `dispatch_gaps` are that shared counter.
`observations` keeps at most 32 rows. The counters stay exact when the window
drops older rows, and `observations_truncated` is then true. An observation
is `page_script` or `live_call`, `sample` or `gap`. A gap has
`reason: native_wasm_dispatch_budget_incomplete` and `sample_index: null`.
A sample carries the instance, document token, document epoch, function
index, and module byte offset of the real `br_table` opcode. Page script and
a live call share one counter. The 17th observation is a gap and does not
invent sample index 16.

This is the attached instance, not a heap scan of every Wasm object.

## Actions

Every action is a JSON object with `confirmed: true` and the four identity
fields copied from the attachment. An unconfirmed body is HTTP 400 and does
not connect. Identity strings are canonical decimal. Argument and result
`bits` are the unsigned bit pattern, so i32 `-1` is `4294967295`. An i32 or
f32 value that does not fit in 32 bits is refused before a command is sent.

| Action | Body | Effect |
| --- | --- | --- |
| `read_memory` | `memory`, `offset`, `length` 1 to 4096 | browser-control, sensitive-capture |
| `write_memory` | `memory`, `offset`, `bytes` 1 to 4096 values 0 to 255 | browser-control, live-target-mutation |
| `call_export` | `export`, `arguments` of `{type, bits}` | browser-control, live-target-mutation, code-execution |
| `call_function` | `function_index` 0 to 16777215, `arguments` | browser-control, live-target-mutation, code-execution |

A slice that would pass the end of the memory is `out_of_bounds`. It is not
clipped. Shared and memory64 memories are not sliced. A successful write's
`memory.bytes` are read back from the memory.

A call checks the declared signature before the function is entered.
`signature_mismatch` has `entered: false` and spends no dispatch sample.
`unknown_export` and `unknown_function` do not enter. `trap` was entered and
trapped, with no result. `did_not_return` was entered and still running after
this peer's 64-instruction step limit, with no result. Those statuses are
fields on the HTTP 200 result. They are not page-script text.

`stale_document` is a document token or epoch that is not the attachment.
`instance_mismatch` is the same document and a different instance. The
document check is first. Neither writes memory or enters a function. The
result echoes the identity that was requested. Read `get_live_wasm` again for
the current epoch.

A call may reach an import. This peer refuses an imported or non-executable
function before entry (`unsupported`, `entered: false`). That is not a
promise that an export body is side-effect free. The call actions therefore
carry a state-dependent `network-access` effect for a callee that navigates,
fetches, or mutates through an import.

## Socket

The backend is a client. It does not start the peer and it does not interpret
page Wasm. The socket must sit in a directory owned by the same user with
mode `0700`, and the socket itself must be mode `0600`, the same user, and
not a symlink. The peer checks the connected process is the same user.

A connect failure before a command is sent is 503 and is a no-op. After the
request bytes are written, a dropped or mismatched reply is 408 or 422
`command_outcome_unknown`. That is not a confirmed no-op.

The framing is little-endian. Magic is `0x31574C52`, version 1. The request
header is 56 bytes: magic, version, opcode, request id, instance, document
token high, document token low, document epoch, payload length, reserved 0.
Opcodes are list 1, read 2, write 3, call export 4, call function 5. The
response header is 32 bytes: magic, version, status, request id, entered,
samples consumed, gap flag, payload length, reserved 0. The payload is JSON
for a result and empty for a framing reject. Header and JSON must agree on
status, entered, samples consumed, and the gap flag.

This peer also refuses a start function, data segments, more than 64
functions, and more than 16 memories. It does not apply data segments, so a
module whose initial memory is not the memory under test is the wrong module
to attach. The interpreter covers the numeric operations the contract tests
use. A body it cannot execute is `unsupported` and is not entered.

## What this does not do

- It does not list every Wasm object in a page.
- It does not change dispatch capture, its budget, or its gap records.
- It does not turn a call that does not return into a broker observation.
  That remains separate work. `did_not_return` is only this command's status.
- It does not evaluate page JavaScript. The native console still cannot name
  a function index, and a navigated document there is `stale_target` rather
  than this command's `stale_document`.
