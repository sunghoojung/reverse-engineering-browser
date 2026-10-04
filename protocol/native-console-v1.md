# Native Console v1

Origin Trace's Console panel runs explicit JavaScript commands in a separately
launched custom Brave process with a fresh disposable profile. It never selects
baseline tabs. Start session is the visible opt-in to mutation and reading page
values. Arbitrary expressions can reveal sensitive content; use only authorized
synthetic or research data. Results stay in bounded panel memory, are never
written to evidence stores, and are cleared explicitly or when Origin Trace
closes. There is no export or automatic command replay.

## Operation

Build the custom browser from the pinned integration before using this feature.
Set `REB_BRAVE_BINARY` to its executable and launch Origin Trace's live backend.
Open **Console**, enter an authorized HTTP or HTTPS URL, start a session, refresh
if the page is still loading, and select a document explicitly. Enter JavaScript
such as `window.location.href`, then use Run or Enter (Command/Ctrl+Enter also
works). Shift+Enter inserts a new line. Up/Down recalls commands still present in
the bounded output. Refreshing
invalidates the selection. Navigation, closure, and document replacement reject
old IDs. Disconnect in the connection menu kills the owned browser process group
and removes its profile.
The offline bundled interface reports the required live backend explicitly.

Console in the top workspace strip opens a bottom dock beneath the current workspace.
The prompt and submitted commands are syntax colored with inert text spans;
primitive results are colored by type. Coloring never evaluates page code.
Each result exposes type, status, session and document IDs, and truncation through
an expandable ellipsis on hover or keyboard focus. Truncated previews keep their
label visible. Routine execution status is shown by the result;
actionable connection errors, stale selections and output eviction remain visible.
Command/Ctrl+J toggles it; closing the dock keeps the session alive. Its top divider supports
dragging, arrow-key resizing, and Home to reset the saved height. The prompt
follows the output in the same scroll area. The compact toolbar keeps session
setup, refresh and disconnect in a connection menu. Enter submits the plain `>`
prompt without a separate Run button.

The existing debugger console drawer remains a log viewer. This panel uses
native associated Mojo messages and V8, without creating an Inspector session,
page-global bridge, extension, or remote-debugging endpoint. Websites can still
observe expression effects, timing, browser differences, and resulting network
traffic. This feature makes no promise of undetectability or zero active cost.

## Ownership and limits

The path is panel -> loopback Rust API -> private C++ pipe bridge -> authenticated
Unix socket -> browser UI dispatch -> selected renderer's existing main-world
V8 context. Renderer code never opens sockets or files. Launch flags enable it
only for the disposable profile; without them no console agent, session worker,
or watchdog is created. Existing observational probes are separate.

Requests are serialized, monotonically numbered, and never retried. Session IDs
and document IDs are canonical decimal u64 strings at the HTTP boundary. Target
IDs are opaque listing-local handles; browser weak-document references and
renderer document tokens independently guard navigation. Source and result text
are each at most 8192 UTF-8 bytes; listings contain at most 64 documents and each
origin has at most 256 bytes. Partial listings and truncated previews are visible.
The panel retains at most 32 entries and 256 KiB of expression/result text and
reports eviction. It inserts every value as inert text.

Execution is synchronous. Primitive results are copied; objects, functions,
symbols, and promises receive generic previews with no retained V8 handles.
There is no property enumeration, custom formatting, autocomplete, or promise
awaiting. Primitive thrown strings are copied; other exceptions receive a generic
message so formatting cannot invoke page accessors or `Error.prepareStackTrace`.

A renderer watchdog requests V8 termination after 200 ms and clears its own
termination before returning. This is a soft synchronous budget, not a hard CPU
or heap quota. Expressions can allocate page memory or schedule asynchronous
work; native blocking calls and worker scheduling can delay termination. Earlier
side effects are not rolled back. The browser rejects commands queued beyond
500 ms, retires a connection if its reply is missing after 2 seconds, and expires
its authenticated connection after one hour. Losing the control channel requests browser exit with unload handlers bypassed.
Backend state/action checks retire expired or dead sessions; Stop or graceful
backend shutdown disposes their profiles. A forced backend crash can leave its
private temporary directory on disk.
Do not interpret a timeout or transport failure as proof that no command ran.

## Wire layout

`common/native_console_protocol.h` in the Brave overlay owns the little-endian,
trivially copyable layouts and ABI checks. Magic is `0x43424552`; version is 1.
The socket authenticates first with the existing 64-byte native IPC hello and
256-bit token. The directory is user-owned mode 0700; socket and token are 0600.
The C++ bridge also checks peer UID. Reserved fields must be zero.

| Record | Fields in byte order |
| --- | --- |
| Request, 32 bytes | magic u32, version u16, operation u16, request u64, target u64, source bytes u32, reserved u32 |
| Response, 32 bytes | magic u32, version u16, status u16, request u64, type u16, flags u16, item count u32, payload bytes u32, reserved u32 |
| Target, 272 bytes | ID u64, origin bytes u16, flags u16, reserved u32, origin bytes[256] |

Operations are 1 (list documents, target and source zero) and 2 (evaluate,
nonzero target, nonempty source immediately following the header). Status codes
are 0 ok, 1 malformed, 2 stale target, 3 forbidden, 4 exception, 5 timeout,
6 disconnected. Types are 0 undefined, 1 null, 2 boolean, 3 number, 4 string,
5 bigint, 6 symbol, 7 function, 8 object, 9 promise, 10 target listing.
Flag bit 0 means truncated. Listings contain exactly item-count target records;
other responses have item count zero and contain bounded UTF-8 text. Empty
transport-timeout responses retire the connection. Invalid lengths, enums,
request IDs, or UTF-8 fail closed before unbounded allocation.

`common/native_console.mojom` describes document identity and evaluation between
browser and renderer. The browser owns target metadata; renderer-owned tokens
and V8 handles never leave their lifetime boundary. HTTP shapes and actions are
specified in [openapi.json](openapi.json).

## Verification

`make native-console-check` exercises the actual C++ bridge and public HTTP API
with an explicitly synthetic browser wire peer. It proves authentication,
transport, bounds, session ownership, disposal, and failure responses. It does
not prove that the Brave overlay compiles or executes JavaScript.

After rebuilding the pinned custom browser, run:

```sh
python3 tools/check-native-console.py --binary build/reb-console --browser /absolute/path/to/custom-brave
```

This adds real renderer execution, exception handling, infinite-loop timeout
and recovery, safe object previews, UTF-8 truncation, navigation rejection, and browser exit on control-channel loss.
Native browser compilation, real execution, and performance measurements remain
required before treating this feature as runtime verified.
