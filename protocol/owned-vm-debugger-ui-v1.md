# Owned native VM debugger UI v1

The live component consumes the existing loopback debugger API. It is separate
from `vm_semantics.js`, imported `reb-vm-trace-v1`, and its int32 hypothesis
engine. It contains no interpreter, synthetic execution fallback, arbitrary
program input, source capture, or Traffic identity constructor.

## Integration

Load `apps/research-ui/vm_debugger.js` as a classic script, then call
`mountOwnedVmDebugger(root, {request, onState})`. Both options are optional:

- `request(path, init)` defaults to `fetch` and accepts a fetch-compatible
  response. Test doubles may return a parsed envelope. Requests use same-origin
  credentials, no-store reads, an abort deadline, and fixed API paths.
- `onState(validatedView)` is an informational callback for the app's compact
  current-run return control. It must not execute or replay controls.

The return value exposes `toolbar`, `panes`, `refresh()`, `setVisible(boolean)`
and `destroy()`, as well as named stable control elements for integration tests.
Place the toolbar in the persistent VM-provider strip, outside hidden
Findings/Imported/Live detail roots. A compact navigation return entry can expose
the current run when another workspace is shown. Do not add a global overlay or
change Requests/Console layout to host it.

`setVisible(false)` hides detail panes and suspends polling. It does not pause,
stop, close, reset or cancel the backend's run. Integration keeps reads active
while the VM screen is visible and either Live details or the persistent
active-session controls are visible; Findings/Imported can therefore retain
fresh controls without showing Live details. Leaving the VM screen or hiding
the page suspends reads and marks the toolbar last-observed. Returning performs
an inert state read. `destroy()` cancels future local polls; it is not a control
command. The server's bounded lifetime remains authoritative.

Component styling is scoped under `owned-vm-debugger-` classes. The toolbar wraps
controls; the three detail panes are navigation, retained execution, and state
inspection. Tables/history/audit need bounded scroll containers and `min-width:
0`; long identifiers and full uint64 decimal/hex strings must remain readable.
Use clear `:focus-visible`, and stack panes on narrow viewports. Keep the
toolbar visible and all buttons reachable without horizontal page overflow.

## Control and reconciliation

Mounting, returning, filtering, selecting rows, changing inspector tabs and
reading raw audit data issue no execution action. Create is explicit and accepts
only the fixed `register` or `stack` fixture. The initial snapshot has no fake
completed instruction row.

All mutation requests have a fresh command ID. Existing-run actions include the
exact backend-instance/session/run/generation scope. Run additionally binds the
control revision. Step binds both control revision and executed count.
Pause/Stop/Reset/Close do not bind a progress counter that could change while
running. Unsafe actions are disabled during pending commands; Pause and Stop
remain reachable where the exact run is known. Pending text says requested and
does not claim the stable outcome before its acknowledgment.

Only one status GET is outstanding. Scheduled status reads begin no faster than
250 ms after the previous read completes and only while the page/VM screen and
either live details or persistent active-session controls are visible. Explicit refresh and post-control reconciliation are inert reads, not
automatic command retries. Responses from reads begun before a newer command
cannot overwrite its result. Within one exact run, lower control/snapshot
revisions or a decreasing executed count cannot regress the displayed view.
Reset and backend restart invalidate old run selection. A late Step response
cannot undo a newer Stop.

HTTP cancellation is not rollback. A missing, malformed, mismatched or uncertain
acknowledgment disables Run/Step until status reconciles the command or the user
explicitly resets/closes the run. The UI never resends a command. Shared typed
rejection codes are distinguished from unknown transport outcomes, but neither
is automatically retried. Expiry and helper-disposal failure remain visible;
disposal failure blocks replacement.

If Create loses its response and a subsequent same-backend read still has no
session, the UI cannot conclude that the earlier command was cancelled. It
offers a separate **Create new attempt** button only after that fresh read. The
warning explains that the old request can still take effect and the new command
may be rejected. Only an explicit click submits a fresh command ID; the backend
admits at most one starting/active session before spawning, never replacing it.
Repeated rejected attempts preserve the original ambiguity. A subsequently
discovered session removes this recovery path.

Successful Stop/Close can acknowledge an unknown in-flight instruction outcome.
Their strict outer annotation is `code: command_outcome_unknown` with
`details: {phase: command_exchange, cause: disconnected}`. This is not an error
envelope. Stop retains last-confirmed evidence with unknown execution state;
Close returns no session only after confirmed disposal. A failed disposal is a
separate error and blocks replacement.

## Evidence and navigation

Native snapshots, before/after records, operands, effects, counters and recorder
scope retain their wire types. All guest values, PCs, addresses, ticks, identity
counters and revisions are canonical uint64 decimal strings. Rendering uses
BigInt for lossless hexadecimal and comparison; it never converts guest data to
Number or the imported int32 model. Unknown evidence remains unknown and carries
zero stored bits; absent cells are distinct from unknown cells and observed zero.
Duplicate JSON keys, noncanonical numeric encodings, unexpected fields, unknown
enums and excess array bounds fail closed while preserving the prior view.

The live cursor always shows the current last-confirmed native snapshot. A
selected retained sequence is independent and stays pinned as more records
arrive. Return to live cursor is explicit. Loss can leave a current snapshot
without a retained transition; this is shown directly, not bridged across the
gap. Retained sequence gaps and individual recorder counters are visible, and
are never added together as if they were independent loss counts.

The Instruction tab exposes typed operands and every reported read/write effect.
Registers, Stack and Memory show before/after evidence, changes, absent cells and
explicit accesses. Opcode names are declared semantics of these two fixtures,
not inferred universal opcode definitions. The expandable raw audit preserves
the full validated session/provenance, recorder identity, loss, diagnostics and
selected native record. Guest addresses are never host pointers.

Buttons use native Enter/Space activation. Arrow/Home/End handling is scoped to
the retained row or inspector tab that has focus and only changes selection.
It ignores composition, repetition and modifiers. There are no F8/F10/global
execution shortcuts in this slice. Before a local pending command disables its
focused button, focus moves to stable Refresh status. The original button is
restored only if it is enabled when the command settles and the user has never
moved focus elsewhere. Otherwise Refresh remains usable. Ordinary polls update
stable nodes and never switch inspector tabs. Focus relocates only if its owner
is about to be disabled (for example on expiry) or a scope replacement removes
the currently focused history/opcode control. A recovery button that loses eligibility while focused stays
inert until the user leaves it, then hides.

## Validation

`node tools/check-owned-vm-debugger-ui.mjs` runs deterministic strict-codec,
controller and lightweight DOM checks. These are not rendered acceptance.

`node tools/check-owned-vm-debugger-ui.mjs --browser` additionally runs authored
HTTP-response UI checks with normal sandboxed Chromium, using the actual
component and app CSS at 1440×900, 1024×768 and 390×844. Its page explicitly labels
the responses as authored and never claims native execution. Set
`REB_UI_CHROMIUM` for a supported browser and `REB_OWNED_VM_UI_OUTPUT` for the
receipt/screenshot directory; default output is a temporary-directory folder.
Do not bypass a browser sandbox or socket denial to run it.

The exported `checkOwnedVmDebuggerInteractions({evaluate, viewport, click, key,
screenshot, root, toolbarRoot})` requires an isolated actual backend and helper.
It exercises initial paused state, three expected register instructions,
Run/Pause quiescence, history selection, halt, Reset, Stop/Close, and a stack
fixture step. `root` selects the live detail root; `toolbarRoot` selects an
ancestor containing relocated controls. This flow is authored for the rendered
real-helper gate, not a fake-response replacement for it. Native packaging and
macOS interaction remain separate required acceptance checks.

A durable real-backend command is:

```sh
node tools/check-owned-vm-native-browser.mjs \
  --backend apps/origin-trace-backend/target/debug/origin-trace-backend \
  --helper build/reb-native-vm-fixture \
  --browser /path/to/chromium \
  --output /path/to/validation
```

All four paths are required. This runner creates fresh temporary evidence stores,
starts the actual Rust backend on an ephemeral loopback port with the specified
native helper, loads the integrated UI in a normal sandboxed Chromium, and opens
Advanced → VM workspace → Live owned fixture through rendered controls. It then
runs the real-helper keyboard/state/provider-switch flow. It never starts a
mock-response server or substitutes a JavaScript VM.

Each invocation creates a unique `run-*` subdirectory under the requested output
directory with a private validation receipt and any screenshots. Missing
binaries, browser startup restrictions, runtime exceptions, failed assertions,
or cleanup failures produce failed receipts. Teardown sends an explicit
exact-scoped Close if a session remains, then requests graceful backend SIGTERM
and verifies process exit. Forced backend termination is a failure and cannot
claim confirmed helper disposal. Browser cleanup is restricted to its owned
process group. Temporary profiles/stores are retained if cleanup is unverified.
