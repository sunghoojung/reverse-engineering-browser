# Paused import-object map v1

`POST /api/debugger/actions`, action `inspect_paused_import_object`, returns an
ephemeral `import_object` report with host-side module/name labels even when
`guest_position` is null. Its closed request/response contracts are in
[OpenAPI](openapi.json), `DebuggerAction` and `DebuggerImportObjectResult`.
The debugger sidebar **Captured document** pane and the VM workbench
**Captured document VM Lab** call this action for a selected local, closure, or
block binding. The report
does not alter the persisted [VM host links](vm-host-links-v1.md) and does not
invent a guest program counter. Existing `inspect_wasm` (`GET /api/wasm`)
inspection supplies static module/name imports for a retained Wasm artifact;
matching those names to this selected object is an analyst comparison, not an
automatic instance or invocation join.

## Evidence boundary

The analyst selects one local, closure or block-scope binding on one attached,
paused page. `Runtime.getProperties` reads own data descriptors only. The action
never evaluates a page expression, invokes an accessor, traverses a proxy,
changes a breakpoint, resumes, or navigates. It does not discover import objects
automatically. Inherited entries, symbols and dynamic getters are not resolved.
An import-shaped object is not proof that a Wasm instance used it: provenance is
`selected-paused-own-properties`, invocation is `unproven`, and guest positions
remain null. A function's own `name` is a mutable label, not its identity.
Available host locations include the exact live script ID, source hash and
execution context, not URL-matched guesses. Missing native/bound-function
locations remain null.

The initial request must match the latest debugger generation and document
owner. During inspection, every CDP read is pinned to the original connection
and rechecks target, document, source catalog, frame/scopes and a monotonic pause
serial. Resume/re-pause with reused frame IDs, reconnect, navigation, source
replacement or detachment discards the result. Scope enrichment alone does not
change the pause owner. Results carry the initial generation and must not be
reused as current source evidence after the owner changes.

The response retains at most 16 namespaces and 64 import entries overall,
examines at most 256 descriptors per object, and has a four-second deadline
with one-second command caps. Bounded omissions are explicit. Overlong names and
symbols are omitted, never truncated into misleading identities. Transport
limits still apply to CDP replies; this is not a claim that the renderer itself
enumerates a large object incrementally. No object handles or function source
text are returned. There is no automatic persistence/export.

## API workflow

1. Pause the owned page in the glue function where its import object is a local
   or closure binding. Read `get_debugger` after scope enrichment settles.
2. Call `debugger_action` with `action: "inspect_paused_import_object"`,
   `expected_generation` from that snapshot, `owner` containing its network
   `instance_id`, network `capture_epoch` as `connection_epoch`,
   `target_document_epoch` as `document_epoch`, and target ID as `target_id`.
   Supply the selected `call_frame_id`, zero-based `scope_index`, and exact
   `binding_name`. No expression or caller-supplied remote object ID is accepted.
3. Inspect the returned namespace/import labels and available host locations.
   A getter/proxy row explicitly says it was not traversed. Missing bindings or
   stale owners fail rather than selecting a different object.
4. To observe a call, explicitly select the mapped original live JavaScript
   location in Sources, Add a source-mode Runtime Hook labeled with the import
   name, then confirm captured-document mutation and Arm. Keep logic/conditions
   empty and return mode `none` for observational entry/return hits. This uses
   existing target/document/source/session guards; mapping grants no consent.
5. Resume the page and trigger the owned benign event. Hook hits retain label,
   timestamp, bounded local/argument bindings and available return values.
   These are hook observations, not fabricated native host events, Wasm call
   sites or dispatch samples. Do not join them by approximate time or label.
6. Disarm and erase the captured hook session with its expected session ID.
   The captured tab remains open. Navigation invalidates consent; select again.

MCP's existing `--allow-effects` visibility and action-owner gates remain
unchanged. The new action is analysis-only, but its shared action endpoint is
not promoted to the default read-only tool set.

## Owned fixture and validation

Run `node apps/runtime-hook-demo/lab.mjs --page imports --port 7321`, then attach
the authorized page at `http://127.0.0.1:7321/`. Choose **Pause before
instantiation**. Select `createOwnedModule`'s local `imports` binding with the
API above. The `env.clock` row resolves to `ownedClock`; the other namespaces
exercise getter/proxy refusal. Add a hook inside `ownedClock`, explicitly arm,
resume, and choose **Run benign Wasm call**. The counter increments and the
getter/proxy trap count remains zero. No CAPTCHA, authentication, request
replay or extracted code is involved.

Rust tests exercise the public action, response schemas, own-property command
allowlist, getter/proxy rejection, missing/ambiguous bindings, stale generation,
frame/scope/document/source/reused-pause/connection rejection, bounds and unavailable
locations using a deterministic local CDP transport. The existing browser E2E
captured-hook test covers real entry/return hits without a disposable navigation.
`make javascript-check` also runs the authored Wasm through the real in-process
V8 inspector, checking function locations, static import names, a benign call
and zero getter/proxy trap executions. These checks are not proof of matched-
Brave acceptance on an arbitrary captured page.
