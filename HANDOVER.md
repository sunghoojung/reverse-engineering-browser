# Handover

Stop here. The live Brave session is already killed. This note is for the next agent.

## Do not

- Do not build a captcha bypass, decoder, key recovery, or solver.
- Do not paste bytecode, script source, deobfuscated output, or request bodies.
- Do not execute captured page bytecode in the owned VM debugger or opcode experiments.
- Do not touch the dirty checkout at `/Users/sunghoojung/Documents/reverse-engineering-browser`. It is `main` at `8fa5922`, 221 commits behind `origin/main`, with uncommitted wire-proxy work (`.codex/`, `response.rs`, `wire_proxy.rs`, `protocol/field-provenance-worker-v1.md`, and the listed script/README edits). Leave it.
- Do not bump Origin Trace past unpublished `0.3.2`, publish a release, or rebuild `Origin Trace.app` unless asked.
- Do not treat `--allow-effects` as authorization or redaction. `SAFETY.md` still governs targets.
- Do not combine `REB_NATIVE_QUIET_MODE=1` with `REB_CDP_NETWORK_CAPTURE=1`. The launcher rejects that.

## Where the work is

- Worktree: `/Users/sunghoojung/.t3/worktrees/reverse-engineering-browser/origin-trace-mcp`
- Branch: `feat/origin-trace-openapi-mcp`
- Base: `f81f757` (`origin/main` at the time of this branch)
- App version stays `0.3.2` (`OriginTraceReleaseType=companion`)
- This PR adds `reb-api mcp`, a stdio projection of the existing loopback OpenAPI. It is not a new HTTP API.

## MCP adapter

`protocol/openapi.json` root extension `x-reb-mcp` is the contract. The server refuses to start if it does not match.

- Command: `reb-api mcp`
- Tool name: `operationId`
- Default tools: the 24 read-only-eligible operations
- `--allow-effects`: also lists the other 15, including VM analysis GETs and owned-fixture actions
- Inline JSON limit: 131072 bytes. Larger JSON is a structural summary, not a truncated document. Source, bytecode, disassembly, and long strings are omitted.
- Binary responses, including `get_artifact_content`, are refused before any HTTP request.
- Root URL must be loopback.

Read-only is not the HTTP verb. Eligibility requires `kind: operation`, effects only `[]` or `analysis`, and empty state-dependent effects, uncertainties, and confirmations. `get_vm_analysis`, `get_deobfuscation`, `get_vm_host_links`, `get_vm_opcode_workspace`, and every `*_action` are outside the default set.

QA already passed for the adapter: `cargo fmt --check`, default `cargo clippy -D warnings` (not `--all-targets`), full `cargo test --locked` for `apps/origin-trace-backend`, `git diff --check`, and `scripts/check-repository-hygiene.sh`. `make lint`, `make check`, `make e2e`, and `make sanitize` were not run. `cargo clippy --all-targets -D warnings` still fails on older test-only lints (`tests/owned_vm_http.rs` `manual_is_multiple_of`; `src/evidence.rs` and `src/vm_opcode.rs` `cloned_ref_to_slice_refs`). Leave those unless the official Makefile lint fails.

## hCaptcha demo QA

Target was the vendor sandbox `https://accounts.hcaptcha.com/demo`. One CDP-attached live session, then MCP with `--allow-effects`. Canvas image capture stayed off. No quiet-mode pass.

Launch that worked:

- Session root: `/tmp/reb-hcaptcha-live/14818819587567938556` (killed; safe to delete)
- `REB_ORIGIN_TRACE_APP` pointed at the existing app in the dirty checkout. The worktree has no `build/Origin Trace.app`, and the launcher exits before Brave if that directory is missing. `REB_OPEN_COMMAND` was a no-op so the old 0.3.1 app UI was not opened.
- Backend wrapper added `--owned-vm-fixture` from this worktree (`build/reb-native-vm-fixture`) and `--deobfuscator` from the dirty checkout's Oct 15 debug worker.
- Broker, artifact receiver, debugger transport, heap snapshot, and decoder binaries came from the dirty checkout `build/`. They spoke to this worktree's backend well enough for this session. That does not prove ABI compatibility in general.
- Brave was the development build under `browser/worktree` in the dirty checkout. A wrapper appended the demo URL because `scripts/run-live-session.sh` has no start-URL flag.
- `REB_CDP_NETWORK_CAPTURE=1`, `REB_USE_SYSTEM_KEYCHAIN=0`, `REB_CAPTURE_CANVAS_IMAGES=0`.

The first launch failed in 0.18s with `Origin Trace is missing. Run: make app-build` before `REB_ORIGIN_TRACE_APP` was set.

## What the session showed

Provenance `capture_mode` was `cdp-attached`. Health was `status: ok`, broker and artifact receiver connected, debugger state `running`.

Four artifacts, every `parent_artifact_id` `0`:

| id | kind | origin | bytes | host |
| --- | --- | --- | ---: | --- |
| 1 | javascript | network_response | 389901 | js.hcaptcha.com |
| 2 | wasm | webassembly_module | 8 | newassets.hcaptcha.com |
| 3 | javascript | network_response | 1497047 | newassets.hcaptcha.com |
| 4 | wasm | webassembly_instantiate | 984082 | newassets.hcaptcha.com |

No `bytecode_buffer` artifact. Event types had no `vm_dispatch_sample` (0 lines). Categories that did fire included network, runtime, artifact, navigator, canvas, webrtc, storage, permissions, web_audio, and webgl. Canvas image capture was off; canvas events still arrived. One `gap` event was present (`input_coverage` reason `capture-gap`).

Catalog retained 12 records, skipped 4, dropped 0. Visible method/host/path rows included GET `js.hcaptcha.com` `/1/api.js`, GET `accounts.hcaptcha.com` `/favicon.ico`, GET `newassets.hcaptcha.com` widget assets, GET logo hosts, and POST `api.hcaptcha.com` `/checksiteconfig`. One logo host was `failed` in the debugger network list. The page was not paused when `/api/debugger` was read (`state: running`). Initial script load and `checksiteconfig` happened with CDP attached. That does not show whether a later inspector check poisoned guest execution.

`get_origin_trace` requires `request_id` in OpenAPI even though the description sounds optional. Request id `1` returned `status: partial`, 1 step, 0 artifacts, 1 gap.

## VM features through MCP

Called with `reb-api mcp --allow-effects` against `http://127.0.0.1` from `research-ui.endpoint`.

| tool | result |
| --- | --- |
| `get_health` | ok, debugger running |
| `get_vm_debugger` | helper available, no session yet |
| `get_owned_opcode_experiments` | empty records |
| `get_vm_opcode_workspace` | returned inline |
| `get_artifacts` | 4 artifacts, parents 0 |
| `get_events` | limit 20 returned |
| `get_api_observation_catalog` | returned |
| `get_vm_analysis` | HTTP success, then MCP omitted the body |
| `get_vm_host_links` | same omission |
| `get_debugger` | same omission |
| `get_deobfuscation` artifact 1, mode `analysis` | same omission |
| `inspect_wasm` artifact 2 | decoded, 8 bytes, 0 sections, 0 functions |
| `inspect_wasm` artifact 4 | HTTP success, body omitted |
| `vm_debugger_action` create/step/pause/stop `register` | completed on `owned-register-v1` |
| `get_vm_debugger_trace` | retained the owned step |
| `run_owned_opcode_experiment` using the captured workspace digest | HTTP 409 `Owned experiment source or workspace selection is stale` |
| experiments after that 409 | still empty |
| `vm_pack_apply` with `assets/anti-bot-pack-v1.json` | HTTP success, body omitted because the report embeds the full analysis |
| `vm_pack_compare` of the live workspace against that pack | HTTP 400 `Selected source digest has no declared program-family binding` |
| `get_origin_trace` without `request_id` | MCP `Missing parameter: request_id`, no request sent |

Direct loopback reads were used only where MCP had already received a success and then dropped the body. Those reads were reduced to counts before they were kept.

VM analysis (`origin-trace-vm-detector` 1.3.0), 4 artifacts, 0 failures:

- artifact 1 JavaScript `candidate`, score 100, status `partial`, bytecode snapshot unavailable
- artifact 2 wasm `none`, score 75, the 8-byte module
- artifact 3 JavaScript `candidate`, score 100, status `partial`, bytecode snapshot unavailable
- artifact 4 wasm `likely-vm`, score 75, status `partial`

Opcode workspace (`origin-trace-vm-opcode` 2.1.0), `capture_mode: cdp-attached`:

- summary: 3 workspaces, 18 handlers, 0 samples, 0 snapshots, 6 unknowns
- artifacts 1 and 3: JavaScript, model `unknown`, 0 handlers, 0 characterized bytes, traversal incomplete, 0 edges. Unknowns: no proven fixed opcode mapping, no stack or register identifier. Omissions: `handler-unavailable`, `sampler-unavailable`, `runtime-snapshot-unavailable`, `reachable-frontier`, `snapshot-bytes-unavailable`
- artifact 4: wasm, 18 handlers (17 inferred, 1 unknown), 0 samples, 0 snapshots, 0 characterized bytes, traversal incomplete, 0 edges. Unknowns: guest model, operand widths, and state effects unknown; WASM selectors are not proven guest opcodes or handler bodies. Same sampler, snapshot, frontier, and snapshot-byte omissions

Host links: 100, 256, and 256 rows. Every row reason was `dispatch-samples-unavailable`. Guest positions were empty. The link lists are not evidence that a guest instruction caused a host event.

Wasm inspection of artifact 4: schema `wasm-inspection-v1`, status `partial`, 984082 bytes, 9 sections, 15 defined functions, 186 imported functions, 7876 instructions, row cap 8192 with 1 omission. Notice: static decoding only.

Deobfuscation of artifact 1: HTTP 200, schema `deobfuscation-analysis-v1`, engine `rust-oxc`, mode `analysis`, source not truncated (389484 chars). Only key names and collection sizes were kept. Do not fetch `original_source` into a report.

Owned fixture: create paused at pc 0, one step retained, pause and stop completed, `target_kind: owned_fixture`, program `owned-register-v1`. That run did not add page dispatch samples. The captured-workspace experiment was rejected before execution.

## Second demo pass

Fresh session `3943300171726072501` under `/tmp/reb-hcaptcha-mcp`. The page was opened once with CDP `PUT /json/new`. The checkbox was not clicked. Canvas image capture stayed off. Mock keychain was on. The session is stopped.

The branch launcher passes `--native-console-live-directory`. The installed Origin Trace.app `0.3.2` (32) backend rejects that flag, so this pass used that app's own launcher and binaries, and the branch `reb-api mcp --allow-effects` against its loopback root. Brave Development was `151.1.95.0`. Provenance `capture_mode` was `cdp-attached`. Health was ok, with the broker and artifact receiver connected and the debugger `running`.

Five artifacts, every `parent_artifact_id` `0`:

| id | kind | origin | bytes | host |
| --- | --- | --- | ---: | --- |
| 1 | javascript | network_response | 40274 | newtab |
| 2 | javascript | network_response | 389901 | js.hcaptcha.com |
| 3 | wasm | webassembly_module | 8 | newassets.hcaptcha.com |
| 4 | javascript | network_response | 1478662 | newassets.hcaptcha.com |
| 5 | wasm | webassembly_instantiate | 971370 | newassets.hcaptcha.com |

Event tail: 1269 records. `property_read` 862, `api_call` 309, `request_initiated` 56, `request_started` / `response_started` / `request_completed` 12 each, `artifact_captured` 5, `gap` 1. No `vm_dispatch_sample`.

Catalog: 23 retained, 15 skipped, 0 dropped, 7 endpoint groups. `GET /1/api.js` and the widget script were 200. `POST /checksiteconfig` was 200. One logo response was `failed`. Response bodies that were present were truncated. No request body was copied into this note.

MCP with the structural summary, 39 tools listed:

| tool | result |
| --- | --- |
| `get_vm_analysis` | summary of 1407433 bytes |
| `get_vm_host_links` | summary of 133675 bytes |
| `get_vm_opcode_workspace` | inline, under the limit |
| `inspect_wasm` artifact 3 | inline, decoded, 8 bytes, 0 sections |
| `inspect_wasm` artifact 5 | summary of 1102127 bytes |
| `get_deobfuscation` artifacts 2 and 4 | summaries, `original_source` omitted |
| `get_origin_trace` without `request_id` | `Missing parameter: request_id`, no request sent |

`vm_pack_apply` and the owned debugger were not called.

VM analysis is `origin-trace-vm-detector` 1.2.0 from the installed app, not 1.3.0. Summary: analyzed 5, likely-vm 3, failed 0, candidates 0, mixed 0. Input coverage is incomplete, one `capture-gap`.

- artifact 1: tier `none`, score 0, anti-bot 80, status `partial`
- artifact 2: `likely-vm`, score 60, anti-bot 100, status `partial`. Omissions `javascript-unterminated-function` and `capture-gap`. Bytecode snapshot unavailable. Family `dispatch`
- artifact 3: tier `none`, score 0, anti-bot 75, status `partial`. Omissions `runtime-graph-edge-limit` and `capture-gap`
- artifact 4: `likely-vm`, score 60, anti-bot 100, status `partial`. Omissions `javascript-unterminated-function`, `runtime-graph-edge-limit`, and `capture-gap`. Families `dispatch` and `handlers`
- artifact 5: `likely-vm`, score 95, anti-bot 75, status `partial`. Omissions `runtime-graph-edge-limit` and `capture-gap`. Families `wasm.dispatch-loop` and `wasm.handler-table`

Opcode workspace is `origin-trace-vm-opcode` 2.0.0, `capture_mode: cdp-attached`. Summary: 3 workspaces, 105 handlers, 0 samples, 0 snapshots, 6 unknowns. Artifacts 2 and 4: model `unknown`, 0 handlers, 0 characterized bytes, traversal incomplete, 0 edges. Omissions `handler-unavailable`, `sampler-unavailable`, `runtime-snapshot-unavailable`, `reachable-frontier`, `snapshot-bytes-unavailable`. Artifact 5: 105 handlers (104 inferred, 1 unknown), 0 samples, 0 characterized bytes, 0 edges. Same omissions except `handler-unavailable`.

Host-link summary: artifact 2 has 100 rows, artifacts 4 and 5 have 256. Every reason is `dispatch-samples-unavailable`. Every `guest_position` is null.

Wasm artifact 5 summary: status `partial`, 971370 bytes, 9 sections, 24 defined functions, 188 imports, 7863 instructions, 8192 rows, 1 omission. Instruction text was omitted.

Deobfuscation summaries: engine `rust-oxc`, mode `analysis`. Artifact 2 classification `minified`, confidence 95, source omitted (389484 chars). Artifact 4 classification `packed`, confidence 55, source omitted (1478662 chars). String-table entry values were not inlined.

## Gaps that still exist

1. No live producer emitted `vm_dispatch_sample`. Workspace omission `sampler-unavailable` is still the live result.
2. No runtime bytecode snapshots. `snapshot_count` is 0, there is no `bytecode_buffer` artifact, and both JavaScript bytecode snapshots are unavailable. The older "allocate-then-XOR snapshot is zeros" bug was not observable because no snapshot was retained (`runtime-snapshot-unavailable`, `snapshot-bytes-unavailable`).
3. `parent_artifact_id` is 0 on every artifact, including the five from the second pass. Child scripts and the wasm instantiate did not join a parent.
4. JavaScript opcode workspaces for the two large scripts have zero handlers. The wasm `likely-vm` workspace has static handler candidates only. Model stays `unknown`.
5. Guest CFG is absent: traversal incomplete, 0 edges, omission `reachable-frontier`. Characterized guest bytes are 0.
6. Host events (canvas, webgl, audio, network) are stored, and host-link rows exist, but none attach to a guest position.
7. Owned debugger and owned opcode experiments stay on the repository fixture. They do not fill the page opcode workspace. The captured hCaptcha workspace was refused.
8. `vm_pack_compare` has no program-family binding for this capture. `vm_pack_apply` was not repeated. An oversized pack report now returns a structural summary instead of an omitted body.
9. CDP was attached for the whole session. Scripts and `checksiteconfig` still loaded, and the debugger was `running` rather than paused at read time. A quiet-mode comparison was not done. Quiet mode would drop CDP, the debugger tools, and this network catalog. The second pass also did not click the checkbox.
10. Oversized JSON now returns a structural summary. On the second pass that covered VM analysis, host links, both deobfuscations, and the real wasm inspection. Source and string-table values stayed omitted. The opcode workspace was still small enough to inline.

## Suggested next product work

Stay on owned fixtures, imported traces, or static findings. Do not add page-guest VM tracing, inspector hiding, or decryption of stored bytes.

Useful follow-ups, in order:

- A live `vm_dispatch_sample` producer is still missing. Until it exists, opcode evidence on a page stays static and `sampler-unavailable`.
- Runtime buffer snapshots and `parent_artifact_id` joins are still missing on this capture path.
- JavaScript dispatch regions on this demo produced workspaces with no handlers. That is a static extractor gap, separate from the missing sampler.
- Re-run only if asked, and prefer a fresh `/tmp` session. Delete `/tmp/reb-hcaptcha-live` and `/tmp/reb-hcaptcha-mcp` when they are no longer needed. The `/tmp` wrappers (`reb-no-open.sh`, `reb-brave-demo.sh`, `reb-backend-vm.sh`) were session-local and are not part of this branch.
