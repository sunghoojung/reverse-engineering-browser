# Agent feature coverage

Every user-facing Origin Trace feature, mapped to the `reb-api` operations an
agent calls for it. Tool names are OpenAPI operation IDs, so the same names
work in the in-app agent, in `reb-api mcp`, and with `reb-api call`.
[`protocol/openapi.json`](../../protocol/openapi.json) owns the contract and
[`x-reb-mcp`](../../protocol/http-api.md#permission-levels-and-content-reads) owns which tools a
connection lists.

**Level** is the lowest permission level at which the in-app agent, or a
client started with `reb-api mcp --permission`, can use the feature:

- **R**: Read only. Structural reads, with captured content omitted.
- **A**: Ask for actions, and Auto-approve actions. The same tools; Ask needs
  Allow once per action, Auto-approve does not.
- **F**: Full access. Content reads, local store paths and drafts, and the
  agent's own live capture sessions.

**Status** says whether an agent could use the feature before this change
(*Covered*), can now (*Added*), can use part of it (*Partial*, with what is
missing), or cannot, with the reason (*Not exposed*). Operations marked "Ask"
in the cookbook are the same as level A here.

Recipes for the calls are in the [agent cookbook](agent-cookbook.md).

## Session and capture

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Session identity, capture mode, capture options, admission | `get_session_context` | R | Covered; now also reports `mcp_admission` (the level) |
| What a capture recorded, gaps, checks | `get_session_summary` | R | Covered |
| Backend health and local store paths | `get_health` | F | Covered; in the dock only at Full access, because it names local paths |
| Capture state in the sidebar | `get_session_context`, `get_session_summary` | R | Covered |
| Stop probes, Clear events (Fingerprinting buttons) | `capture_action` `stop`, `clear` | A | Covered |
| Wait for new activity after an action | `wait_for_events` | R | Covered |
| Start a live capture session with named options | `start_live_session` (MCP) or `reb-api session start` | F | Covered for outside clients; Added for the in-app agent |
| Open a URL, click, type, press, scroll, list inputs in that session | `session_action` | F | Covered for outside clients; Added for the in-app agent |
| Reset both Wasm sample budgets without a new session | `session_action` `reset_wasm_sample_budgets` | F | Covered for outside clients; Added for the in-app agent |
| End a session the agent started | `session_action` `end` | F | Covered; the connection now returns to the session it was opened on |
| New Live Session… for the researcher's own capture | none | none | Not exposed: SAFETY.md keeps the researcher's session under the researcher's control; the agent starts its own sessions instead |
| Keychain toggle in New Live Session… | none | none | Not exposed: agent sessions never use the macOS Keychain (SAFETY.md) |
| Open Live Workspace, Quit, window menus | none | none | Not exposed: window management of the app itself |

## Live session options and capture switches

Every option is off unless the start names it, and none is inherited.

| Option | `start_live_session` field | Level | Status |
| --- | --- | --- | --- |
| Page to open | `url` | F | Covered |
| Wasm `br_table` dispatch | `wasm_dispatch` | F | Covered |
| Wasm `call_indirect` targets | `wasm_call_indirect` | F | Covered |
| Sampling budgets per function and per indirect site | `wasm_samples_per_function`, `wasm_samples_per_indirect_site` | F | Covered |
| Function allow and deny lists, module allowlist | `wasm_function_allow`, `wasm_function_deny`, `wasm_module_allowlist` | F | Covered |
| Guest adapter recipe | `guest_adapter` | F | Covered |
| JavaScript dispatch sites | `js_dispatch_sites` | F | Covered |
| Ignore page `debugger;` statements | `quiet` | F | Covered |
| Capture category mask, duration, loopback-only fixtures | `category_mask`, `duration_seconds`, `localhost_only` | F | Covered |
| Request call stacks | `request_stacks` | F | Covered |
| Document-start Console permission | `document_start` | F | Covered |
| Invocation sites from a file, or the agent's saved set | `js_invocation_sites`, `js_invocation_saved_sites` | F | Covered |
| Request content (paths, queries, bodies, headers, cookies, response bodies) | `request_content` with `confirm_sensitive_capture` | F + sensitive | Covered; under `--permission full` also needs `--allow-sensitive-capture` (the dock's sensitive box) |
| Request content budget | `request_content_budget_mib` | F + sensitive | Covered |
| Response body budget | `response_body_budget_mib` | F + sensitive | Added |
| Element images, audio, video and fonts | `response_media` | F + sensitive | Added |
| Canvas images | `canvas_images` with `confirm_sensitive_capture` | F + sensitive | Covered |
| Invocation value digests | `js_invocation_digests` with `confirm_sensitive_capture` | F + sensitive | Covered |
| Publish the canonical endpoint, Brave binary, start timeout | `publish_canonical_endpoint`, `brave_binary`, `timeout_seconds` | F | Covered |
| Browser-internal pages and extension traffic | none | none | Not exposed: SAFETY.md says agent-started sessions never set `REB_CAPTURE_BROWSER_INTERNAL` or `REB_CAPTURE_EXTENSION_TRAFFIC` |
| Packaged-app opt-outs (`REB_NATIVE_WASM_DISPATCH=0` and similar) | none | none | Not exposed: they configure the researcher's own app session; agent sessions name each switch instead |

## Traffic

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Request table with exact totals, sort, order and filter tokens (`domain:`, `status-code:` and the rest) | `get_requests` (`q`, `sort`, `order`, `type`, `tab_id`, `domain`, `failed`, `third_party`, `through`) | R | Covered |
| Browser tabs and request owners | `get_requests` `tab_id`; `get_events` | R | Covered |
| Timing strip (request starts over time) and its range filter | `get_requests` (`since`, start times in rows) | R | Covered; the chart itself is drawn by the page |
| General tab | `get_requests`, `get_events` per member | R | Covered |
| Headers tab | `get_request_headers` | R | Covered; credential header values are withheld at every level |
| Payload tab (request body) | `get_artifact_text` on the `request_body` artifact | F | Added (before: binary only, refused by MCP) |
| Preview and Response tabs (response body) | `get_artifact_text` on the `response_body` artifact; `get_source_format` for JSON and JavaScript bodies | F | Added; Preview's rendered image or page is drawn by the page and stays there |
| Cookies tab and cookie provenance | `get_request_cookies`, `get_cookie_provenance` | R | Covered; cookie values are withheld at every level |
| Initiator tab (call stack) | `get_request_stack` | R | Covered |
| Timing tab | `get_events` for the request's records | R | Covered |
| Signals tab | `get_request_signal_profile` | R | Covered |
| Evidence tab and Inspect observations & artifacts | `get_events`, `get_artifacts` with filters | R | Covered |
| Trace origin | `get_origin_trace` | R | Covered |
| Decode value | `decoder_action` `transform` with the value | A, or F to read the value | Partial: below Full access captured values are omitted, so the agent can decode only values it can see or the researcher pinned |
| Related VM candidates | `get_vm_analysis` | A | Covered |
| Save to Collection | `get_api_collection`, `replace_api_collection` | F to read, A to write | Covered; the dock reads the Collection only at Full access, because it holds the researcher's drafts |
| Rename request (evidence names) | `get_analyst_workspace`, `analyst_action` `replace_local_analyst_workspace` | F to read, A to write | Covered; names live in one Analyst file |
| Export… (Go, JavaScript or Python client project) | none | none | Not exposed: the generator runs in the page and writes a ZIP through the macOS Save dialog the researcher controls. An agent reads the same inputs (`get_requests`, `get_request_headers`, `get_request_cookies`, `get_artifact_text`) and writes a client itself |
| Copy URL | none | none | Not exposed: clipboard only; the URL is in `get_requests` |
| Column choice, widths, pane layout | none | none | Not exposed: per-viewer layout stored in the page |

## Sources

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Source tree, Captured tab, Open file, quick open | `get_artifacts` (`kind`, `host`, `frame_id`, `sha256`) | R | Covered |
| Source text in the editor | `get_artifact_text` (pages of 64 KiB); `get_source_format` (`start_line`, `line_count`) | F | Added |
| Pretty print `{ }` | `get_source_format` | A (layout), F (text) | Covered; below Full access the laid-out text is omitted, at Full access request and response bodies are laid out too |
| Search text in all retained files | `search_artifact_text` | F | Added (before: the page read every file itself) |
| Find in source, Go to line | `search_artifact_text` (`artifact_id`), `get_artifact_text` (`offset`) | F | Added |
| Inspect (Wasm disassembly) | `inspect_wasm` with `row_offset`, `row_limit`, `sections` | R (structure), F (instruction text) | Added row windows; below Full access row text is omitted |
| Graph (basic-block graph) | `get_wasm_functions`, `get_wasm_function_graph` | R | Covered |
| Map (entropy and kind map) | `get_artifact_map` | R | Covered |
| Facts | `get_source_facts` | A | Covered |
| Track calls (saved invocation sites) | `get_js_invocation_sites`, `resolve_js_invocation_site`, `js_invocation_site_action` | R to read, A to change | Covered |
| Static cleanup (deobfuscation) | `get_deobfuscation` | A (structure), F (transformed source) | Covered |
| Decode range | `decoder_action` with bytes read by `get_artifact_text` `encoding=hex` | F | Partial: two calls instead of one selection |
| Rename | `analyst_action` (evidence names file) | A | Covered |
| Cross-references for the selection (X) | `get_xrefs` | R | Covered |

## VM

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Findings, Program Trees and handlers | `get_vm_analysis`, `get_vm_opcode_workspace` | A | Covered (they write a derived cache, so they are actions) |
| Execution and host links | `get_vm_host_links` | A | Covered |
| Live fixture (owned VM debugger) | `get_vm_debugger`, `get_vm_debugger_trace`, `vm_debugger_action` | R to read, A to run | Covered |
| Opcode experiments | `get_owned_opcode_experiments`, `run_owned_opcode_experiment` | R to read, A to run | Covered |
| Analysis packs | `vm_pack_apply`, `vm_pack_compare` | R | Covered |
| Guest bytecode snapshots | `get_artifacts` `kind=bytecode_buffer`, `get_artifact_text` `encoding=hex` | F | Added |
| Static bytecode, Contextual, Opcode ledger | none; `vm_pack_apply` and raw bytes cover the inputs | none | Partial: these views decode researcher-imported definitions in the page and store nothing a server could read. The agent applies a declarative pack server side with `vm_pack_apply` and reads bytecode with `get_artifact_text` |

## Fingerprinting and Backtraces

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Overview, Activity, Request link | `get_events` (category and type filters), `get_request_signal_profile` | R | Covered |
| Stop probes, Clear events | `capture_action` | A | Covered |
| Backtraces: load a trace, steps, events | `get_origin_trace`, `get_events` | R | Covered |

## Evidence screen and metadata packages

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Observations, Selected record, Previous, Next | `get_events`, `get_artifacts` with cursors | R | Covered |
| Metadata package export | `export_evidence_package` | R | Covered; the page's Save dialog is the page's |
| Validate a supplied package | `validate_evidence_package` | R | Covered |
| Compare supplied packages | `compare_evidence_packages` | R | Covered |

## Collection, Analyst and notebook

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Collection folders, requests, variables | `get_api_collection`, `replace_api_collection` | F to read, A to write | Covered |
| Analyst folders, scripts and notes | `get_analyst_workspace`, `analyst_action` `replace_local_analyst_workspace` | F to read, A to write | Covered |
| Run and cancel a saved script, run history | `get_analyst_runner`, `analyst_action` `run_local_analyst_script`, `cancel_local_analyst_script` | R to read, A to run | Covered |
| Investigation notebook | `get_analyst_workspace`, `analyst_action` (the notebook is an Analyst file) | F to read, A to write | Covered |

## Tools

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Decoder chain | `get_decoder_state`, `decoder_action` `transform` | R to read, A to run | Covered |
| JWT inspect, verify and create | `decoder_action` `jwt_inspect`, `jwt_verify`, `jwt_create` | A | Covered |
| Float32 comparison | `compare_float32` | R | Covered |
| Analysis catalog | `get_analysis_catalog` | R | Covered |

## Docks and panels

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Cross-references dock | `get_xrefs` | R | Covered |
| Console: documents, frames, connect, evaluate, messages | `get_native_console`, `native_console_action` | A | Covered |
| Console document-start scripts | `native_console_action` `arm_document_start`, `clear_document_start`; `get_native_console_document_start` | A | Covered |
| Console snippets, filter, command history | none | none | Not exposed: editor state of the panel; the agent evaluates any source directly |
| Live Wasm memory and calls | `get_live_wasm`, `live_wasm_action` | A | Covered; a current Brave has no peer, so it reports unsupported |
| Native debugger (breakpoints, stepping) | `get_native_debugger`, `native_debugger_action` | A | Covered; reports unsupported until a pausing debugger ships |
| Agent dock (provider, model, transcript, permission) | none | none | Not exposed: the agent's own controls stay with the researcher |

## Workspace chrome

| Feature | Operations | Level | Status |
| --- | --- | --- | --- |
| Command palette search | `get_requests` `q`, `get_artifacts`, `search_artifact_text` | R, F for text | Covered through the reads it searches |
| Investigation Back, Forward, Clear return history | none | none | Not exposed: the viewer's navigation history |
| Appearance (theme), sidebar collapse, pane sizes | none | none | Not exposed: per-viewer visual preferences |

## Totals

The tables have 100 rows.

- **Before this change**, 76 rows were covered for a client started with
  `--allow-effects --allow-session-start`. The in-app agent had nine fixed
  reads (`get_session_context`, `get_session_summary`, `get_events`,
  `get_artifacts`, `get_origin_trace`, `get_request_signal_profile`,
  `get_analysis_catalog`, `get_js_invocation_sites`, `inspect_wasm`) plus,
  with actions on, every effectful operation. It could not read content or
  start sessions, and every action needed Allow once.
- **Now** 85 rows are covered: the 76, plus 9 added (request and response
  bodies, source text, search across files and within one, Wasm row windows,
  guest bytecode, and the two response options), and the in-app agent can use
  all of them at the level each row names, including session control at Full
  access.
- **3 rows are partial**: Decode value and Decode range need the value read
  first (Full access, or a pin), and the Static bytecode, Contextual and
  Opcode ledger views decode researcher-imported definitions in the page.
- **12 rows are not exposed**, each for the reason in its row: per-viewer
  layout and preferences (columns, panes, theme, navigation history, Console
  snippets and history), the clipboard, the app's own windows and menus, the
  researcher's own session and Keychain choice, browser-internal and extension
  capture, the packaged app's own opt-outs, the Save-dialog client export, and
  the agent's own controls.
