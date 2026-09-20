# reverse-engineering-browser — code-verified gap audit

Date: 2026-09-20 · Method: shallow clone of `main` at `/tmp/reb-inspect`, five parallel read-only audits (analysis workspaces, VM/WASM, native probe coverage, memory/experiment, network/agent). Every claim below is backed by file:line in code, not by `docs/product/*.md`. Where the docs and code disagree, the code wins.

## 0. Corrections to the earlier doc-based pass

| Earlier claim | Code reality |
| --- | --- |
| "Deobfuscation Workspace: nothing at all" | There is a naive beautifier + "Readable derived view" toggle, but it is a stub (see 2.1). |
| "Value Trace: nothing" | Backward request trace, temporal memory origin trace and value/regex/object-shape search exist; forward/causal value flow does not (see 2.2). |
| "VM Lab: detection only" | Detection is deeper than expected — real WASM binary decoding, two-tier scoring, content-addressed evidence, native wire record with tests (see 1.6). |
| "No session scope in the native envelope" | `session_id`, `category_mask` and monotonic expiration ARE in the envelope and enforced at three layers. What is missing is origin allowlisting, sensitivity-as-event-field, and rate limits (see 2.6). |
| "Fingerprint coverage gaps" | Mostly right, with nuance: WebGL *has* real native hooks (parameters, extensions, readPixels, shader precision) — it just never captures readback pixels; fonts have metadata coverage but no enumeration (see 2.5). |

## 1. Verified as genuinely implemented

### 1.1 Evidence pipeline and storage
- Dependency-free C++ event/queue core, 1024-record bounded queue with dropped-count gap records, multi-producer, session re-validation in the broker (`common/native_probe_queue.h:20,73-76,209`; `services/event-broker/main.cpp:158-167,419`).
- Content-addressed artifacts with 128-byte header, expected SHA-256, 16 MiB/artifact and 32 MiB active budgets, ack-driven captured/failed events (`common/native_artifact_header.h:24-104`; `browser/native_artifact_capture_sink.cc:31-32,290-330`).
- Durable on-disk sessions: JSONL stores under `build/sessions/live`, atomic mode-0600 replacement, evidence-store validator (`scripts/run-live-session.sh:20-24`; `apps/research-ui/durable_files.py`; `tools/validate-evidence-store.py`).

### 1.2 Native fingerprint probes (custom Brave build)
- Canvas 2D ops + readbacks via hand-written hooks and generated bindings; opt-in `toDataURL` image capture capped at 2 MiB, routed on a separate sensitive artifact channel (`patches/chromium/0006`, `patches/0007`, `renderer/native_probe_sink.cc:48,108-127`).
- WebGL: real hooks for `getContextAttributes`, `getActiveAttrib/Uniform`, `getAttribLocation`, `getExtension`, `getParameter`, `getProgramParameter`, `getShaderParameter`, `getShaderPrecisionFormat`, `getSupportedExtensions`, `readPixels`, `generateMipmap` (`patches/chromium/0006:381-476`).
- Web Audio: call-site hooks for analyser reads, `connect`, `start`, `createAnalyser/Oscillator/DynamicsCompressor`, `startRendering`, buffer channel reads (`patches/chromium/0002`, `patches/0004`).
- Runtime fingerprinting: V8 use counters for 22 Math functions + `Date.getTimezoneOffset`, Blink counters for Intl, Performance APIs (`patches/v8/0001`, `patches/chromium/0008`, `patches/0007`).
- 90-interface generated-binding allowlist covering Navigator(+UAData), plugins/mimeTypes, media devices/capabilities/tracks/recorder, Screen/ScreenDetailed, VisualViewport, Permissions, CacheStorage/IDBFactory/Storage, WebRTC (peer connections, data channels, RTCRtp sender/receiver), WorkerNavigator, FontFace/FontFaceSet, WebGPU interface names (`patches/0007:20-175`).
- Native quiet mode: `REB_NATIVE_QUIET_MODE` drops the remote-debugging endpoint and adds a V8 flag that ignores page `debugger` statements (`scripts/run-live-session.sh:31,313,315`; `patches/chromium/0003`).

### 1.3 Network workspace
- CDP capture of method, credential-stripped URL, resource type, timing, status, protocol, mime, cache/SW flags; headers capped 128/64 KiB with authorization/cookie/proxy-authorization/set-cookie replaced by `<redacted>`; request body ≤128 KiB; response bodies fetched async with an 8-slot queue and explicit available/empty/missing/error states; 1000-request FIFO with visible drop counter (`debugger_bridge.py:7129-7460`; `debugger/limits.py:50-57,121-126`).
- Interception (continue/block/drop/rewrite/fulfill + synthetic CORS preflight), Repeater (variables, cancel, 24-entry history, status/headers/body-sha compare), Action Scope (global vs one page over disposable targets) — all real (`debugger/requests.py:236-420,561-641`; `debugger_bridge.py:3457-3900,6042-6140`).

### 1.4 Automation, analyst, decoder
- Automation recipes: manual/created/before-load/after-load triggers, nonce-verified `addScriptToEvaluateOnNewDocument`, private session variables, 2 s timeout + watchdog with `terminateExecution`, cancellation, dropped-trigger accounting (`debugger_bridge.py:4116-4948,5001-5076`).
- Local Analyst: saved scripts over a frozen snapshot, run in a hardened node process (`--permission`, rlimits, `--disable-proto=throw`), 2.5 s wall timeout, SIGKILL/SIGTERM paths (`local_analyst.py:1-60,560-757`).
- Decoder/JWT: allowlisted transforms with a bounded 16-step chain, HMAC verify, explicit unsigned-token path (`decoder_service.py`; `include/reb/decoder.hpp:25-38`).

### 1.5 Memory and experiment
- Heap snapshots via `HeapProfiler.takeHeapSnapshot`, 256 MiB collector cap; search scopes reachable/unreachable with BFS from node 0; retaining paths depth 12; incoming references ranked internal/hidden/weak/other; Lengauer-Tarjan dominators and retained-size diff (`debugger_bridge.py:6192-6245`; `src/analysis/heap_snapshot.cpp:1041-1270,1545-1611,1671-1759`).
- Live object search by property/value/class/regex/JSON-shape with Jaccard similarity, using `Object.getOwnPropertyDescriptor` so accessors are never invoked (`debugger/runtime_scripts.py:143-306`).
- Runtime hooks: entry + up to 32 synchronous return points, local-scope binding capture (accessors not invoked), conditions, injected logic, `Debugger.setReturnValue` override; Promise logic/returns refused.
- Mutations are confined to the disposable context, require `confirmed:true`, reject accessor/non-writable/non-configurable/non-extensible targets and `__proto__`/`constructor`/`prototype`, and are audited with SHA-256 value digests (`debugger_bridge.py:922-955,1152-1373,1434-1480`).

### 1.6 VM/WASM detection + correlation
- Two-tier model: `candidate` (score ≥ 20) vs `likely-vm` (dispatch rule + score ≥ 60 + ≥ 3 evidence families) (`vm_analyzer.py:37-39,1135-1143`).
- JS detection rules for dispatch loops, instruction-pointer mutation, indexed bytecode reads, state effects, handler selection, bounded exits; WASM detection via a real bounded LEB128 section/instruction decoder incl. `br_table`, `call_indirect`, loop depth (`vm_analyzer.py:201-280,462-825`).
- Static bytecode snapshot limited to literal `Uint8Array` initializers, with producer offset, inferred consumer, sha256 and 256-byte cap (`vm_analyzer.py:975-1001`).
- Content-addressed evidence with profile/document digests and a verifier; native `VmFindingPayload` fully implemented with byte-parity tests (`vm_analyzer.py:1310-1640`; `include/reb/vm_finding.hpp`; `tests/vm_finding_test.cpp`).
- Request Signal Profile and Request Origin Trace are real correlation features with explicit gaps and confidence labels (`src/evidence/request_signal_profile.cpp`, `origin_trace.py:1-463`).

## 2. Verified as missing or stubbed

### 2.1 Deobfuscation — effectively absent
- Only `formatJavaScript` in `source_syntax.js:50`, which returns early if the source has more than 5 lines — so it never touches a real bundle. The toggle relabels the pane "Readable derived view" (`app.js:6064-6069`) but there is **no mapping back to original bytes**: breakpoint gutters are disabled in pretty mode (`app.js:5998-5999,6033`) and columns are forced to 0 (`app.js:5892-5893`).
- Absent entirely: code classification (minified/packed/obfuscated), string-array/table recovery, control-flow unflattening, proxy-function/packer detection, anti-debug detection, identifier renaming with confidence, source transformation log. (The `ParseStringArray` hits are heap-metadata parsing; `rename` hits are `std::filesystem::rename` and a folder rename button.)

### 2.2 Value Trace — partial, non-causal
- Present: backward request origin trace over recorded edges; memory origin trace (first appearance of a value across debugger steps, sampling-based, `debugger_bridge.py:2525-2800`); value/regex/object-shape search.
- Absent: value-level backward trace from a selected request *field* (the field is ignored — `app.js:1695-1706` keys only off the request root), forward/consumer tracing, causality across promises/microtasks/timers/workers, byte-pattern search.
- The code explicitly disclaims it: `include/reb/origin_trace.hpp:78` "never infers value flow"; `vm_analyzer.py:1085,1172` "Exact value provenance is not claimed."

### 2.3 VM Lab — detection only, analysis missing
- Absent: opcode/handler workspace (no mapping, operands, state effects, handler enumeration), reachable-guest traversal with characterized/uncharacterized coverage, hypothesis confirmation by bounded dispatch/IP tracing (`kHypothesis` is an enum + UI label only), target-specific analysis packs (single hard-coded `anti-bot-vm-detection-v1` profile), cross-version comparison of randomized instruction sets.
- Anti-bot scoring is shallow: 5 static regexes + runtime signal counts, `min(100,sum)`; no timing/entropy/sensor/telemetry signals and no ranked pack.
- **Producer gap:** the overlay defines `NativeVmFindingPayload` but nothing in the browser emits VM findings — only the demo `apps/reb-event-producer/main.cpp:88-109` does. Live capture produces no VM findings; the Python analyzer is the effective producer.
- JS detection is regex/heuristic, not a parser; `js.bounded-exit` matches any `return`/`break`/`throw`.

### 2.4 WASM Lab — bytes only
- WASM renders as a raw hex dump (`source_syntax.js:37-48,176`). No disassembly, mnemonics or readable derived representation.
- Import section parsed only to count functions; export/type/memory/global/custom/name sections unparsed — no imports/exports/types/globals/strings/data-segment contents.
- No compile/instantiate lifecycle analysis, exported/imported call recording, trap/memory-growth analysis, or observed JS↔WASM crossings (the "mixed" finding only follows a declared manifest parent link, `vm_analyzer.py:1550-1572`).

### 2.5 Native probe gaps
- **Fonts:** no OS font-list or font-file probe and no measurement values — only interface metadata for FontFace/FontFaceSet/`Document.fonts` plus canvas `measureText`/TextMetrics names (`patches/0007:35-36,114,124`).
- **GPU:** no GPU-process/command-buffer/driver probe; WebGPU appears only as interface names bucketed into the Navigator category. There is no Font or GPU event category (`common/native_probe_event.h:22-33`).
- **WebGL renders:** `readPixels` is recorded as metadata; no pixels or rendered output captured (unlike Canvas `toDataURL`).
- **Web Audio:** per-call metadata only; audio samples, rendered buffers, node parameters and return values are never copied (`overlay/README.md:39-44`).
- **Workers/OOPIF/service workers:** no execution-context enumeration; worker and detached-frame events are explicitly left unattributed (`overlay/README.md:24`); service workers exist only as network flags. Tab attribution only maps the process's tracked frames.

### 2.6 Session scope in the native envelope
- Present: `session_id`, category mask, monotonic expiry, enforced in renderer, browser session and broker.
- Missing: any origin field (the overlay README says origin allowlisting is intentionally not adopted for lack of trustworthy origin identity), sensitivity as an event field (artifact-stream flag only), and rate limits (only a bounded queue with drops).

### 2.7 Export / reproducible bundles — absent
- Repo-wide grep for export/bundle/archive/zip/tar/sign/reproduce finds no endpoint or command. `server.py` exposes read APIs plus capture stop/clear only (`server.py:174-637`). Durable on-disk storage + validator ≠ export.
- UI-side: the analyst snapshot (`app.js:4740-4782`) is in-memory; the VM analyzer emits a `graph` structure (`vm_analyzer.py:1003-1080`) that **nothing in the UI consumes** — no causal-graph view.
- Research extras absent: bookmarks, annotations, user hypotheses, unified investigation timeline (the only "timeline" is the automation run history).

### 2.8 Memory/experiment edges
- Mutation is set/delete of one own property on a retained live object — no method invocation, no expression evaluation, no expose-to-console, no function replacement, no prototype/non-own-property patch, no nested/closure-state mutation.
- Runtime hooks are synchronous-only (Promise logic/returns refused); no explicit argument capture (arguments surface only implicitly through local-scope bindings); no async/await stepping inside hooks.
- No forward dataflow, no `crypto.subtle` boundary logging, no action-scoped allocation diff (heap diff is manual baseline → compare).

### 2.9 Agent surface
- No MCP (explicitly deferred in `AGENTS.md:50`), no auth token, no capability API, no agent CLI. The only gate is loopback Host/Origin validation (`server.py:594-633`). The "local capability API for authorized agent access" in `technical-architecture.md:263` and `feature-list.md:150` exists only in documentation. An agent can drive the harness today only by scripting the localhost HTTP endpoints.

## 3. Doc-vs-code discrepancies worth fixing

1. `docs/product/wirebrowser-parity.md` contradicts itself: duplicate stale rows re-mark Request Interception, Repeater, API Collection, Expose/patch live object and Runtime Hooks as "Missing" directly below rows marking them "Implemented".
2. `api_collection.py` stores no execution history (no history/run/execution fields), yet parity doc claims "execution history" — run history lives only in Repeater and is linked by `collection_request_id`.
3. Request interception arms the request stage only (`Fetch.enable` with `requestStage: Request`); response rewriting/fulfilment of page traffic is not possible, which the features list does not make obvious.
4. README and release block advertise v0.1.4 while `main` carries 0.1.6/0.1.7 commits.
5. `docs/architecture/technical-architecture.md:261-273` advertises a capability-based agent API that has no code.

## 4. Priority order (code-backed)

1. **Deobfuscation Workspace v1** — the only large area with essentially no implementation, and the derived-representation + byte-mapping substrate that Value Trace, VM Lab and WASM Lab all need.
2. **Value Trace v1** — close the explicit "future work" disclaimers in two shipped designs; start with field-level backward tracing (the UI prompt already exists but ignores the selected field) and forward/consumer tracing.
3. **VM Lab v2** — opcode/handler workspace, guest traversal coverage, hypothesis confirmation; also wire a real native VM-finding producer, since today only the demo emits them.
4. **WASM Lab completion** — disassembly/derived representation, section detail, lifecycle, JS↔WASM crossings.
5. **Fingerprint parity** — font enumeration, WebGL readback capture, Web Audio buffers/graph, run-to-run diffing.
6. **Session export + reproducible evidence bundles** — already promised publicly; cheap relative to its value; includes rendering the existing analyzer `graph` as a causal view.
7. **Research workspace** — bookmarks/annotations/hypotheses and a unified timeline.
8. **Doc cleanup + scope decision** on the agent surface (MCP or a documented authenticated local API) and on the out-of-scope items from the link stash (TLS/JA3 impersonation, PoW/captcha solving, proxy rotation, farbling).
