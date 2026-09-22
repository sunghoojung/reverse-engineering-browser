# reverse-engineering-browser — what's built vs what's left

Audit date: 2026-09-20 · sources: repo `main` (shallow clone), `docs/product/*`, source tree, plus your 15 links in #reb.

## A. What already ships

- **Native capture core:** dependency-free C++ event/queue foundation, event broker, artifact receiver, debugger transport, local IPC (`src/`, `services/`, `include/reb/`).
- **Brave integration overlay:** canvas + WebGL op capture, opt-in canvas image output, Web Audio call capture, fingerprint Web IDL ops, runtime-generated artifact capture, native network lifecycle, V8 runtime fingerprinting.
- **Origin Trace workspaces (UI):** Traffic, Fingerprinting/Signals (Request Signal Profile), Origin Trace, Sources + full debugger, Memory (heap snapshot/diff/origin trace/heap reference inspection v2), Object Lab, Hooks, Automation, Interception, Repeater, API Collection, Decoder + JWT, Local Analyst, Experiments, VM findings.
- **WireBrowser parity inventory:** every pinned workflow marked implemented.
- **Version reality check:** `main` carries 0.1.6 → 0.1.7 commits (PR #70, #71); README/release block still advertises v0.1.4.

## B. Roadmap items with no (or partial) implementation

Your own `docs/product/feature-list.md` promises these; code does not back them yet.

1. **Deobfuscation Workspace — missing entirely.** Zero code hits, no versioned design doc. Nothing for: readable/minified/packed/obfuscated classification, original-vs-derived side-by-side, static expression simplification, string-table recovery, control-flow-flattening / proxy-function / packer / anti-debug detection, identifier inference with confidence, derived-range→original-byte mapping, transformation log.
2. **Value Trace — missing entirely.** Zero code. Two shipped designs explicitly call it future work (`request-origin-trace-v1.md`, `request-signal-profile-v1.md`: "Exact value flow remains future work"). No backward/forward producer→consumer tracing, no cross-promise/microtask/frame/worker causality, no search by value/regex/byte pattern/object shape, no causal-story view.
3. **Virtual Machine Laboratory — detection v1 only.** `vm_analyzer.py` + `vm-analysis-v1` schema exist, but the UI has no opcode workspace (0 hits for "opcode" in `index.html`/`app.js`). Missing: opcode→handler mapping, recursive reachable-guest traversal with coverage accounting, isolated-experiment confirmation of dispatch/state movement, target-specific analysis packs, cross-version comparison of randomized instruction sets, content-addressed evidence.
4. **WebAssembly Laboratory — partial.** Module bytes, hashes and provenance are captured; VM analyzer decodes WASM sections. Missing: disassembly/readable derived representation UI, compile/instantiate/exported-call/trap/memory-growth lifecycle, JS↔WASM crossing map, cross-runtime value search, bounded offline semantic provider.
5. **Fingerprint Explorer gaps.** No font enumeration/measurement activity (only a doc mention), no WebGL rendered results/hashes/run-to-run diffs, no Web Audio graph reconstruction or rendered buffers + hashes, no canvas run-to-run diff, no attribution of a fingerprint op to its artifact/WASM module, no links from fingerprint results to outgoing requests/transformations.
6. **Memory Workspace gap.** Live object experiment is read-only plus typed own-property set/delete; feature list still wants method invocation, exposure and patching in experiment mode.
7. **Native capture gaps.** No session export/compare/reproducible evidence bundles (no export/bundle control anywhere in the UI) despite README + feature-list promises; service-worker / OOPIF coverage completeness; optional GPU probes not built (`system-architecture.md` calls Blink/V8/GPU expansion planned); session scoping by sensitivity, rate limits and expiration acknowledged as not yet trustworthy in the native envelope; local capability API for authorized agents (MCP intentionally deferred by policy).
8. **Research workspace gaps.** No unified investigation timeline/causal graph, no bookmarks, annotations or hypotheses UI (0 code hits).

## C. Documentation bugs worth fixing first (cheap)

- `docs/product/wirebrowser-parity.md` contains duplicate stale rows that re-list Request Interception, Repeater, API Collection, Expose/patch live object and Runtime hooks as "Missing" directly beneath rows marking them "Implemented". That file currently contradicts itself.
- README + releases advertise v0.1.4 while `main` is on 0.1.6/0.1.7.

## D. Your #reb link stash, mapped

### D1 — links that land exactly on your own unbuilt roadmap

| Link | Maps to |
| --- | --- |
| synthesis.to recon26 agentic deobfuscation (Blazytko) | Deobfuscation Workspace + agent loop driving analysis tools |
| disasm.dev "Writing a JavaScript VM in Go" | VM Lab opcode/dispatch reconstruction; also vendor hiding tricks (Kasada literal splicing, Incapsula coercion) |
| emro.cat Kasada takedown (post removed) | Its own list = your VM milestone backlog: VM disassembly, permutation extraction, CFG recovery, decompilation, fingerprint ID, payload generation, encryption, PoW |
| JSREI org | Bulk AST hooking to auto-locate the responsible function instead of manual breakpoints; cookie-write monitor with conditional breakpoints; redirect-origin attribution; protobuf RE for bodies |
| ghostwire | Invisible hooks via `Debugger.setBreakpointOnFunctionCall` (no wrapping, defeats native-code/monkeypatch checks); `--remote-debugging-pipe` instead of an open WS port; whole-graph auto-attach (workers, OOPIFs); `followReturn` forward dataflow; `crypto.subtle` boundary logging; runtime-driven string-array recovery; verify-oracle against a ground-truth corpus |
| proofofbots/web-re-toolkit (wre) | Dispatch-loop discovery + concolic handler probing + bytecode→JS lifting; 26-pass deobf pipeline to fixpoint; equivalence gate; shape-hash/lockfile drift tracking; payload oracle & grading |
| Dryxio/auto-re-agent, morluto/rea | Reverser/checker agent roles, bounded loops, evidence records, knowledge/domain graph, MCP registration |
| hypersolutions powhttp + HAR analyzer | Exact header order + TLS fingerprint capture; HAR tooling; build-time codegen to request-based clients that drop the browser |
| scrapfly audio fingerprint math | Sub-ULP entropy analysis, noise averaging, platform math (FFT/libm) reproduction |
| internetwache exposed-.git | Path/content and VCS disclosure recon, packfile/object-graph reconstruction |

### D2 — links whose capability is deliberately outside REB's stated scope

These need an explicit scope change before touching, since AGENTS.md says: do not optimize for bypassing access controls or concealing malicious activity.

- TLS/JA3/JA4 + HTTP/2 impersonation, embedded V8 realm running vendor code headlessly, SOCKS5/residential proxy rotation, PoW + captcha solving, farbling/persona simulation, commercial anti-bot solving APIs, bulk target scanning, batch proxy/captcha marketplaces (sneakerdev), abliterated LLM as a backend choice (@abliteration_ai).

### D3 — genuinely in-scope capability nobody planned

- **Anti-bot vendor attribution** (mmewni/antibot-detect): header/cookie/body signature DB for Cloudflare, Akamai, DataDome, HUMAN, Imperva, Kasada, AWS WAF, captcha vendors, with confidence levels. Your harness shows *what a site does*, never *which product it is*.
- **Third-party fingerprinting detection** (the Brave/AliExpress silent-audio tweet): classifying a page's probing of the user, not just probing your own session.
- **Automation-marker detection** (wre's 64 markers: what a tool leaves behind vs what hiding it leaves behind).

## E. Suggested build order

1. Deobfuscation Workspace v1 — biggest hole; Value Trace, VM Lab and WASM Lab all lean on derived representations.
2. Value Trace v1 — closes promises already documented in two shipped designs.
3. VM Lab v2 — opcode/handler workspace plus isolated-experiment confirmation.
4. WASM Lab completion — disassembly, lifecycle, JS↔WASM crossings.
5. Fingerprint parity — WebGL/Web Audio/font coverage and run-to-run diffing.
6. Session export + reproducible evidence bundles — cheap, already promised in the README.
7. Doc cleanup (parity duplicates, release drift), then decide on agent capability API / MCP.
