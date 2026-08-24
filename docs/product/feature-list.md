# Feature List

## Native capture

- Authorized sessions scoped by origin, tab, frame, worker, feature, sensitivity, and expiration.
- Native Blink, V8, Network Service, and optional GPU probes.
- Passive event capture without page JavaScript wrappers.
- Coverage for pages, frames, OOPIFs, workers, and service workers.
- Live evidence streaming to a local UI, CLI, or authorized agent.
- Session export, comparison, and reproducible evidence bundles.

## Fingerprint Explorer

- Canvas operation capture and visual reconstruction.
- Rendered Canvas images, readbacks, hashes, and differences between runs.
- WebGL parameters, extensions, shaders, draws, readbacks, and rendered results.
- Web Audio graph reconstruction, rendered buffers, and hashes.
- Font enumeration and measurement activity.
- Navigator, permissions, storage, media-device, WebRTC, screen, locale, and timing access.
- Attribution to the responsible script, frame, worker, or WASM module.
- Links from fingerprint results to transformations and outgoing requests.

## Artifact Explorer

- Capture external, inline, module, worker, service-worker, blob, data URL, and dynamic-import scripts.
- Capture runtime-generated code from `eval` and `Function` constructors.
- Preserve original bytes, hashes, source maps, URLs, initiators, contexts, and creation events.
- Search source, strings, imports, exports, and observed execution.
- Trace generated code back to the artifact or event that created it.
- Navigate between artifacts, events, values, requests, and experiments.

## Deobfuscation Workspace

- Classify code as readable, minified, packed, or likely obfuscated.
- Show immutable original source beside a readable derived representation.
- Format source and apply available source maps.
- Safely simplify static expressions and recover string tables.
- Detect control-flow flattening, proxy functions, packers, and anti-debugging checks.
- Detect JavaScript-hosted virtual machines and route them to the shared Virtual Machine Laboratory without classifying ordinary obfuscation as virtualization.
- Highlight fingerprinting, environment detection, encoding, cryptography, and payload construction.
- Infer descriptive identifier labels with visible confidence.
- Map every derived range back to the original bytes.
- Record every transformation without automatically executing extracted code.

## WebAssembly Laboratory

- Detect network-loaded modules and modules compiled from runtime bytes.
- Preserve module bytes, hashes, origin, creator artifact, and lifecycle events.
- Display imports, exports, types, functions, tables, memories, globals, strings, data segments, and custom sections.
- Provide disassembly and a readable derived representation.
- Record compilation, instantiation, exported calls, imported calls, traps, and memory growth.
- Connect JavaScript-to-WASM and WASM-to-JavaScript crossings.
- Search for values moving between WASM, JavaScript, browser APIs, and network requests.
- Analyze captured modules through a bounded offline semantic provider that preserves byte offsets for every derived function, instruction, control-flow edge, call, and data reference.
- Detect WASM-hosted virtual machine candidates and route them to the shared Virtual Machine Laboratory without classifying ordinary compiled WASM as a nested VM.

## Virtual Machine Laboratory

- Analyze custom virtual machines regardless of whether their interpreter is implemented in JavaScript or WebAssembly.
- Normalize JavaScript AST and control-flow evidence and WASM instruction evidence into a shared model of dispatchers, exits, instruction pointers, stacks, registers, memory, bytecode sources, and handlers.
- Locate bytecode embedded in artifacts, fetched separately, generated at runtime, or exposed only after decoding or decryption while preserving its creator and transformation provenance.
- Detect JavaScript VM structures such as switch dispatch, function arrays, object maps, indexed bytecode reads, stack arrays, and dynamically generated handlers.
- Detect WASM VM structures such as dispatch loops, `br_table`, indirect calls, tables, advancing address locals, repeated linear-memory access, and bytecode-like regions.
- Keep interpreter, guest program, invocation, host-binding, hypothesis, and coverage evidence separate with explicit confidence.
- Build an evidence-linked opcode workspace that maps candidate opcodes to handlers, operands, state effects, atomic operations, fused superoperators, confidence, and unresolved ambiguity.
- Traverse reachable guest code recursively while reporting characterized and uncharacterized coverage.
- Confirm VM hypotheses only in an isolated Experiment session by tracing bounded opcode dispatch, handler selection, instruction-pointer movement, and selected state changes against explicit inputs.
- Support target-specific analysis packs above a stable evidence contract instead of assuming one universal VM design.
- Support content-addressed evidence, residual unknowns, agent-guided investigation, and cross-version comparison of randomized instruction sets and handler semantics.

## Value Trace

- Start from a request field, browser API result, JavaScript value, byte sequence, object shape, or WASM boundary.
- Trace backward to producers and forward to consumers.
- Show transformations, serialization, storage, and transmission.
- Preserve causality across promises, microtasks, timers, events, frames, messages, and workers.
- Search by exact value, regex, byte pattern, object shape, and structural similarity.
- Label relationships as exact, inferred, correlated, heuristic, or unknown.
- Present a short causal story instead of an unfiltered event flood.

## Network Workspace

- Request and response capture, filtering, search, highlighting, and inspection.
- Optional size-limited body capture with sensitive fields redacted by default.
- Request and response editing, blocking, forwarding, dropping, and replacement.
- HTML response preview.
- Links from network values to memory, source, fingerprints, WASM, and Value Trace.
- Editable Repeater with cancellation, history, variables, and response comparison.
- API Collection with folders, scoped variables, saved requests, and execution history.

## Memory Workspace

- Live object search by property, value, class, regex, or selected root.
- Structural-similarity search for cloned or mutated objects.
- Heap snapshot capture, search, comparison, and retaining paths.
- Inspection of hidden and otherwise unreachable references.
- Origin Trace for likely creation and mutation boundaries.
- Links from objects and snapshots to source, network, and causal events.
- Object inspection, method invocation, exposure, and patching in Experiment mode.

## Sources and Runtime Instrumentation

- Script tree organized by page, frame, worker, context, and artifact origin.
- Original source, source maps, readable derived source, search, and annotations.
- Create a hook from a selected function or source location.
- Inspect arguments, locals, closures, stack, source, and return values.
- Conditional logging and selected-value capture.
- Step into, over, out, and across selected asynchronous continuations.
- Modify variables and override synchronous return values in Experiment mode.
- Follow a produced value toward likely consumers.

## Automation

- Permission-controlled analyst recipes that query captured evidence.
- Browser-context scripts for explicit Experiment sessions.
- Manual execution or scoped automatic execution on page creation, before load, or after load.
- Access to selected browser, memory, instrumentation, debugger, network, and artifact capabilities.
- Reusable files, folders, variables, logs, and execution results.

## Experiment Lab

- Branch an immutable Baseline into a disposable experiment.
- Patch selected values, objects, functions, browser API results, requests, or responses.
- Replay captured actions and requests with explicit fixtures.
- Use isolated profiles, credentials, cookies, storage, and permissions.
- Compare artifacts, events, values, fingerprints, network activity, and outcomes against Baseline.
- Save or discard experiments without changing the original evidence.

## Research Workspace

- Request Signal Profile for Canvas, WebGL, Web Audio, Navigator, Permissions,
  Storage, and WebRTC activity, with observed parent chains, correlated
  same-context evidence, and explicit retention coverage.
- Request-first Origin Trace over the versioned broker edge sidecar, with exact
  request-root selection, bounded traversal, explicit gaps, and supporting
  evidence rows.
- Unified investigation timeline and causal graph.
- Source-to-event and event-to-source navigation.
- Bookmarks, annotations, hypotheses, and evidence-backed conclusions.
- Console, scratchpad, byte viewer, decoder chains, and JWT inspection.
- Baseline, Deep Analysis, and Experiment status shown at all times.
- Global, tab, frame, worker, origin, artifact, and session scopes.
- Human, agent, and synthetic actions identified separately.
- Local capability-based API for authorized agent access.
