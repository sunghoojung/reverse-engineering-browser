# Reverse Engineering Browser: Feature Catalog

## Product promise

Reverse Engineering Browser is a Brave-based research browser for authorized website analysis. It helps a human researcher or an AI agent answer four questions:

1. What code and WebAssembly did this site run?
2. What browser signals and data did it access?
3. Where did a value come from, how did it change, and where did it go?
4. How can I reproduce and test a hypothesis without altering the live session?

## Browse and capture

- Browse with normal Brave behavior and an isolated research session.
- Create scoped sessions with allowed origins, probe categories, sensitivity rules, rate limits, and expiration.
- Capture browser events without JavaScript wrappers in the page environment.
- Handle top-level pages, frames, OOPIFs, workers, and relevant browser services.
- Stream live evidence to a research UI, CLI, or authorized agent.
- Save, export, compare, or discard local captures.

## Artifact explorer

- Catalog external scripts, inline scripts, worker scripts, modules, source maps, and WebAssembly modules.
- Preserve original bytes, content hashes, URLs, initiators, load times, frames, workers, and execution contexts.
- Search source, strings, imports, exports, and observed execution.
- Track dynamically created code, including blob URLs, data URLs, dynamic imports, worker code, runtime-generated JavaScript, and WASM built from runtime bytes.
- Trace generated code back to the artifact or event that created it.

## Code and WebAssembly analysis

- Show the original source next to a readable derived representation.
- Classify code as readable, minified, or likely obfuscated.
- Format code, use source maps, simplify safe static expressions, recover strings, and label identifiers.
- Keep a transformation log and map every readable result back to original source bytes.
- Inspect WASM imports, exports, strings, disassembly, lifecycle, traps, and JavaScript crossings.
- Analyze virtualized or bytecode-based code through bytecode traversal, opcode labeling, disassembly, and annotations.
- Never overwrite source evidence or automatically execute extracted code.

## Behavior and browser signals

- Observe navigation, storage, permissions, navigator properties, canvas, WebGL, Web Audio, GPU activity, and scoped network metadata.
- Record which script, frame, worker, or WASM module accessed a browser capability.
- Connect browser API results to later transformations and outgoing requests.
- Redact sensitive data by default and require explicit permission for cookies, credentials, authorization headers, or response bodies.

## Value tracing and correlation

- Select a value from a request, API event, JavaScript object, or WASM boundary.
- Trace its creation, transformations, serialization, and destination.
- Label each conclusion as exact, inferred, or heuristic.
- Search by exact value, pattern, object shape, and structural similarity.
- Preserve causality across promises, microtasks, timers, events, message channels, workers, and frames.
- Reveal unknown or ambiguous links instead of pretending they are known.
- Compare two authorized runs to explain behavioral differences.

## Research workspace

- Navigate from an event to source and from source to related events.
- Use a short causal timeline instead of a raw event flood.
- Record an authorized scenario as one evidence trail: navigation, human or agent action origin, created artifacts, browser-signal access, WebAssembly activity, requests, and outcomes.
- Label interactions as human input, agent-requested action, or isolated synthetic experiment.
- Bookmark artifacts, events, source ranges, and values.
- Add annotations, hypotheses, and experiment results to an investigation.
- Create reproducible evidence bundles with browser build, configuration, artifact hashes, fixtures, and recorded outcomes.
- Let agents produce evidence-cited explanations while preserving uncertainty.

## Experiment Lab

- Create a disposable experiment from a script, function, WASM module, or captured request.
- Perform static analysis without execution.
- Run selected code in a throwaway origin and profile with explicit DOM, storage, input, permission, and response fixtures.
- Replay an authorized page scenario in an isolated profile with explicit dependency stubs.
- Compare experiment behavior with the captured session.
- Keep experiments separate from the active website, production cookies, account state, and credentials.

## Safety and reliability

- Keep all control and evidence traffic local by default.
- Authenticate local clients and enforce session scope before commands reach the browser.
- Maintain audit logs for commands and sensitive capture.
- Never block the renderer for UI, storage, network delivery, or an agent.
- Measure compatibility, performance, event drops, and resource usage against the matching official Brave release.
- Treat observational equivalence as a measured engineering target, not an absolute guarantee.
