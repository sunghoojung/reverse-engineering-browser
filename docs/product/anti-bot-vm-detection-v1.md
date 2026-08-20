# Anti-Bot VM Detection v1

## Status

This document is the authoritative product and architecture specification for
the first virtual-machine detection milestone. It records the decisions made
during the design interview and defines the boundary between this milestone,
later opcode reconstruction, and later exact value tracing.

The feature is for authorized research into client-side anti-bot behavior. It
explains observed collection, virtualization, challenge, and token-construction
behavior. It does not solve challenges, generate bypass tokens, evade access
controls, or conceal automation.

## Release promise

Given an authorized Deep Analysis capture, Origin Trace automatically scans
captured JavaScript and WebAssembly artifacts, identifies bytecode and virtual
machine candidates with deterministic evidence, and ranks the candidates most
likely to participate in anti-bot behavior.

The researcher can also start from a selected request or request field and see
the VM, bytecode, browser-signal, stack, artifact, and request evidence that is
observed, inferred, correlated, or still unknown.

Version 1 is a detection milestone. It does not promise recovered opcode
semantics, complete guest disassembly, or exact value provenance through every
transformation.

## Decisions

### Product outcome

- Detection is the first release gate.
- Reconstruction and exact value tracing remain later milestones.
- Detection covers pure JavaScript VMs, pure WebAssembly VMs, and mixed VMs
  whose interpreter, bytecode production, or host bindings cross the two
  runtimes.
- The generic VM detector remains useful outside anti-bot research. A separate
  anti-bot analysis pack ranks generic VM evidence by its relationship to
  fingerprinting, environment checks, automation checks, timing, entropy,
  encoding, cryptography, sensor aggregation, and outgoing telemetry.

### Two-tier findings

The analyzer exposes broad low-confidence candidates without promoting them to
confirmed VM findings. A `likely-vm` hypothesis requires multiple independent
evidence families.

The two result tiers are:

1. `candidate`: one or more relevant structures were observed, but evidence is
   insufficient to claim a VM.
2. `likely-vm`: the configured deterministic threshold and required independent
   evidence families were satisfied.

No finding uses the word `confirmed`. Confirmation requires a later isolated
experiment that observes bounded dispatch and state movement.

### User workflows

Version 1 has two primary entry points:

1. Automatic scan after artifacts arrive during an authorized Deep Analysis
   session.
2. Request-first analysis from a selected anti-bot request or field, ranking
   related artifacts and VM candidates without claiming exact value flow.

Artifact-first navigation remains available as a supporting workflow.

### Two-stage analysis

Every captured JavaScript and WebAssembly artifact receives cheap, bounded
triage. Deep semantic analysis runs only for candidates selected by one or more
of these conditions:

- triage score reaches the configured candidate threshold;
- the artifact is linked to a selected request;
- the artifact creates or consumes runtime-generated code or candidate
  bytecode;
- a researcher explicitly requests deeper analysis.

Triage and deep-analysis limits are versioned analyzer-profile inputs. Reaching
a limit produces partial coverage with named omissions. It never produces a
complete result from a bounded prefix.

### Capture coverage

Detection covers both network-loaded and runtime-generated artifacts. Deep
Analysis must preserve creator provenance for:

- external, inline, module, worker, service-worker, blob, data URL, and dynamic
  import JavaScript;
- `eval` and `Function` constructor source;
- network-loaded WebAssembly;
- WebAssembly compiled or instantiated from runtime bytes;
- decoded or decrypted candidate bytecode buffers when a bounded observation
  point is available.

Unsupported creation paths, exhausted queues, and unavailable bytes remain
visible coverage gaps. Page JavaScript is not the authoritative capture layer.

### Deep Analysis authority

Complete runtime-generated source and byte capture is available only in a
visibly enabled Deep Analysis session. Authorization is scoped by origin,
frame, category, sensitivity, duration, artifact count, per-artifact bytes, and
total bytes.

Inactive probes remain allocation-free. Active probes never block the renderer
on analysis, storage, UI, or socket delivery. Every queue has explicit drop and
sequence-gap evidence.

### Candidate bytecode

When observable within the session limits, the system preserves a bounded
snapshot of candidate guest bytecode together with its producer, consumer,
artifact, source range or runtime buffer identity, digest, and truncation
status.

When bytes cannot be captured safely, the finding retains the candidate
location and an explicit unavailable reason. Continuous guest-instruction
tracing is outside version 1.

### Fingerprint evidence graph

The internal representation is a graph because values and control can cross
shared functions, promises, tasks, frames, workers, and JavaScript/WebAssembly
boundaries. The UI may project a selected acyclic portion as a tree.

Version 1 links Canvas, WebGL, Navigator, screen, locale, timezone, hardware,
platform, and automation-indicator evidence to responsible artifacts and VM
candidates, then continues toward likely anti-bot requests using
evidence-labeled correlation.

Every edge has exactly one epistemic state:

- `observed`: a native API boundary, runtime stack frame, artifact creation,
  JavaScript/WebAssembly boundary, or request event was captured;
- `inferred`: bounded static analysis identified a relationship;
- `correlated`: frame, task, artifact, initiator, request, or bounded timing
  evidence supports a relationship without proving causality;
- `unknown`: required evidence was unavailable, ambiguous, or outside coverage.

Version 1 does not relabel correlation as exact value provenance.

### Runtime stacks and adaptive exploration

Deep Analysis initially captures bounded, deduplicated runtime stacks. Unique
stacks are stored once and referenced by identifier. Each capture states its
maximum depth, truncation status, sample policy, and dropped count.

When a high-value fingerprint event remains ambiguous, the analyzer may
automatically request a deeper stack within the already authorized Deep
Analysis session. Escalation is restricted to a named API, frame, artifact, or
VM candidate, with independent time, event-count, depth, and byte limits. It
cannot silently become site-wide unlimited stack capture.

If the event will not recur, the UI may offer an explicit scoped reload. A
failed or incomplete exploration remains visible.

### Deterministic scoring

Version 1 uses versioned deterministic rules. Machine learning does not decide
finding tiers. Agent interpretation may explain or prioritize evidence but
cannot change the stored score or promote a finding.

Every score contains its contributing rule identifiers, weights, evidence
references, evidence-family coverage, threshold, and analyzer profile. Exact
weights are fixture-driven and versioned rather than treated as universal
truth.

The generic JavaScript signal families include:

- a persistent loop with switch, function-array, object-map, or indirect
  dispatch;
- instruction-pointer reads, writes, and advancement;
- indexed reads from a candidate bytecode source;
- stack, register, memory, or shared-state effects;
- handler functions or generated handler candidates;
- bounded exits and unknown dispatch frontiers.

The generic WebAssembly signal families include:

- a dispatch loop containing `br_table`, `call_indirect`, or table-based
  selection;
- locals or globals behaving like an instruction pointer;
- repeated linear-memory loads and stores around dispatch;
- tables or function indices behaving like handlers;
- data segments or runtime buffers read as bytecode;
- bounded exits and unknown dispatch frontiers.

Anti-bot relevance is a separate score derived from observed or correlated
fingerprint API access, environment and automation checks, encoding and
cryptography candidates, sensor aggregation, and request relationships. Vendor
names, URLs, or hashes may add relevance but can never establish `likely-vm`.

### Analysis packs

The generic detector owns normalized evidence and scoring semantics. Optional,
versioned target-specific analysis packs may add selectors, relationships,
labels, and weights above that contract.

A pack cannot discard generic residual unknowns, weaken capture authorization,
or turn a vendor signature into proof. Unknown or changed versions fall back to
generic analysis.

## Shared analysis model

JavaScript and WebAssembly frontends produce the same runtime-neutral model:

- interpreter candidate;
- dispatcher and exit;
- guest-program or candidate-bytecode source;
- instruction pointer;
- stack, register set, and memory region;
- opcode or handler candidate;
- invocation;
- host binding;
- hypothesis;
- coverage and residual unknown.

Frontend-specific coordinates remain attached to every observation:

- JavaScript uses artifact identity, exact byte and source ranges, callable
  identity, and AST observation identity.
- WebAssembly uses artifact identity, section, function index, byte offset,
  instruction offset, and optional data or memory range.
- Mixed evidence links the original frontend observations and uses
  `host_runtime=mixed`; it never erases the boundary.

The existing fixed-size `VmFindingPayload` remains a bounded timeline summary.
Detailed rules, graph nodes, edges, stacks, bytecode snapshots, analysis
profiles, and residual unknowns belong in a versioned cold-path analysis
document keyed by session, investigation, artifact digest, and analyzer-profile
digest.

## REA integration boundary

[REA](https://github.com/morluto/rea) is useful as an offline JavaScript
analysis provider and an architectural reference. The reviewed upstream commit
is `07888ec096f69753a1535703fb7b3c3070e786b7`.

Reusable REA capabilities include inert Babel parsing, source-map inventory,
lexical scopes and bindings, uniquely resolved local calls, argument and return
flow, object operations, async relationships, request construction, function
fingerprints, deterministic graph identifiers, explicit unknowns, and bounded
coverage.

REA does not currently provide the required WebAssembly semantic analyzer and
its published package exposes a CLI rather than a stable library export. Origin
Trace therefore uses a provider boundary and never imports private REA build
paths. Version 1 may use a pinned CLI adapter for stable public output or adapt
MIT-licensed algorithms with attribution. VM-specific JavaScript structures
that REA does not expose remain owned by the Origin Trace JavaScript frontend.

REA is not part of Brave capture, the renderer hot path, or the normalized VM
contract. MCP remains out of scope.

## Processing pipeline

```text
native capture and immutable artifacts
  -> bounded artifact triage
  -> JavaScript frontend or WebAssembly frontend
  -> runtime-neutral VM evidence model
  -> generic deterministic VM scoring
  -> anti-bot relevance pack
  -> fingerprint and request evidence graph
  -> cold-path analysis store and summary VM events
  -> Origin Trace automatic and request-first views
```

Analysis failures never modify captured evidence. Results are content-addressed
derived records that name their producer, version, profile, inputs, limits,
coverage, and transformation history.

## User interface

Automatic scan presents ranked candidates with separate VM confidence and
anti-bot relevance. Each result shows runtime, tier, score, contributing
signals, coverage, source location, related browser signals, related requests,
and residual unknowns.

Request-first analysis starts from a selected request or field and shows a
tree projection containing only evidence relevant to that selection. Edge
styling and accessible text expose observed, inferred, correlated, and unknown
states. The researcher can pivot from every node to its immutable artifact,
source range, WASM offset, runtime stack, bytecode preview, event, or request.

The UI includes loading, empty, disconnected, malformed-analysis,
partial-coverage, sequence-gap, unavailable-artifact, and exploration-failed
states. Search and filtering never mutate stored evidence.

## Validation corpus

Repository CI requires source-owned deterministic fixtures for:

1. pure JavaScript, pure WebAssembly, and mixed VM positives;
2. minified, packed, and obfuscated non-VM negatives;
3. fingerprinting and anti-bot-like code without virtualization;
4. malformed, truncated, oversized, cyclic, deeply nested, and unsupported
   artifacts;
5. scoring thresholds, stable reruns, named limits, omissions, residual
   unknowns, and false-positive regression cases.

Operator-local authorized real targets are release acceptance evidence, not a
stable CI gate. Expectation manifests contain bounded identities and expected
finding classes without committing proprietary captures, personal content,
credentials, challenge solutions, or bypass material.

## Version 1 acceptance gates

Version 1 is complete only when:

1. Automatic analysis detects the source-owned JavaScript, WebAssembly, and
   mixed VM fixtures and does not promote negative fixtures.
2. Network-loaded and runtime-generated artifacts preserve creator provenance,
   limits, drops, and unavailable reasons through the intended capture path.
3. Candidate bytecode snapshots are bounded, content-addressed, and linked to
   their producers and consumers when observable.
4. Canvas/WebGL and Navigator/device events attribute to runtime stacks,
   artifacts, and VM candidates; selected requests show evidence-labeled
   correlation without claiming exact causality.
5. Deterministic scores are reproducible, decomposable, profile-bound, and
   covered by threshold and false-positive tests.
6. The full required repository validation passes, including native,
   end-to-end, sanitizer, Python compilation, application packaging, code-sign
   verification, and available Brave integration checks.

If a required platform or Brave toolchain is unavailable, the exact gap is
reported and the corresponding acceptance gate remains unclaimed.

## Explicit non-goals for version 1

- assigning semantic names to every opcode;
- complete guest control-flow reconstruction or disassembly;
- continuous opcode dispatch or memory tracing;
- exact value provenance across every transformation;
- challenge solving, token generation, anti-bot bypass, or stealth behavior;
- mutation of the observed page or captured evidence;
- unbounded stack, source, bytecode, or memory capture;
- provider-specific facts presented as generic observed truth.
