# Expert API investigation workflow audit

Base: `921a816e2071d16df5ded865b132452db897af5b` (2026-10-13).
Scope: the existing observed API catalog, exact-capture navigation and reviewed
client handoff. No probe, capture, authorization, network execution, persistence,
SDK generator or MCP changes.

## Findings and bounded improvement

The existing catalog already distinguishes observed structure from unknown
bodies and binds each source to its backend instance, capture epoch, request,
target and unrounded start time. Those properties are the foundation to keep.
However, finding an operation required expanding groups manually, and comparing
multiple observations required reading two shape lists by eye.

The UI now supports literal structural search and response-state filtering,
followed by an explicit two-observation comparison within an exact endpoint
group. The comparison shows per-body type and occurrence differences, preserving
unknowns independently for request and response. It neither infers optional
fields nor promotes observed differences into API changes. The original coverage
remains visible beside filter match counts, and exact source links lead to the
existing Traffic, Field trace, reviewed Repeater and Go/JavaScript client paths.

REA's source-pinned API-surface and completeness work inspired this
retained-evidence/explicit-limitations workflow. The new UI implementation is
original; the existing source attribution and MIT notice remain in
[`third_party/rea`](../../third_party/rea/README.md). No runtime or new dependency
is added, and no route-template or service-semantic inference is imported.

## Refactor boundary

The catalog contract, identity helpers and controller moved out of the general
`traffic_view.js` renderer into `api_catalog.js`. Navigation and captured-client
exports continue using the same exact-identity functions. Browser script order,
the backend public asset allowlist, native scheme allowlist and packaged asset
copy all include the module. The existing package contract check compares those
lists with the actual HTML dependencies.

The validated 64-observation snapshot is indexed once per explicit refresh.
Keystrokes filter the index rather than rescanning retained raw bodies. Endpoint
contents remain lazily rendered. Comparing two shapes is bounded by each side's
64 non-root paths plus the root; canonical typed coordinates keep array elements
separate from literal property names. Duplicate typed paths are rejected before
comparison rather than silently overwritten by a map. Source availability is synchronized once
per rendered filter result from one indexed Traffic snapshot. A deterministic
regression covers all 64 groups expanded against 1,000 retained requests: one
ledger read and 384 identity-field encodes, while duplicate IDs across capture
owners still fail closed.

## Test-file review

No test files were removed. Each nearby file protects a distinct boundary:

- `check-api-observation-catalog-ui.mjs`: catalog schema/identity, structural
  filtering/comparison, controller lifecycle and real browser interactions.
  Existing authored fixtures were extended in place; no parallel suite was added.
- `check-captured-client-project.mjs`: exact request/provenance, redaction,
  unsupported inputs, ZIP reader interoperability and generated client behavior.
  Its module-loading list was updated for the extraction.
- `check-client-project-export.swift`: native archive admission and validation,
  which browser tests cannot replace.
- `client-project-go_test.txt`: generated Go runtime and transport semantics,
  which JavaScript client checks cannot establish.
- `client-project-ui/`: real out-of-process macOS Save-panel interaction, which
  archive and DOM tests do not cover.
- `check-origin-trace-package.mjs`: source/native/backend allowlist parity plus
  relocated packaged-app checks. This catches missing extracted assets.

These are not interchangeable assertions or dead tests. Deleting them would
reduce coverage unrelated to the new expert workflow.

## Verification routes

Use `node tools/check-api-observation-catalog-ui.mjs` for the bounded model and
controller checks, and add `--browser` for actual keyboard/pointer interactions,
filtering, comparison, narrow viewports and retained screenshots. The browser
suite also repeats the exact capture-to-Repeater and explicit export path.
Run `node tools/check-captured-client-project.mjs --go` for both generated clients
and `node tools/check-origin-trace-package.mjs --contract-only` for asset parity.

The repository's full `make lint`, `make check`, `make e2e`, `make sanitize`,
`make app-build` and strict code-signature gates still apply. Contract/DOM
fixtures are not rendered or native QA; unavailable local tools and platforms
must be reported separately from the exact-commit CI result.
