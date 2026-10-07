# Analysis Catalog v1

`GET /api/analysis/catalog` and the existing CLI's `get_analysis_catalog`
operation expose a deterministic, local inventory of the current VM detector.
This is a working metadata endpoint, not a source downloader or plugin loader.
It returns the shared live profile, its digest, all structural and relevance
rules, and a small reviewed-source ledger. No captured evidence is needed or
modified; no URL is fetched and no code is executed.

## Use the definitions with a finding

1. Obtain a document from `GET /api/analysis/vm` or `origin-trace-vm`.
2. Match its producer ID/version to `current_producer` and its `profile_digest`
   exactly to `current_profile_digest`. Build identity is not recorded; these
   matches do not prove the same analyzer binary.
3. Resolve each `observations[].rule_id` and `anti_bot_observations[].rule_id`
   in `rules`, then resolve its `source_ids` in `sources`.
4. Keep the finding's exact artifact range or event reference as the evidence.
   A research citation explains the rule or concept; it is not that evidence.

The catalog covers one current profile, not every analyzer in REB. Its rules
reuse the detector's structural, lexical relevance, and runtime relevance
weights. JavaScript structure remains name-dependent lexical triage over
masked approximate function regions; anti-bot source relevance still includes
comments and literal text. WASM is decoded structurally without recovering a
guest ISA. Runtime surface use can be observed or contextually correlated,
without proving return success, fingerprinting, or causal value flow.

## Identity and historical compatibility

The getter preserves the existing profile JSON and digest exactly. Source-review
updates change `catalog_digest` without changing evidence or stored analyses.
The [HTTP contract](../../protocol/http-api.md#analysis-definitions-and-reviewed-sources)
defines canonicalization and bounds; the [OpenAPI schema](../../protocol/openapi.json)
is embedded in `reb-api`, so `describe get_analysis_catalog` is self-contained.

The v1 VM document schema still accepts historical profile shapes. This catalog
contains no historical definition archive and never relabels older findings as
current. If the producer or digest differs, use that document's embedded profile and producer
version; current rule metadata is not an exact resolution. Static relevance
weights are exposed here but are absent from the existing profile digest
projection, so that digest alone never promised identity of every analyzer
implementation detail. A digest identifies content, not authenticity or accuracy;
a heuristic weight is not a calibrated probability.

## Reviewed source status

The embedded [source ledger](../../apps/origin-trace-backend/assets/analysis-sources.json)
contains concise original summaries, primary URLs, reviewed revisions where
available, dates, applicability, limitations, and reuse status. Its evidence
levels distinguish inspected implementation, primary documentation, author
claims, discovery catalogs, and unavailable material. Upstream source inspection
is not an upstream execution/test result or a claim that REB adopted a technique.

- REA, Ghostwire, ReAgent, web-re-toolkit, the educational Go VM, and focused
  JSREI projects are pinned individually. No library or runtime is imported.
- Hyper documents a hosted service; its server implementation was not available.
  The plugin and antibot-detect have incomplete inspected license documentation.
  JSREI's AST-hook license file is empty. No code from those sources is copied.
- The emro URL now holds a withdrawal notice dated 2026-04-26. It is historical
  context and is deliberately absent from rule source references.
- Scrapfly's audio measurements are author-reported. Reviewed Chromium
  `151.0.7922.108` selects Accelerate on Mac and PFFFT on non-Mac. This does not
  establish ARM/x86 causation or a CPU classifier.
- Unpinned web documents carry a review date and null revision, not an invented
  immutable snapshot. Native origin allowlisting and native audio sample capture
  are still absent; the catalog does not close those gaps.

Historical design/audit documents retain their original context. The current
catalog and source code take precedence over old proposed integrations and
Python-era ownership descriptions.
