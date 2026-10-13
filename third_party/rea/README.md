# REA structural observation reference

Reviewed source: [morluto/rea](https://github.com/morluto/rea), commit
[`bb540826d65316c164d2de8ba4ef10f81a8ad073`](https://github.com/morluto/rea/tree/bb540826d65316c164d2de8ba4ef10f81a8ad073),
reviewed 2026-10-13.

`apps/origin-trace-backend/src/debugger/api_catalog.rs` adapts the typed structural
path, value-type union, and repeated-array observation accumulation in REA's
[`src/domain/jsonShape.ts`](https://github.com/morluto/rea/blob/bb540826d65316c164d2de8ba4ef10f81a8ad073/src/domain/jsonShape.ts).
REA-authored material is MIT, Copyright (c) 2026 morluto. The complete upstream
notice is preserved in [LICENSE](LICENSE). The Rust implementation uses a bounded
streaming parser rather than REA's full JSON-value tree, and rejects duplicate
keys or exhausted budgets instead of returning a potentially misleading shape.

REA's
[`CdpCaptureEventBodyShapes.ts`](https://github.com/morluto/rea/blob/bb540826d65316c164d2de8ba4ef10f81a8ad073/src/browser/CdpCaptureEventBodyShapes.ts)
and
[`CdpCaptureCompleteness.ts`](https://github.com/morluto/rea/blob/bb540826d65316c164d2de8ba4ef10f81a8ad073/src/browser/CdpCaptureCompleteness.ts)
informed the explicit unavailable-body and capture-coverage distinctions. Their
code was reviewed, not copied. REB keeps its own capture authorization and raw
local evidence policy; this additional structural view does not change them.

The reviewed
[`WebNetworkCaptureService.ts`](https://github.com/morluto/rea/blob/bb540826d65316c164d2de8ba4ef10f81a8ad073/src/application/WebNetworkCaptureService.ts)
also preserves selected historical record identity and historical-reference
authority. REB's current catalog instead describes its own ephemeral CDP ledger;
it does not import HAR/SAZ or claim historical artifact identity.

REA's API-surface view and accumulator were also reviewed:
[`webNetworkApiSurfaceView.ts`](https://github.com/morluto/rea/blob/bb540826d65316c164d2de8ba4ef10f81a8ad073/src/domain/analysisView/webNetworkApiSurfaceView.ts)
and
[`WebNetworkApiSurfaceAccumulator.ts`](https://github.com/morluto/rea/blob/bb540826d65316c164d2de8ba4ef10f81a8ad073/src/domain/analysisView/WebNetworkApiSurfaceAccumulator.ts).
Their retained-record grouping, source ordinals, and coverage reporting inform
REB's snapshot-local filtering and two-observation structural comparison.
Those UI functions are independently implemented; no additional REA code is
copied. REB does not copy REA's inferred route substitutions: this
catalog retains exact observed paths and per-observation scoped identities.

No REA runtime, npm dependencies, providers, native bridges, or code from REA's
separately licensed third-party components is bundled. REA's MIT license does not relicense components covered by its
[THIRD_PARTY_NOTICES.md](https://github.com/morluto/rea/blob/bb540826d65316c164d2de8ba4ef10f81a8ad073/THIRD_PARTY_NOTICES.md).
No new REA engine or provider capability is claimed by this adaptation.
