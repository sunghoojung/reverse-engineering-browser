# hCaptcha HSW reconstructive notes (`tools/hcap-vm-rev`)

**Not a solver.** No pass tokens, sitekeys, proof bodies, or runnable bypass client.
Analysis-only inventories and reconstructive JS derived from authorized public-demo
captures in Origin Trace. Captured wasm binders and large `hsw.js` blobs are **not**
shipped here.

## Spoof-surface inventories

| File | Role |
|------|------|
| `REQUEST_STAGES_INVENTORY.md` | Public-demo request stages (siteconfig → checkcaptcha) |
| `FINGERPRINT_SURFACES_INVENTORY.md` | Host-import / fingerprint surfaces with citations |
| `SPOOF_CHECKLIST.md` | Checklist → surfaces tagged `observed` \| `inferred` \| `unknown` |
| `BODY_SHAPES_INVENTORY.md` | getcaptcha/encrypt envelopes + `api.js` manifest shapes |

Supporting reverse notes: `REQUEST_FLOW.md`, `OCTET_STREAM.md`, `ENCRYPT_DECRYPT.md`,
`POW_PATH.md`, `HOST_TOOLBOX.md`, `HOST_GATES.md`, `MEMORY_CODEC.md`, `MBA_OPAQUE.md`.

## Quick check

```bash
node guest_ops_live_fixture.js
node guest_ops_art13_fixture.js
node guest_ops_e449_fixture.js
node cff_graphs_fixture.js
node mba_opaque_roundtrip.test.js
node hsw_reconstruct.test.js
```

Wasm path presence is skipped unless `HCAP_REQUIRE_WASM=1` (local reverse trees only).

## Explicit non-goals

- Request-based hCaptcha solver / forged `checkcaptcha` POST
- Shipping captured wasm or full binder sources
- Inventing MBA/cipher math still marked unknown

See repository `SAFETY.md`.
