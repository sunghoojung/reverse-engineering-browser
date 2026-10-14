# Owned stock-check investigation fixture

A small owned target for the [existing-tool workflow](../../../docs/development/website-replication-workflow.md).
The request contains a nonsecret derived `lookup_key`; it is deliberately not an
authentication token. No accounts, production data or third-party requests are
used. All servers bind an ephemeral port on `127.0.0.1` and reject foreign
Host/Origin or cross-site requests. Failure scenarios are startup choices, not
remotely mutable endpoints.

## Run the reproducible Node lane

From the repository root with Node 22 or newer:

```sh
node tools/check-stockcheck-investigation.mjs
# Retain an independently inspectable result in a new, nonexisting directory:
node tools/check-stockcheck-investigation.mjs --output build/stockcheck-investigation
```

The parent of the output directory must exist. Existing output directories are
refused to avoid overwriting evidence. Default runs use and remove a temporary
directory. No target contacts occur except this test's owned loopback servers.

The check performs:

1. The actual authored `mountStockcheck` click handler through a minimal DOM
   stub, then real HTTP to the independent fixture server.
2. Source-supported hypotheses, store/variant/SKU one-variable A/B/A tests,
   and an intentionally stale-key request. Source hash and observations are
   retained in a small case ledger.
3. Exact-identity refusal checks and the existing `capturedClientProject`
   exporter, using an explicitly synthetic Traffic adapter. No captured script
   is executed and no native/CDP records are claimed to have been collected.
4. The resulting generated Node transport with the reviewed `client.mjs` domain
   adapter and `agent-cli.mjs`, copied **after** export as `src/stockcheck.mjs`
   and `examples/check-stock.mjs`. This does not expand the export ZIP format or
   its file limit. The original `stockcheck-export.zip` stays unmodified.
5. Independent server-log and inventory checks for in-stock, zero-stock and
   unknown results; login-required, expired catalog, malformed/duplicate JSON,
   rate limit, changed schema, truncation, timeout, no-retry and no-send cases.

Retained files: the original export ZIP, expanded project plus reviewed adapter
and CLI, `validation.json` and `owned-server-log.json`. These are all authored
fixture data. The expanded project is reusable; the ephemeral test server stops
when validation ends, so its captured origin is not a persistent destination.

This is component integration, **not** a rendered REB acceptance run. The receipt
marks real browser input, REB capture/initiator, source facts, runtime hooks,
Repeater UI, native export and Go execution `not_run`. It must stay that way
until the real tools execute those stages. It does not show that an agent
independently discovered the algorithm or that any third-party site works.

## Use the fixture for a real REB investigation

```sh
node tools/fixtures/stockcheck/server.mjs
```

Use the exact printed origin in a researcher-selected disposable REB context.
In the fixture page, select SKU/variant/store and click **Check stock**. Follow
the workflow using the real catalog, exact Traffic identity, initiating source,
optional source/return hooks, controlled experiments, Repeater and export.
Record actual tool results and manual handoffs in a separate case; never relabel
the Node receipt as browser evidence. Ctrl+C disposes the fixture.

The source keeps `lookupKey` synchronous and separate from the action handler
so existing source hooks can investigate it. A literal-candidate bridge cannot
bind arbitrary computed expressions. Ordinary live script/location hooks are
the fallback, within their documented limits and permissions.

Other startup modes: `login-required`, `schema-change`, `malformed`,
`duplicate-key`, `rate-limit`, `slow`. Start a new fixture for a clean reset and
review its new origin before sending. Static inventory is never mutated by a
stock request. A login-required mode intentionally has no login endpoint or
credential acceptance; report the barrier instead of attempting recovery.

## Reviewed example client contract

After exporting and copying the two reviewed adapter files as above, write
`selection.json` with these four string fields:

```json
{"sku":"TEA-01","variant":"small","store":"NORTH","catalog_version":"fixture-v1"}
```

Run from the expanded project, supplying the exact currently running fixture
origin (replace `PORT` with its printed port):

```sh
node examples/check-stock.mjs --input selection.json --origin http://127.0.0.1:PORT
node examples/check-stock.mjs --input selection.json --origin http://127.0.0.1:PORT --send
```

Only `--send` sends, once. Inputs and origin are validated before transport.
This example deliberately permits only the owned IPv4 loopback HTTP origin and
has no proxy, authentication, browser-session fallback or automatic refresh.
The thin adapter does not replace the generated transport implementation.

Output is one JSON object. Success preserves matched SKU/variant/store,
`availability` (`in_stock`, `out_of_stock`, `unknown`), catalog version and the
server observation ID. Quantity is omitted for unknown, never inferred as zero.
Failure emits `{ "ok": false, "error": { "code": "..." } }`; raw server errors
or source instructions are never executed or copied into an agent instruction.
Exit 0 means dry-run or validated success; 2 input/origin failure; 3 target/login/
expired/rate-limit/redirect failure; 4 malformed/incomplete/changed response;
5 transport/client failure. Timeout/network failure is explicitly outcome
unknown and is never retried. The adapter accepts the fixture's flat primitive
JSON response only, rejects duplicate keys and does not claim general schema
inference. Go transport acceptance remains in the existing generated-client
test lane, separate from this Node domain example.
