# Runtime Hook demo labs

Two local, educational fixtures show different instrumentation boundaries. Use
fake inputs only.

## 1. Page callback: REB's current hook target

Run from the REB repository root:

```sh
python3 -m http.server 7320 --bind 127.0.0.1 --directory apps/runtime-hook-demo
```

Open `http://127.0.0.1:7320/`. The sample token
`LAB.PIXEL-42.2D` passes a toy checksum; the tampered sample fails. This is
not authentication, signing, or a real credential. The page sends no requests
and stores nothing.

In Chrome DevTools → Sources → `demo.js`, set a breakpoint on
`const weighted =` and process a sample. The paused anonymous callback
exposes `character`, `index`, and closure-local `salt`. Anonymous
JavaScript is **not** immune to ordinary DevTools breakpoints.

In Origin Trace → Experiments → Hooks, create an isolated context, open
`http://127.0.0.1:7320/` as its disposable page, select the live `demo.js`
script, and place the cursor on the `const weighted =` line. Add an
entry/return hook, confirm the isolated-page mutation warning, arm, and process
a sample in that page. REB resolves the inner arrow function and uses CDP
breakpoints to collect bounded hits while resuming automatically. A JSON
synchronous return replacement of `0` is an optional experiment: it should
change the computed check only in the disposable page. Disarm or dispose
afterward. This REB interaction still needs a live, recorded end-to-end check;
the explanation is the intended contract, not a claimed screenshot result.

## 2. Obfuscated worker signer: Ghostwire's stronger example

The exact upstream `examples/obfuscated_app` fixture is copied into
[ghostwire-worker](ghostwire-worker/) from Ghostwire commit
`c3377f8be59fc2b2f2a620bbae75714902b0c114` (MIT license; see its
`LICENSE`). Run it from the REB repository root:

```sh
python3 apps/runtime-hook-demo/ghostwire-worker/lab.py --port 8766
```

Open `http://127.0.0.1:8766/`, leave the synthetic message and nonce at
their defaults, and choose **Prepare shipment**. The page posts the values to
a dedicated Web Worker. Its obfuscated, closure-local signer computes a
`ws1.` payload using an anonymous `.map((byte, index) => …)` callback and
sends the payload to `/api/submit`. The local server returns a receipt.

The example backend does **not** validate a signature; it accepts any string
payload and hashes it into a receipt. This demo is about locating and
observing the client-side transformation, not breaking authentication.

Chrome DevTools → Sources lists `signer-worker.js` under a separate worker
target. Pretty-print it, select a source location, and set a breakpoint if
you want to inspect the worker manually. Obfuscation makes finding the useful
location difficult, but normal DevTools can still debug it.

For Ghostwire's full recovery, use the upstream checkout and its pinned npm
dependencies:

```sh
git clone https://github.com/sofianeelhor/ghostwire.git
cd ghostwire
npm ci --ignore-scripts --no-audit --no-fund
python3 examples/obfuscated_app/worker_reverse.py --url http://127.0.0.1:8766/
```

Observed on 2026-09-23 with the upstream fixture: Ghostwire identified the
`/api/submit` request as a `worker` request, recovered the rotated lookup
names and 13-byte closure secret, traced the transformation, and matched the
live signer on **4/4** inputs. Its evidence and recovered implementation are
written under its own `artifacts/worker-signer-recovery/`; do not commit
those generated traces into REB.

**Observed REB page-hook baseline (before worker support):** In Origin Trace's
disposable context, the fixture page's inline script was selectable but
`signer-worker.js` was not.
A cursor at page line 12, column 9 resolved to the anonymous submit-click
arrow beginning at 11:43. REB armed two bounded CDP points. Clicking
**Prepare shipment** in that isolated page produced one entry and one return
hit, and the page still received its receipt. The callback returns
`undefined` and has no local data properties to capture; these hits
demonstrate the page-to-worker handoff, **not** the worker's signing steps.
The hook was disarmed after capture, leaving its two ephemeral hits visible.

**Worker-aware REB workflow:** With a build containing worker-aware Runtime
Hooks, open the fixture in the disposable Experiment page and wait for
`signer-worker.js` to appear in Sources as a Worker script. In its original
source, search for the `const _0x379be2` statement near the start of
`function _0x2a814c`, select a character in that statement, and use the Hook
pivot. In the pinned one-line file, the `const` starts at line 1, column
12,270 (the UI uses one-based columns). An entry/return source hook should resolve the signer rather than the
page handoff; arm it with the isolated-target confirmation, then click
**Prepare shipment**. The Hooks panel separates worker hits from page hits and
shows the worker's `/api/submit` request with any nearby-hit association
labeled temporal/inferred.

Observed on 2026-09-24 in an isolated Origin Trace session using Brave Browser
Development 151.1.95.0: `signer-worker.js` appeared as a Worker source, and a
source hook at line 1, column 12,270 recorded an entry and return hit in
`_0x2a814c`. **Prepare shipment** still returned a receipt. Runtime Hooks
showed the worker's `POST /api/submit` with status 200 and related it to the
return hit as **same-context temporal proximity, inferred**, not a proven
causal chain. The hook was disarmed and the disposable context was erased
after verification.

Live-function-object mode offers an additional entry-only test using
`self.onmessage` in the worker target. It is not automatic recovery of the
closure-held `_0x2a814c` signer. Ghostwire's object discovery and REB's
source-location hook are distinct approaches; both use CDP rather than native
V8 instrumentation.
