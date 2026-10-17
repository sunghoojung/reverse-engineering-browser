# Opt-in passive public-demo QA

This manual smoke check is optional, requires explicit authorization for the
named targets and observation methods, and never runs in required CI. Public demo access
is not permission for security testing. Follow [SAFETY.md](../../SAFETY.md).
Use an approved disposable environment, not a personal browser profile.

## Scope and stop conditions

For one authorized session, visit each of these pages once:

- <https://demo.fingerprint.com/playground>
- <https://accounts.hcaptcha.com/demo>

Allow ordinary page loading and read-only inspection of the resulting REB
Traffic and Fingerprinting evidence. Do not click the hCaptcha checkbox or
Submit, solve challenges, sign in, change fingerprints, install hooks, replay
requests, fuzz endpoints, or change browser/network security settings. Do not
press Fingerprint's **Analyze my browser again**. Stop on a verification block,
permission prompt, browser startup failure, or expired session. Record a blocked
or unavailable result; never weaken the sandbox to obtain a pass.

## Prepare a real capture session

1. Record the exact REB revision, dirty status, OS, browser version, capture mode,
   and whether the browser is the pinned instrumented Brave build or ordinary
   Chrome/Chromium. Verify the normal build/start prerequisites in the
   [workspace guide](../../apps/research-ui/README.md) and
   [browser setup](../../browser/README.md).
2. Start a fresh isolated session through the supported product launcher. On a
   supported development host with the pinned custom Brave build, the documented
   content-capture route is `REB_CDP_NETWORK_CAPTURE=1 make live`. Keep Canvas
   image retention off unless separately authorized. Explicitly opt into bounded
   content capture only when the authorization covers request/response content;
   otherwise choose metadata-only and mark content assertions unavailable.
3. Keep the session and its loopback backend private. Confirm browser/debugger
   readiness and the active capture mode before navigation. Open no unrelated
   sites: current native events do not enforce an origin allowlist. Do not attach
   REB to an existing managed browser with unrelated tabs.
4. Navigate once to each allowed page in the session's own browser. Wait for
   ordinary page rendering within a short, recorded observation window, then
   stop the session. For simultaneous-tab acceptance, both targets must remain
   open throughout the same observation window; sequential visits do not
   establish that property.

Ordinary managed-browser viewing is useful for availability and page-state
observations, but it does not establish that REB attached, ingested, retained,
or displayed any event. Ordinary Chrome can establish CDP-only behavior only
when the actual REB backend and UI are connected and independently verified;
it cannot establish custom Brave native fingerprint probes.

## Inspect and record

For each target, record pass, fail, unavailable, or not observed separately:

- Page state: title and whether the expected playground signals or unchecked
  hCaptcha widget appeared. Vendor verdicts describe this browser at this time;
  they are not independent ground truth or REB assertions.
- Traffic: the relevant target/session ownership, a retained navigation/request
  row, status, and whether changing the UI filter preserves ownership. A missing
  row is a capture observation, not proof that the page made no request.
- Content: available header/body state, encoding, displayed truncation or error,
  and capture-mode limits. Never turn a missing/blocked body into an empty-body
  success. Do not export real content simply to complete this smoke check.
- Coverage: visible attached/pending/failed target counts, gaps, drops, and
  incomplete-coverage warnings. Passive attachment may miss early requests;
  do not claim lossless collection from a few visible rows.
- Fingerprinting: native operation/category rows and their session/document
  attribution in the actual REB workspace. A vendor's own signal table is not
  native probe evidence. Absence of an operation means **not observed**, unless
  a controlled test independently proves the operation occurred.

Keep raw URLs, cookies, headers, bodies, visitor IDs, IP addresses, screenshots,
and tokens local. For repository reports, manually write only nonsecret
summaries, versions, counts, limitations and outcomes. Best-effort redaction
is not sufficient evidence that a raw export is safe to publish.

## Deterministic acceptance stays local

Public sites, network conditions and vendor classifications change. Their
smoke observations must not gate builds or replace controlled pass/fail cases.
Continue using the authored loopback CDP/browser tests, backend tests, and the
[Traffic capture runtime fixture](traffic-capture-runtime-qa.md). That fixture
covers UI/export contracts, not real CDP collection or native probe capture.
The browser tests cover only the boundaries they explicitly assert. Full
required validation remains defined by [AGENTS.md](../../AGENTS.md).

## Optional manually dispatched CI observation

The separate `Optional public demo passive smoke` workflow uses installed stock
Chrome, one fresh shared profile with two distinct tabs, and the real REB
backend/debugger transport.
Dispatch once with authorization text `passive-one-visit-per-demo`. It is not
triggered by pushes, pull requests or a schedule, and never retries site visits.
It arms both exact blank targets before concurrently issuing one navigation
per demo, keeps both open for the same 15-second observation window, verifies
both targets remain present and capture-ready, then closes owned processes.
Per-target counts include only rows with that exact top-level target identity;
rows from separate child/worker targets are reported as unattributed counts,
never silently assigned to either tab. Same-process frame traffic may share the
parent CDP target and is not separately frame-attributed. Global coverage
remains distinct from per-target counts. A request row is an observation,
not an assertion of successful page behavior or complete collection. This path
checks the backend only; rendered Traffic UI and native fingerprint probes stay
explicitly **not tested**. The released macOS app/custom Brave path is separate;
this workflow neither downloads it nor substitutes stock Chrome for its probes.

Only `public-demo-summary.json` is uploaded, for three days. Its schema contains
fixed target labels, outcome/stage enums, counts and known endpoint hosts,
resource types and HTTP statuses. Simultaneous open/ready flags are backend
observations; they do not prove both rendered UI panels work at once. Unrecognized hosts become `other`; paths,
queries, bodies, headers, errors, titles, IP addresses, IDs and screenshots are
omitted. Unknown coverage counts stay null, not fabricated zeros. Browser and
backend output is discarded; private profiles are removed after process exit.
A cleanup failure is reported without exposing a private directory. Required CI
runs only the deterministic opt-in/summary privacy contract test, not websites.

## Recorded cloud observation: 2026-10-17 UTC

One ordinary managed-cloud-Chrome visit per target rendered the Fingerprint
playground's signal results and the hCaptcha sample form with an unchecked
human-verification widget. No challenge was attempted and no form was submitted.
Fingerprint labeled that browser a good bot, detected developer tools, and did
not report tampering. These are site-displayed observations, not REB results.

The separate code executor could bind IPv4 loopback, but creating an AF_UNIX
socket failed with `PermissionError: [Errno 1] Operation not permitted`.
The managed browser was available through its own UI tool, but no REB transport,
broker or instrumented-browser connection to that managed browser was
established. No attempt was made to evade the socket restriction.

Result: public page availability observed; actual public-site REB Traffic
capture, body display and native Fingerprinting integration **not established**.
The next integration check belongs in an explicitly approved environment where
REB's normal browser and local transports can run, using the procedure above.
