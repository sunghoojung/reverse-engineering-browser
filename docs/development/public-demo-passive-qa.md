# Opt-in passive public-demo QA

This manual smoke check is optional, requires explicit authorization for the
named targets and observation methods, and never runs in required CI. Public demo access
is not permission for security testing. Follow [SAFETY.md](../../SAFETY.md).
Use an approved disposable environment, not a personal browser profile.

## Scope and stop conditions

For one authorized session, visit each of these pages once:

- <https://demo.fingerprint.com/playground>
- <https://accounts.hcaptcha.com/demo>
- <https://httpbin.org/redirect/2>
- <https://demo.playwright.dev/api-mocking/>
- <https://mdn.github.io/dom-examples/web-workers/simple-web-worker/>

The three additions are public demonstration endpoints, verified against their
maintainers' documentation on 2026-10-18:

- [httpbin's official API specification](https://httpbin.org/spec.json) documents
  `/redirect/{n}`. One navigation to `/redirect/2` should produce two HTTP 302
  document-response rows followed by the final response.
- [Playwright's official API demo instructions](https://playwright.dev/docs/mock)
  document the SPA and its automatic fruit API request. The
  [official source examples](https://github.com/microsoft/playwright/blob/main/docs/src/mock.md)
  identify `/api-mocking/api/v1/fruits`. This test observes the ordinary request;
  it does not mock, intercept, edit or submit API data.
- [MDN's example source](https://github.com/mdn/dom-examples/blob/main/web-workers/simple-web-worker/main.js)
  creates `worker.js` during initial loading. The smoke check counts an observed
  request for that script under the page target, without changing either input.
  A script request is not proof of worker execution or complete worker capture.

The original two sites retain sibling-tab concurrency and passive iframe/site
complexity coverage. No additional exploratory tabs or repeat visits are made.

Allow ordinary page loading and read-only inspection of the resulting REB
Traffic and Fingerprinting evidence. Do not click the hCaptcha checkbox or
Submit, solve challenges, sign in, change fingerprints, install hooks, replay
requests, fuzz endpoints, or change browser/network security settings. Do not
press Fingerprint's **Analyze my browser again**. Stop on a verification block,
permission prompt, browser startup failure, or expired session. Record a blocked
or unavailable result; never weaken the sandbox to obtain a pass.

## Prepare a real capture session

1. Record the exact REB revision, dirty status, OS, pinned custom Brave version
   and capture mode. Native capture requires the pinned instrumented Brave
   build; ordinary Chrome/Chromium produces no REB evidence. Verify the normal
   build/start prerequisites in the
   [workspace guide](../../apps/research-ui/README.md) and
   [browser setup](../../browser/README.md).
2. Start a fresh isolated session through the supported product launcher. On a
   supported development host with the pinned custom Brave build, use
   `make live`. Keep Canvas image retention off unless separately authorized.
   Native Traffic records method, URL or host, status and lifecycle timing
   only, so request/response content assertions are not applicable.
3. Keep the session and its loopback backend private. Confirm browser readiness
   and the active capture mode before navigation. Open no unrelated
   sites: current native events do not enforce an origin allowlist. Use the session's
   own isolated profile, never an existing browser profile with unrelated tabs.
4. Navigate once to each allowed page in the session's own browser. Wait for
   ordinary page rendering within a short, recorded observation window, then
   stop the session. For simultaneous-tab acceptance, all five targets must remain
   open throughout the same observation window; sequential visits do not
   establish that property.

Ordinary browser viewing is useful for availability and page-state
observations, but it does not establish that REB captured, ingested, retained,
or displayed any event. Only the pinned custom Brave build running under the
REB session produces native network and fingerprint evidence.

## Inspect and record

For each target, record pass, fail, unavailable, or not observed separately:

- Page state: title and whether the expected playground signals or unchecked
  hCaptcha widget appeared. Vendor verdicts describe this browser at this time;
  they are not independent ground truth or REB assertions.
- Traffic: the relevant target/session ownership, a retained navigation/request
  row, status, and whether changing the UI filter preserves ownership. A missing
  row is a capture observation, not proof that the page made no request.
- Coverage statement: the request's General view states that headers and bodies
  are not captured. Record that as expected native coverage, never as an
  empty-body success.
- Coverage: visible pending/failed request counts, sequence gaps, queue drops,
  and incomplete-coverage warnings. Do not claim lossless collection from a few
  visible rows.
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
Continue using the backend tests, the offline UI model checks, and
`make rendered-ui-check` for the packaged app. They cover only the boundaries
they explicitly assert, not native probe capture of a live site. Full
required validation remains defined by [AGENTS.md](../../AGENTS.md).

## No CI observation

No workflow visits these sites. The former manually dispatched public-demo
smoke drove stock Chrome through the removed debugger transport and was retired
with it; there is no native replacement in CI. Run this check manually under
the procedure above.

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
