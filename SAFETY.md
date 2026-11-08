# Safety, Authorization, and Capture Policy

Reverse Engineering Browser (REB) is a local-first research harness for
authorized website security research. This file is the source of truth for
authorization, scope, capture, privacy, and local-operation policy. Other
documents describe the implementation and link here for the policy that governs
it.

## Authorized targets and scope

- Use REB only on systems you own or are explicitly authorized to test. A
  friend's site or a capture-the-flag target is in scope only when its owner or
  organizer authorizes the specific target and testing activity.
- Follow applicable law, contracts, and the rules provided by the system owner
  or challenge organizer.
- Keep testing within the authorized target, methods, time window, and any
  limits set by the owner or organizer. Permission to visit a site does not by
  itself authorize security testing.
- REB does not maintain a list of preapproved sites, verify ownership, or
  determine whether a user has permission.
- Current native event records do not carry a trustworthy origin identity, so
  origin allowlisting is not implemented. Session category masks and expiration
  do not enforce a domain boundary. Treat architecture documents that describe
  origin-scoped sessions as intended design unless the implementation and its
  contracts show otherwise.
- Do not intercept, capture, or modify activity outside the authorization for
  the target being tested. Agents and people follow the same scope.

## Default capture

- Opening the packaged Origin Trace app starts a visibly labeled local research
  session with implemented native capture categories. CDP collection and injected
  JavaScript hooks have been removed. Launch only for authorized targets/data.
  The session expires after one hour. The packaged app also enables native Wasm
  `br_table` and `call_indirect` dispatch instrumentation and ignores page
  `debugger;` statements by default; set `REB_NATIVE_WASM_DISPATCH`,
  `REB_NATIVE_WASM_CALL_INDIRECT` or `REB_NATIVE_QUIET_MODE` to `0` to opt out.
  The standalone `make live` launcher leaves all three off unless set to `1`.
  Wasm dispatch needs a rebuilt browser. Native guest-program
  capture is a further opt-in on top of it: it needs a researcher-supplied
  adapter recipe file and records typed local values and bounded bytecode
  snapshots that the recipe names. Recipes are evidence inputs, not proof of
  guest semantics. Guest capture is native only; no debugger protocol is used.
  Native JavaScript dispatch-site capture is a separate opt-in: it needs a
  rebuilt browser and a researcher-supplied site file, observes at most 8
  sites, and records only selector kinds and integer low bits, V8 script IDs,
  source positions and the armed site's source digest, never argument,
  receiver or string contents.
  Native JavaScript invocation identity is a separate opt-in with the same
  rebuilt-browser and site-file requirements (`REB_NATIVE_JS_INVOCATION_SITES`,
  at most 8 functions). It records, per admitted call (at most 256 per
  configuration), argument kinds and integer low bits, the result's kind and
  length, the frame and a digest of the document token, and which Wasm
  records and loader requests ran inside the call. It never records argument,
  receiver, return or exception contents. Captures the packaged app starts arm
  its saved site set (at most 8 functions, saved from Sources with **Track
  calls**), which the start dialog lists and the titlebar names while the
  session runs. Saving a site changes nothing in the open page or the running
  capture; tracking starts with the next capture. Each saved site keeps its
  script's raw source URL beside it, locally and user-only, like the artifact
  manifest. An explicit `REB_NATIVE_JS_INVOCATION_SITES`, even an empty one,
  replaces the saved set. Agent-started sessions arm invocation sites only when
  the start request names them (`js_invocation_sites`, a file the agent wrote,
  or `js_invocation_saved_sites`), never inherited, and keep their own saved
  set, so an agent cannot read or change what the researcher's next capture
  arms.
- Standalone probes remain inactive without an enabled session. Enabled artifact
  capture retains raw source URLs locally; metadata is not necessarily secret-free.
- With Network capture on, every native request records its body's length,
  normalized content type and SHA-256. A digest of a short or predictable body
  can be confirmed by guessing; password form posts keep no digest. Request
  paths, queries and body bytes are sensitive capture: they are retained only
  with `REB_CAPTURE_REQUEST_CONTENT=1`, which the packaged app's default content
  mode sets, at most 256 KiB per body and 1,024 bodies or 64 MiB per session. See
  [Native network v2](protocol/native-network-v2.md). The backend's request
  index keeps a private derived copy of those paths beside the event store;
  capture clear removes it ([request index v1](protocol/request-index-v1.md)).
- Historical captures can include sensitive URLs, headers, bodies and source.
  Removal of CDP does not sanitize previously saved evidence. Only collect and
  disclose data covered by authorization.
- Operational bounds remain enforced. Missing data, truncated prefixes and
  evictions must be visible; raw display never means complete wire capture.
- Redaction is an explicit export-copy operation. It never rewrites retained
  captures. The best-effort copy is not a guarantee that arbitrary secrets have
  been removed; review it before sharing. Existing `reb-metadata-only-v1`
  evidence packages remain a distinct explicitly selected metadata export.
- Keep routine logs free of secrets and personal content. Never send raw captures
  to AI services, cloud services or repositories automatically.

## Sensitive capture

- Sensitive capture requires an enabled, visibly labeled session. Content mode
  is the default for captures the packaged app starts: for its bounded session
  it turns on retention of request paths, queries and bodies up to 256 KiB each
  and of Canvas images, and the titlebar labels that session "Content
  capture". **Metadata
  only** is the opt-out, chosen in **New Live Session…** or with
  `REB_AUTOMATIC_CAPTURE_MODE=metadata`; any other value but `content` also
  selects it. The app saves no choice between launches, and a choice made in the
  dialog holds for the rest of that app run. The standalone `make live` launcher
  leaves request content and Canvas images off unless set to `1`. Agent-started
  sessions (`reb-api session start`, MCP `start_live_session`) retain request
  content only when the start request names it (`request_content` with
  `confirm_sensitive_capture`), never inherited, and turn Canvas images on only
  with the same explicit confirmation.
- Settled-value digests of armed JavaScript invocations are a sensitive
  capture path: `REB_NATIVE_JS_INVOCATION_DIGESTS=1`, accepted only with an
  invocation site file and labeled when the session starts. Each fulfilled
  string (UTF-8) or byte value of at most 1 MiB gets a SHA-256 and a 64-bit
  rolling hash, retained in the local event store so Origin Trace can find the
  exact value in a retained request body. Both are content-derived; evidence
  package exports never include them. A digest is not redaction: a short or
  guessable value can be confirmed from it. Content-mode captures the packaged
  app starts with saved invocation sites record these digests by default; the
  start dialog says so, and the launch log and titlebar label the session.
  Metadata mode never records them. Agent-started sessions record them only
  when the start request names them (`js_invocation_digests` with named sites
  and `confirm_sensitive_capture`), never inherited. An explicit
  `REB_NATIVE_JS_INVOCATION_DIGESTS=0` opts out in Content mode. A Brave
  without invocation capture starts without the saved sites, so it records
  no digests either.
- Enable sensitive capture only when the authorization for that session
  specifically covers the data being collected. Keep the capture bounded, audit
  the action, and document new capture paths, their limits and explicit export-copy checks.
- Audit commands and sensitive capture where the feature provides that audit.
- Do not treat a session category or expiration as proof of target
  authorization. Current origin-scope limitations are described above.

## Observation and experiments

- Probes remain disabled by default and observational. A visibly enabled
  experiment and an explicit researcher action are required for browser
  mutation. A Wasm execution deadline only records that an instrumented call
  is still running. Interrupting that call is a separate explicit action: it
  traps the call so the host can continue. The deadline does not do that.
- Origin Trace has no Chrome DevTools Protocol path. The browser debugger,
  runtime hooks, live objects, element screenshots and the CDP live Wasm
  inspection routes used it and were removed with it; those retired contracts
  remain only as history. Confirmed live Wasm memory and call commands are a
  separate local socket (`get_live_wasm`, `live_wasm_action`). They stay behind
  the existing effect and confirmation gates, do not replace dispatch capture,
  and report the command unavailable when no peer is configured. They do not
  invent memory bytes or return values. A current Brave build does not implement
  that peer. Other Wasm evidence comes from native capture and stored artifacts.
  The owned VM debugger controls only the project's own native fixture helper.
- An agent starts, drives and ends a live capture session only through the
  session tools: `start_live_session` or `reb-api session start`, and
  `session_action` with `open_url` or `end`. They stay hidden until the
  researcher runs the MCP server with `--allow-effects` and
  `--allow-session-start`. Those flags are not authorization. The researcher
  still names the authorized target, and the agent opens only URLs inside it.
  An agent-started session is an ordinary visibly labeled capture session with
  its own fresh browser profile, every capture switch off unless named, and the
  usual one-hour expiry. Through MCP, `session_action` acts only on a session
  that connection started, never on the researcher's own session. `open_url`
  reaches only that session's capture browser, only while its capture broker
  runs, and never through page JavaScript. A running broker does not prove the
  browser records, so `open_url` reports `capture_observed`; when it is false
  the page was not recorded and the agent ends the session. An agent may turn
  on sensitive capture (Canvas images, request content or invocation value
  digests) only with `confirm_sensitive_capture`, and only when the
  researcher's authorization for that session covers that content. The start
  result, the first line of its launch log and the session context name every
  such switch the session runs with.
  An agent may supply guest adapter or dispatch-site files it wrote for the
  authorized target; they only select what is sampled. Agent sessions do not
  use the macOS Keychain; do not sign in with real credentials unless the
  authorization covers it.
- Agents can click, type, press keys and scroll in their own session's page
  with `session_action` input actions. These send real macOS input events,
  which pages cannot tell from a person's, so use them only where the
  authorization covers interacting with the target. They need Accessibility
  granted to the app that started the session, bring the capture browser to
  the front and move the real pointer; do not use the Mac while an agent sends
  input. A click or scroll is sent only when a hit test finds the capture
  browser's page (and the named control) under the point, keys only while the
  keyboard focus is inside the page, and there is no right click, so input
  never reaches the address bar, browser dialogs, DevTools or another
  application. `list_inputs` reads control names, which are page text; it
  does not read field values, though a name can include label text that
  embeds one. No DevTools protocol or page JavaScript is involved.
- Run mutable tools in a disposable experiment context by default. Experiments
  do not read or modify baseline tabs, production cookies, storage, or
  credentials. Never execute extracted code automatically.

- The native Console defaults to a separate disposable browser profile. Explicit
  Live capture mode additionally requires a specifically selected native document
  and confirmation that commands can mutate that live document before the first
  mutable command. Commands are pinned to its native document generation and
  capture binding. Navigation, replacement, or lost ownership clears authorization
  and requires explicit reselection or reconnection. Never select an execution
  target by URL, remap automatically, retry a command, or fall back to a disposable
  browser without an explicit mode change. The console
  cannot set breakpoints, step, or inspect paused frames. Expressions and
  primitive results may contain sensitive values; they stay in bounded,
  ephemeral panel memory and are not automatically captured, redacted, logged,
  exported, or added to evidence. Clear output before sharing the interface.
  Commands require an explicit document selection and are never automatically
  retried. See [Native Console v2](protocol/native-console-v2.md) for these limits.

- Document-start Console scripts are a separate, separately armed experiment and
  a deliberate exception to the explicit-document rule above, not a loophole in
  it. An armed snippet runs automatically in every **new** document that matches
  a declared rule, so the declaration itself is the authorization boundary. A
  rule names one exact serialized origin, exactly one frame kind, and an optional
  literal path prefix. There is no pattern, wildcard, host suffix, URL guessing,
  automatic remapping, or retroactive injection into documents that were already
  open. Arming requires a rebuilt browser, an explicit browser-session switch,
  and a separate confirmed action; a live capture additionally requires the
  existing selected-document live opt-in, and nothing is relaunched to obtain any
  of them. The packaged app grants that browser-session permission to every live
  capture it starts, and the Console header shows it, reading "Doc-start:
  permitted" before any Console connection; an explicit
  `REB_CONSOLE_DOCUMENT_START=0` opts out. The permission arms
  nothing: the declared rule, armed by that separate confirmed action, remains
  the authorization boundary, and nothing runs until a rule is armed. A browser
  built without the experiment ignores the switch and the Console reports it
  unavailable. The standalone `make live` launcher and the disposable Console
  grant it only when asked, and agent-started sessions (`reb-api session start`,
  MCP `start_live_session`) receive it only when the start request names it
  (`document_start: true`), never inherited. An agent arms a rule only through
  the same live Console connection to a selected document and the same
  confirmed action. Clearing the set, disconnecting, ending the session, or session expiry
  removes the scripts and their output; when the browser cannot confirm a removal,
  the Console reports it unconfirmed instead of idle. Snippet output is bounded, ephemeral
  page-JavaScript observation with provenance `console-document-start-script`: it
  is never native evidence, never correlated, and never exported automatically. A
  snippet runs in the page main world, so log only argument kinds, lengths,
  counts and digests, never raw strings, tokens, cookies, credentials or bodies.
  See [Native Console v3](protocol/native-console-v3.md) for these limits.

## Local operation and evidence

- Keep control and evidence traffic on `localhost` or another user-only local
  transport. Keep the unauthenticated research HTTP API bound to loopback; do
  not expose it on a network interface. Remote access requires real
  authentication and authorization and an explicitly approved threat-model
  change.
- Socket transports use user-only permissions and authenticate local clients
  before enforcing session scope.
- Keep evidence on the machine in the local session store. Never upload it
  automatically.
- Keep captured evidence and credentials out of commits, logs, and shared
  artifacts.

## Enforcement status

This policy states the project rules; it does not claim that REB verifies a
researcher's authorization. The following implementation points enforce parts
of the data-handling policy:

| Boundary | Enforcement point |
| --- | --- |
| Sensitive artifact rejection without an enabled session | `src/evidence/artifact.cpp` |
| Loopback-only research API trust check | [`config.rs`](apps/origin-trace-backend/src/config.rs) and [`app.rs`](apps/origin-trace-backend/src/app.rs) |
| Artifact receiver `--allow-sensitive` gate | `services/artifact-receiver/main.cpp` |
| Request path and body gate (`--reb-capture-request-content`) | Brave overlay `native_probe_socket_client.cc` and `native_network_capture_sink.cc`; receiver `--allow-sensitive` |
| Canvas image opt-in | Brave overlay renderer `native_probe_sink.cc` and browser `native_artifact_capture_sink.cc`, which refuses an image the session did not opt in to |
| Capture category mask and session expiration | `protocol/README.md`, native probes |
| Agent-started sessions get request content, document-start permission, invocation sites and digests only when the start request names them, never inherited | [`session_launch.rs`](apps/origin-trace-backend/src/session_launch.rs) |
| JavaScript invocation value digests opt-in | `scripts/run-live-session.sh`, the overlay's `native_probe_session.cc`, and the renderer sink, which refuses a digest without it |
| App-started digest default and agent-session exclusion | `LiveSessionCoordinator.captureDefaults` (Content mode with saved sites only, explicit value wins) and `session_launch.rs` (agent sessions remove an inherited site file and digest switch, and arm only named sites from a private copy) |
| Origin allowlisting | Not implemented; the native event envelope lacks trustworthy origin identity |

## Related documents

- [`AGENTS.md`](AGENTS.md) is the coding-agent operating contract.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) describes the repository workflow.
- [`docs/README.md`](docs/README.md) is the documentation index.
- [`protocol/README.md`](protocol/README.md) owns the transport contracts that
  implement the capture boundaries above.
