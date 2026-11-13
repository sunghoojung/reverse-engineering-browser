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
  Every session the app starts uses an isolated research profile with
  Chromium's mock Keychain, so the browser neither reads nor writes the macOS
  Keychain; the start panel offers no Keychain choice. The only route to the
  macOS Keychain for an app session is `REB_AUTOMATIC_USE_SYSTEM_KEYCHAIN=1`,
  which applies to the automatic launch and a reopen's restart, never to a
  session the panel starts or retries. The standalone `make live` launcher reads
  `REB_USE_SYSTEM_KEYCHAIN`. Do not save real credentials in an isolated profile.
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
  calls**), which the start panel lists and the titlebar names while the
  session runs. Saving a site changes nothing in the open page or the running
  capture; tracking starts with the next capture. Each saved site keeps its
  script's raw source URL beside it, locally and user-only, like the artifact
  manifest. An explicit `REB_NATIVE_JS_INVOCATION_SITES`, even an empty one,
  replaces the saved set. Agent-started sessions arm invocation sites only when
  the start request names them (`js_invocation_sites`, a file the agent wrote,
  or `js_invocation_saved_sites`), never inherited, and keep their own saved
  set, so an agent cannot read or change what the researcher's next capture
  arms.
- Request call stacks (`REB_NATIVE_REQUEST_STACKS`, on by default in the
  packaged app when Network and Artifact are captured) record script IDs and
  positions of the stack that started each document or worker request or
  script navigation, and of the stack that scheduled each async task it came
  from, including the stack that posted a message to a port, a broadcast
  channel or a worker, never names or values. `REB_NATIVE_PROMISE_STACKS=1`,
  off by default everywhere, also records the stack of each promise
  registration. Content capture sessions also retain the source of
  each script a stack names as an artifact; metadata-only sessions do not.
  Agent-started sessions record them only when the start names
  `request_stacks`.
  See [Native network v3](protocol/native-network-v3.md).
- A posted message (`MessagePort`, `BroadcastChannel`, or a dedicated worker's
  `postMessage` either way) carries a task origin to the thread and renderer
  process that handle it, while request stacks are recorded and capture is
  active on the posting thread. It is at most 1,544 bytes: an 8-byte header
  (version, segment count, and whether the chain was cut or went on past 32
  segments) and up to 32 segments of 48 bytes. Each segment is a task kind; a
  state (captured, not retained, not recorded, scheduled with no script, or
  ended at a rejected origin); two flags (the walk stopped at its frame limit,
  and, for a promise reaction with no recorded registration, whether promise
  registration stacks were on); a promise registration kind; a frame count;
  and the SHA-256 digest naming a stack artifact. Segments travel onward: a
  handler that posts again carries the segments it received after its own, so
  a segment and its digest can reach every renderer a chain of messages later
  passes through, never more than 32 segments in one message. Each digest
  names the artifact that the renderer which walked that segment stored: the
  poster for its own segment, an earlier renderer in the chain for one the
  poster had received. The origin names no process, thread, table or serial,
  and holds no URL, name, source, value or frame. Page JavaScript in no
  renderer can read it: Blink hands it only to the stack sink, never to a
  `MessageEvent`. Each receiving renderer process holds the bytes, and a
  `MessagePort` transferred to a cross-site frame makes that a cross-site
  process. A compromised receiving renderer would learn how many async tasks
  of which kinds led to the post, their stack depths and promise registration
  kinds, whether their stacks were retained or promise stacks were on, and the
  digests. A digest reveals no strings, but equal digests mean equal stacks,
  and since a digest covers the walking renderer's frame identities (script
  IDs and positions) and its process ID, thread kind and isolate key, such a
  renderer could confirm guessed values of those. A receiver writes the
  carried digests into the stack artifacts of requests its handler starts, so
  they are stored in that handler's evidence. On the posting thread itself a
  receipt links to the posting segment through a record of that thread's last
  16 posts, which never leaves the thread. An origin that does not validate,
  or is longer than 1,544 bytes, is rejected without being stored and counted
  as a `message_task_origin_rejected` gap.
- Debugger observation rules (Console `watch`) are off until armed on one
  selected live document and never pause it. They record request matches,
  listener dispatch, timers, CSP violations, exceptions and mutations of at most
  4 selected elements as script IDs, positions, kinds, the blocked host and
  attribute names, never values, text, paths or queries. Navigation, `unwatch`,
  a Console Stop or a new capture disarms them. A lost backend connection leaves
  them armed until navigation or the capture ends. See
  [Native debugger observation v1](protocol/native-debugger-observation-v1.md).
- With Artifact capture on, every script V8 compiles records its V8 script ID,
  realm, kind, UTF-8 length, SHA-256 and, for `eval` and `Function`, the script
  and position that created it. A digest of a short or predictable source can be
  confirmed by guessing. Source text that no response body carried (`eval` and
  `Function` strings, inline, inserted and `blob:` scripts) is page content and
  is sensitive capture: it is retained only with `REB_CAPTURE_REQUEST_CONTENT=1`,
  which the packaged app's default content mode sets, at most 16 MiB per script
  and 64 MiB of distinct text per renderer and configuration. See
  [Native compiled scripts](protocol/native-compiled-scripts-v1.md).
- Standalone probes remain inactive without an enabled session. Enabled artifact
  capture retains raw source URLs locally; metadata is not necessarily secret-free.
- With Network capture on, every native request records its body's length,
  normalized content type and SHA-256. A digest of a short or predictable body
  can be confirmed by guessing; password form posts keep no digest. Request
  paths, queries and body bytes are sensitive capture: they are retained only
  with `REB_CAPTURE_REQUEST_CONTENT=1`, which the packaged app's default content
  mode sets, at most 16 MiB per body and 256 MiB of unique body and full-URL
  bytes per session unless `REB_REQUEST_CONTENT_BUDGET_MIB` or the start panel's
  **Request content budget** sets another, from 1 MiB to 4 GiB. Those bytes
  include uploaded files, blobs and stream bodies, which the
  browser reads for that purpose. See [Native network v2](protocol/native-network-v2.md). The same
  sessions retain response bodies, at most 16 MiB each and 512 MiB of unique
  bytes unless `REB_RESPONSE_BODY_BUDGET_MIB` sets another budget, including
  partial copies of bodies still arriving, which use at most a quarter of it; images,
  audio, video and fonts that page elements load need
  `REB_CAPTURE_RESPONSE_MEDIA=1` or the start panel's **Capture media and
  fonts**, and the panel's **Response body budget** sets that budget, from
  1 MiB to 16 GiB. See [Native network v3](protocol/native-network-v3.md).
  The backend's request index keeps a private derived copy of those paths
  beside the event store; capture clear removes it
  ([request index v1](protocol/request-index-v1.md)).
  A load Blink answers from a resource it already holds (its memory cache, or
  a `data:` URL or MHTML archive resource it decodes itself) makes no request
  and is still recorded as one row: its host, status, decoded size, Blink
  resource type, frame and the ID of the renderer request that loaded it
  always, and its path and query only in content
  capture and only as a 116-byte prefix, which for a `data:` URL is the start
  of the data itself. At most 4,096 are recorded per renderer configuration;
  the rest, and those in pages that are not ordinary, such as an SVG image's
  own document, are counted
  ([Native network v3](protocol/native-network-v3.md#memory-cache-reuse)).
- Browser-internal pages (WebUI, DevTools) and extension background workers are
  counted, not recorded. `REB_CAPTURE_BROWSER_INTERNAL=1` and
  `REB_CAPTURE_EXTENSION_TRAFFIC=1` record them, extension traffic under its
  extension id, with the same content gates; agent-started sessions never set
  them.
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
  it turns on retention of request paths, queries and bodies and of response
  bodies, up to 16 MiB each, of request and response headers, including `Cookie`, `Set-Cookie` and
  `Authorization`, of the cookies each request sent and received and the
  cookie names and value digests page script used, and of Canvas images, and
  the titlebar labels that session "Content capture". **Metadata
  only** is the opt-out, chosen in the start panel that **New Live Session…**
  opens, or with `REB_AUTOMATIC_CAPTURE_MODE=metadata` for the automatic
  launch too; any other value but `content` also selects it. The app saves no choice between launches, and a choice made in the
  start panel holds for the rest of that app run. The standalone `make live` launcher
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
  start panel says so, and the launch log and titlebar label the session.
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
- Origin Trace exposes no Chrome DevTools Protocol endpoint and opens no
  remote debugging port. The browser debugger, runtime hooks, live objects,
  element screenshots and the CDP live Wasm inspection routes used a protocol
  connection to the browser and were removed with it; those retired contracts
  remain only as history. Confirmed live Wasm memory and call commands are a
  separate local socket (`get_live_wasm`, `live_wasm_action`). They stay behind
  the existing effect and confirmation gates, do not replace dispatch capture,
  and report the command unavailable when no peer is configured. They do not
  invent memory bytes or return values. A current Brave build does not
  implement that peer. Other Wasm evidence comes from native capture and stored
  artifacts. The owned VM debugger controls only the project's own native
  fixture helper. Confirmed pausing debugger commands are a third local
  socket (`get_native_debugger`, `native_debugger_action`), behind the same
  effect, confirmation and content gates: a selection needs explicit
  confirmation, every pausing action is effectful, and values read out of a
  paused page, with the page-derived names they are keyed by, reach a model
  only at Full access. No Brave build implements that peer. Without one the
  state is `availability: unsupported` and every action is refused before
  anything is sent, so nothing pauses, steps or resumes and no frames, scopes
  or values are invented. What a browser implementation must do, and what it
  can and cannot confine, is written in
  [Native debugger pause v1](protocol/native-debugger-pause-v1.md) and
  [Native debugger v1](docs/product/native-debugger-v1.md): a pause stops a
  whole renderer main thread, a lease the browser itself holds ends it, and
  an authorization ends on navigation, replacement, a lost renderer
  connection or five minutes without a command. Those rules become policy
  here only when a compiled, live-verified browser half lands with maintainer
  approval; until then they are a specification, not a description of this
  product. Pausing would be detectable, and hiding it from the page is a
  non-goal.
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
  cannot set breakpoints, step, or inspect paused frames; those
  belong to the pausing debugger commands above, never to a console command. Expressions and
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
- The in-app agent is off by default and is turned on per session by an
  explicit researcher action, after a disclosure of what leaves the machine
  and a choice of one of four permission levels: Read only (the default), Ask
  for actions, Auto-approve actions and Full access. Below Full access, the
  question, researcher-pinned excerpts and the structural results of the tools
  the model calls (identifiers, counts, URLs and hosts; no source, bytecode,
  disassembly or request bodies) go to the selected model provider. Read only
  offers only read-only tools. Ask for actions runs each effectful tool only
  after the researcher's **Allow once**; Auto-approve actions runs them without
  asking. Every tool call and its full result is shown in the transcript at
  every level. Provider keys stay in the macOS Keychain and are added by the
  native app; the web view never holds one.
- Full access also lets the model read captured content through its tools and
  start, drive and end its own visibly labeled live sessions. At this level
  source, Wasm bytes and disassembly, VM bytecode, request and response bodies,
  the researcher's Collection and Analyst drafts, local store paths and every
  other content field of a tool result go to the provider. Choose it only when
  the target's authorization and the provider's terms allow that data to leave
  the machine. The request header and cookie reads withhold cookie values and
  credential header values (by header name) at every level, and the text reads
  and search never return header blocks or cookie lists. Other header values,
  such as `Location` or `Referer`, are returned as captured and can still hold
  a secret, and script the agent evaluates in a connected document at Full
  access returns whatever that page can read, such as `document.cookie`. The
  agent's own sessions can name request content, response media, canvas images
  or invocation value digests only when the researcher also ticks a separate
  sensitive-capture box, off by default and never remembered. Consent in the
  agent dock turns a level on: it shows what leaves the machine for that
  level, with the warning for Auto-approve actions and Full access, beside a
  button that names the level, and there is no other confirmation. The native
  app accepts only a known level, and the sensitive-capture choice only with
  Full access, then holds the level and enforces it: it decides every tool
  call by the running level for every provider and CLI, remembers no level
  above Ask for actions across launches, and lowers the level at once from the
  dock menu; raising it goes back through consent. No level authorizes a
  target, widens session scope or exempts the agent from this policy.
- `reb-api mcp --permission read-only|ask|auto|full` applies the same levels to
  a local coding agent connected through `scripts/reb-api-mcp.sh`. `full` (or
  `--allow-content`) sends captured content to that client's model provider in
  the same way, and `--allow-sensitive-capture` is the same separate consent
  for sensitive options in the sessions it starts.
- Researcher names for Wasm functions (Analyst evidence names) are joined
  into the Wasm reads as `analyst_name` at every level, like identifiers, so
  they go to the provider with the structural results. They are the
  researcher's own text, at most 80 characters; do not put a captured secret
  in a name. Request, source and VM handler names are not joined into any
  read. See [Wasm function names](protocol/wasm-function-names-v1.md).
- The agent can instead use the researcher's own subscription. A ChatGPT
  subscription signs in through OpenAI token sharing in the researcher's
  browser; its tokens and client registration stay in the macOS Keychain and
  are added by the native app only to the fixed Responses and model-list
  endpoints. Claude and Grok subscriptions run the researcher's own installed
  and signed-in CLI, for their own local use. Origin Trace never reads the
  CLI's credentials. It starts the CLI with only the reb-api tool server and no
  built-in tools, user settings, hooks, memory or other MCP servers, refuses
  any other tool the CLI asks to run, and ends the CLI when the agent is
  switched off. On these paths the data the chosen level allows goes to that
  vendor under the terms of the researcher's plan, and the
  vendor's CLI may keep its own local record of the session (Grok under
  `~/.grok/sessions`).

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
| Compiled script source opt-in (`--reb-capture-request-content`) | Brave overlay renderer `native_probe_sink.cc` and browser `native_artifact_capture_sink.cc`, which refuses the text outside content capture |
| Canvas image opt-in | Brave overlay renderer `native_probe_sink.cc` and browser `native_artifact_capture_sink.cc`, which refuses an image the session did not opt in to |
| Capture category mask and session expiration | `protocol/README.md`, native probes |
| Agent-started sessions get request content, document-start permission, invocation sites and digests only when the start request names them, never inherited | [`session_launch.rs`](apps/origin-trace-backend/src/session_launch.rs) |
| JavaScript invocation value digests opt-in | `scripts/run-live-session.sh`, the overlay's `native_probe_session.cc`, and the renderer sink, which refuses a digest without it |
| App-started digest default and agent-session exclusion | `LiveSessionCoordinator.captureDefaults` (Content mode with saved sites only, explicit value wins) and `session_launch.rs` (agent sessions remove an inherited site file and digest switch, and arm only named sites from a private copy) |
| In-app agent permission level and per-call decision for the LangGraph and CLI loops | `AgentPermission.requested` (the level and sensitive choice consent sends) and `AgentToolGate` in [`AgentCore.swift`](apps/research-ui/macos/AgentCore.swift), held by `enable` and changed only by `lowerPermission` in [`AgentBridge.swift`](apps/research-ui/macos/AgentBridge.swift) |
| Tool server content, effect and sensitive-capture gates (`--permission`, `--allow-content`, `--allow-sensitive-capture`) | [`mcp.rs`](apps/origin-trace-backend/src/bin/reb_api/mcp.rs) |
| Header blocks and cookie lists never returned by the text reads or search, at any level | `WITHHELD_KINDS` in [`artifact_text.rs`](apps/origin-trace-backend/src/artifact_text.rs) |
| Message task origins bounded before they are read and validated before use | `CloneableMessage` traits and `ShallowClone` in Chromium patch `0047-carry-message-task-origins.patch`, then `DecodeNativeTaskOrigin` in the overlay's `common/native_request_stack.h` |
| Origin allowlisting | Not implemented; the native event envelope lacks trustworthy origin identity |

## Related documents

- [`AGENTS.md`](AGENTS.md) is the coding-agent operating contract.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) describes the repository workflow.
- [`docs/README.md`](docs/README.md) is the documentation index.
- [`protocol/README.md`](protocol/README.md) owns the transport contracts that
  implement the capture boundaries above.
