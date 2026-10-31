<h1 align="center">Reverse Engineering Browser</h1>

> Capture is native-only. CDP transport, injection and live debugger features have
> been removed; saved historical evidence remains inert. Native Wasm dispatch
> instrumentation requires a rebuild and explicit opt-in; see
> [the contract and remaining limitations](protocol/native-wasm-dispatch-v1.md).
> Native JavaScript dispatch-site observation is a separate rebuilt-browser
> opt-in; see [its contract](protocol/native-js-dispatch-v1.md).

<p align="center">
  <strong>See the browser evidence behind fingerprints, requests, scripts, and runtime behavior.</strong>
</p>

<p align="center">
  <a href="https://github.com/sunghoojung/reverse-engineering-browser/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/sunghoojung/reverse-engineering-browser/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/sunghoojung/reverse-engineering-browser/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/sunghoojung/reverse-engineering-browser?label=release"></a>
  <a href="#build-the-custom-brave-browser-for-the-first-time"><img alt="Platform: macOS on Apple silicon" src="https://img.shields.io/badge/platform-macOS%20%7C%20Apple%20silicon-007AFF"></a>
</p>

<p align="center">
  A local-first research browser and macOS workspace for inspecting authorized
  web applications.
</p>

## Research workbench

Origin Trace connects captured requests, source bytes, runtime observations and
local research notes in one macOS workspace.

[Download v0.3.1: Origin Trace + Brave](https://github.com/sunghoojung/reverse-engineering-browser/releases/tag/v0.3.1)
· [Release validation](https://github.com/sunghoojung/reverse-engineering-browser/actions/runs/38192572669)
· [Changes since v0.3.0](https://github.com/sunghoojung/reverse-engineering-browser/compare/v0.3.0...v0.3.1)

### Preparing v0.3.2: Origin Trace companion only

The v0.3.2 candidate updates Origin Trace without building or distributing Brave.
The latest published paired release remains v0.3.1 until this candidate passes
acceptance and is explicitly published. The companion ZIP targets Apple silicon; macOS 15 acceptance is required before
publication. Earlier macOS versions are unverified; no Intel, Windows or Linux
app is supplied.

This candidate has **no validated native-browser pair**. Brave distributed with
v0.3.0/v0.3.1 lacks newer native runtime-buffer and VM capture features. A matching
bundle ID does not establish compatibility. Before starting a discovered browser,
Origin Trace warns about these limits and defaults to **Continue Offline**;
**Start Unverified Session** remains an explicit choice for each session.
Offline evidence inspection remains available. Packaging checks do not establish
native Brave instrumentation or Finder automatic launch. The current source
provides no CDP or stock-browser capture fallback.

The companion workflow records source/run identity, SHA256 checksums and these
compatibility limits. It uses ad-hoc signing, without Apple notarization. The
paired workflow and historical browser-equivalence guard remain separate and are
not relaxed. See [companion release procedure](docs/development/companion-release.md).

### Latest release: v0.3.1

These published artifacts and their validation history are unchanged; they do
not describe the current branch's native-only capabilities.

- **Native Close/Quit repair:** an aborted Close sheet cannot approve a fresh
  Quit. Stay preserves the exact draft and save state; Close Anyway requires a
  later explicit choice. Native acceptance passed, including per-request UUID
  checks and the repeated Close/Close/Quit case in five fresh processes.
- **Validated macOS app pair:** the new Origin Trace companion and the exact
  packaged Brave browser passed live-session, backend/debugger readiness,
  relocated WebKit UI and cleanup checks in the linked release workflow.
- **Traceable downloads:** the release includes SHA256 checksums and pair
  provenance with the companion source revision and exact browser pins. Brave
  is byte-for-byte the v0.3.0 archive, retaining its original local-build
  provenance; it was not rebuilt in clean CI.

Both app bundles are ad-hoc signed, not Apple-notarized. The release checks do
not establish Finder automatic launch or complete native capture/Canvas QA.

### v0.3.0 feature highlights

The v0.3.0 features remain available in v0.3.1:

- **Connected investigations:** follow retained Requests, Backtraces, Sources
  and Decoder ranges with identity-checked Back/Forward navigation. Save
  evidence-linked investigation notebooks that survive reloads.
- **Richer Traffic inspection:** search retained request and response content,
  trace request fields to original source candidates, preview isolated HTML,
  and compare captured requests and bounded response-body diffs without replay.
- **A native Console workbench:** explicitly run JavaScript in a separate
  disposable browser, with a persistent composer, bounded output, completion,
  object inspection and document-scoped commands.
- **Source and evidence tools:** search complete retained sources, explore
  lexical references and captured WASM, inspect deobfuscation changes, and
  compare Canvas, Memory and Float32 evidence.
- **Safer local workflows:** protect Analyst drafts, reconcile uncertain saves,
  and require a native Stay/Close Anyway decision before abandoning unsaved or
  unconfirmed work. Rust services power the local backend and analysis tools.

Worker and proxy foundations remain dormant; live proxy routing is not
implemented. Read the [workspace guide](apps/research-ui/README.md) for feature
boundaries and the [capture policy](SAFETY.md) before starting a session.

[v0.3.0 archives and validation history](https://github.com/sunghoojung/reverse-engineering-browser/releases/tag/v0.3.0)
· [v0.3.0 feature changes](https://github.com/sunghoojung/reverse-engineering-browser/compare/v0.2.2...v0.3.0)

### Feature changelog

- **v0.3.1:** released native Close/Quit lifecycle repair, per-request acceptance
  traces, and a checksum-verified Origin Trace + Brave pair with packaged QA.
- **v0.3.0:** connected investigation notebooks, richer Traffic and source
  analysis, native Console tools, evidence comparisons, Rust runtime services,
  and workspace save/close safeguards. See the highlights above.
- **v0.2.1:** redesigned live Traffic as a readable full-width request table
  with path and host hierarchy, compact request metadata, follow-to-bottom
  updates, a new-request jump, and full-URL inspection and copying.
- **v0.2.0:** added per-session metadata or bounded-content capture controls,
  prompt-free isolated profiles with explicit Keychain opt-in, verified browser
  readiness and retry/relaunch flows, private Brave diagnostics, a semantic
  deobfuscation benchmark corpus, and automated developer-tool bootstrap.
- **v0.1.10:** fixed the launch-time WebKit cancellation race that could show
  `NSURLErrorDomain error -999` while Origin Trace switched from its offline
  shell to the newly started live workspace.
- **v0.1.9:** made normal app launch start the broker, artifact receiver,
  debugger, analyzers, loopback UI, and instrumented custom Brave session
  automatically; packaged the required helpers and added explicit startup
  failure reporting and owned cleanup.
- **v0.1.8:** added bounded Rust/Oxc deobfuscation inside Sources, original-byte
  provenance, nesting protection, proxy and custom decoder evaluation, explicit
  JSFuck coercion assumptions, and bounded loop/switch dispatcher recovery.
- **v0.1.7:** refreshed the research interface and reorganized advanced tools,
  source inspection, request details, fingerprinting, memory, and experiments.
- **v0.1.6:** added stronger source, memory, request-signal, and analyst
  workflows with native application packaging and validation updates.
- **v0.1.5:** expanded the native research workflow and macOS distribution.
- **v0.1.4:** expanded native fingerprint probes, added per-tab newest-first
  activity and live tab counts, opt-in Canvas image capture, clearer queue-gap
  reporting, and controls to stop probes or clear the current session's events.
- **v0.1.3:** removed sample requests, events, and Canvas output from the
  production app bundle so every session starts with real captured evidence.
- **v0.1.2:** added the Fingerprinting workspace with Canvas image output, a
  local replay preview, captured drawing functions, fingerprint activity, event
  details, filters, and request correlation.

## Features

- **Native network observations:** inspect bounded method/host and request
  lifecycle metadata from the custom Brave build. Native metadata does not
  provide full URLs, headers, request bodies or arbitrary response bodies.
- **Tab and domain organization:** separate traffic by browser tab, then narrow
  a tab to a specific destination domain or resource type.
- **Native browser evidence:** record calls and property reads across Canvas,
  WebGL, Web Audio, device and layout APIs, Permissions, Storage, WebRTC, and
  JavaScript runtime fingerprinting, plus request lifecycle metadata from a
  custom Brave build.
- **Evidence navigation:** follow retained event and artifact identities;
  missing links and correlations do not establish request-value provenance.
- **Source inspection and native Console:** inspect retained sources and static
  analysis, or explicitly run commands in a selected native Console document.
  Live page breakpoints, stepping, paused scopes and watches are unavailable.
- **Artifact capture:** retain bounded copies of network-delivered and
  runtime-generated JavaScript and WebAssembly with hashes and provenance, plus
  explicitly authorized Canvas image output.
- **VM evidence:** inspect retained VM findings and bounded native runtime
  buffers. Opt-in Wasm guest observations require a rebuilt browser and a
  reviewed adapter; they do not provide arbitrary interpreter guest-PC recovery.
  See the [guest observation contract](protocol/native-wasm-guest-v1.md).
- **Research workflows:** save request definitions and evidence-linked analyst
  notes locally. Collections do not send requests; replay and CDP experiments
  are unavailable.
- **Local and bounded capture:** native queues and artifact transfers have
  explicit limits. Artifacts and historical captures may contain sensitive
  content; review them before sharing. No DevTools attachment or fallback is
  used, and no undetectability guarantee is made.

## How to use it

### Download the compiled macOS apps

1. Download both apps from [v0.3.1](https://github.com/sunghoojung/reverse-engineering-browser/releases/tag/v0.3.1):
   - [Origin Trace for macOS](https://github.com/sunghoojung/reverse-engineering-browser/releases/download/v0.3.1/Origin-Trace-v0.3.1-macos.zip)
   - [Brave Browser Development for Apple silicon](https://github.com/sunghoojung/reverse-engineering-browser/releases/download/v0.3.1/Brave-Browser-Development-v0.3.1-macos-arm64.zip)
2. Verify both ZIPs against [SHA256SUMS-v0.3.1.txt](https://github.com/sunghoojung/reverse-engineering-browser/releases/download/v0.3.1/SHA256SUMS-v0.3.1.txt).
   The [pair provenance](https://github.com/sunghoojung/reverse-engineering-browser/releases/download/v0.3.1/Origin-Trace-Brave-v0.3.1.provenance.json)
   records the exact companion source and reused browser pins.
3. Unzip both files and place the applications beside each other, or install
   Brave Browser Development in `/Applications`.
4. Open Origin Trace. It starts the capture services and an isolated custom
   Brave session automatically.

The compiled apps are for Apple silicon Macs. Origin Trace is built by the
release workflow; the reused Brave bundle retains its local-build provenance.
Read the selected release's validation results and limits. Origin Trace contains
no bundled sample evidence. The applications are ad-hoc signed but not
Apple-notarized.

In these published releases, opening Origin Trace starts an isolated one-hour
research session with the implemented capture categories, bounded request/response
content and Canvas artifacts enabled. Use it only for authorized targets. **New Live
Session…** offers metadata-only controls. Enabled content capture can retain
credentials without automatic masking; review captures before sharing.

**Validation history:** the v0.3.0 tagged app build and packaging checks passed,
but a separate [main CI run](https://github.com/sunghoojung/reverse-engineering-browser/actions/runs/37878440864)
timed out waiting for Stay dismissal in the repeated-close/Quit scenario.
The [v0.3.1 release workflow](https://github.com/sunghoojung/reverse-engineering-browser/actions/runs/38192572669)
passed the repaired native lifecycle gate and exact packaged-pair checks.
Quit now reaches the guard while a Close sheet is open; AppKit aborts that
sheet, and a fresh Quit decision checks the current document again. The v0.3.0
release tag and downloadable archives remain unchanged.

Downloading the compiled Brave app does not require a 100+ GiB source checkout.
Allow about 1 GiB to download and extract both apps, plus whatever space you
want to retain for browser profiles and captured sessions.

### Windows 11 and Linux

See the [Windows/Linux build guide](docs/development/windows-linux-build.md) for
the Linux development UI, an unverified WSL 2 route, and the current native
Windows porting requirements. The complete packaged application remains macOS-only.

### Run a live capture with an existing custom Brave build

From the current repository source, select a custom Brave build containing the
required native patches. Previously published browsers lack newer probes:

```sh
REB_BRAVE_BINARY="/path/to/Brave Browser Development.app/Contents/MacOS/Brave Browser Development" \
make live
```

Origin Trace and the custom Brave browser open together. Browse in that Brave
window and select requests in the **Traffic** tab. Close Brave to end the
session. Captured evidence is stored under `build/sessions/live/`.

Capture is native-only. Do not set `REB_CDP_NETWORK_CAPTURE` or configure a
debugger transport: the launcher rejects those removed paths. Native network
metadata is not a complete HTTP recorder; missing headers and bodies remain
unavailable. Retained artifacts and historical captures can still be sensitive.
An explicitly selected best-effort redacted copy does not modify the raw capture
and is not a guarantee that the copy contains no secrets; see the
[Traffic copy contract](protocol/traffic-capture-copy-v1.md).

Fingerprint operation names are captured by default. To also retain the exact
image returned by `HTMLCanvasElement.toDataURL()` for this one session, add
`REB_CAPTURE_CANVAS_IMAGES=1`. Canvas image output can contain page content, so
it is disabled by default, kept only in the local session store, and limited to
2 MiB per image.

### Build the custom Brave browser for the first time

These requirements apply only when compiling Brave from source. They do not
apply when using the downloadable compiled Brave app.

Source-build requirements:

- macOS with full Xcode installed;
- Node.js and pnpm;
- Python 3, a C++20 compiler, zlib, and Make;
- at least 150 GiB free, with 200 to 250 GiB recommended.

Prepare the pinned checkout, apply the integration, verify it, and build Brave:

```sh
./scripts/bootstrap-brave.sh --init
./scripts/sync-browser-integration.sh
make brave-doctor
make brave-probe-check
./scripts/brave-toolchain.sh build
```

The first full build can take several hours. Later builds are incremental and
normally reuse the existing checkout and compiled objects. After it completes,
start live capture with the command from the previous section.

### Native-only capability limits

Native capture never attaches a CDP debugger. Retained Sources/static analysis,
native Console and owned-VM debugging remain available; live page breakpoints,
stepping, watches and CDP memory inspection do not. The native Console requires
explicit commands and is separate from observational capture. See the
[workspace guide](apps/research-ui/README.md#native-only-capture).

Usage, authorization, capture, and privacy boundaries are defined in
[`SAFETY.md`](SAFETY.md).

## Local coding-agent workflow

Use the repository's shared skill with Codex or Claude Code to inspect an
explicitly selected Origin Trace backend, correlate exact evidence, and author
client code with offline synthetic tests. The CLI offers machine-readable
operation discovery and an opt-in read-only effect guard. `scripts/reb-api-mcp.sh`
connects that same loopback API to a same-machine stdio client. Local transport
does not prevent capture data from entering an agent provider's context; agree on
sharing scope before reading captures. See the
[local coding-agent guide](docs/development/local-coding-agents.md) for setup,
MCP client configuration, native-mode limits, and approval boundaries.

## Development and validation

Repository CI covers source checks, native/Rust tests, the event path, macOS app
packaging and rendered acceptance of the packaged app. The packaged-app gates use
synthetic local stores and real WKWebView/AppKit input:

```sh
make lint
make check
make e2e
make sanitize
# macOS only:
make app-build
codesign --verify --deep --strict "build/Origin Trace.app"
node tools/check-origin-trace-native-close.mjs
make rendered-ui-check
```

`make agent-preflight` formats and lints files changed since `origin/main`,
including unstaged edits. `make agent-preflight TYPECHECK=1` also runs
`cargo check` for a changed Rust crate. `make lint` remains the full source gate.
`git config core.hooksPath .githooks` runs the preflight before `git push`.

Pull requests that only change documentation skip the native, Rust, and macOS
gates. Pull requests that only change the Rust backends still run those tests
on Linux and macOS and skip the macOS app archive and rendered UI. A push to
`main`, the daily schedule, and a manual run always use the full gate. The
skip decision fails closed.

`make rendered-ui-check` injects a hosted XCTest bundle into a relocated copy of
the packaged app and drives its WKWebView with native pointer and keyboard input
at the default and minimum window sizes. It covers Traffic, Sources,
Investigation navigation and VM native guest rows built from the real C++
encoders, checks layout, focus order and visible focus, scrolling and inert
captured text, and writes screenshots to `build/rendered-ui-qa/`. See the
[Origin Trace UI guide](apps/research-ui/README.md#rendered-ui-acceptance).

The native close gate exercises 14 scenarios, including clean close/Quit,
Return/Escape safety, missing or late save-state replies, navigation, and
repeated Close/Quit. Ordinary Quit uses queued Command-Q; with a close sheet
already open, the repeated case schedules the native Quit action in default
run-loop mode. It waits for actual delegate receipt before choosing Stay,
checks that the draft survives, then requires a new Close Anyway decision.
The repeated scenario runs in five fresh processes;
every attempt must pass. Per-attempt traces and prompt screenshots are written
to `build/native-close-qa/` and uploaded by CI. Linux contract checks validate
wiring and trace assertions; they do not establish native macOS behavior.

See [contributing](CONTRIBUTING.md), the [documentation index](docs/README.md),
and the [repository guide](AGENTS.md) for subsystem checks and the source map.
