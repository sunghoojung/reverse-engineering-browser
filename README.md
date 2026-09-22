<h1 align="center">Reverse Engineering Browser</h1>

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

## v0.1.8 released

Origin Trace now provides bounded static JavaScript deobfuscation directly in
Sources. It preserves the captured artifact, maps derived expressions back to
their original byte ranges, and keeps unknown or unsafe operations visible.

[Download Origin Trace v0.1.8](https://github.com/sunghoojung/reverse-engineering-browser/releases/download/v0.1.8/Origin-Trace-v0.1.8-macos.zip)
· [Release notes](https://github.com/sunghoojung/reverse-engineering-browser/releases/tag/v0.1.8)
· [Full changelog](https://github.com/sunghoojung/reverse-engineering-browser/compare/v0.1.7...v0.1.8)

### Feature changelog

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

- **Live network traffic:** inspect request methods, full URLs, status codes,
  timing, headers, request bodies, and response bodies captured through CDP.
- **Tab and domain organization:** separate traffic by browser tab, then narrow
  a tab to a specific destination domain or resource type.
- **Native browser evidence:** record calls and property reads across Canvas,
  WebGL, Web Audio, device and layout APIs, Permissions, Storage, WebRTC, and
  JavaScript runtime fingerprinting, plus request lifecycle metadata from a
  custom Brave build.
- **Origin tracing:** follow a request backward through the observed events,
  scripts, frames, execution contexts, and captured artifacts that contributed
  to it.
- **Source inspection and debugging:** browse page sources, set breakpoints,
  pause and step through JavaScript, inspect scopes, evaluate watches, and use a
  live console.
- **Artifact capture:** retain bounded copies of network-delivered and
  runtime-generated JavaScript and WebAssembly with hashes and provenance, plus
  explicitly authorized Canvas image output.
- **Memory and backtrace tools:** inspect heap snapshots, live objects, decoded
  stack frames, and VM-related findings.
- **Research workflows:** save requests to collections, replay isolated
  requests, run controlled experiments, and keep local analyst notes.
- **Local and bounded capture:** evidence remains on the machine. Sensitive
  request headers are redacted, bodies are capped at 128 KiB in CDP capture,
  and native queues and artifact transfers have explicit limits.
- **Native quiet mode:** run native evidence capture without attaching DevTools
  when request and response content is not required.

## How to use it

### Download the compiled macOS apps

1. Download
   [Origin Trace v0.1.8](https://github.com/sunghoojung/reverse-engineering-browser/releases/download/v0.1.8/Origin-Trace-v0.1.8-macos.zip)
   and the
   [Brave Browser Development preview](https://github.com/sunghoojung/reverse-engineering-browser/releases/download/brave-build-20260914/Brave-Browser-Development-brave-build-20260914-macos-arm64.zip).
2. Unzip both files.
3. Use the compiled Brave executable as `REB_BRAVE_BINARY` when starting a live
   session from the repository, as shown below.

The compiled apps are for Apple silicon Macs. The linked Brave Browser
Development preview predates current probe support. Build the pinned Brave
integration from this release's source to use every native probe; the
downloaded preview cannot demonstrate them. Origin Trace contains no bundled
sample evidence. The applications are ad-hoc signed but not notarized, so the
first launch may require Control-clicking the app and choosing **Open**.

Downloading the compiled Brave app does not require a 100+ GiB source checkout.
Allow about 1 GiB to download and extract both apps, plus whatever space you
want to retain for browser profiles and captured sessions.

### Run a live capture with an existing custom Brave build

From the repository root:

```sh
REB_CDP_NETWORK_CAPTURE=1 \
REB_BRAVE_BINARY="/path/to/Brave Browser Development.app/Contents/MacOS/Brave Browser Development" \
make live
```

Origin Trace and the custom Brave browser open together. Browse in that Brave
window and select requests in the **Traffic** tab. Close Brave to end the
session. Captured evidence is stored under `build/sessions/live/`.

CDP content capture is explicit because it can retain page content. It redacts
authorization, cookie, proxy-authorization, and set-cookie headers. Streaming,
cached, internal, or already-evicted response bodies may be unavailable.

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

### Run without CDP content capture

For native metadata and artifact capture without a live DevTools attachment:

```sh
REB_NATIVE_QUIET_MODE=1 \
REB_BRAVE_BINARY="/path/to/Brave Browser Development.app/Contents/MacOS/Brave Browser Development" \
make live
```

Sources, breakpoints, stepping, watches, the console, full URLs, headers, and
bodies are unavailable in native quiet mode.

Use this project only on systems you own or are explicitly authorized to
inspect.
