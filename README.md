# Reverse Engineering Browser

Reverse Engineering Browser is a local-first research browser and macOS
workspace for inspecting authorized web applications.

## Features

- **Live network traffic:** inspect request methods, full URLs, status codes,
  timing, headers, request bodies, and response bodies captured through CDP.
- **Tab and domain organization:** separate traffic by browser tab, then narrow
  a tab to a specific destination domain or resource type.
- **Native browser evidence:** record request initiation and lifecycle events,
  Canvas and Web Audio activity, and correlated browser-process metadata from a
  custom Brave build.
- **Origin tracing:** follow a request backward through the observed events,
  scripts, frames, execution contexts, and captured artifacts that contributed
  to it.
- **Source inspection and debugging:** browse page sources, set breakpoints,
  pause and step through JavaScript, inspect scopes, evaluate watches, and use a
  live console.
- **Artifact capture:** retain bounded copies of network-delivered and
  runtime-generated JavaScript and WebAssembly with hashes and provenance.
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

1. Download `Brave-Browser-Development-v0.1.1-macos-arm64.zip` and
   `Origin-Trace-v0.1.1-macos.zip` from
   [GitHub Releases](https://github.com/sunghoojung/reverse-engineering-browser/releases/latest).
2. Unzip both files.
3. Use the compiled Brave executable as `REB_BRAVE_BINARY` when starting a live
   session from the repository, as shown below.

The compiled apps are for Apple silicon Macs. Origin Trace contains no bundled
sample evidence. The applications are ad-hoc signed but not notarized, so the
first launch may require Control-clicking the app and choosing **Open**.

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

### Build the custom Brave browser for the first time

Requirements:

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
