# Windows 11 and Linux: build guide and support status

**The full Origin Trace + instrumented Brave application is currently a macOS
product. Native Windows support requires a port, not just a different build
command.** The C++ tools, Rust backend and browser-based development UI already
have Linux CI coverage. Windows users can try that smaller development workflow
inside WSL 2; it does not produce a Windows executable or the complete research
browser.

This guide addresses [issue #53](https://github.com/sunghoojung/reverse-engineering-browser/issues/53).
It was checked against source revision
[`e264787`](https://github.com/sunghoojung/reverse-engineering-browser/tree/e264787)
on 2026-10-13. Windows and WSL have **not** been build-tested for this guide.
The WSL instructions are an adaptation of the Linux targets, not a verified
Windows release. The implementation and CI links below identify the supported
boundaries.

## Choose a route

| Goal | Current route | Limit |
| --- | --- | --- |
| Use the complete packaged product | [macOS release and setup](../../README.md#how-to-use-it) | Apple silicon app pair |
| Develop native helpers, backend, or shared web UI on Linux | [Linux instructions below](#linux-and-wsl-2-development-workflow) | CI covers Linux tools/backend and selected rendered UI journeys |
| Explore the same development UI from Windows 11 | WSL 2, then the Linux instructions | Linux processes inside WSL; this specific setup is unverified |
| Run native Windows Origin Trace or capture from a Windows custom Brave | [Porting work below](#what-a-native-windows-port-needs) | No supported build, installer, or Windows CI job yet |
| Build the complete instrumented browser on Linux | [Browser porting notes](#building-the-instrumented-brave-browser) | Upstream Brave supports Linux; this project's full integrated path is not verified there |

A successful `make ui` shows deterministic demo evidence. It does not enable
native fingerprint probes in ordinary Chrome/Edge/Brave. Viewing the UI in a
Windows browser does not turn that browser into the capture target.

## Linux and WSL 2 development workflow

### 1. Windows only: enter a Linux environment

Follow Microsoft's [WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install).
For a machine without WSL, run this in an administrator PowerShell window:

```powershell
wsl --install -d Ubuntu
```

Restart if requested, launch Ubuntu, and finish creating your Linux user.
Check the distribution is using version 2 with `wsl --list --verbose` in
PowerShell. Existing WSL users can use their existing WSL 2 Linux distribution.

Run all remaining shell commands in **Linux/Ubuntu**, not PowerShell, Command
Prompt, Git Bash, or a Windows Python/Node installation. A native Linux machine
can start at step 2.

### 2. Install the small-workspace dependencies

For Ubuntu/Debian, the base packages are:

```sh
sudo apt-get update
sudo apt-get install --yes \
  build-essential git python3 python3-venv curl ca-certificates \
  pkg-config zlib1g-dev
```

Also install, **inside Linux/WSL**:

- A current stable Rust toolchain through the official
  [Rust installation instructions](https://rust-lang.org/tools/install/).
  Both crates use edition 2024, and locked Oxc dependencies can require a newer
  compiler than the distribution's packaged Rust. Keep the committed Cargo
  lockfiles; do not remove them to work around an old compiler.
- [Node.js](https://nodejs.org/en/download) 22 or newer for test tooling and the
  development workflows. Node 24 is a useful common choice. The separate Brave
  bootstrap is stricter: it currently requires Node `>=24.16.0` and `<25`.

If Rust is already managed with rustup, select an updated stable toolchain for
this terminal:

```sh
rustup toolchain install stable
export RUSTUP_TOOLCHAIN=stable
```

Check the tools resolve to Linux executables and are available:

```sh
command -v c++ make git python3 node cargo
c++ --version
node --version
rustc --version
cargo --version
```

The small workspace does not need Xcode, Visual Studio, pnpm, or the massive
Brave/Chromium checkout. Cargo downloads its locked dependencies on the first
build, so that build needs network access and space for Rust build outputs.

### 3. Clone onto the Linux filesystem

```sh
mkdir -p ~/src
cd ~/src
git clone https://github.com/sunghoojung/reverse-engineering-browser.git
cd reverse-engineering-browser
git rev-parse HEAD
```

In WSL, keep the checkout and session/workspace stores under your Linux home
(e.g. `~/src`), rather than `/mnt/c`. Microsoft's
[filesystem guidance](https://learn.microsoft.com/en-us/windows/wsl/filesystems)
recommends this for Linux performance; this project also relies on Unix file
ownership, permissions, locks and local sockets. Network shares and mounted
Windows filesystems are not validated evidence/workspace stores.

### 4. Build and run the development UI

**Use a development checkout.** `make e2e` and `make ui` overwrite
`build/sessions/demo.jsonl`, `build/sessions/origin-trace.jsonl` and
`build/sessions/request-signals.jsonl`, and delete/recreate
`build/sessions/artifacts`. Keep real evidence elsewhere before running them.

From the repository root:

```sh
make all
make origin-trace-backend deob-worker-build
make e2e
make ui
```

`make all` builds the standalone C++ tools. The next target builds the Rust
backend/analysis binaries and deobfuscation worker. `make e2e` generates and
checks synthetic event, trace, signal and artifact fixtures. `make ui` runs that
fixture setup again and starts the backend with demo evidence at:

```text
http://127.0.0.1:7319
```

Open that address in a browser; stop the foreground server with Ctrl+C.
Do not open `apps/research-ui/index.html` as a file; the interactive workspace
needs its backend.

For WSL, try the same address in your Windows browser. Microsoft's
[WSL networking documentation](https://learn.microsoft.com/en-us/windows/wsl/networking#accessing-linux-networking-apps-from-windows-localhost)
describes Windows-to-Linux localhost forwarding. If it does not connect, first
check `curl --fail http://127.0.0.1:7319/` inside WSL and the server's terminal
output. Then check your WSL localhost-forwarding configuration. Do not expose
the backend on `0.0.0.0` or forward it to a LAN: the backend intentionally accepts
only loopback hosts.

This route lets you inspect demo evidence and work on shared UI/backend code.
It does not provide the macOS menu bar, native save/close dialogs, automatic
packaged session launcher, or a working custom Windows browser. Features that
need a live custom browser, captured evidence or platform integration remain
unavailable until those dependencies are present and verified.

### 5. Validate development changes

The repository handoff gate is:

```sh
make lint
make check
make e2e
make sanitize
git diff --check
```

`make lint` additionally needs clang-format, Ruff, ShellCheck, actionlint and
Rust's rustfmt/Clippy components. Follow the pinned versions and install steps
in [CI](../../.github/workflows/ci.yml): clang-format `18.1.8`, Ruff `0.12.8`,
actionlint `1.7.7`, plus ShellCheck. Install the Python tools in a virtual
environment and put its `bin` directory on `PATH`. The existing
`make bootstrap-dev-tools` helper falls back to **Homebrew** when ShellCheck or
actionlint is missing; it is not a complete Ubuntu installer.

Rendered UI and live-debugger tests additionally need a Linux
Chromium-compatible browser. See the [backend test guide](../../apps/origin-trace-backend/README.md)
for `ORIGIN_TRACE_TEST_BROWSER`, and CI for `REB_UI_CHROMIUM`. A browser used for
synthetic CDP tests does not validate the project's native Brave probes. WSL
browser/sandbox/display behavior has not been verified here; do not disable
browser security to make a failing test pass.

A missing tool, skipped test, or sanitizer restriction is not a passing check.
The [validation contract](../../AGENTS.md#validation) describes what to report.

## Why native Windows does not work yet

These are source-inspected blockers, not results from a Windows compilation:

- **Native application:** [build-research-app.sh](../../scripts/build-research-app.sh)
  exits on non-macOS hosts. The shell uses Swift/AppKit/WKWebView under
  [apps/research-ui/macos](../../apps/research-ui/macos/), `xcrun`, `.app`
  resources and `codesign`. It cannot be rebuilt unchanged as a Windows app.
- **Standalone transport and helpers:**
  [local_ipc.cpp](../../src/transport/local_ipc.cpp),
  [debugger_transport.cpp](../../src/transport/debugger_transport.cpp), the
  broker and artifact receiver use POSIX headers/APIs, Unix-domain sockets,
  file descriptors, Unix ownership/modes and `/dev/urandom`. The Makefiles use
  Unix commands and GCC/Clang flags; there is no equivalent MSVC build route.
- **Backend and safe saves:**
  [native_console.rs](../../apps/origin-trace-backend/src/native_console.rs)
  unconditionally imports `std::os::unix`, uses Unix process groups and sends
  POSIX signals. It is part of the backend, so building the Rust crate alone
  does not bypass the port. Other platform guards fail closed: for example,
  [workspace_lease.rs](../../apps/origin-trace-backend/src/workspace_lease.rs)
  rejects non-Unix cooperative saves, and safe evidence clearing is unsupported
  on non-Unix in [evidence.rs](../../apps/origin-trace-backend/src/evidence.rs).
- **Browser integration:** the probe/artifact socket clients and
  [native_local_ipc_client.cc](../../browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_local_ipc_client.cc)
  have `IS_POSIX` implementations and non-POSIX failure/no-op stubs. Even if
  those files compile on Windows, capture is not implemented there. Newer
  [native_console_session.cc](../../browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_console_session.cc)
  and [native_console_io.cc](../../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_console_io.cc)
  have unguarded POSIX dependencies and are included by the browser target.
- **Launch, packaging and tests:** `make live` depends on `app-build`;
  [run-live-session.sh](../../scripts/run-live-session.sh) defaults to macOS
  bundle paths and `open`. CI has Ubuntu/macOS jobs and macOS release packaging,
  not a Windows build or native Windows runtime acceptance suite.

Windows support in upstream Brave, Rust or C++ does not automatically port
these project-owned boundaries. Git Bash, MSYS2 or changing the compiler cannot
supply the missing application, ownership and lifecycle implementations.

## Building the instrumented Brave browser

Upstream [Brave supports Windows](https://github.com/brave/brave-browser/wiki/Windows-Development-Environment)
and [Linux](https://github.com/brave/brave-browser/wiki/Linux-Development-Environment).
Those guides build upstream Brave; they do not establish support for this
repository's overlays, services and companion app.

The project's current pins are:

- [Brave](../../browser/config/brave-core.rev): `v1.95.52`
- [Chromium](../../browser/config/chromium.rev): `151.0.7922.108`
- [V8](../../browser/config/v8.rev): `20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921`

Treat those files as authoritative if they change. Do not substitute today's
upstream main branch or mix a browser with an unrelated companion revision.

[brave-toolchain.sh](../../scripts/brave-toolchain.sh) currently calls its Xcode
check for every command, defaults to `out/Component_arm64`, and uses
`buildtools/mac/gn` in generation/probe checks. The integrated builder explicitly
requires Apple silicon macOS, and distribution scripts package macOS bundles.
Setting `REB_BRAVE_OUTPUT_DIRECTORY` alone does not make these scripts portable.
Bootstrap/source download success would not prove a Linux or Windows build.

There is therefore no validated full-browser command sequence for Linux or
Windows in this guide. Porting contributors should first establish an upstream
build using the requirements corresponding to the pinned source, then adapt the
project tooling and compile/test the overlays on that platform. Consult the
[upstream Chromium Windows prerequisites](https://chromium.googlesource.com/chromium/src/+/main/docs/windows_build_instructions.md)
for the Visual Studio/SDK requirements when planning a native Windows port;
current upstream requirements can drift from the pinned revision.

The project's Brave initialization guard requires at least 150 GiB free;
200–250 GiB is recommended in the [browser guide](../../browser/README.md).
Recheck upstream requirements before provisioning a porting machine. That large
checkout is unnecessary for the Linux demo workflow above.

WSL builds Linux programs, not a native Windows package. Using a Windows
`brave.exe` with Linux helpers would additionally cross filesystem, socket,
process-lifecycle and debugger boundaries that the current launcher does not
support. Cross-compiling from Linux would still require the Windows port and
Windows runtime tests; it is not a shortcut around these blockers.

## What a native Windows port needs

The evidence formats, shared web UI, much of the analysis code and the Chromium
renderer/Mojo design can be reused. A staged port could:

1. Add Windows implementations for local IPC, debugger transport, randomness,
   file ownership/ACL checks, locking, atomic safe saves and evidence access.
   Preserve authentication, versioned records, bounded I/O and fail-closed
   behavior; do not replace private local transports with unauthenticated LAN
   listeners.
2. Port the Rust/C++ process supervision and Console boundaries, including
   descendant cleanup, cancellation and profile ownership. Make the browser
   overlay transport functional on Windows rather than silently accepting its
   current no-op stubs.
3. Start with the shared browser UI and backend. Then implement a Windows
   launcher/native host if packaged parity is needed, preserving the existing
   unsaved-work protections and explicit capture controls.
4. Make bootstrap, pin verification, overlay synchronization, GN/toolchain
   selection, executable discovery and packaging platform-aware. Keep the
   generated upstream checkout out of Git.
5. Add Windows CI and real Windows acceptance for capture-to-evidence delivery,
   artifacts, Console, debugger, saves, failure/retry, cleanup and privacy
   controls. Verify the exact packaged browser/companion pair before claiming
   Windows support.

A Linux full-product port can reuse more of the existing POSIX transport, but
still needs portable browser-build tooling and a replacement for the macOS
launcher/native host, followed by real integrated-browser testing. Linux tool
CI is useful evidence for that work, not proof that the entire app is supported.
