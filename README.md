# Reverse Engineering Browser

Private workspace for a Brave-based browser harness used in authorized website
security research.

The project goal is to observe browser behavior through native browser
instrumentation, not page JavaScript hooks. Native C++ probe surfaces emit
bounded telemetry to a browser-process broker, which streams normalized events
to a local research interface.

## Start here

Validate the tracked workspace and native foundation:

```sh
make check
./build/reb-event-demo
```

Prepare the pinned upstream Brave checkout without downloading Chromium:

```sh
./scripts/bootstrap-brave.sh
```

When you are ready for the large Chromium download, initialize Brave and then
apply the integration tracked by this repository:

```sh
./scripts/bootstrap-brave.sh --init
./scripts/sync-browser-integration.sh
```

Initialization uses Brave's shallow Chromium history mode by default. If an
investigation specifically requires complete Chromium Git history, opt in with
`./scripts/bootstrap-brave.sh --init --full-history`.
Bootstrap refuses to switch a checkout with local changes when its revision
does not match the requested pin, leaving those changes untouched.

Check the local Apple toolchain and compile the tracked Brave probe:

```sh
make brave-doctor
make brave-probe-check
```

## Current implementation

The repository includes a dependency-free C++ vertical slice for the probe event path:

- a fixed-size, versioned event record;
- bounded multi-producer, single-consumer shared-memory queues;
- explicit dropped-event accounting;
- a bounded broker with validation, sequence-gap detection, and eviction accounting;
- an authenticated, user-only Unix socket from Brave to the broker;
- a native binary event stream and versioned JSONL evidence store;
- a native macOS Origin Trace application that reads the broker evidence store;
- a threaded producer and consumer demo;
- unit tests and sanitizer support.

The deterministic producer validates the same broker boundary without launching
Brave. The tracked Brave integration carries renderer records through shared
memory and Mojo into the browser process, then sends them to the broker socket.

## Native development

Requirements:

- a C++20 compiler;
- GNU Make or a compatible `make` implementation.

```sh
make
make test
./build/reb-event-demo
```

## Origin Trace application

On macOS, build the demo evidence and open the native Origin Trace application:

```sh
make app
```

This builds `build/Origin Trace.app`, writes the demo evidence, and opens the
application. It is a native WebKit window with no browser address bar and no
localhost server. The application and broker stay local.

The demo includes linked Navigator, Canvas, WebAssembly, and Network events.
The research workflow starts from a request field and works backward through
the available evidence.

For browser-based UI development only, run:

```sh
make ui
```

Then open `http://127.0.0.1:7319`.

After building the complete custom Brave application, launch one live capture
session with:

```sh
make live
```

The launcher creates a session-scoped broker socket and token, opens Origin
Trace, and starts the custom Brave executable with the matching session flags.
Set `REB_BRAVE_BINARY` when the executable is outside the default component
output directory.

## CI and release builds

Every pull request runs formatting, shell, Python, workflow, repository hygiene,
and evidence-contract checks. The native test suite runs on macOS and Ubuntu.
Linux also runs the full end-to-end and sanitizer paths. The macOS job builds
and verifies the application bundle, then keeps a downloadable preview for
three days.

After installing the pinned tool versions listed in the CI workflow, run the
fast source and repository checks with:

```sh
make lint
```

To publish a versioned macOS download, push a version tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions verifies the application, creates a ZIP archive, and attaches it
to a GitHub Release. Release builds are locally signed for development; Apple
notarization is intentionally deferred until external distribution is needed.

Run sanitizer checks. Linux uses AddressSanitizer and UndefinedBehaviorSanitizer;
macOS uses UndefinedBehaviorSanitizer:

```sh
make sanitize
```

## Layout

```text
.github/workflows/      pull-request checks and tag-triggered releases
apps/                   runnable demos, producers, and Origin Trace
  research-ui/macos/    native macOS shell and application icon source
browser/                tracked Brave integration and ignored source worktree
docs/                   product and architecture documentation
  architecture/         technical architecture and system diagram
  product/              feature roadmap and product catalog
include/ and src/       dependency-free native event foundation
protocol/               shared browser, broker, and UI contracts
services/event-broker/  local browser-process bridge and evidence broker
scripts/                setup, app packaging, and workspace validation
tests/                  native unit and concurrency tests
tools/                  development and analysis utilities
```

All project-owned Brave changes live in `browser/integration/brave` as tracked
overlays and patches. The pinned upstream `brave-core` checkout and Chromium
build output live under `browser/worktree` and are intentionally excluded from
Git. This keeps every unique project file in one GitHub repository without
duplicating hundreds of gigabytes of reproducible upstream source.

Brave and Chromium initialization requires substantial storage. Keep at least
150 GiB free before running `./scripts/bootstrap-brave.sh --init`; 200 to 250
GiB is recommended for comfortable development and updates. The default
shallow history avoids downloading unnecessary historical Git objects.

## Docs

- [Documentation index](./docs/README.md)
- [Technical architecture](./docs/architecture/technical-architecture.md)
- [System architecture](./docs/architecture/system-architecture.md)
- [Feature roadmap](./docs/product/feature-list.md)
- [Feature catalog](./docs/product/feature-catalog.md)
- [Brave integration](./browser/README.md)
