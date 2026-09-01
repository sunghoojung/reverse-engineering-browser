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

On memory-constrained machines, set `REB_BRAVE_JOBS` to a positive integer to
bound concurrent Brave compiler jobs, for example `REB_BRAVE_JOBS=4 make
brave-probe-check`.

## Current implementation

The repository includes a dependency-free C++ vertical slice for the probe event path:

- a fixed-size, versioned event record;
- bounded multi-producer, single-consumer shared-memory queues;
- explicit dropped-event accounting;
- a bounded broker with validation, sequence-gap detection, and eviction accounting;
- an authenticated, user-only Unix socket from Brave to the broker;
- a native binary event stream and versioned JSONL evidence store;
- a bounded request signal profile for fingerprint-relevant browser activity;
- an authenticated, acknowledged artifact socket with immutable SHA-256 blobs;
- a native macOS Origin Trace application that reads the broker evidence store;
- bounded read-only live JavaScript object search plus native C++ V8
  heap-snapshot search, comparison, retaining paths, and dominator analysis;
- bounded browser-context automation recipes with confirmed manual runs and
  explicitly armed created, before-load, and after-load triggers inside a
  disposable Experiment BrowserContext;
- a shared bounded action-scope policy that applies interception and automation
  to every disposable page or one exact page without reaching baseline tabs;
- a persistent Local Analyst Workspace with reusable async scripts,
  non-executable scratchpads, private variables, frozen bounded evidence
  snapshots, isolated helper processes, cancellation, and visible limits;
- a bounded native C++ Decoder Lab with branchable Base64, hex, URL,
  compression, Base36, and JSON transforms plus explicit HMAC JWT verification;
- a threaded producer and consumer demo;
- unit tests and sanitizer support.

The deterministic producer validates the same broker boundary without launching
Brave. The tracked Brave integration carries renderer records through shared
memory and Mojo into the browser process, then sends them to the broker socket.
The browser process also tees JavaScript and WASM response bodies into a
separate bounded artifact queue without delaying or changing the response
delivered to the page.

## Native development

Requirements:

- a C++20 compiler;
- zlib development headers and library;
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

The demo includes linked Navigator, Canvas, Web Audio, WebAssembly, and Network
events, plus separately transferred JavaScript and WASM artifacts in the
Sources tab. Its Web Audio record identifies the
`OfflineAudioContext.startRendering` call, and both demo request profiles link
that record through their observed parent chains.
The research workflow starts from a live request and works backward through a
versioned, bounded Origin Trace edge store to the available browser evidence.
The request inspector also summarizes retained Canvas, WebGL, Web Audio,
Navigator, Permissions, Storage, and WebRTC activity with explicit confidence
and coverage.

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

The launcher creates session-scoped event and artifact sockets with one
user-only token, opens Origin Trace, and starts the custom Brave executable
with the matching session flags. It also starts the research UI on a random
loopback port and attaches an allowlisted debugger bridge to Brave's isolated,
session-scoped profile. Sources then provides live scripts, breakpoints,
stepping, sync and async call stacks, bounded scopes and watches, special
breakpoints, and a console drawer. Memory adds property, primitive value,
class, regular expression, and JSON-shape search over live JavaScript objects.
The scan never invokes accessors, returns read-only previews, and enforces
time, candidate, property, and result limits. Memory can also search an
explicit temporary V8 heap snapshot through a bounded native C++ indexer,
including scoped unreachable values, retaining paths, and prioritized hidden,
internal, weak, and ordinary incoming references. Heap Diff keeps an explicit
local baseline and compares a later capture by object signature, self size, and
exact retained size over the reachable non-weak edge graph. Memory Origin Trace
samples bounded function-return pauses, uses an early-exit native heap probe,
and highlights the first sampled source function containing a value. Selected
request values can pivot directly into a prefilled Memory search. Artifact success events are
emitted only after the receiver has committed the manifest record; capture or
transfer failures remain visible as normal evidence events. Session
directories and evidence files are user-only. When the Artifact category is
disabled, the launcher omits the artifact receiver and exits normally with
Brave.
Set `REB_BRAVE_BINARY` when the executable is outside the default component
output directory. Live sessions enable Canvas, Web Audio, Network, and Artifact
by default with category mask `1285` and expire after one hour. Override those
startup limits with `REB_CAPTURE_CATEGORY_MASK` and
`REB_CAPTURE_DURATION_SECONDS`.

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
.agents/skills/         repo-scoped validation and testing workflows
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
services/artifact-receiver/ bounded cold-path artifact receiver and store
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
