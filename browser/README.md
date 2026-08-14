# Browser Workspace

Brave is part of this project without being copied into Git history.

```text
browser/
├── config/                 pinned upstream revision
├── integration/brave/      tracked source, overlays, and patches
└── worktree/src/brave/     ignored local upstream checkout
```

This keeps all project-owned work in one GitHub repository while avoiding a
massive duplicate of Brave and Chromium.

## Set up Brave

Prepare the pinned Brave checkout:

```sh
./scripts/bootstrap-brave.sh
```

Verify Xcode, Node.js, and pnpm without changing the system-wide developer path:

```sh
make brave-doctor
```

Download Chromium and complete Brave initialization only when needed:

```sh
./scripts/bootstrap-brave.sh --init
```

Apply the project-owned integration after Chromium is initialized:

```sh
./scripts/sync-browser-integration.sh
```

This uses Brave's supported `--no-history` initialization mode, keeping the
Chromium checkout shallow. Use `--init --full-history` only when an
investigation needs complete Chromium Git history.
Bootstrap refuses to switch a checkout with local changes when its revision
does not match the requested pin.
The sync command verifies both `browser/config/brave-core.rev` and
`browser/config/chromium.rev` before copying or patching anything. A mismatch
is reported with the current and pinned commits, and the checkout is left
untouched.

The initialized checkout requires at least 150 GiB free. Keep 200 to 250 GiB
available for builds and updates.

Compile the exact native probe integration and its Chromium prerequisites:

```sh
make brave-probe-check
```

The project helper automatically uses `/Applications/Xcode.app` when present
and Brave's bundled Python. A complete browser build remains available through
`./scripts/brave-toolchain.sh build` and may take several hours.

## Manual test target

Use the [Fingerprint Playground](https://demo.fingerprint.com/playground) as a
repeatable website target when manually testing browser observations and
fingerprint-related evidence capture.

## Ownership rule

Never commit `browser/worktree/`. New complete files belong in the mirrored
overlay tree. Small changes to upstream files belong in ordered patch files.
That makes every project change visible and reproducible from the pinned Brave
revision.

The current integration contains dormant native Canvas and network lifecycle
probe boundaries. Network observation reuses Brave's production URL loader
factory proxy and correlates browser lifecycle records with the renderer request
identifier. A bounded shared-memory queue and Mojo lifecycle bridge carry
renderer records into the browser process. The browser process connects to the
event broker through an authenticated, session-scoped Unix socket and a second
bounded queue keeps socket writes off probe paths. No MCP layer is included.
