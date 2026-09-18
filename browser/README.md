# Browser Workspace

Brave is part of this project without being copied into Git history.

```text
browser/
├── config/                 pinned Brave, Chromium, and V8 revisions
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
The sync command verifies `browser/config/brave-core.rev`,
`browser/config/chromium.rev`, and `browser/config/v8.rev` before copying or
patching anything. A mismatch is reported with the current and pinned commits,
and the checkout is left untouched.

The initialized checkout requires at least 150 GiB free. Keep 200 to 250 GiB
available for builds and updates.

Compile the exact native probe integration and its Chromium prerequisites:

```sh
make brave-probe-check
```

The project helper automatically uses `/Applications/Xcode.app` when present
and Brave's bundled Python. A complete browser build remains available through
`./scripts/brave-toolchain.sh build` and may take several hours.

For a self-contained Apple silicon browser ZIP, use the separate
[Brave distribution build](../docs/development/brave-distribution.md). The
fast component output below is not portable by itself.

### Fast local iteration

The macOS development output supports a local `sccache` compiler cache. Install
it with `brew install sccache`, then add these overrides after the import in
`out/Component_arm64/args.gn`:

```gn
cc_wrapper = "sccache"
symbol_level = 0
blink_symbol_level = 0
v8_symbol_level = 0
use_lld = false
use_clang_modules = false
```

Component builds and Siso remain enabled by Brave's development defaults. The
reduced symbol levels and Apple linker shorten local compilation and linking.
Clang header modules are disabled because `sccache` does not cache those
commands. A tracked Brave patch preserves the required extended BitInt frontend
option with an equivalent cacheable spelling only while `sccache` is selected.
The first compile populates the cache; later identical compilations can reuse
it. `sccache --show-stats` reports hit rates, and the default local cache remains
bounded to 10 GiB.

## Manual test target

Use the [Fingerprint Playground](https://demo.fingerprint.com/playground) as a
repeatable website target when manually testing browser observations and
fingerprint-related evidence capture.

## Ownership rule

Never commit `browser/worktree/`. New complete files belong in the mirrored
overlay tree. Small changes to upstream files belong in ordered patch files.
That makes every project change visible and reproducible from the pinned Brave
revision.

The current integration contains dormant native hooks and generated Web IDL
binding probes across 90 selected Canvas, WebGL, WebGPU, Web Audio, browser,
layout, font, media, Permissions, Storage, and WebRTC interfaces. V8 runtime
hooks add selected Math, Intl, and timezone operations. Fingerprint metadata
retains fixed operation names only. An explicit per-session switch can
also retain the bounded data URL returned by Canvas readback; it never retains
the earlier drawing arguments. WebGL results, audio samples, buffers,
parameters, and results remain outside capture.
Network observation reuses Brave's production URL loader factory proxy and
correlates browser lifecycle records with the renderer request identifier. A
bounded shared-memory queue and Mojo lifecycle bridge carry renderer records
into the browser process. The browser process connects to the event broker
through an authenticated, session-scoped Unix socket and a second bounded queue
keeps socket writes off probe paths. No MCP layer is included.
