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

Apply the project-owned integration:

```sh
./scripts/sync-browser-integration.sh
```

Download Chromium and complete Brave initialization only when needed:

```sh
./scripts/bootstrap-brave.sh --init
```

The initialized checkout requires at least 150 GiB free. Keep 200 to 250 GiB
available for builds and updates.

## Ownership rule

Never commit `browser/worktree/`. New complete files belong in the mirrored
overlay tree. Small changes to upstream files belong in ordered patch files.
That makes every project change visible and reproducible from the pinned Brave
revision.

The current integration contains a dormant native Canvas probe boundary. It
does not yet connect Brave to the event broker, and no MCP layer is included.
