# Brave Integration

This directory is the tracked source of truth for changes applied to Brave.
The large upstream checkout lives at `browser/worktree/src/brave` and remains
ignored by the parent repository.

## Layout

- `overlay/` contains complete authored files, mirroring their `brave-core`
  destination paths.
- `patches/` contains small edits to upstream-owned files.

Apply the tracked integration to the local checkout with:

```sh
./scripts/sync-browser-integration.sh
```

The command is safe to run again. It copies overlays and applies each patch
only when it has not already been applied.

The current Canvas probe is dormant until a non-blocking emitter is registered.
Its inactive path performs one atomic load and does not change Canvas output.
The renderer transport and browser-process bridge are intentionally future work.
