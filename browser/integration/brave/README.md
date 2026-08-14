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

Initialize Chromium with `./scripts/bootstrap-brave.sh --init` first. The sync
command verifies the tracked Brave and Chromium pins, preflights both checkouts
and every patch before copying overlays, is safe to run again, and applies each
patch only when needed. Revision mismatches fail with the current and expected
commits without changing either checkout.

The integration now observes renderer request initiation and the browser-side
request, redirect, response, completion, and failure lifecycle. It reuses
Brave's production `BraveProxyingURLLoaderFactory` and client proxy instead of
installing a second interception layer. The capture boundary records metadata
and a bounded payload prefix only. Request payload prefixes contain the method
and destination host, not URL paths, queries, fragments, or credentials.
Browser lifecycle records also carry Chromium's opaque 128-bit BrowserContext
token, which disambiguates Brave request IDs generated independently per
profile without exposing a profile path.

All probes remain dormant until a session-scoped, non-blocking, non-throwing
emitter is registered. Their inactive paths perform one atomic load and do not
change network or Canvas behavior. Renderer events use a bounded shared-memory
queue with Mojo lifecycle control and coalesced wake-ups. The browser process
authenticates to the event broker with a session identifier and a mode-0600
token file, then sends exact fixed-size records over a Unix socket. A bounded
browser-process queue keeps those socket writes off the capture paths.
