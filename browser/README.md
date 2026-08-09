# Browser Integration Workspace

`browser/worktree/` is the local Brave and Chromium build workspace. The private `brave-core` submodule is tracked at `src/brave`; downloaded Chromium source and build output are ignored.

The actual browser source project is [`brave/brave-core`](https://github.com/brave/brave-core), not `brave/brave-browser`. Brave expects it at this path:

```text
browser/worktree/src/brave/
```

## Prepare the checkout

Initialize the private shallow submodule:

```sh
./scripts/bootstrap-brave.sh
```

Initialize Chromium only when ready for the large download:

```sh
./scripts/bootstrap-brave.sh --init
```

The initialization script requires at least 150 GiB free. For repeated builds and Chromium updates, 200 to 250 GiB free is recommended.

## Source ownership

- Native Blink, V8, network, browser-process, and renderer instrumentation belongs in the private `brave-core` submodule.
- Reusable patch experiments belong in `browser/patches/` until their permanent Brave integration point is known.
- The event broker, UI, MCP server, protocol documentation, and research-session tests belong in the control repository.

Do not copy the Chromium source tree into this repository.
