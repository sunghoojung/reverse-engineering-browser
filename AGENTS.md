# Project Agent Instructions

## Architecture boundaries

- Treat `browser/worktree/` as downloaded source and build output. The only tracked entry inside it is the private `brave-core` submodule.
- Put Chromium and Brave C++ instrumentation in the separate `brave-core` submodule checkout.
- Put the research UI, MCP adapter, broker, shared protocol, documentation, and tests in this repository.
- Keep the renderer probe path bounded, allocation-free, non-blocking, and disabled by default.
- Route both the UI and MCP server through the broker. They must not instrument page JavaScript independently.
- Version every message that crosses the browser-to-broker boundary.

## Validation

- Run `make check` for normal changes.
- Run `make sanitize` for changes to native event or queue code.
- Keep sensitive request data redacted unless an explicitly authorized session enables it.
