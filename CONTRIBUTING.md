# Contributing

Reverse Engineering Browser welcomes focused improvements to its native event
path, local evidence pipeline, Origin Trace application, versioned contracts,
and reproducible Brave integration.

Only test against systems you own or are explicitly authorized to assess. Do
not contribute features whose primary purpose is bypassing access controls,
capturing sensitive content by default, or concealing malicious activity.

## Before you change code

1. Read the nearest subsystem README and the relevant contract or design under
   `protocol/` or `docs/`.
2. Check the current working tree and preserve unrelated changes.
3. For a bug, reproduce it through the closest user-facing or end-to-end path.
4. Keep the change focused and include tests for failures, limits, and disabled
   behavior when relevant.

Coding agents must also follow [AGENTS.md](./AGENTS.md), which documents source
ownership, architectural invariants, skill routing, and the complete handoff
contract.

## Local development

The core workspace requires a C++20 compiler, Python 3, zlib, and Make.

```sh
make check
make e2e
```

On macOS, build the native Origin Trace application with:

```sh
make app
```

The full Brave and Chromium checkout is optional and requires substantial disk
space. Follow [browser/README.md](./browser/README.md) only when a change reaches
the browser integration.

## Quality gate

Run the complete local gate before opening a pull request:

```sh
make lint
make check
make e2e
make sanitize
git diff --check
```

User-visible Origin Trace work also requires end-to-end interaction and visual
verification. Native macOS packaging changes require `make app-build` followed
by strict code-signature verification. Brave integration work must reproduce
from the pinned upstream revisions and compile with the strongest locally
available toolchain.

If a platform tool is unavailable, state exactly what is missing and which
check could not run. Do not present a skipped check as passing.

## Pull requests

Keep each pull request to one coherent change. In the description:

- state the user-visible or system behavior that changed;
- explain the architectural boundary affected;
- list the validation evidence;
- call out privacy, compatibility, performance, and toolchain implications;
- identify any remaining validation gap.

Do not commit `browser/worktree/`, build output, captured evidence, credentials,
generated changelogs, or unrelated formatting changes.
