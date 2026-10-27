# Safety, Authorization, and Capture Policy

Reverse Engineering Browser (REB) is a local-first research harness for
authorized website security research. This file is the source of truth for
authorization, scope, capture, privacy, and local-operation policy. Other
documents describe the implementation and link here for the policy that governs
it.

## Authorized targets and scope

- Use REB only on systems you own or are explicitly authorized to test. A
  friend's site or a capture-the-flag target is in scope only when its owner or
  organizer authorizes the specific target and testing activity.
- Follow applicable law, contracts, and the rules provided by the system owner
  or challenge organizer.
- Keep testing within the authorized target, methods, time window, and any
  limits set by the owner or organizer. Permission to visit a site does not by
  itself authorize security testing.
- REB does not maintain a list of preapproved sites, verify ownership, or
  determine whether a user has permission.
- Current native event records do not carry a trustworthy origin identity, so
  origin allowlisting is not implemented. Session category masks and expiration
  do not enforce a domain boundary. Treat architecture documents that describe
  origin-scoped sessions as intended design unless the implementation and its
  contracts show otherwise.
- Do not intercept, capture, or modify activity outside the authorization for
  the target being tested. Agents and people follow the same scope.

## Default capture

- Opening the packaged Origin Trace app starts a visibly labeled local research
  session with implemented native capture categories. CDP collection and injected
  JavaScript hooks have been removed. Launch only for authorized targets/data.
  The session expires after one hour. Native Wasm dispatch instrumentation is
  an additional explicit opt-in requiring a rebuilt browser. Native guest-program
  capture is a further opt-in on top of it: it needs a researcher-supplied
  adapter recipe file and records typed local values and bounded bytecode
  snapshots that the recipe names. Recipes are evidence inputs, not proof of
  guest semantics. Guest capture is native only; no debugger protocol is used.
- Standalone probes remain inactive without an enabled session. Enabled artifact
  capture retains raw source URLs locally; metadata is not necessarily secret-free.
- Historical captures can include sensitive URLs, headers, bodies and source.
  Removal of CDP does not sanitize previously saved evidence. Only collect and
  disclose data covered by authorization.
- Operational bounds remain enforced. Missing data, truncated prefixes and
  evictions must be visible; raw display never means complete wire capture.
- Redaction is an explicit export-copy operation. It never rewrites retained
  captures. The best-effort copy is not a guarantee that arbitrary secrets have
  been removed; review it before sharing. Existing `reb-metadata-only-v1`
  evidence packages remain a distinct explicitly selected metadata export.
- Keep routine logs free of secrets and personal content. Never send raw captures
  to AI services, cloud services or repositories automatically.

## Sensitive capture

- Sensitive capture requires an enabled, visibly labeled session. The packaged
  app's automatic research profile enables it for its bounded session;
  standalone and metadata-only sessions leave it disabled.
- Enable sensitive capture only when the authorization for that session
  specifically covers the data being collected. Keep the capture bounded, audit
  the action, and document new capture paths, their limits and explicit export-copy checks.
- Audit commands and sensitive capture where the feature provides that audit.
- Do not treat a session category or expiration as proof of target
  authorization. Current origin-scope limitations are described above.

## Observation and experiments

- Probes remain disabled by default and observational. A visibly enabled
  experiment and an explicit researcher action are required for browser
  mutation.
- Origin Trace has no Chrome DevTools Protocol path. The browser debugger,
  runtime hooks, live objects, element screenshots and live Wasm inspection used
  it and were removed with it; their retired contracts remain only as history.
  Wasm evidence comes from native capture and stored artifacts. The owned VM
  debugger controls only the project's own native fixture helper.
- Run mutable tools in a disposable experiment context by default. Experiments
  do not read or modify baseline tabs, production cookies, storage, or
  credentials. Never execute extracted code automatically.

- The native Console defaults to a separate disposable browser profile. Explicit
  Live capture mode additionally requires a specifically selected native document
  and confirmation that commands can mutate that live document before the first
  mutable command. Commands are pinned to its native document generation and
  capture binding. Navigation, replacement, or lost ownership clears authorization
  and requires explicit reselection or reconnection. Never select an execution
  target by URL, remap automatically, retry a command, or fall back to a disposable
  browser without an explicit mode change. The console
  cannot set breakpoints, step, or inspect paused frames. Expressions and
  primitive results may contain sensitive values; they stay in bounded,
  ephemeral panel memory and are not automatically captured, redacted, logged,
  exported, or added to evidence. Clear output before sharing the interface.
  Commands require an explicit document selection and are never automatically
  retried. See [Native Console v2](protocol/native-console-v2.md) for these limits.

## Local operation and evidence

- Keep control and evidence traffic on `localhost` or another user-only local
  transport. Keep the unauthenticated research HTTP API bound to loopback; do
  not expose it on a network interface. Remote access requires real
  authentication and authorization and an explicitly approved threat-model
  change.
- Socket transports use user-only permissions and authenticate local clients
  before enforcing session scope.
- Keep evidence on the machine in the local session store. Never upload it
  automatically.
- Keep captured evidence and credentials out of commits, logs, and shared
  artifacts.

## Enforcement status

This policy states the project rules; it does not claim that REB verifies a
researcher's authorization. The following implementation points enforce parts
of the data-handling policy:

| Boundary | Enforcement point |
| --- | --- |
| Sensitive artifact rejection without an enabled session | `src/evidence/artifact.cpp` |
| Loopback-only research API trust check | [`config.rs`](apps/origin-trace-backend/src/config.rs) and [`app.rs`](apps/origin-trace-backend/src/app.rs) |
| Artifact receiver `--allow-sensitive` gate | `services/artifact-receiver/main.cpp` |
| Capture category mask and session expiration | `protocol/README.md`, native probes |
| Origin allowlisting | Not implemented; the native event envelope lacks trustworthy origin identity |

## Related documents

- [`AGENTS.md`](AGENTS.md) is the coding-agent operating contract.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) describes the repository workflow.
- [`docs/README.md`](docs/README.md) is the documentation index.
- [`protocol/README.md`](protocol/README.md) owns the transport contracts that
  implement the capture boundaries above.
