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
  session with all implemented native capture categories, bounded CDP request
  and response content, and Canvas image artifacts enabled. Launch this profile
  only for authorized targets and data. The session expires after one hour.
  **New Live Session…** offers metadata-only capture;
  `REB_AUTOMATIC_CAPTURE_MODE=metadata` selects that mode for automatic launch.
- Standalone probes remain inactive without an enabled session. Metadata-only
  sessions follow the defaults below; full-content research sessions follow
  the sensitive-capture limits and credential redaction rules.
- Capture metadata, sizes, hashes, stable identifiers, and bounded previews by
  default.
- Do not capture credentials, authorization or proxy-authorization headers,
  cookies, `set-cookie` values, request bodies, response bodies, or personal
  content by default.
- Redact sensitive fields at capture and storage boundaries. Keep routine logs
  free of secrets and personal content.

## Sensitive capture

- Sensitive capture requires an enabled, visibly labeled session. The packaged
  app's automatic research profile enables it for its bounded session;
  standalone and metadata-only sessions leave it disabled.
- Enable sensitive capture only when the authorization for that session
  specifically covers the data being collected. Keep the capture bounded, audit
  the action, and document new capture paths and their redaction checks.
- Audit commands and sensitive capture where the feature provides that audit.
- Do not treat a session category or expiration as proof of target
  authorization. Current origin-scope limitations are described above.

## Observation and experiments

- Probes remain disabled by default and observational. A visibly enabled
  experiment and an explicit researcher action are required for browser
  mutation.
- Run mutable tools such as interception, automation, runtime hooks, replay, and
  object changes only in a disposable experiment context and within its bounded
  pages or exact selected page.
- Experiments do not read or modify baseline tabs, production cookies, storage,
  or credentials. Never execute extracted code automatically.

- The native Console panel visibly opts into arbitrary JavaScript in a separate
  disposable browser profile. Expressions and primitive results may contain
  sensitive values; they stay in bounded, ephemeral panel memory and are not
  automatically captured, redacted, logged, exported, or added to evidence.
  Clear output before sharing the interface. Commands require an explicit
  document selection and are never automatically retried. See
  [Native Console v2](protocol/native-console-v2.md) for these limits.

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
| Credential-free experiment request validation | [`requests.rs`](apps/origin-trace-backend/src/debugger/requests.rs) |
| Artifact receiver `--allow-sensitive` gate | `services/artifact-receiver/main.cpp` |
| Capture category mask and session expiration | `protocol/README.md`, native probes |
| Origin allowlisting | Not implemented; the native event envelope lacks trustworthy origin identity |

## Related documents

- [`AGENTS.md`](AGENTS.md) is the coding-agent operating contract.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) describes the repository workflow.
- [`docs/README.md`](docs/README.md) is the documentation index.
- [`protocol/README.md`](protocol/README.md) owns the transport contracts that
  implement the capture boundaries above.
