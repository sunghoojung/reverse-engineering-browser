# Safety, Authorization, and Capture Policy

Reverse Engineering Browser (REB) is a local-first research harness for
inspecting systems you are authorized to test. This file is the single source of
truth for the project's authorization, capture, privacy, and local-operation
rules. Other documents link here instead of restating them.

## Authorized use

- Use REB only on systems you own or are explicitly authorized to inspect.
- Comply with applicable law, contracts, and the terms that govern each system
  you inspect.
- Do not intercept, capture, or modify traffic on systems outside that
  authorization.

## Default capture

- Capture metadata, sizes, hashes, stable identifiers, and bounded previews.
- Do not capture credentials, authorization or proxy-authorization headers,
  cookies, `set-cookie` values, request bodies, response bodies, or personal
  content by default.
- Redact sensitive fields by default at every capture and storage boundary.

## Sensitive capture

- Sensitive capture is disabled by default and is enabled per session.
- Enabling it must be visible to the researcher, scoped to one session,
  documented in the change that adds it, and covered by redaction tests.
- A session may enable it only when the researcher's visible authorization scope
  permits the specific data captured.
- Commands and sensitive capture are audited.

## Local-first operation

- Keep all control and evidence traffic on `localhost` or another user-only
  local transport.
- The research HTTP API is intentionally unauthenticated and must stay local. Do
  not expose it on a network interface. Remote access requires real
  authentication and authorization first, which is a separate, explicitly
  approved change to the threat model.
- Socket transports use user-only permissions and a shared session token.
- Authenticate local socket clients and enforce session scope before commands
  reach the browser.

## Evidence handling

- Evidence stays on the machine in the local session store.
- Never upload evidence automatically.
- Keep captured evidence out of commits, logs, and shared artifacts.

## Disposable experiment scope

- Mutable tools (interception, automation, runtime hooks, replay) run only in a
  disposable experiment context, on its bounded pages or one exact page.
- They never read or modify baseline tabs, production cookies, storage, or
  credentials.

## Enforcement map

| Boundary | Enforced in |
| --- | --- |
| Sensitive artifact rejection without an enabled session | `src/evidence/artifact.cpp` |
| Loopback-only research API trust check | `apps/research-ui/server.py` |
| Credential-free experiment request validation | `apps/research-ui/debugger/requests.py` |
| Artifact receiver `--allow-sensitive` gate | `services/artifact-receiver/main.cpp` |
| Capture category mask and session expiration | `protocol/README.md`, native probes |

## Related documents

- [`AGENTS.md`](AGENTS.md) is the coding-agent operating contract.
- [`docs/README.md`](docs/README.md) is the documentation index.
- [`protocol/README.md`](protocol/README.md) owns the transport contracts that
  implement the capture boundaries above.
