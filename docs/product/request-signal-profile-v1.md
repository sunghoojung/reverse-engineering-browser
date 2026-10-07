# Request Signal Profile v1

Request Signal Profile answers one bounded question from a selected network
request: which fingerprint-relevant browser surfaces were observed or
correlated before this request?
Project-wide authorization and capture policy is in
[`SAFETY.md`](../../SAFETY.md); this design defines which signals the profile
can retain.

## Research basis

The reviewed systems converge on four useful principles:

1. Begin with a concrete request or runtime observation instead of an
   unbounded source-code search.
2. Preserve immutable evidence and distinguish observed relationships from
   contextual correlation.
3. Use the live browser as the ground-truth oracle, while keeping capture
   separate from interpretation.
4. Bound every collection and analysis pass, then expose missing coverage.

The [analysis catalog](./analysis-catalog-v1.md) records the reviewed revisions
and limits of REA, Ghostwire, ReAgent, web-re-toolkit, Hyper's plugin, the
educational Go VM, focused JSREI projects, and fingerprint research. These are
conceptual references, not proof that REB implements every upstream technique.
Hyper's hosted analysis is not a locally inspected server implementation;
antibot-detect's tiers are uncalibrated, and SneakerDev is a discovery catalog.
The [emro URL](https://emro.cat/blog/how-i-broke-the-anti-bot-behind-nike-kick-and-twitch/)
now contains a withdrawal notice dated 2026-04-26, so it is historical context
only and cannot support technical findings. Retained Web Audio calls are useful
request context; they do not contain samples or establish fingerprinting.

## Evidence path

1. The event broker validates and stores a normalized browser event.
2. When `--signal-store` is enabled, a bounded cold-path index records retained
   signal categories and event references.
3. A `request_initiated` or `request_started` event produces one immutable
   profile sidecar record.
4. The local HTTP server or native app selects the profile by exact session,
   request, process, and sequence identity.
5. The Traffic inspector renders category counts, confidence, last evidence
   reference, and coverage state under **Signals**.

The renderer queue, Mojo transport, and browser-to-broker event record are
unchanged. The index is absent unless the sidecar is configured.

## Relationship semantics

- `parent_chain` means the broker followed explicit retained parent event IDs
  from the request root. Its confidence is `observed`.
- `same_context` means an earlier signal shared session, process, navigation,
  and frame with the request. Its confidence is `correlated`.
- A browser-process request may copy a renderer request profile only through
  the existing explicit initiator process and request identifiers. The copied
  profile retains the renderer initiator event reference.

The profile never states that a captured signal value produced a request
field. Exact value flow remains future work.

## Bounds and failure behavior

- The index retains at most the broker's configured event capacity and evicts
  in deterministic insertion order.
- A request reports at most eight fixed categories: Canvas, WebGL, Web Audio,
  device and layout, Permissions, Storage, WebRTC, and Runtime.
- Parent traversal stops after 32 events and reports the limit in coverage.
- Retention eviction remains visible as `retention_truncated`.
- A saturated category count remains visible as `count_saturated`.
- The UI reads at most 10,000 profiles of 8 KiB each and validates the complete
  closed contract before replacing the last valid state.
- Missing profiles render an explicit empty state. Malformed stores render an
  error and do not mutate the evidence.
- The benchmark exercises one million cold-path events and guards a minimum of
  500,000 indexed events per second. The broker path does not run this index
  when `--signal-store` is absent.

## Privacy

Profiles contain only category names, counts, stable event references, request
context identifiers, and coverage flags. They do not include API return values,
audio buffers, canvas pixels, headers, cookies, credentials, URLs, or bodies.
