# Request Signal Profile v1

Request Signal Profile answers one bounded question from a selected network
request: which fingerprint-relevant browser surfaces were observed or
correlated before this request?

## Research basis

The reviewed systems converge on four useful principles:

1. Begin with a concrete request or runtime observation instead of an
   unbounded source-code search.
2. Preserve immutable evidence and distinguish observed relationships from
   contextual correlation.
3. Use the live browser as the ground-truth oracle, while keeping capture
   separate from interpretation.
4. Bound every collection and analysis pass, then expose missing coverage.

These principles recur in the
[Hyper Solutions request-scraper workflow](https://hypersolutions.co/blog/claude-code-plugin-ai-scraping),
[REA evidence model](https://github.com/morluto/rea),
[Ghostwire](https://github.com/sofianeelhor/ghostwire),
[web-re-toolkit](https://github.com/proofofbots/web-re-toolkit/), and
[auto-re-agent](https://github.com/Dryxio/auto-re-agent). The VM-focused
[anti-bot analysis](https://emro.cat/blog/how-i-broke-the-anti-bot-behind-nike-kick-and-twitch/),
[JavaScript VM implementation](https://disasm.dev/blog/writing-a-javascript-vm-in-go/),
[JSREI projects](https://github.com/JSREI), and
[SneakerDev research catalog](https://www.sneakerdev.com/blog?ref=d_blog_ch)
reinforce that browser-surface access, runtime ordering, and outgoing payloads
must remain connected during later VM or deobfuscation work. The passive
[anti-bot detector](https://github.com/mmewni/antibot-detect) demonstrates the
value of explainable, evidence-backed classification. Brave's
[Web Audio fingerprinting report](https://x.com/brave/status/2091232672659972110?s=46)
provided the most direct missing user workflow: make audio and other
fingerprint-surface activity visible from the request being investigated.

The first version intentionally does not classify a vendor, identify a bypass,
or claim that a signal value was transmitted. It presents the evidence needed
for a researcher to decide which request and artifact deserve deeper analysis.

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
- A request reports at most seven fixed categories: Canvas, WebGL, Web Audio,
  Navigator, Permissions, Storage, and WebRTC.
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
