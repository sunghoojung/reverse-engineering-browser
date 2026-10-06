# Web Audio Function-Call Capture v1

Web Audio Function-Call Capture records fingerprint-relevant Web Audio API
operations as bounded native browser events. It makes live Web Audio activity
visible in the evidence timeline and in the Request Signal Profile without
copying audio content.
Project-wide capture and privacy rules are defined in
[`SAFETY.md`](../../SAFETY.md); this design describes the Web Audio fields that
are retained.

## Captured calls

Version 1 records these operation names at their corresponding native API
boundaries:

- `BaseAudioContext.createOscillator`
- `BaseAudioContext.createDynamicsCompressor`
- `BaseAudioContext.createAnalyser`
- `AudioNode.connect`
- `AudioScheduledSourceNode.start`
- `OfflineAudioContext.startRendering`
- `AnalyserNode.getFloatFrequencyData`
- `AnalyserNode.getByteFrequencyData`
- `AnalyserNode.getFloatTimeDomainData`
- `AnalyserNode.getByteTimeDomainData`
- `AudioBuffer.getChannelData`
- `AudioBuffer.copyFromChannel`

This set covers the common construction, render, and readback boundaries used
by Web Audio fingerprinting. Complete graph reconstruction and exact value
provenance remain later milestones.

Call events do not carry a success or failure result. Hooks that already have a
clear success boundary, including `AudioNode.connect` and
`AudioScheduledSourceNode.start`, emit only after that boundary. Readback entry
hooks remain visible even when a later validation step rejects the call; for
example, `AudioBuffer.copyFromChannel` records an attempted call without
copying its arguments or error.

## Evidence and limits

Each observation uses the existing fixed 320-byte event record with category
`web_audio`, type `api_call`, and one fixed operation name in the bounded inline
payload. The inactive path performs one atomic emitter load. Active calls use
the existing bounded renderer queue, expiration deadline, category policy,
drop accounting, and sequence-gap reporting.

The probe is disabled unless the session category mask includes Web Audio bit
`4`. Live sessions enable it by default as part of mask `4095`, alongside every
other fingerprint family, Network, and Artifact. Events rejected by policy or
expiration do not consume sequence numbers.

In addition to these lower-level boundaries, the Blink bindings generator
records fixed names for methods and property reads across selected Web Audio
interfaces. Explicit exclusions prevent duplicate events where a generated
callback reaches one of the hooks listed above.

The normalized timeline retains the fixed operation name. Request Signal
Profiles do not duplicate it: they retain bounded Web Audio counts, observed or
correlated relations, confidence, and exact event references. The deterministic
demo records `OfflineAudioContext.startRendering` and links it into both request
profiles as observed parent-chain evidence.

## Privacy and behavior

The probe does not capture audio samples, rendered buffers, analyser output,
node parameters, return values, credentials, or page content. It is
observational and does not change the value returned to the page or Brave's
existing audio farbling behavior.

## Retained VM relevance

The offline VM analyzer and `GET /api/analysis/vm` also consume retained Web Audio
call metadata. One runtime audio family contributes at most 25 anti-bot relevance
points per artifact; it cannot change structural VM confidence or establish that
the site fingerprints users. Static audio keyword matching is not used.

Each observation keeps the original session, process, and sequence identity.
An explicit nonzero artifact match is labeled observed. Matching known-frame
metadata without script attribution is labeled correlated. Zero/unknown frames
cannot connect unrelated artifacts. Current native operation probes do not
capture script identity or stacks, so ordinary live audio is usually correlated
and worker attribution can be unavailable. Partial graphs and invalid/conflicting
event identities remain explicit omissions. Event-only capture changes refresh
the analysis without waiting for another artifact.

The analyzer copies no audio content or API arguments and never infers an audio
result, signal value, CPU model, or exact request provenance. See
[the retained-evidence contract and limits](anti-bot-vm-detection-v1.md#retained-runtime-evidence-implementation).
