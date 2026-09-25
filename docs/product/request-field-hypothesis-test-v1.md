# Request Field Hypothesis Test v1

This is a guided, ephemeral comparison inside Runtime Hooks, not general value
provenance. It answers a bounded question: when an isolated worker function's
synchronous return is changed, does one selected JSON request field change?

## Researcher workflow

1. Create the disposable Experiment context and open a credential-free page.
2. Locate a candidate dedicated-worker function in Sources and add an
   observation-only entry/return hook. Arm it and trigger the request once.
3. Select the worker request in the hook trail, choose **Test a field**, enter a
   JSON Pointer such as `/payload`, and confirm selected-field capture. The
   request URL must have no credentials, query, or fragment. The matcher uses
   its exact redacted URL and uppercase method.
4. Disarm, then arm the observation-only hook again and repeat the same input.
   This creates a baseline observation.
5. Disarm, edit the candidate hook to use a typed synchronous return
   replacement, arm it, and repeat the same input. This creates a variant.
6. Disarm and compare the two available observations. The result shows whether
   the selected value's SHA-256 changed and whether the variant has a retained
   successful override hit at the same retained source location as an observed
   baseline return hit. The result links to the override hit in Sources.

The UI calls this **intervention-associated**, not exact value provenance. It
cannot prove the entire producer-to-network chain. Time, randomness, server
state, cache, and changed page state can confound repeated actions. Reversing
the intervention and repeating the baseline improves confidence. A Promise
return or detached worker cannot be overridden by this feature.

## Capture and ownership

Capture is disabled by default and requires explicit confirmation for one
exact request URL, method, and JSON Pointer. Only dedicated workers belonging
to the disposable Experiment BrowserContext are eligible. The worker's CDP
`Network.requestWillBeSent` event supplies a body when available; an explicitly
configured test may ask `Network.getRequestPostData` for the exact matching
request when the event omits it. No body is fetched for unrelated requests.

The Python debugger bridge queues at most two bounded extraction jobs. The
bundled Rust worker parses the JSON and RFC 6901 pointer, returning only a
selected value up to 4 KiB. The bridge retains a 256-byte preview, SHA-256,
byte count, request and target IDs, and related hit IDs; it never retains a
complete request body. Observations stay in debugger memory only, with at most
16 retained and explicit eviction count. The body limit is 128 KiB. Missing,
oversized, malformed, busy, or unavailable outcomes are shown instead of
inventing a value. Clearing hits erases observations and comparison. Stopping
the test or disposing the context erases its configuration and values.

The bridge and UI own this versioned ephemeral state. Neither the C++ event
record nor broker evidence store changes. Rust is used for bounded, inert JSON
selection because the existing packaged Rust/Oxc worker already serves
untrusted source analysis; Go would add a separate runtime and build path.
