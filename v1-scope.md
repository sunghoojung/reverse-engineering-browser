# Version 1 Scope

## Purpose

Version 1 is a Brave-based, local research browser for authorized analysis of a website's fingerprinting-relevant browser API use and related network activity.

The first question it answers is:

> Which selected browser APIs did an authorized website call, and which network requests followed?

## In scope

- A custom Brave build with native C++ probes at a small, explicit allowlist of browser APIs.
- Per-renderer shared-memory SPSC ring buffers. The renderer writes compact events; the browser-process broker reads them.
- A browser-process instrumentation broker that batches events and communicates with the local harness.
- A local Unix domain socket on macOS and Linux, or a named pipe on Windows, between the broker and harness.
- A local harness with authorized session scope, selected probe categories, event streaming, and drop counters.
- Scoped network-request metadata that can correlate API use with subsequent requests. Sensitive request fields are redacted by default.

The initial API allowlist should focus on fingerprinting-relevant operations, such as Canvas, WebGL, Web Audio, navigator properties, permissions, storage, and WebRTC or media-device capability access. Each category remains disabled unless an authorized session enables it.

## Explicitly out of scope

- Recording ordinary DOM updates or every DOM mutation.
- Tracing every JavaScript function call.
- Replacing or wrapping page JavaScript functions.
- V8-level execution tracing unless a later research question cannot be answered from targeted browser-API probes.
- Full request or response bodies, credentials, cookies, and authorization headers unless a future session explicitly authorizes and constrains them.
- Full artifact analysis, value causality, and experiment-lab features.

## Event path

```text
Authorized website calls a selected browser API
  -> normal Brave implementation runs
  -> native C++ probe writes a bounded event to its renderer ring
  -> browser-process broker drains and batches the event
  -> local IPC sends it to the harness
  -> CLI, UI, or MCP client receives normalized evidence
```

The page must receive its normal API result without waiting for event delivery.

## Performance rules

The renderer-side probe must:

- do nothing when disabled except a cheap configuration check;
- avoid heap allocation, disk I/O, socket I/O, JSON encoding, and blocking locks;
- write fixed-size or strictly bounded records only;
- drop an event and increment a per-category counter if its ring is full;
- never wait for the broker, harness, UI, or an agent.

## Version 1 success criteria

1. An authorized session enables one selected API category for one allowed origin.
2. A page's normal browser API call returns unchanged.
3. The harness receives a corresponding event with process, frame, navigation, and monotonic-time metadata.
4. The harness shows related scoped network-request metadata.
5. Under a deliberately overloaded event stream, Brave continues rendering and the system reports dropped events instead of blocking the page.

## First vertical slice

Build only this path first:

```text
one selected browser API probe
  -> one renderer ring
  -> browser broker
  -> local harness CLI
```

Compare page behavior, timing, CPU, memory, and dropped-event counts with the matching official Brave release before adding another probe category.
