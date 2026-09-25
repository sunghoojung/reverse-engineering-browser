# Request Value Test v2

This is a reusable, opt-in hypothesis test for an observed HTTP request, not a
universal code-provenance engine. It can observe one selected request value
without a hook. When a suitable function exists, it can also ask whether
changing its synchronous JavaScript return in a disposable Experiment is
associated with a change in that value.

## Coverage

- Hook sources may be in the isolated page or an attached dedicated worker.
  Request events from either target enter the same ephemeral trail.
- Select one JSON Pointer in a JSON request body, one URL-encoded form field,
  one query parameter, one request header, or the raw text request body. The
  method and query-free URL path scope capture. A query-bearing request at that
  path qualifies, but a change in any unselected query input makes the
  comparison inconclusive.
- Each result shows a bounded preview, SHA-256, byte count, target and request
  IDs, and related hook hits. Comparison requires a retained observed baseline
  return and successful variant return override at the same source location.
  An unrelated or missing hit yields **inconclusive**. Even a positive result
  is called **intervention-associated**, not a complete value-flow proof.

## Workflow

1. Open a disposable Experiment page. If a candidate function is available in
   Sources, add an observation-only return hook. Otherwise, use observation
   mode without a hook.
2. Reproduce the request. The hook request trail in Traffic offers **Test a
   field** as a pivot when armed; the configuration can also be entered by hand.
3. Disarm and configure a method, query-free request URL, value type, and field
   name or JSON Pointer. Raw text body takes no field name. Explicitly confirm
   selected-value capture.
4. Repeat the same action/input to collect observations. If a candidate return
   hook exists, collect an armed observation baseline, disarm, change the hook
   to a typed synchronous return override, re-arm, and repeat.
5. Compare the two observations. A pair without a matched controlled override
   can show a value change, but is **inconclusive** about causation. For an
   intervention pair, follow the override-hit link to Sources. Removing the
   override and reproducing the original value is a useful reversal check.

## Boundaries and retention

Capture is disabled by default. It runs only in the disposable Experiment
context for one selected method and path. Up to 16 observations are retained in
debugger memory. Bodies over 128 KiB, selected values over 4 KiB, query strings
over 8 KiB, duplicate selected form/query keys, missing fields, unavailable
post data, and malformed JSON have explicit non-comparable outcomes. Raw text
body selection can reveal sensitive body content; the UI says so before the
researcher opts in. Only 256 selected-value preview bytes, its digest, and an
ephemeral keyed digest of unselected query input are retained, never a complete request body
or complete query string. Clearing hits, stopping capture, or disposing the
context erases the observations and comparison.

Header selection uses the request event and, when available after it, the
correlated network-stack extra-header event. The [CDP Network protocol](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
says extra-header events are optional and may arrive before the request event.
REB does not buffer an unrelated request's headers while waiting for a URL
match. A header not present in available CDP data is therefore **missing** or
**unavailable**, not proof that it was absent on the wire.

This covers ordinary page and dedicated-worker JavaScript that Chrome DevTools
Protocol exposes. It does not guarantee coverage for every site or code path:
cross-origin frames, service/shared workers, WebAssembly internals, native
browser code, inaccessible or generated functions, asynchronous Promise
continuations, binary/multipart bodies, inaccessible post data, redirects, and
anti-debugging behavior may prevent capture or intervention. Those cases need
separate adapters and should report an explicit unsupported or inconclusive
result, never fabricated provenance. Repeated requests can also differ because
of time, randomness, cache, server state, or changed page state.

The existing Rust worker performs inert, bounded JSON Pointer extraction.
Python selects bounded query, form, header, and raw-text values from the CDP
event or an explicitly requested post-data fetch. The UI and bridge retain only
ephemeral selected-value evidence; native evidence storage is unchanged.
