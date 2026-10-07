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

1. In Runtime Hooks, create a disposable context and open the page. Choose
   **Test a request value** in Session to jump to capture setup. No hook is
   required for observation. An isolated request in Traffic offers the same
   pivot with its method and query-free URL prefilled; active hooks are disarmed
   before opening capture setup.
2. Choose a method, query-free request URL, value type, and exact field name or
   JSON Pointer. Raw text body takes no field name. Explicitly confirm
   selected-value capture and select **Start value capture**. Editing a capture
   setting clears confirmation. The active summary shows what is actually being
   captured even when the form contains an unsubmitted draft.
3. Repeat the request in the isolated page or dedicated worker to collect
   observations. A distinct available pair from one target is selected
   automatically; your chosen pair is preserved across refreshes. Older
   observation evictions are visible in the capture summary. Restarting capture
   erases the previous observations and comparison.
4. Optionally add an observation-only synchronous return hook and collect an
   armed baseline. Disarm, remove that hook, and add its return-override variant
   at the same source location. Re-arm and repeat the same action/input. Entry
   hooks and live-function-object mode cannot supply a return intervention.
5. Select baseline and variant observations and **Compare observations**, even
   while hooks remain armed. A pair without a matched controlled override can
   show a value change, but is **inconclusive** about causation. For an
   intervention pair, follow the override-hit link to Sources. Removing the
   override and reproducing the original value is a useful reversal check.
6. Disarm hooks before changing capture settings or selecting **Stop and erase**.
   Disarming hooks alone does not stop an enabled selected-value capture.

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

The isolated page's network subscription excludes post bodies from ordinary
request events. When a selected body is needed, REB fetches post data only for
the matched request after confirmation. With general network-content capture
off, the page network subscription stops when both hooks and the field test are
inactive.

Header selection uses the request event and, when available after it, the
correlated network-stack extra-header event. The [CDP Network protocol](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
says extra-header events are optional and may arrive before the request event.
REB does not buffer an unrelated request's headers while waiting for a URL
match. A header not present in available CDP data is therefore **missing** or
**unavailable**, not proof that it was absent on the wire.
If a later extra-header event changes a retained observation, its prior
comparison is cleared so the researcher must compare the updated values.

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
The Rust backend selects bounded query, form, header, and raw-text values from the CDP
event or an explicitly requested post-data fetch. The UI and bridge retain only
ephemeral selected-value evidence; native evidence storage is unchanged.
