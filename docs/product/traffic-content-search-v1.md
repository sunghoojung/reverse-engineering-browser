# Traffic retained-content search v1

Traffic can find a literal value across retained request and response headers
and text bodies, then open the matching evidence directly. The URL, method, and
status filter remains the default. **Include headers and bodies** explicitly
adds content already retained for the session; it never changes capture policy.

## Search and navigation

The query is trimmed, limited to 512 characters, and matched case-insensitively
using JavaScript lowercase comparison. It has no regular expression syntax.
Tab, domain, and resource-type filters run before content search. Results retain
their normal chronological table order and identify the first matching location:
URL/method/status, request header, request body, response header, or response body.
Headers compare their name and value separated by one space. Body matching uses
retained raw text, preserving JSON escape sequences rather than searching a
derived interpretation.

Selecting a content match opens Request / Response, chooses the matching side
on narrow windows, and opens Header or Raw body with Find populated. A researcher
can clear Find or switch views normally. Unchanged refreshes preserve the pane,
focus, and scroll position; a changed query replaces the search projection.
Search controls and result rows support the existing keyboard navigation.

## Bounds and incomplete evidence

Search inspects the newest scoped requests first within 8,388,608 UTF-16 code
units per render. Whole records are preflighted before header joining, byte
decoding, or case folding. Textual byte bodies conservatively charge their
retained byte length and decode at most the existing 128 KiB body limit.
No lowercase body index or additional evidence store is retained.

A record that cannot fit is omitted from content inspection, while its URL,
method, and status remain searchable. Smaller earlier records can still fit.
The partial notice reports how many scoped requests were inspected and asks the
researcher to narrow the scope. An empty partial result explicitly describes
inspected content instead of implying complete absence.

Only available text bodies and retained headers are searched. Textual byte
bodies use the viewer's text/JSON/JavaScript/XML MIME classification. Binary,
missing, loading, error, empty, and redacted bodies add no searchable text.
Retained truncated prefixes remain searchable. Coverage notices explain these
limits even when the search budget is sufficient.

## Ownership and privacy

`traffic_view.js` owns bounded matching and content navigation; `app.js` owns
scope, status, result rendering, and live refresh. Search inserts captured text
through existing text-node rendering. It does not execute captured markup,
retrieve bodies, enable content capture, transmit queries, mutate baseline
pages, or change any wire or storage contract. Sensitive header values remain
redacted at the capture boundary under [SAFETY.md](../../SAFETY.md).
