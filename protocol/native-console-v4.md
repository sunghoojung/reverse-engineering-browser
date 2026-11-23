# Native Console v4

Version 4 removes every bound in the Console that refused, cut short or evicted
data only because of a fixed count or size. A source, a result, a message, a
stack, a document listing, a document-start set or report, the transcript and
the history are carried and kept whole, however large. A connection has no
lifetime. The Console's behavior is otherwise the one
[v2](native-console-v2.md) and [v3](native-console-v3.md) describe, and where
they name a bound this page replaces it.

Helpers, backend, packaged assets and browser are rebuilt together. A peer of
another wire version refuses the connection, so a v3 browser with a v4 backend,
or the reverse, fails closed with the rebuild explanation instead of misreading
a record. Nothing the Console carries is stored, so there is no stored record
to migrate: transcript, history, armed sets and their output are ephemeral, as
before.

## What is whole now

| Was | Now |
| --- | --- |
| Command source: one 64 MiB record | Any size the record format names: 4 GiB, counting a runtime command's JSON escapes |
| Legacy result 8192 bytes, runtime response 64 KiB, value preview 2048 bytes, per-value `truncated` | Whole. No value, location, stack, property name or message carries `truncated` |
| Targets: 64, origin 256, label 128, URL 512 bytes | Every eligible document, its metadata whole. Chromium refuses URLs past 2 MiB, so none is longer |
| Renderer messages: 32 / 32 KiB | Kept whole until polled, up to 64 MiB retained per document for an owner that stops polling |
| Browser activity: 64 events | Kept until read, up to 64 MiB retained for an owner that stops reading |
| Property paging: first 65536 array indices | Every index and every property, 16 a page |
| Completion: 8 path components, 24 suggestions, 1024 lexical names, 4096 names per prototype, 8 prototypes | Any path depth, every match from every object on the chain |
| UI transcript: 128 entries, 256 KiB, 8192 DOM elements, eviction | Every entry until Clear; only the rows near the viewport are in the document |
| UI history and snippets: 128 / 256 KiB, 16 / 64 KiB | Every command, a repeat of the previous one kept once, and every snippet |
| UI object expansion: depth 8 | Any depth, one level and one page at a time |
| Activity view: 128 records | Every delivered record |
| Await: ten seconds | Until the promise settles or **Stop waiting** |
| Session: one hour | Until the owner disconnects, the browser exits, or an exchange fails |
| Document-start command: one 64 MiB record, listing half a reply | One record of up to 4 GiB; the listing is never refused |
| Document-start report: 8192 bytes | Whole |
| Document-start rule origin and path prefix: 256 bytes each | Any length |
| Document-start reply: 64 MiB with every record that fits | A page of 8 MiB, the first record whole however large, with `more` |
| Document-start set: replaced as a whole | Built and pruned one script at a time with `add` and `remove`; `arm` still replaces |

## Wire

`common/native_console_protocol.h` owns the ABI. Magic stays `0x43424552`; the
version is **4**. Headers stay 32 bytes, and the hello, authentication, peer
UID check and operations 1 to 5 keep their meanings.

- **Record length.** A header's u32 payload length is the only bound. Every hop
  reads a payload as its bytes arrive, growing its buffer with what actually
  arrived, so a declared length alone allocates nothing, and a transfer fails
  only when it makes no progress for its stall interval. Mojo carries renderer
  records as `BigString`, which moves anything large to shared memory. Each end
  asks for 1 MiB socket buffers, because macOS defaults a local socket to 8 KiB
  and would move a large record in thousands of round trips.
- **Targets.** A listing is `item_count` variable-length records: a 24-byte
  header `{u64 id; u32 origin_bytes; u32 label_bytes; u32 url_bytes; u16 flags;
  u16 reserved}` followed directly by the origin, label and URL bytes, with no
  padding. Target flag 2 is top frame. The count can be no larger than the
  headers the payload has room for, and each target's lengths are checked as it
  is read.
- **Flags.** Response flags are allowed only on a target listing. Flag 1 means
  a listed document did not describe itself in time, so the listing is
  partial; flag 2 is v3's document-start support. Nothing else is ever cut to
  fit a record, so any other response with a flag is malformed.
- **Pages.** A reply that drains a queue, a message `poll`, a `traffic` read or
  a document-start `state`, carries at least one record and stops adding them
  past 8 MiB, then sets `more: true`, so a large backlog arrives as several
  replies instead of one that every hop holds whole. The owner reads again at
  once while `more` is true. A page size refuses and drops nothing.

### Runtime commands

`evaluate` takes a source of any size. `inspect` takes any offset up to
2<sup>53</sup> - 1 and pages every member. `complete` takes a path of any depth
and a prefix of any length and returns every match. `poll` and `traffic` add
`more`. Values, their locations, exception stacks and listener lists are whole.

### Document-start operations

Operation 4 commands are UTF-8 JSON of any size, with `target_id == 0`:

| Command | Meaning |
| --- | --- |
| `{"operation":"arm","scripts":[…]}` | Replaces the whole set atomically and discards the previous set's output. |
| `{"operation":"add","scripts":[…]}` | Adds scripts beside the armed ones, which keep running, reporting and their output. |
| `{"operation":"remove","script_ids":["…"]}` | Removes the named armed scripts and stops any of their injections still running. Their records stay. Every id must be armed. |
| `{"operation":"clear"}` | Removes every script and its output. |
| `{"operation":"state","after":"<sequence>"}` | The registry, counters and one page of the records after that sequence. |

A refusal leaves the set and its output exactly as they were. Script ids
increase and are never reused, and output sequences never restart within a
browser session, whatever the set does, so a reader's cursor only moves
forward. Each change bumps `generation`. A report of any length is one record.
Every reply reports `contract_version: 4` and `output.more`.

## HTTP and API

The [OpenAPI contract](openapi.json) owns the exact fields. Command envelopes
keep `contract_version: 2`, without per-value `truncated`. Document-start
surfaces report `contract_version: 4`.

| Change | Detail |
| --- | --- |
| `add_document_start` | `scripts`, `confirm_document_start: true`; adds beside the armed set |
| `remove_document_start` | `script_ids`, canonical decimal ids, each named once; removes them |
| `limits` | `{record_bytes, page_bytes, retained_bytes}`: 4294967295, 8388608 and 67108864 |
| Start URL | Up to 2 MiB, the longest URL Chromium accepts |
| Request body | Up to six whole records plus their JSON envelope; the body deadline grows a second per 16 MiB |
| Browser answer | A listing or document-start answer must start within 6 seconds plus a second per 4 MiB of command, because the browser receives and parses the whole command first |

A Console connection no longer expires. `GET /api/native-console` never retires
a session for its age, and an idle live binding stays bound until Disconnect,
the capture ending, or a failed exchange.

## Origin Trace

The transcript keeps every entry until **Clear** and renders only the rows near
the viewport, measuring each row once it has been drawn, so a page that logs
for hours keeps scrolling, searching and following the end at the same cost.
A row never drawn counts as the median drawn height, so one very tall message
does not stretch the rest. WebKit cannot lay out an element taller than about
33.5 million px, so a transcript taller than 16.7 million px is drawn
compressed into that extent: a wheel, key or touch scroll moves the content by
exactly its own distance, a scrollbar drag maps proportionally onto the whole
transcript, and both ends stay reachable. The layout never moves a scroll the
reader is making, which would stop momentum or a keyboard scroll animation
part way, or the extent it scrolls through, which would leave it short of
where it was aimed: a row measured during that scroll moves the space around
the drawn rows, and a scroll that reaches either end of the extent shows that
end of the transcript. The scroll offset and extent take up the difference
once the scroll has stood still, for three frames after `scrollend` or for
300 ms. A `scrollend` alone does not end it, because WebKit also fires one for
an animation that a newer scroll cancels, such as a PageDown that Home
interrupts. Home, End, Command-Up and Command-Down scroll the focused
transcript to that edge itself, as WebKit does after bug 330293; before it,
WebKit aims them by a distance from the position it last knew, so one pressed
while PageDown still moves would land short. That WebKit can also drop a
scroll asked for while its keyboard scroll still moves, stopping PageDown and
starting nothing, so the transcript asks again once it has stood still short
of the edge for four frames, up to eight times, until another key, a wheel or
a pointer takes over. The end is followed when entries
arrive or **Latest** is chosen, never against the reader's scroll, and a
scroll down that ends within 40 px of the end lands on it.
WebKit measures a word, text with no break opportunity, as one width, and past
a few thousand characters that width loses precision, so a 1 MiB message's
lines held a character too many or too few. A word of more than 4096 code
units, without a space, tab or line break, is drawn as runs of at most that
many, each ending on a grapheme boundary and the next after a `<wbr>`, in a
span that breaks anywhere: every line stays full up to the wrap width, the
layout stays linear, and copy, Find and `textContent` see one text. Text
around such a word wraps as before.
Search and level filters run over every entry, including rows that are not in
the document, and an evaluation link reveals its command wherever it is. A
command is shown whole in the transcript. History keeps every command, a
repeat of the previous one kept once, and completion lexes only the edited line
onward, so a source of any size completes as it is typed. Each armed document-start script has its own
**Remove** button, and **Arm** adds a script beside the armed ones.

## Bounds that remain

Each protects an invariant that no reasonable design avoids, and none of them
silently loses data.

| Bound | Why |
| --- | --- |
| A record is at most 4 GiB | The header names its payload with 32 bits. V8 cannot build a string whose UTF-8 form comes near it |
| 64 MiB retained per document for renderer messages, 64 MiB of browser activity, 64 MiB of document-start output | A renderer and the browser must stay bounded for an owner that stops reading, or a page logging in a loop would grow until the process is killed. The oldest records go first, counted in a visible saturating `dropped`; a connected Console reads continuously, so it is never behind by this much, and one record larger than the bound is still kept alone |
| 8 MiB pages | Keeps a backlog moving as several replies instead of one that every hop holds whole. A page always carries a record, so nothing is refused |
| 16 properties a page | Paging, not a cap: **Next** reaches every member |
| Dispatch 500 ms, record transfer stall 2 seconds, Stop answer 5 seconds | Liveness of the hand-offs around a command. A command itself runs until it returns, and a transfer moves for as long as it keeps moving |
| Browser answer 6 seconds plus a second per 4 MiB of command | Liveness of browser work, proportional to what it was handed |
| URLs up to 2 MiB | Chromium's own URL limit; no document can have a longer one |
| Transcript drawn within 16.7 million px | WebKit's layout coordinates end near 33.5 million px. A taller transcript is compressed into the extent, not cut: every entry stays reachable |
| Counters saturate at 2147483647 | A drop or record count that would overflow stays at its largest value instead of wrapping |

## Verification

- `make native-tests` runs `tools/check-native-console-document-start.cpp`:
  ten thousand scripts and an 80 MiB snippet that round-trip, a 1 MiB path
  prefix, a hundred variable-length targets with 2 MiB URLs read back whole,
  and response flags admitted only on listings.
- `make native-console-check` drives the real C++ bridge and the HTTP API
  against the synthetic peer: input past 64 MiB through the bridge and over
  HTTP, a 3 MiB message polled whole, a 300-document listing with a 1 MiB URL
  and a 64 KiB label, `add` and `remove` beside an armed set, a document-start
  command past 64 MiB, paged reads of every retained record, and a payload
  that ends short of its declared size.
- The backend's Rust tests cover the v4 peer, the scaled answer deadline, and
  `add`, `remove` and listing metadata whole.
- `node tools/check-console-workspace.mjs` and the two Console DOM fixtures
  cover the windowed transcript with 12,000 entries, search over rows that are
  not rendered, a tall row that does not stretch the estimate, a compressed
  transcript scrolled step by step and by drag to both ends, a reader's scroll
  whose offset and extent the layout never moves, even past a `scrollend` from a
  cancelled animation, Home, End and Command-Up and -Down scrolled to their edge
  by the transcript and asked again when the engine drops the request, every
  other key left to WebKit, a long word drawn in
  bounded runs on grapheme boundaries with the text around it whole, a command
  past 64 MiB sent whole, the incremental completion
  lexer against a fresh lex, and the document-start panel's add, remove and
  paged reads.

None of these prove Blink or V8. After rebuilding the browser, backend and
packaged app, the live acceptance is:

1. Evaluate a source over 1 MiB in a live document; it runs whole.
2. `console.log` a string over 1 MiB; the transcript shows it whole.
3. Open more than 64 documents; every one is listed and selectable.
4. Log more than 10,000 rows; every row stays, scrolling stays smooth, and
   search finds rows that are not rendered.
5. Keep a connection open for more than an hour, or show that nothing expires
   it; it keeps evaluating.
6. Arm two document-start scripts one at a time, remove one, and confirm the
   other keeps running and both keep their records.
