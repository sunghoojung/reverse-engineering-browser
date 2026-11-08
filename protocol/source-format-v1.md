# Source format v1

`GET /api/source-format` (`get_source_format`) returns a Prettier-style layout
of one immutable JavaScript artifact. It is a derived display layer: the
artifact and its retained bytes never change.

## Request

- `session_id` and `artifact_id` select one artifact exactly. The blob must be
  `kind: javascript`, at most 16 MiB, match its size and SHA-256, and decode as
  strict UTF-8.
- `start_line` and `line_count` are optional and only valid together. They
  return formatted lines `start_line` to `start_line + line_count - 1`
  (1-based, at most 10,000 lines). `line_count` in the response always counts
  the whole layout.
- Other parameters are refused.

## Layout

- Oxc 0.155 parses the source as a sloppy script, then as a module. JSX and
  TypeScript are not accepted.
- The layout follows Prettier's document model: groups, indentation, soft line
  breaks, 80 columns and 2-space indentation. Lists stay on one line when they
  fit and put one item per line when they don't; a last object, array or
  function argument expands alone; member chains of more than two call groups
  break before each call.
- Every token and comment is printed as its original source slice. No
  semicolon, quote, parenthesis or comma is added, removed or rewritten.
- One empty line between statements, class members and object properties is
  kept. Line breaks are never placed where JavaScript forbids them (after
  `return`, `throw`, `break`, `continue`, `yield` or `async`, or before `=>`
  and postfix `++`/`--`).

## Fidelity

`mapping: "whitespace-only"`: removing ECMAScript WhiteSpace and
LineTerminator characters from `text` and from the original source gives the
same string. Two checks enforce it:

1. The worker re-lexes its output and requires the same token kinds and texts
   and the same comments, in order.
2. The service repeats the whitespace-only comparison on the exact bytes it
   returns.

A consumer can therefore map every non-whitespace character to its original
offset by walking both texts in step.

## Containment and cost

- The formatter runs in the contained JavaScript worker process: no network,
  no file access, a heap ceiling of 64 MiB plus 128 bytes per source byte
  (measured peaks are 80 to 100), and a deadline of 30 seconds plus 15 seconds
  per MiB. A 12 MiB bundle formats in about 5 seconds in a debug build.
- One formatter runs at a time. Results are cached in memory by SHA-256: at
  most 4 entries and 96 MiB of text.

## Response

`schema: "source-format-v1"`, the public artifact identity in `source`,
`language`, `engine`, `layout`, `mapping`, `line_count`, `window`, `text`,
`cached` and `limits`.

`status` is `formatted` or `unavailable`. An unavailable result is a successful
response with `text: null` and one `reason`:

| Reason | Meaning |
| --- | --- |
| `parse-failed` | The source is not a valid script or module. |
| `output-limit` | The layout would exceed four times the source size. |
| `fidelity-check-failed` | The layout did not reproduce the original tokens. |
| `memory-limit` | The worker reached its heap ceiling. |

Worker start failures are 503, deadlines are 408, and a crash or malformed
reply is 502. No fallback layout is ever returned; Origin Trace falls back to
its in-page formatter and says so.
