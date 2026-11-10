# Native compiled scripts v1

Every script V8 compiles in a capture session gets one `script_compiled` record,
whether or not the page's CSP checks eval, and in document, dedicated worker,
shared worker and service worker isolates. The record names the V8 script, the
realm it compiled for, and for `eval` and `Function` the script and position
that created it.

This replaces capture inside Blink's code generation callback. V8 returns from
`Compiler::ValidateDynamicCompilationSource` before that callback unless the
context disallows code generation from strings, which Blink only does when CSP
or Trusted Types is checking eval. On every other page `eval` left no evidence.

## Producer

V8 patch `0018` adds `v8::Isolate::SetCompiledScriptCallback`. It reports after
each successful compile from `ScriptCompiler::CompileUnboundInternal`, the
streaming path, `ScriptCompiler::CompileFunction` and
`Compiler::GetFunctionFromEval`, so code cache consumers and background
compiles are included. An eval compilation cache hit is reported again with the
cached script's ID. Debug-evaluate is skipped: it is the researcher's own
expression. Chromium patch `0037` installs the callback in
`V8Initializer::InitializeV8Common`, which runs for every isolate.

The enabled callback is one atomic load. With capture off V8 creates no handle
and Blink converts no string. The callback runs no JavaScript and never waits.

## Record

`script_compiled` is event type 51, category `artifact`, `artifact_id`,
`parent_event_id` and `request_id` 0, `frame_id` 0 for a worker. Payload 128
bytes, little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | kind |
| 5 | 1 | retention |
| 6 | 2 | reserved, zero |
| 8 | 4 | V8 script ID, nonzero |
| 12 | 4 | start line in its document or resource, 0-based |
| 16 | 4 | start column, 0-based |
| 20 | 4 | creator V8 script ID, 0 when none |
| 24 | 8 | execution context ID of the script's realm, nonzero |
| 32 | 8 | source length in UTF-8 bytes |
| 40 | 32 | SHA-256 of the UTF-8 source, zero for retention 6 and 7 |
| 72 | 4 | creator position, 0 when there is no creator |
| 76 | 52 | reserved, zero |

| Kind | Meaning |
| ---: | --- |
| 1 `script` | Classic script: external, inline, inserted, `setTimeout(string)`, `javascript:` |
| 2 `module` | JavaScript module |
| 3 `function` | Compiled function body, such as an inline event handler |
| 4 `eval` | Direct or indirect `eval` |
| 5 `function_constructor` | `Function`, `GeneratorFunction` or `AsyncFunction` |

A V8 script ID is unique within one isolate. Read it with the record's process,
thread and execution context. The execution context ID is the fold of the
frame's or worker's token, so a worker has an identity even with frame 0.

## Creator

Only kinds 4 and 5 have a creator. V8 records the function that ran the call in
`Script::eval_from_shared`. The creator position is the UTF-16 offset of the
call in the creator's source, read through `Script::GetEvalPosition`. For direct
`eval` that is the source position of the call. For indirect `eval` and the
`Function` constructors V8 stores the caller's negated bytecode offset, and
`GetEvalPosition` translates it, which can compile source positions for that
one function. A creator of 0 means no JavaScript was running. A chain of nested
`eval`s is followed by repeating the join on each creator ID.

Scripts of kinds 1 to 3 record no creator, including a `<script>` inserted by
running JavaScript. V8 keeps no creator for them.

For `new Function` the source is V8's synthesized text,
`(function anonymous(a\n) {\nbody\n})`, so offsets match V8's script and not the
strings the page passed.

## Retention

Every record has exactly one retention value. It is what a reader checks to
learn why bytes are or are not stored.

| Value | Meaning |
| ---: | --- |
| 1 `queued` | Sent as an artifact whose `creator_event_id` is this record |
| 2 `duplicate` | The same digest was already queued on this thread in this configuration |
| 3 `network_fetched` | A response body carries this source; join by SHA-256 |
| 4 `not_permitted` | The session is not content capture |
| 5 `budget_spent` | The renderer's source budget for this configuration is spent |
| 6 `too_large` | Over the 16 MiB artifact limit, so not hashed |
| 7 `unavailable` | V8 could not provide the text |

A source skips the network when it is `eval` or `Function` text, has no script
name, is named `blob:`, `data:` or `about:`, or is named by its own document's
URL, which is what inline and inserted scripts carry. A worker's entry script
also carries its context's URL, but it was fetched, so that rule only applies to
documents. The join by SHA-256 to a response artifact fails, and is reported as
unresolved, when the response was not UTF-8 or had a byte order mark. Nothing is
inferred from a URL.

Sources are stored as `javascript` artifacts. `eval` and `Function` text uses
capture origin 2 `dynamic_javascript`; the rest use 14 `compiled_script`.

### Sensitive capture

Retained text is page content that no response body carried, so it needs content
capture (`--reb-capture-request-content`), the same opt-in as request bodies. The
record's digest, length and lineage do not. The renderer reports
`not_permitted`, and the browser independently refuses both capture origins
outside content capture with `script_source_capture_disabled`.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| One source | 16 MiB | The artifact limit |
| Queued source per renderer and configuration | 64 MiB of distinct text | Bounds generated code without counting a repeated source |
| Remembered scripts per thread | 4,096 | Direct-mapped: a collision repeats a record, never loses one |
| Remembered digests per thread | 4,096 | Same; a collision stores the bytes again and the store dedupes them |

Hashing and UTF-8 conversion run on the compiling thread, for one source of at
most 16 MiB per compile. Tables are allocated on first use during capture and
reset by a new configuration. The first `too_large` and `budget_spent` on a thread also emit one
named `artifact_capture_failed` record, `compiled_script_source_too_large` or
`compiled_script_source_budget`. A record refused by a full queue counts as a
queue drop, spends no budget and queues no source.

## Validation

`IsValidScriptCompiled` in `include/reb/compiled_script.hpp` and
`tools/validate-evidence-store.py` enforce the same rules. V8 tests
`RebNativeCompiledScript*` run in the `native-v8-runtime` workflow,
`make native-probe-admission-check` covers the sink, and
`make native-artifact-capture-check` covers the browser refusal.
`make compiled-script-capture-check` drives a real capture browser through every
case above and needs a Brave built from this source.
