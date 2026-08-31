# Live Object Experiment v1

## Purpose

Live Object Experiment lets an authorized researcher search and patch JavaScript
objects while preserving the captured baseline as immutable evidence. The feature
uses the existing disposable Experiment BrowserContext. It never mutates the
baseline debugger target, captured artifacts, broker records, or evidence store.

## Isolation and lifecycle

1. The researcher explicitly creates a disposable Experiment context.
2. The researcher explicitly opens one HTTP or HTTPS URL in its credential-free
   page. URL credentials are rejected. The page has no baseline cookies or storage.
3. Live search runs only when that exact disposable page is attached.
4. A search retains a bounded object collection for the current navigation. A new
   search or navigation releases the previous collection before continuing.
5. Disposal deletes the BrowserContext and clears search references, previews,
   mutation values, and the complete audit. A target disconnect invalidates every
   retained reference and requires another search.

The request Interceptor, Repeater, API Collection runner, and Object Lab share one
disposable context. Active request work must finish or be cancelled before an
object action can start.

## Mutation contract

The v1 control plane accepts only two operations on an own property of one retained
search result:

- `set` defines a JSON data value without invoking an inherited or own setter;
- `delete` removes an existing configurable own property.

Property names are explicit printable text. `__proto__`, `prototype`, and
`constructor` are rejected. Accessor properties, non-configurable deletes,
non-writable and non-configurable writes, non-extensible additions, arbitrary
expressions, functions, method calls, and prototype changes are rejected.

Set values must be valid JSON with at most 16 KiB of canonical UTF-8 text, eight
container levels, 256 total container entries, and 4 KiB per string. Non-finite
numbers are rejected. Each mutation is applied synchronously to the selected
object, then its bounded preview is read back without invoking getters.

## Bounds

| Resource | Limit |
| --- | ---: |
| Search results | 50 |
| Search candidates | 25,000 |
| Search time | 750 ms |
| Properties inspected per candidate | 256 |
| Preview properties | 16 |
| Retained search collections | 1 |
| Mutation attempts per session | 256 |
| Retained audit entries | 128 |
| Property name | 256 UTF-8 bytes |
| Canonical mutation value | 16 KiB |
| JSON container depth | 8 |
| JSON container entries | 256 |
| JSON string value | 4 KiB |
| Navigation wait | 15 seconds |

## Audit and privacy

Every accepted mutation attempt creates one ordered audit record, including failed
runtime attempts. The record contains the session, navigation, search, result,
operation, property name, target class, outcome, before and after value types,
canonical set-value byte count and SHA-256 digest, and a redacted page URL. It does
not retain the value, page content, query, fragment, credentials, cookies, headers,
request bodies, or object reference.

The audit is ephemeral debugger state. It is never appended to the immutable
evidence store. The UI labels Object Lab as mutation-capable and Experiment-only,
requires an explicit confirmation for each patch, and keeps failures visible.

## Performance boundary

Object search and mutation are cold-path DevTools commands initiated by a person.
They add no renderer probe, browser capture hook, queue traffic, or inactive-path
work. The C++ event path remains observational, bounded, non-blocking, and
allocation-free while disabled.
