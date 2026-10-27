# Private cookie import v1 — retired

Browser cookie import is removed as part of the native-only, no-CDP boundary.
`tools/cookie-import-browser.mjs` and the parser's browser application method
are removed. No alternate browser, transport, or silent fallback is provided.
This retirement does not claim a native cookie import replacement.

## Former command

`node tools/import-browser-cookies.mjs` is a compatibility refusal entry point.
Every invocation except standalone `--help` exits with status 2 and a fixed
removal diagnostic. Standalone `--help` prints the same notice and exits 0;
this means help was displayed, not that an import succeeded.

The command does not prompt, consume stdin, read an export, inspect a profile,
launch a browser, create a context, transmit credentials, or navigate. Old
`--browser` invocations fail before these actions. Arguments and private source
values are not included in diagnostics.

## Remaining offline boundary

`tools/cookie-import.mjs` retains bounded Chrome/Firefox JSON export validation
and name/value-free review for synthetic tests and explicitly selected offline
files. Its review object has no browser application method and does not retain
cookie names or values after validation. JavaScript strings cannot be securely
erased; this is not a secure-erasure guarantee.

The strict supported subset still rejects ambiguous scope, unsupported stores,
partitioned cookies, malformed flags, duplicate identities, expired values,
invalid prefixes and excess input. Limits remain 256 KiB and 64 cookies.
The legacy 30–300 second destination lifetime field is validated metadata only;
it does not create a browser context or schedule an import.

The file reader accepts only explicit absolute regular-file paths, rejects
symlink components, opens read-only, bounds the read, checks changes during the
read, and clears its temporary byte buffer. It does not discover profiles or
read OS cookie stores. This helper is not called by the retired command.

## Verification

```sh
node tools/check-cookie-import.mjs
python3 tools/check-cookie-import-terminal.py
```

These checks use synthetic data only. They cover offline validation, safe
inspection, selected-file safety, explicit CLI refusal, no input consumption,
no browser spawn and unchanged source files. Real-browser/CDP acceptance and
its executable fixtures are removed, not silently skipped or reported passing.
Passing these checks does not establish any browser cookie import capability.
