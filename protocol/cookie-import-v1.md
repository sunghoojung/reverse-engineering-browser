# Private user-operated cookie import v1

This is a separate REB tool for an explicitly selected export file. It is not
an HTTP API action, `reb-api` command, automatic login, existing-profile importer,
or permission to handle real credentials through an agent. The researcher must
operate the real-file selection and confirmations in their own local terminal.
Development and acceptance fixtures use synthetic cookies only.

Follow [SAFETY.md](../SAFETY.md). A cookie can be a reusable authentication
credential. Do not paste it into chat, logs, bug reports, source control, an
agent's file inputs, or a normal Origin Trace capture.

## Product entry point

From the REB checkout, with Node.js 22+ and an already installed trusted Chromium
browser, run:

```sh
node tools/import-browser-cookies.mjs --browser /absolute/path/to/chromium
```

On macOS, select the executable inside the installed browser application, for
example its `Contents/MacOS/` executable, rather than an existing profile. Linux
and macOS process ownership are implemented; Windows is explicitly refused.
The tool neither installs software nor disables the browser sandbox. A failure
to launch must be fixed in a supported environment, not with `--no-sandbox`.

This is a terminal workflow, not a native Origin Trace menu. Its separate
browser is not attached to Traffic, Console, the debugger API, an agent browser,
or any capture session. Existing REB Experiment contexts deliberately remain
credential-free: their raw Traffic surface is unsuitable for private import.

1. Enter the path to a file you explicitly exported and selected, its documented
   format (`chrome` or `firefox`), an exact HTTPS origin and a 30–300 second lease.
   All terminal input is hidden; backspace edits it. Ctrl-C/Ctrl-D cancel. A
   file path is typed directly, without shell expansion, and never saved to
   history. Use a real absolute path rather than a symlink.
2. Review the exact origin, a **new off-record context** in a new private profile,
   lifetime, row count, and every row's domain scope, path, flags and expiration.
   Names, values, source filenames and source digests are absent from the review.
3. Type `IMPORT`. Any other answer cancels before browser launch. The importer
   creates the fresh context, denies downloads, applies once, and privately reads
   back the cookie jar to verify the supported semantics and values. It has not
   created a page, navigated, or issued a target request. If any field differs,
   it closes the context rather than reporting a successful partial import.
4. Read the separate browsing warning. Type `OPEN` only if you want the dedicated
   browser to navigate to the reviewed origin's `/`. Any other answer clears and
   closes it. After OPEN, the browser is handed to you for manual use. Press
   Enter in the terminal to clear and close early; the deadline closes it
   automatically. Keep the terminal alive while using the browser.

There is no source/value/origin argument, stdin import, `--yes`, HTTP endpoint,
or noninteractive CLI mode. TTY checks and typed confirmations are workflow
guards, **not authentication or proof of a human** against another local process.
An agent must hand the real workflow to the user; importing implementation
modules or fabricating a pseudo-terminal is not an authorized workaround.

## Supported source formats and refusals

The input is a UTF-8 JSON array matching the documented `cookies.getAll()` return
objects from [Chrome WebExtensions](https://developer.chrome.com/docs/extensions/reference/api/cookies)
or [Firefox WebExtensions](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/cookies/Cookie).
Chrome-compatible exports include Brave and Edge only when they retain this
same complete shape. This does not claim a universal browser export format or
compatibility with an arbitrary cookie-export extension's schema. No extension
is installed, invoked, or granted cookie permissions by this tool.

Required common fields: `domain`, `hostOnly`, `httpOnly`, `name`, `path`,
`sameSite`, `secure`, `session`, `storeId`, `value`. `expirationDate` is required
only for persistent cookies and forbidden for session cookies. `partitionKey`
may be absent or null; any actual partition key is refused. Firefox also
requires `firstPartyDomain`, exactly the empty string.

- At most 256 KiB and 64 cookies. Reject empty arrays, invalid UTF-8, duplicate
  JSON keys, excessive nesting, unknown fields and duplicate cookie identities.
- Chrome stores must be `0` or `1`; Firefox stores must be `firefox-default` or
  `firefox-private`. A file must use one store. Firefox containers and first-party
  isolation are refused; they must not be silently merged into another context.
- All domains, after removing the domain-cookie leading dot, must exactly equal
  the selected hostname. Parent-domain and unrelated cookies are refused.
  Host-only cookies must have no leading dot. Domain cookies preserve their
  subdomain scope, using a leading dot for CDP and verifying it on readback.
- The destination is a canonical HTTPS origin with an ASCII DNS hostname, no
  userinfo, path, query or fragment, and no trailing slash. IP literals,
  single-label hosts, trailing dots and browser-specific schemes are refused.
  An explicit HTTPS port is allowed. There is no HTTP downgrade.
- Cookie names use a bounded nonempty ASCII token subset. Values use the
  RFC cookie-octet subset, with combined name/value at most 4096 bytes. Non-ASCII,
  whitespace, quotes, comma, semicolon, backslash and control bytes are refused
  rather than encoded or repaired. Paths must begin with `/`, be printable ASCII
  at most 1024 bytes, and contain no semicolon or backslash.
- Preserve `Secure` and `HttpOnly` booleans and valid security prefixes.
  CDP receives `domain` without a leading dot for host-only cookies and with a
  leading dot for domain cookies. `url` is omitted: Chromium otherwise promotes
  `secure:false` to true for an HTTPS cookie URL. This is storage construction,
  not navigation; the separately reviewed destination remains HTTPS. Readback
  still requires the exact reviewed Secure flag, including false. See Chromium's
  [cookie parameter normalization](https://chromium.googlesource.com/chromium/src/+/ab1bea184dd1273785ed3510992f2a977e94c180/content/browser/devtools/protocol/network_handler.cc#402).
  Preserve `strict`, `lax`, `no_restriction` and `unspecified` SameSite separately;
  unspecified is omitted from CDP, not rewritten to explicit Lax.
  SameSite=None without Secure is refused.
- Expiration is finite epoch seconds, more than five seconds in the future and
  at most 400 days away. Recheck immediately before applying. Do not clamp a
  long-lived cookie to [Chromium's 400-day limit](https://developer.chrome.com/blog/cookie-max-age-expires).
  Readback must match within two microseconds, accounting for the browser's
  microsecond time representation. Session state must match exactly.
- Partitioned/CHIPS cookies, Firefox first-party/container semantics, Safari
  stores, browser databases, Netscape text jars, plain Cookie/Set-Cookie headers,
  CDP dumps and inferred/stripped fields are unsupported. Netscape format does
  not carry enough SameSite/partition information for a faithful adapter.

The source file is read only, bounded using an open file descriptor, checked for
changes during reading, and never copied or rewritten. Symlink leaves and
parents, directories, devices and pipes are refused. This assumes an ordinary
user-owned local filesystem; it is not a defense against a hostile same-user
process changing directory components during selection.

## Context, privacy and lifecycle contract

The browser is an owned process group with a fresh private temporary directory,
fresh profile, minimal inherited environment and no inherited `REB_*` capture
settings. `HOME`, config/cache locations and temporary-file location are scoped
to that directory. Password saving/autofill are disabled in that new profile.
Browser diagnostic output is discarded; crash reporting/background features
are disabled with supported launch flags. No debugging TCP port is opened.
The only control channel is an inherited, bounded CDP pipe.

The helper creates `Target.createBrowserContext` with `disposeOnDetach: true`.
Every `Storage.getCookies`, `Storage.setCookies` and `Storage.clearCookies` call
includes that exact nondefault context ID. It refuses a nonempty destination,
never reads the default store, and has no connection option for an existing
browser. The supported CDP commands and fields are documented in the
[primary protocol definitions](https://github.com/ChromeDevTools/devtools-protocol/blob/master/json/browser_protocol.json).

The actual browser store is off-record: cookies are not intentionally persisted
to a profile cookie database. The source export remains wherever the user saved
it. Staged data and private readback exist temporarily in process memory; byte
buffers are cleared where practical and references dropped. JavaScript and
browser strings, swap, OS crash dumps, filesystem recovery and hostile same-user
processes are outside a secure-erasure guarantee. A browser may write ordinary
temporary profile metadata, which is removed on verified process shutdown.

The lease begins when the private session starts, including verification and
time spent deciding whether to OPEN. Enforcement uses a monotonic clock; displayed
expiration is a separate wall-clock value. Clear, cancellation, ordinary signals,
errors and expiry retire the context. Best-effort clear/readback/dispose precedes
owned process-group termination and temporary-directory removal. A one-second
watchdog bounds normal cleanup; expiry requests process termination immediately.
An in-flight command is never retried. Closing or killing the controller also
closes its private pipe; the off-record context requests disposal on detach.
SIGKILL, machine failure and browser defects can prevent cleanup confirmation.
Timers and cleanup require the controller/process to be running: suspension,
machine sleep or OS scheduling can delay them. This is not a hard real-time
credential lifetime guarantee under those conditions.

Receipts contain only state/reason and booleans for cookie-clear verification,
context disposal, process stop and temporary-profile removal. A process can be
verified stopped after a failed CDP clear, so the receipt preserves both facts.
If process shutdown or profile removal cannot be confirmed, the result is
`cleanup-uncertain`, never a silent success. No receipt contains names, values,
source paths, hashes or browser diagnostics.

## Browsing is a separate informed handoff

Import verification is not proof that a website will accept a session. Cookies
may be expired server-side, device-bound, revoked, or governed by browser policy.
No authentication success is inferred from `Storage.setCookies`.

OPEN issues one initial navigation to the reviewed HTTPS origin's `/`.
There is **no browser-wide origin firewall**. Cookies are host/domain/path
scoped, not origin/port bound; domain cookies can reach subdomains. Redirects,
subresources, workers, WebSockets, WebRTC and page scripts can contact other
destinations during ordinary browser use. No CDP Fetch-only filter is presented
as a security boundary. The user must review the scope and keep subsequent
manual browsing within their authorization. The importer does not record page
content, headers, console output or network requests and does not export them.

## Validation

```sh
node tools/check-cookie-import.mjs
python3 tools/check-cookie-import-terminal.py
node tools/check-cookie-import.mjs --browser /absolute/path/to/chromium
```

The first command covers synthetic parsing, strict refusals, source-file safety,
single-use lifecycle, context ownership, verification failures, expiry/cancel,
secret-free errors, user confirmation and private pipe framing. It is included
in `make javascript-check`.

The Python check exercises the actual local terminal executable with synthetic
file selection, immediate keyboard input, hidden-echo review, cancellation,
Ctrl-C/Ctrl-D and unchanged source bytes. It never launches a browser and is
included in `make python-check`.

The third command adds the real product launcher in headless mode, using synthetic
`.test` cookies only. It applies and privately verifies host/domain scope,
SameSite/session/expiration/HttpOnly/Secure, clears, verifies the empty jar and
disposes without creating a page or contacting a target. It must run with the
browser sandbox intact. A launch failure is an unavailable acceptance result,
not a passing cookie test. Headful terminal/browser handoff and macOS behavior
require their own user-operated product acceptance; mock tests do not establish
them. Never substitute real exported authentication data for these fixtures.
