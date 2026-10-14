# Offline Python client projects v1

This optional repository export reuses one reviewed saved exact-request input,
its immutable evidence and the existing configuration/response-check vocabulary.
It produces a Python-only project using Requests or HTTPX. The native
Go/JavaScript export and Save-panel archive are unchanged. This is one observed
operation, not endpoint discovery, schema inference or a complete SDK.

## Export and use

From the repository with Node.js 22+:

```sh
node tools/export-captured-client.mjs --input request.json --output python.zip --python-client requests
node tools/export-captured-client.mjs --input request.json --output httpx.zip --python-client httpx
```

Raw remains the default. `--mode redacted_copy` explicitly requests the existing
best-effort transformed copy. The saved five-field identity, debugger generation,
unknown window-drop/limit coverage and unsupported-input reasons remain intact.
See the [saved-response bridge](client-project-v1.md#offline-exact-response-export)
for privacy, authenticity, 1 MiB input limits and private no-overwrite publication.
The default command without `--python-client` still generates Go/JavaScript.

The Python ZIP contains `client.py`, `requirements.txt`, `README.md`, shared
`requests/request-001.json`, `config.example.json`, `provenance.json`, `.gitignore`
and retained evidence. Fixed names never interpolate captured strings into
executable source or filenames. The archive stays within the existing 16-file,
1 MiB/file and 2 MiB total bounds. Python virtual environments and bytecode,
local configuration and raw evidence are excluded by the generated `.gitignore`;
this does not make the archive safe to share.

Use Python 3.11+. `python client.py` is a standard-library-only dry run. Review
`requirements.txt` and explicitly install it in your chosen virtual environment
before sending. Direct dependencies are pinned to Requests 2.34.2 or HTTPX 0.28.1;
the client refuses other provider versions before sending. Transitive dependency
resolution is not a full lockfile. Export never installs
packages or connects to a target. Copy the example configuration to `config.json`,
review its contents and set `allowedOrigin`; only `python client.py --send`
performs a request. The module also exposes `send_request` and typed `ClientError`
with a code and optional bounded result; only literal `send=True` opts into a
library send.

## Explicit timeout difference

`configVersion: "reb-python-client-config-v1"` is required for a send. Request,
origin, standard transport, redirect/cookie and response-check fields retain
existing meanings, but `timeoutMs` is deliberately a different capability:

- Requests: connect and read-operation timeout
- HTTPX: connect, read, write and pool-operation timeout
- Both: 100–30000 ms; null inherits the request's `timeout_ms`

Neither provider promises a whole-request deadline. DNS resolution, multiple
address attempts and a slowly progressing response can take longer. This is
stated in generated documentation and `provenance.client_capabilities`; it is
also exercised by a trickling-response fixture. Go/JavaScript
`reb-client-config-v1` files are rejected rather than silently weakening their
whole-request deadline. No new helper process or custom HTTP transport is added.
See [Requests timeouts](https://requests.readthedocs.io/en/latest/user/advanced/#timeouts)
and [HTTPX timeouts](https://www.python-httpx.org/advanced/timeouts/).

## Transport and fidelity

Each deliberate call owns a fresh provider client, with TLS verification on,
ambient environment/netrc/proxy configuration disabled, redirects disabled and
transport retries set to zero. Original browser cookies/authentication are never
loaded. A configured `SSLKEYLOGFILE` is rejected before importing the provider;
this client will not silently write TLS secrets. Neither provider supports the
optional Go browser-profile adapter or claims browser fingerprint parity.

Requests prepares a request with its normal API, then uses its public adapter
send path so `Session.send` cannot silently drain a redirect body while preparing
a next request. Responses remain streamed and bounded even for large 3xx bodies.
HTTPX uses its explicit streaming send path. Neither automatically decompresses
response bytes. Default transport headers can still differ from a browser.

The existing supported request limits remain: complete UTF-8 text up to 64 KiB,
at most 64 header pairs/16 KiB aggregate, and no credential/transport-controlled
headers. Python additionally requires ASCII URLs/header values and well-formed media-type
parameters. Duplicate, malformed, extended or non-UTF-8 charset declarations
are refused before send. Provider
preparation that changes the exact path/query is refused before send; especially
with Requests, percent-encoded unreserved query/path characters may require a
deliberately reviewed reconstruction. Original evidence is never rewritten.
Binary, multipart, missing, truncated and other unsupported inputs remain useful
evidence and require a complete reviewed `config.request` before any send.

Responses retain at most 64 KiB body and 128 headers/64 KiB aggregate header text.
Header overflow fails with an explicit partial result. Transport errors after
attempting a send report unknown server outcome, not a guaranteed zero requests.
Partial response failures preserve observed status, headers and retained body.
The CLI does not print response bodies on errors; library results remain local
caller-owned data. There is no automatic persistence or streaming service client.

Response checks preserve distinct missing/null/type/value failures, exact
integer-token equality, JSON pointers, duplicate-key/Unicode rejection and
truncation refusal. An unconfigured 200 response never reports validated success.
The JSON parser caps files at 1 MiB and depth 64. The original request/config
numeric-token restrictions apply. No captured string is evaluated as Python.

## Validation

- `node tools/check-python-client-project.mjs`: both offline export choices,
  deterministic ZIPs, retained raw/redacted evidence, inert generated source,
  Python compilation, dependency-free dry runs, invalid config/request matrices,
  no implicit requests and rejection of the old timeout contract.
- With the exact provider dependencies already installed, set `REB_PYTHON` to
  that interpreter and add `--providers`. Authored loopback HTTP/TLS fixtures
  exercise both libraries, one deliberate send, exact supported values, refusal
  of target normalization, no ambient credentials/proxy/cookie carryover,
  bounded redirects and raw bodies, unknown/partial outcomes, per-operation
  timeouts, certificate rejection and response-check conformance. No external
  target or real credential is used. Ubuntu CI runs this lane explicitly.
- Run the existing offline/exporter/controller and repository handoff gates.
  Python-only export does not establish new native macOS or browser-profile
  acceptance; those existing validation gaps remain separate.
