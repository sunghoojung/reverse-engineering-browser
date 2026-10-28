# Scoped local overrides v1 (historical)

Live response overrides, interception, and the browser-selected snapshot manager
were removed with CDP. There is no native override replacement. The former
`manage-local-override.mjs` entry point now fails with status 2 before reading an
action file, stdin, or contacting a backend; `--help` explains the removal.
Historical files remain readable, but preparing one does not make it executable.

## Offline preview and preparation

Use Node.js 22+. The retained tools validate an explicitly selected local UTF-8
file and optionally save the historical action format for offline analysis:

```sh
node tools/prepare-local-override.mjs --file ./reviewed.js
node tools/prepare-local-override.mjs --file ./reviewed.js \
  --url 'http://127.0.0.1:17777/fixture.js' \
  --target-id HISTORICAL_TARGET --experiment-id 7 \
  --sha256 REVIEWED_SHA256 --content-type 'text/javascript; charset=utf-8' \
  --ttl-ms 60000 --output ./override-action.json
```

Preview reports byte count and SHA-256 without file contents. Preparation
requires the reviewed digest and rejects changed bytes. The private output
contains response bytes and the exact URL; keep it local and out of source
control. Existing files are never replaced. Neither command sends network
requests, executes JavaScript, arms a rule, watches files, or uploads content.

## Historical format and retained validation

The inert `configure_request_interception` action stores version-1
`local_override` metadata: canonical credential-free HTTP(S) URL, target ID,
experiment ID, absolute expiry, and SHA-256 of the response bytes. These names
are retained only for historical file compatibility, not a supported command.
Preparation validates GET/HEAD, status 200, one supported UTF-8 content type,
and a lifetime of 1–300 seconds. It does not verify a live target or enforce
runtime expiry; no runtime consumer exists.

Input is at most 64 KiB, regular, exact UTF-8. Symlink files and parent
directories, devices, and pipes are refused. The loader checks metadata before
and after its bounded read. Empty files are valid; binary and compressed bodies
are not supported. Outputs use the existing private no-overwrite writer.

## Validation

`node tools/check-local-overrides.mjs` covers offline files, digests, exact
preparation, expiry bounds, private publication, and invalid input. It also runs
the retired manager with stdin left open and checks immediate refusal, and
executes its import-free entry point with a poisoned stdin accessor. No browser
or live fulfillment acceptance is claimed.
