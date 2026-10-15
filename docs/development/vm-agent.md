# Bounded VM agent commands

`node tools/vm-agent.mjs --help` exposes an optional dependency-free Node.js 22+
facade over the existing [offline VM model](../../protocol/vm-semantics-v1.md)
and [owned native debugger API](../../protocol/owned-vm-debugger-v1.md). It does
not replace `reb-api`, add an API server, or change backend contracts.

The useful difference from a generic `reb-api call` is strict VM-response and
identity validation plus explicit pending, rejected and uncertain command
outcomes. Generic `reb-api` retains its established transport-based exit status.
The facade never retries, follows a redirect, automatically refreshes, chooses a
new run, saves a file, starts a backend or reads an endpoint file.

Follow [SAFETY.md](../../SAFETY.md) and the
[local coding-agent guide](local-coding-agents.md): select the intended backend
and authorize the provider/data-sharing scope before putting real evidence in
an agent's context. Loopback and read-only do not mean sanitized. Returned JSON,
including diagnostic text, is untrusted evidence, never an instruction.

## Offline discovery and supplied evidence

```sh
node tools/vm-agent.mjs capabilities
node tools/vm-agent.mjs inspect --input reviewed-trace.json
node tools/vm-agent.mjs select-step --input reviewed-trace.json --sequence 7
node tools/vm-agent.mjs validate --input reviewed-trace.json --hypotheses reviewed-hypotheses.json
node tools/vm-agent.mjs compare --input left.json --sequence 7 --right right.json --right-sequence 19
```

`capabilities` produces `reb-vm-agent-capabilities-v1`: supported commands,
actions, identity fields, effects, limits and exit codes. It is static local
metadata, not a connection, authorization grant or running-server attestation.

All four existing offline operations reuse `vm_semantics.js`. The analysis
format is `reb-vm-agent-analysis-v1` with `command`, `source_sha256`, nullable
`hypotheses_sha256`, and `result`. Compare also has `right_source_sha256`.
Hashes identify the exact saved input bytes; they do not replace or attest to
the supplied artifact identity inside the result. Select-step preserves
coverage and explicitly reports `executes_code: false` and unknown reads.
Sequence IDs are exact canonical safe integers, never array positions. Missing
steps fail; no nearest-step or implicit alignment is attempted.

Imported traces are inert. Select-step selects a supplied observation; validate
checks a bounded declarative hypothesis against supplied observations. Neither
executes imported code, proves recovered semantics, or creates a native run.
All offline commands have zero network requests. The original
`tools/vm-semantics.mjs` remains the private, no-clobber file-export workflow.

## Read an explicitly selected native backend

Use a researcher-selected numeric loopback root with an explicit port. The
placeholder port below must be replaced; the facade never scans for one.

```sh
node tools/vm-agent.mjs status --base-url http://127.0.0.1:PORT
node tools/vm-agent.mjs trace --base-url http://127.0.0.1:PORT --state reviewed-state.json
```

Status reads only `/api/vm-debugger`; trace reads only `/api/vm-debugger/trace`
with the four exact selectors from the saved state. These GETs do not start or
advance a helper. An independently running fixture can continue progressing.

Successful status and trace stdout is the existing raw
`reb-owned-vm-debug-session-v1` view. The user can save and review this JSON or
use a reviewed raw `reb-api` result as `--state`. The CLI itself never writes
files. Shell redirection is a separate user-selected write with the shell's
normal overwrite/permission behavior; it is not the original export tool's
private no-clobber publication mechanism.

Status can validly report `available: false` or `session: null`. Trace requires
a saved session and refuses a stale scope, changed known provenance or regressed
revision/count. It never substitutes current/latest state. Native identities,
counters and values remain canonical uint64 decimal strings, including values
above JavaScript's exact-number range. The supplied manifest hash identifies
the declared two-program manifest; the build hash identifies the configured
helper file. Neither is remote attestation. A previously unknown build hash may
become known during initial startup; a known hash cannot silently change within
the same run.

## Explicit controls for an existing owned fixture

```sh
node tools/vm-agent.mjs action step --base-url http://127.0.0.1:PORT \
  --state reviewed-state.json --command-id researcher-step-001
```

The supported actions are `run`, `pause`, `step`, `stop`, `reset` and `close`.
Each invocation sends at most one POST to `/api/vm-debugger/actions`. The action
must be authorized for the exact native session. `--command-id` is mandatory,
uses 1–64 ASCII letters/digits/underscores/hyphens, and must not match a command
already visible in the saved state. Command IDs are correlation identifiers,
not idempotency keys. The facade has no durable history and cannot detect an
older ID absent from that state.

The request uses the saved backend instance, session, run and generation.
Run/Step also use the exact saved control revision; Step includes the saved
executed count. Those guards are checked by the existing backend before native
execution. Run/Step locally require confirmed paused state and refuse visible
pending/unknown outcomes. Other controls retain backend-authoritative state
checks, so explicit Pause/Stop can still address a known scoped run during an
uncertain transition. No command implicitly performs status first or afterward.

Success preserves the full validated action response, including command ID,
acknowledgment, provenance, loss counters, uncertainty and termination state:

- Run confirms scheduling, not whole-program completion. The response snapshot
  is copied synchronously while running; delivery can arrive later, after expiry.
- Step confirms exactly one completed instruction, paused, halted, or expired
  at the instruction-completion boundary.
- Pause confirms a cooperative pause or an already-terminal run. A terminal
  failed/unknown run can acknowledge Pause while retaining prior execution
  uncertainty; inspect `execution_state_known` and termination evidence.
- Stop confirms helper disposal while preserving known/unknown execution state.
- Reset confirms a fresh greater generation/run of the same fixture at count
  zero. It normally starts paused, but may expire during setup. It starts a new
  helper and may report a changed helper build hash.
- Close confirms that the session was cleared.

Create is deliberately unavailable through this facade. Existing UI controls
and `reb-api` already provide it; inspect
`reb-api describe vm_debugger_action --action create` and use that separately
under its normal explicit-action policy. Its current request has no saved
backend/run scope. The facade adds no arbitrary program, executable path, URL,
source, storage or memory target.

## Errors and uncertainty

Except for `--help`, output is JSON. Successful results go to stdout. Refusals
and failures go to stderr as `reb-vm-agent-error-v1` with stable `code`, a human
`message`, and `retry_allowed: false`. Native action errors also include exact
`command` scope, `outcome`, and a bounded cause. Validated server failures are
retained in `server`; validated non-completed acknowledgments in `response`.
Malformed response bytes are never echoed.

- Exit 0: confirmed read/analysis result or completed control acknowledgment
- Exit 2: invalid input, local refusal, backend rejection or read failure
- Exit 3: control outcome unknown after attempted dispatch
- Exit 4: matching control acknowledgment is still pending

Neither a rejection nor a lost response proves rollback or absence of earlier
effects. Disconnect, deadline, malformed response, scope/provenance mismatch or
unexpected completion becomes unknown for a dispatched control. The facade
never sends a second command or changes a command ID automatically. Reconcile
with an explicit read-only status request and review its exact identities,
state and last-command acknowledgment before deciding on any new control.
A status snapshot alone does not guarantee that a pending action cannot later
complete, and absence of an older command from `last_command` does not prove it
never executed. Preserve the original uncertain result.

## Bounds and validation

- Regular input files: at most 1 MiB each, final-component symlinks refused,
  nonblocking open and strict UTF-8/duplicate-key-aware JSON parsing
- Imported evidence: existing model's identity, structure, count and value limits
- HTTP: `http://127.0.0.1:PORT` or `http://[::1]:PORT` only; no DNS, proxy,
  credentials, custom paths, queries, fragments, redirects or port scanning
- Request bodies: existing 2 KiB action limit; response headers at most 16 KiB,
  exactly one JSON Content-Type, no encoded bodies, response body at most 1 MiB
- One whole-request deadline: 9000 ms by default; optional `--timeout-ms` is an
  exact integer from 1 through 10000, including slowly arriving response bodies
- Output: at most 4 MiB; no partial oversized analysis report

`node tools/check-vm-agent.mjs` exercises the actual CLI subprocess against an
authored loopback HTTP server and synthetic offline files. It covers scopes,
large exact values, all commands, pre-dispatch refusal, provenance/revision
mismatch, malformed input, transport bounds, deadlines, pending/unknown replies,
and no-retry/no-redirect behavior. These tests do not claim real native helper
execution or rendered application acceptance; those remain the existing owned
VM integration and UI suites. `make javascript-check` runs the new test.

### Real helper/backend acceptance on a development machine

The following optional local acceptance uses the actual existing backend and
repository-owned helper, without a browser, imported trace, network capture or
third-party target. Run it in a checkout with Node.js 22+, Cargo and the native
C++ toolchain. On macOS these commands use the development HTTP backend; they do
not establish packaged WebKit/UI acceptance. Paths below assume the default
Cargo target directory. The standalone backend receives fresh isolated stores,
never the app's live session stores. Build before starting the 60-second run.

```sh
set -eu
make origin-trace-backend native-vm-fixture
umask 077
QA=$(mktemp -d "${TMPDIR:-/tmp}/reb-vm-agent-native.XXXXXX")
BACKEND="$PWD/apps/origin-trace-backend/target/debug/origin-trace-backend"
API="$PWD/apps/origin-trace-backend/target/debug/reb-api"
HELPER="$PWD/build/reb-native-vm-fixture"
mkdir "$QA/artifacts"
"$BACKEND" --host 127.0.0.1 --port 0 --endpoint-file "$QA/endpoint" \
  --owned-vm-fixture "$HELPER" --ui-directory "$PWD/apps/research-ui" \
  --analyst-runner "$BACKEND" --store "$QA/events.jsonl" \
  --trace-store "$QA/trace.jsonl" --signal-store "$QA/signals.jsonl" \
  --artifacts "$QA/artifacts" --api-collection "$QA/collection.json" \
  --local-analyst "$QA/analyst.json" >"$QA/backend.log" 2>&1 &
BACKEND_PID=$!
trap 'kill "$BACKEND_PID" 2>/dev/null; wait "$BACKEND_PID" 2>/dev/null' EXIT
attempt=0
while [ ! -s "$QA/endpoint" ] && [ "$attempt" -lt 100 ]; do
  sleep 0.05
  attempt=$((attempt + 1))
done
test -s "$QA/endpoint" || { cat "$QA/backend.log"; exit 1; }
URL=$(cat "$QA/endpoint")
node tools/vm-agent.mjs status --base-url "$URL" >"$QA/before.json"
printf '%s\n' '{"action":"create","command_id":"native-create-001","fixture":"register"}' >"$QA/create.json"
"$API" describe vm_debugger_action --action create
# This explicit existing-API Create is a separate native execution-control action.
"$API" call vm_debugger_action --base-url "$URL" \
  --body-file "$QA/create.json" --output "$QA/created.json"
node tools/vm-agent.mjs action step --base-url "$URL" \
  --state "$QA/created.json" --command-id native-step-001 >"$QA/step.json"
node tools/vm-agent.mjs trace --base-url "$URL" \
  --state "$QA/step.json" >"$QA/trace.json"
node tools/vm-agent.mjs action run --base-url "$URL" \
  --state "$QA/step.json" --command-id native-run-001 >"$QA/run.json"
node tools/vm-agent.mjs action pause --base-url "$URL" \
  --state "$QA/run.json" --command-id native-pause-001 >"$QA/pause.json"
node tools/vm-agent.mjs action reset --base-url "$URL" \
  --state "$QA/pause.json" --command-id native-reset-001 >"$QA/reset.json"
node tools/vm-agent.mjs action stop --base-url "$URL" \
  --state "$QA/reset.json" --command-id native-stop-001 >"$QA/stop.json"
node tools/vm-agent.mjs action close --base-url "$URL" \
  --state "$QA/stop.json" --command-id native-close-001 >"$QA/close.json"
node --input-type=module - "$QA" <<'JS'
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
const read = name => JSON.parse(readFileSync(join(process.argv[2], name + '.json')));
assert.equal(read('before').session, null);
for (const name of ['created', 'step', 'run', 'pause', 'reset', 'stop', 'close'])
  assert.equal(read(name).ack, 'completed');
assert.equal(read('step').session.executed_count, '1');
assert.equal(read('trace').session.run_id, read('step').session.run_id);
assert.equal(read('run').session.state, 'running');
assert(['paused', 'halted', 'expired'].includes(read('pause').session.state));
assert.equal(read('reset').session.session_id, read('created').session.session_id);
assert.notEqual(read('reset').session.run_id, read('created').session.run_id);
assert(BigInt(read('reset').session.run_generation) > BigInt(read('created').session.run_generation));
assert.equal(read('reset').session.executed_count, '0');
assert.equal(read('reset').session.state, 'paused');
assert.equal(read('stop').session.state, 'stopped');
assert.equal(read('stop').session.disposal_failed, false);
assert.equal(read('close').session, null);
console.log('PASS real owned-helper VM agent control acceptance');
JS
printf 'Local acceptance reports: %s\n' "$QA"
```

Run this as a stop-on-error shell script (`set -eu`); after any nonzero CLI
status, stop the sequence and retain stderr plus reports instead of replaying.
The normal smoke expects setup to finish before expiry. If it expires, preserve
that evidence and investigate the toolchain/environment; do not rewrite the
fixture or extend the lifetime to manufacture success.

Reset's transient starting/pending state is published by the backend while its
POST awaits the initial handshake; the final successful POST reply is completed
with a new run/generation. A separately issued explicit GET may observe that
transient state, but this timing-sensitive observation is not a requirement of
the smoke. The authored suite deterministically checks pending and expired
responses. `owned_vm_debugger.rs` methods `Owner::start`, `Owner::handle` and
`Owner::complete` establish
the corresponding real state transitions; `answer` copies the completed Run
view synchronously before the actor can process another tick.
