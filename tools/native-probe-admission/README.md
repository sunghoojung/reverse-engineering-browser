# Renderer admission component regression

Run `make native-probe-admission-check`. The test compiles the actual checked-in
renderer sink, renderer transport, and shared-memory queue. Minimal test-only
Chromium/Mojo boundaries provide deterministic time, borrowed mappings, a frame
lookup pause, and notification counters. No browser is launched. Production
sources are neither extracted nor rewritten by the harness.

Checks cover full-ring recovery and sequence/drop accounting, concurrent
same-site callers, saturation, disable and same-/different-session
reconfiguration with a producer paused after its claim, preservation of newer
accepted/failed claims, masked/malformed/expired events, expiry immediately before
transport admission, property/network callbacks, Canvas creator-event admission, notification
coalescing, the frame attribution a network request record shares with its
sibling collectors, and allocation-free disabled calls. Looping/waiting in the fixture controls deterministic races; production
probe calls make one claim CAS and one TryPush call. The existing queue is
lock-free, not wait-free; its internal contention retries are unchanged.

Script cookie cases (`script_cookie_tests.h`) drive the renderer cookie sink
with a fixture script frame in place of the V8 provider: metadata-only calls
are allocation-free and record nothing; writes carry name, value digest,
lengths, frame and position; reads aggregate at powers of two with the
configuration-end remainder; and a full table and the Network category stay
visible. A `document.cookie` read records one name record per cookie name it
returned, split as the page would, with a name held twice counted once, at
most 360 names, and every name past that bound or past a full table counted on
the read record; reads allocate nothing once a configuration has its table.

Native JavaScript dispatch cases check the byte-exact 128-byte payload and every
validation rule, the 44-byte site records, the inactive epoch, expiry and VM
category refusal, the 64-per-site and 256-per-configuration budgets with their
coalesced gaps, ring-full claim release, transport and input gaps,
compiled-before-arming gaps per slot, and the fixed site list. The V8-facing
calls are checked not to invoke the frame-id provider.

Native JavaScript invocation cases check the disabled, allocation-free path,
category and expiry refusal, an armed configuration with no call, the
64-per-site start budget with its coalesced gap, the exact site match, the
digest opt-in, inside, none, unknown and worker request reads with the
256-record request budget, after which a loader start reads neither the
invocation context nor the frame, status gaps per slot and the fixed site
list. The open-start cases check that a settle closes only its own admitted
start, including when the ring drops its record, its input is refused or its
document went away, and that the settle of a start the site budget refused is
not recorded and closes nothing. The budget-cap cases check that starts
refused as input, and Blink's refusals of starts from a detached document,
spend budget; that a spent site, configuration or request budget stops
admission while the ring is full; and that the held gap is written once,
before the next start or settle record or when the configuration ends.

Native guest cases also check that full document and activation tables are
reclaimed (least recently sampled document; activation that is not an ancestor
of the one being sampled) and refuse only a table of ancestors; that a capture
the transport refuses frees its sample index and fills each sequence slot it
took with a gap, as refused Wasm dispatch and call_indirect records do; and
that a module verdict overwritten in the 256-entry ring is detected and resent.

For ASan/UBSan, run:

```sh
REB_PROBE_TEST_SANITIZERS=address,undefined make native-probe-admission-check
```

This is component evidence only. It does not validate Chromium declarations,
real Mojo wakeups, OS shared-memory lifetime, native browser execution, or
end-to-end delivery. Renderer admission can still be followed by downstream
loss. Mapping reclamation and browser drain fairness are separate concerns.
