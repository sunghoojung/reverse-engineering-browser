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
256-record request budget, status gaps per slot and the fixed site list. The
open-start cases check that a settle closes only its own admitted start,
including when the ring drops its record, its input is refused or its document
went away, and that the settle of a start the site budget refused is not
recorded and closes nothing. The budget-cap cases check that starts refused
as input, and Blink's refusals of starts from a detached document, spend
budget; that a spent site, configuration or request budget stops admission
while the ring is full; and that the held gap is written once, before the next
start or settle record or when the configuration ends.

For ASan/UBSan, run:

```sh
REB_PROBE_TEST_SANITIZERS=address,undefined make native-probe-admission-check
```

This is component evidence only. It does not validate Chromium declarations,
real Mojo wakeups, OS shared-memory lifetime, native browser execution, or
end-to-end delivery. Renderer admission can still be followed by downstream
loss. Mapping reclamation and browser drain fairness are separate concerns.
