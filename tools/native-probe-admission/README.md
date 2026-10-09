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
coalescing, and allocation-free disabled calls. Looping/waiting in the fixture controls deterministic races; production
probe calls make one claim CAS and one TryPush call. The existing queue is
lock-free, not wait-free; its internal contention retries are unchanged.

For ASan/UBSan, run:

```sh
REB_PROBE_TEST_SANITIZERS=address,undefined make native-probe-admission-check
```

This is component evidence only. It does not validate Chromium declarations,
real Mojo wakeups, OS shared-memory lifetime, native browser execution, or
end-to-end delivery. Renderer admission can still be followed by downstream
loss. Mapping reclamation and browser drain fairness are separate concerns.
