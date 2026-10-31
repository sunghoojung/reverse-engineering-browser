# Live-session startup acceptance

This macOS XCUITest target operates the packaged Origin Trace production app.
It uses neither smoke-mode arguments nor a production-only test hook. Run it
through the cloud-only driver from the repository root:

```sh
node tools/check-companion-warning.mjs
```

The target keeps its original companion-release name. It now proves that
Origin Trace starts a live session with whatever Brave Browser Development it
finds, without a browser pairing prompt, and that the startup failure, Retry,
Continue Offline and reopen paths behave.

The driver requires macOS and `CI=true`, builds no browser, and owns an inert,
unsigned `com.brave.Browser.development` application whose executable records
one line and exits. The paired release workflow supplies the built app. This
test proves the launch boundary and its decisions; it does **not** establish
native browser compatibility or capture completeness.

The driver passes these environment variables to the test runner through
Xcode's `TEST_RUNNER_` prefix:

- `REB_COMPANION_WARNING_APP`: absolute path to the packaged Origin Trace app
- `REB_COMPANION_WARNING_ROOT`: owned temporary fixture directory
- `REB_COMPANION_WARNING_BRAVE`: absolute path to the inert app executable

Each scenario has pre-created `stores`, `home`, and `stores/artifacts`
directories, with empty `events.jsonl`, `traces.jsonl`, and `signals.jsonl` under
`stores`. The runner does not create or inspect files in that tree. It passes
production store environment overrides to the app; command-line `--store`
arguments would disable the automatic live-session path. `HOME` and
`CFFIXED_USER_HOME` provide additional isolation, but are not a guarantee that
Foundation will redirect every Application Support path. The production live
coordinator currently replaces several live-session path overrides. Therefore
this suite is limited to disposable cloud CI with synthetic data.

The three serial scenarios verify:

- `automatic`: launch reaches the inert browser with no pairing prompt, its real
  startup failure offers Retry and Continue Offline, and Continue Offline stays
  offline
- `retry`: Return on the failure alert is Retry and relaunches, reported by a
  failure naming a new session log; after Continue Offline, **New Live Session…**
  shows its setup panel and Start Session launches again
- `modal-reopen`: Launch Services reopens the same app while the failure alert is
  modal without starting another session behind it; Return still reaches Retry,
  and after Continue Offline a later reopen stays offline

Every final Continue Offline observes a 65-second quiet window, exceeding the
coordinator's 60-second startup deadline. This avoids passing a receipt check
just because test termination canceled an unintended launch before its helpers
finished starting. Short dialog transitions use a two-second quiet window.

The runner emits named, retained XCTest screenshot attachments at each phase.
The outer driver exports them from the result bundle and checks receipts after
the sandboxed runner exits: `automatic`, `retry` and `modal-reopen` must record
exactly one, three and two launches. This catches a prompt that blocks startup,
and accidental starts on Continue Offline or modal reentry, without needing
filesystem writes or receipt access from inside the UI-test runner sandbox.
