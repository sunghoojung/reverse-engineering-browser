# Companion warning acceptance

This macOS XCUITest target operates the packaged Origin Trace production app.
It uses neither smoke-mode arguments nor a production-only test hook. Run it
through the cloud-only driver from the repository root:

```sh
node tools/check-companion-warning.mjs
```

The driver requires macOS and `CI=true`, builds no browser, and owns an inert
`com.brave.Browser.development` application whose executable records one line
and exits. The release workflow supplies the built companion app. This test
proves the warning decisions and launch boundary; it does **not** establish
native browser compatibility or capture completeness.

The driver passes these environment variables to the test runner through
Xcode's `TEST_RUNNER_` prefix:

- `REB_COMPANION_WARNING_APP`: absolute path to the packaged companion app
- `REB_COMPANION_WARNING_ROOT`: owned temporary fixture directory
- `REB_COMPANION_WARNING_BRAVE`: absolute path to the inert app executable

Each scenario has pre-created `stores`, `home`, and `stores/artifacts`
directories, with empty `events.jsonl`, `traces.jsonl`, and `signals.jsonl` under
`stores`. The runner does not create or inspect files in that tree. It passes
production store environment overrides to the app; command-line `--store`
arguments would disable the automatic warning path. `HOME` and
`CFFIXED_USER_HOME` provide additional isolation, but are not a guarantee that
Foundation will redirect every Application Support path. The production live
coordinator currently replaces several live-session path overrides. Therefore
this suite is limited to disposable cloud CI with synthetic data.

The four serial scenarios verify:

- `keyboard-offline`: Return selects Continue Offline; a later session from
  the real application menu shows a fresh warning
- `button-offline`: explicitly clicking Continue Offline dismisses the warning
- `retry`: explicit Start Unverified Session reaches the inert executable,
  its real startup failure offers Retry, and Retry requires another decision
- `modal-reopen`: Launch Services reopens the same app while the warning is
  modal; one decision retains keyboard focus, Return dismisses it, and later
  reopen stays offline

Initial Return, explicit Continue Offline, and final reopen each observe a
65-second quiet window, exceeding the coordinator's 60-second startup deadline.
This avoids passing a zero-receipt check just because test termination canceled
an unintended launch before its helpers finished starting. Short dialog
transitions use a two-second quiet window.

The runner emits named, retained XCTest screenshot attachments at each phase.
The outer driver exports them from the result bundle and checks receipts after
the sandboxed runner exits: `retry/launches.txt` must contain exactly one launch;
all other scenarios must have none. This catches accidental starts on Return,
Continue Offline, later-session setup, Retry, or modal reentry without needing
filesystem writes or receipt access from inside the UI-test runner sandbox.
