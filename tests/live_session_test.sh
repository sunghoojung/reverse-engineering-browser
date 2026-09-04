#!/usr/bin/env bash

set -euo pipefail

if (($# != 3)); then
  echo "Usage: $0 LIVE_SCRIPT EVENT_PRODUCER ARTIFACT_PRODUCER" >&2
  exit 2
fi

readonly live_script="$1"
readonly event_producer="$2"
readonly artifact_producer="$3"
readonly web_audio_payload_hex="4f66666c696e65417564696f436f6e746578742e737461727452656e646572696e67"
test_root="$(mktemp -d)"
readonly test_root
test_succeeded=false
live_pid=""

cleanup() {
  if [[ "${test_succeeded}" != true ]]; then
    echo "live_session_test failed" >&2
    find "${test_root}" -type f -maxdepth 4 -print -exec sed 's/^/  /' {} \; >&2 || true
  fi
  if [[ -n "${live_pid}" ]] && kill -0 "${live_pid}" 2>/dev/null; then
    kill "${live_pid}" 2>/dev/null || true
    wait "${live_pid}" 2>/dev/null || true
  fi
  rm -rf "${test_root}"
}
trap cleanup EXIT

readonly fake_app="${test_root}/Origin Trace.app"
readonly fake_brave="${test_root}/fake-brave"
readonly fake_open="${test_root}/fake-open"
readonly fake_analyzer="${test_root}/fake-analyzer.py"
readonly analyzer_started="${test_root}/analyzer-started"
readonly analyzer_stopped="${test_root}/analyzer-stopped"
readonly open_arguments="${test_root}/open-arguments"
readonly brave_arguments="${test_root}/brave-arguments"
mkdir -p "${fake_app}"

# The single-quoted values are the literal source of the generated fixture.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf "%s\n" "$@" >"${REB_BRAVE_ARGUMENTS}"' \
  'event_socket=""' \
  'artifact_socket=""' \
  'token_file=""' \
  'session_id=""' \
  'category_mask=""' \
  'for argument in "$@"; do' \
  '  case "${argument}" in' \
  '    --reb-broker-socket=*) event_socket="${argument#*=}" ;;' \
  '    --reb-artifact-socket=*) artifact_socket="${argument#*=}" ;;' \
  '    --reb-broker-token-file=*) token_file="${argument#*=}" ;;' \
  '    --reb-session-id=*) session_id="${argument#*=}" ;;' \
  '    --reb-category-mask=*) category_mask="${argument#*=}" ;;' \
  '  esac' \
  'done' \
  'test -n "${event_socket}"' \
  'test -n "${artifact_socket}"' \
  'test -n "${token_file}"' \
  'test -n "${session_id}"' \
  'test -n "${category_mask}"' \
  'if [[ -n "${REB_ANALYZER_STARTED:-}" ]]; then' \
  '  for _ in {1..200}; do' \
  '    [[ -f "${REB_ANALYZER_STARTED}" ]] && break' \
  '    sleep 0.01' \
  '  done' \
  '  test -f "${REB_ANALYZER_STARTED}"' \
  'fi' \
  '"${REB_EVENT_PRODUCER}" --socket "${event_socket}" --token-file "${token_file}" --session-id "${session_id}"' \
  'if ((category_mask & 1024)); then' \
  '  "${REB_ARTIFACT_PRODUCER}" --socket "${artifact_socket}" --token-file "${token_file}" --session-id "${session_id}"' \
  'fi' \
  >"${fake_brave}"

# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf "%s\n" "$@" >"${REB_OPEN_ARGUMENTS}"' \
  >"${fake_open}"
chmod +x "${fake_brave}" "${fake_open}"

printf '%s\n' \
  'import os' \
  'import signal' \
  'import time' \
  'from pathlib import Path' \
  'started = Path(os.environ["REB_ANALYZER_STARTED"])' \
  'stopped = Path(os.environ["REB_ANALYZER_STOPPED"])' \
  'def stop(_signal, _frame):' \
  '    stopped.write_text("stopped\n", encoding="utf-8")' \
  '    raise SystemExit(0)' \
  'signal.signal(signal.SIGINT, stop)' \
  'signal.signal(signal.SIGTERM, stop)' \
  'started.write_text(str(os.getpid()) + "\n", encoding="utf-8")' \
  'while True:' \
  '    time.sleep(1)' \
  >"${fake_analyzer}"

REB_BRAVE_BINARY="${fake_brave}" \
REB_ORIGIN_TRACE_APP="${fake_app}" \
REB_VM_ANALYZER="${fake_analyzer}" \
REB_ANALYZER_STARTED="${analyzer_started}" \
REB_ANALYZER_STOPPED="${analyzer_stopped}" \
REB_LIVE_SESSION_ROOT="${test_root}/sessions" \
REB_OPEN_COMMAND="${fake_open}" \
REB_OPEN_ARGUMENTS="${open_arguments}" \
REB_BRAVE_ARGUMENTS="${brave_arguments}" \
REB_EVENT_PRODUCER="${event_producer}" \
REB_ARTIFACT_PRODUCER="${artifact_producer}" \
REB_CAPTURE_DURATION_SECONDS=60 \
  "${live_script}" >"${test_root}/live.out" 2>"${test_root}/live.err"

test -f "${analyzer_started}"
test -f "${analyzer_stopped}"
analyzer_process_id="$(cat "${analyzer_started}")"
readonly analyzer_process_id
if kill -0 "${analyzer_process_id}" 2>/dev/null; then
  echo "VM analyzer remained alive after the live session stopped" >&2
  exit 1
fi

session_directory="$(find "${test_root}/sessions" -mindepth 1 -maxdepth 1 -type d -print -quit)"
readonly session_directory
test -n "${session_directory}"
test "$(wc -l <"${session_directory}/events.jsonl" | tr -d ' ')" = 6
test -s "${session_directory}/origin-trace.jsonl"
test -s "${session_directory}/request-signals.jsonl"
test "$(wc -l <"${session_directory}/artifacts/manifest.jsonl" | tr -d ' ')" = 3
grep -Fq '"category":"network"' "${session_directory}/events.jsonl"
test "$(grep -c "\"category\":\"web_audio\",\"type\":\"api_call\".*\"payload\":\"${web_audio_payload_hex}\"" "${session_directory}/events.jsonl")" = 1
test "$(grep -c '\"category\":\"web_audio\",\"relation\":\"same_context\",\"confidence\":\"correlated\",\"event_count\":\"1\"' "${session_directory}/request-signals.jsonl")" = 2
grep -Fq '"kind":"wasm"' "${session_directory}/artifacts/manifest.jsonl"
grep -Fxq -- '--artifacts' "${open_arguments}"
grep -Fxq -- "${session_directory}/artifacts" "${open_arguments}"
grep -Fxq -- '--trace-store' "${open_arguments}"
grep -Fxq -- "${session_directory}/origin-trace.jsonl" "${open_arguments}"
grep -Fxq -- '--signal-store' "${open_arguments}"
grep -Fxq -- "${session_directory}/request-signals.jsonl" "${open_arguments}"
grep -Fxq -- '--ui-url' "${open_arguments}"
grep -Eq '^http://127\.0\.0\.1:[0-9]+/$' "${open_arguments}"
grep -Fxq -- '--remote-debugging-port=0' "${brave_arguments}"
grep -Fxq -- "--user-data-dir=${session_directory}/brave-profile" "${brave_arguments}"
grep -Fq 'accepted=3' "${session_directory}/artifact-receiver.log"
test ! -e "/tmp/origin-trace-${UID}-$(basename "${session_directory}").sock"
test ! -e "/tmp/origin-trace-${UID}-$(basename "${session_directory}")-artifacts.sock"

mode_of() {
  case "$(uname -s)" in
    Darwin) stat -f '%Lp' "$1" ;;
    Linux) stat -c '%a' "$1" ;;
    *) echo "Unsupported operating system: $(uname -s)" >&2; return 1 ;;
  esac
}

test "$(mode_of "${session_directory}")" = 700
test "$(mode_of "${session_directory}/artifacts")" = 700
test "$(mode_of "${session_directory}/events.jsonl")" = 600
test "$(mode_of "${session_directory}/origin-trace.jsonl")" = 600
test "$(mode_of "${session_directory}/request-signals.jsonl")" = 600
test "$(mode_of "${session_directory}/broker.log")" = 600
test "$(mode_of "${session_directory}/artifact-receiver.log")" = 600
test "$(mode_of "${session_directory}/research-ui.log")" = 600
test "$(mode_of "${session_directory}/broker.token")" = 600
test "$(mode_of "${session_directory}/artifacts/manifest.jsonl")" = 600
artifact_blob="$(find "${session_directory}/artifacts/blobs" -type f -name '*.bin' -print -quit)"
test -n "${artifact_blob}"
test "$(mode_of "${artifact_blob}")" = 600

readonly disabled_sessions="${test_root}/disabled-sessions"
REB_BRAVE_BINARY="${fake_brave}" \
REB_ORIGIN_TRACE_APP="${fake_app}" \
REB_LIVE_SESSION_ROOT="${disabled_sessions}" \
REB_OPEN_COMMAND="${fake_open}" \
REB_OPEN_ARGUMENTS="${open_arguments}" \
REB_BRAVE_ARGUMENTS="${brave_arguments}" \
REB_EVENT_PRODUCER="${event_producer}" \
REB_ARTIFACT_PRODUCER="${artifact_producer}" \
REB_CAPTURE_CATEGORY_MASK=257 \
REB_CAPTURE_DURATION_SECONDS=60 \
  "${live_script}" >"${test_root}/disabled-live.out" 2>"${test_root}/disabled-live.err" &
live_pid=$!
for _ in {1..200}; do
  if ! kill -0 "${live_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if kill -0 "${live_pid}" 2>/dev/null; then
  echo "Live session did not stop when artifact capture was disabled" >&2
  exit 1
fi
wait "${live_pid}"
live_pid=""
disabled_session_directory="$(find "${disabled_sessions}" -mindepth 1 -maxdepth 1 -type d -print -quit)"
test -n "${disabled_session_directory}"
test "$(wc -l <"${disabled_session_directory}/events.jsonl" | tr -d ' ')" = 5
if grep -Fq '"category":"web_audio"' "${disabled_session_directory}/events.jsonl" ||
  grep -Fq '"category":"web_audio"' "${disabled_session_directory}/request-signals.jsonl"; then
  echo "Live session retained Web Audio outside the authorized category mask" >&2
  exit 1
fi
test ! -e "${disabled_session_directory}/artifact-receiver.log"
test ! -e "${disabled_session_directory}/artifacts/manifest.jsonl"

readonly quiet_sessions="${test_root}/quiet-sessions"
REB_BRAVE_BINARY="${fake_brave}" \
REB_ORIGIN_TRACE_APP="${fake_app}" \
REB_VM_ANALYZER="${fake_analyzer}" \
REB_ANALYZER_STARTED="${analyzer_started}" \
REB_ANALYZER_STOPPED="${analyzer_stopped}" \
REB_LIVE_SESSION_ROOT="${quiet_sessions}" \
REB_OPEN_COMMAND="${fake_open}" \
REB_OPEN_ARGUMENTS="${open_arguments}" \
REB_BRAVE_ARGUMENTS="${brave_arguments}" \
REB_EVENT_PRODUCER="${event_producer}" \
REB_ARTIFACT_PRODUCER="${artifact_producer}" \
REB_CAPTURE_CATEGORY_MASK=257 \
REB_CAPTURE_DURATION_SECONDS=60 \
REB_NATIVE_QUIET_MODE=1 \
  "${live_script}" >"${test_root}/quiet-live.out" \
  2>"${test_root}/quiet-live.err"

grep -Fxq -- '--js-flags=--reb-ignore-debugger-statements' "${brave_arguments}"
if grep -Fxq -- '--remote-debugging-port=0' "${brave_arguments}"; then
  echo "Native quiet mode exposed a remote debugging endpoint" >&2
  exit 1
fi
grep -Fq 'Live debugger: disabled (native quiet mode)' \
  "${test_root}/quiet-live.out"

test_succeeded=true
echo "live_session_test passed"
