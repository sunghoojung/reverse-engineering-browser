#!/usr/bin/env bash

set -euo pipefail

if (($# != 3)); then
  echo "Usage: $0 LIVE_SCRIPT EVENT_PRODUCER ARTIFACT_PRODUCER" >&2
  exit 2
fi

readonly live_script="$1"
readonly event_producer="$2"
readonly artifact_producer="$3"
test_root="$(mktemp -d)"
readonly test_root
test_succeeded=false

cleanup() {
  if [[ "${test_succeeded}" != true ]]; then
    echo "live_session_test failed" >&2
    find "${test_root}" -type f -maxdepth 4 -print -exec sed 's/^/  /' {} \; >&2 || true
  fi
  rm -rf "${test_root}"
}
trap cleanup EXIT

readonly fake_app="${test_root}/Origin Trace.app"
readonly fake_brave="${test_root}/fake-brave"
readonly fake_open="${test_root}/fake-open"
readonly open_arguments="${test_root}/open-arguments"
mkdir -p "${fake_app}"

# The single-quoted values are the literal source of the generated fixture.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'event_socket=""' \
  'artifact_socket=""' \
  'token_file=""' \
  'session_id=""' \
  'for argument in "$@"; do' \
  '  case "${argument}" in' \
  '    --reb-broker-socket=*) event_socket="${argument#*=}" ;;' \
  '    --reb-artifact-socket=*) artifact_socket="${argument#*=}" ;;' \
  '    --reb-broker-token-file=*) token_file="${argument#*=}" ;;' \
  '    --reb-session-id=*) session_id="${argument#*=}" ;;' \
  '  esac' \
  'done' \
  'test -n "${event_socket}"' \
  'test -n "${artifact_socket}"' \
  'test -n "${token_file}"' \
  'test -n "${session_id}"' \
  '"${REB_EVENT_PRODUCER}" --socket "${event_socket}" --token-file "${token_file}" --session-id "${session_id}"' \
  '"${REB_ARTIFACT_PRODUCER}" --socket "${artifact_socket}" --token-file "${token_file}" --session-id "${session_id}"' \
  >"${fake_brave}"

# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf "%s\n" "$@" >"${REB_OPEN_ARGUMENTS}"' \
  >"${fake_open}"
chmod +x "${fake_brave}" "${fake_open}"

REB_BRAVE_BINARY="${fake_brave}" \
REB_ORIGIN_TRACE_APP="${fake_app}" \
REB_LIVE_SESSION_ROOT="${test_root}/sessions" \
REB_OPEN_COMMAND="${fake_open}" \
REB_OPEN_ARGUMENTS="${open_arguments}" \
REB_EVENT_PRODUCER="${event_producer}" \
REB_ARTIFACT_PRODUCER="${artifact_producer}" \
REB_CAPTURE_DURATION_SECONDS=60 \
  "${live_script}" >"${test_root}/live.out" 2>"${test_root}/live.err"

session_directory="$(find "${test_root}/sessions" -mindepth 1 -maxdepth 1 -type d -print -quit)"
readonly session_directory
test -n "${session_directory}"
test "$(wc -l <"${session_directory}/events.jsonl" | tr -d ' ')" = 5
test "$(wc -l <"${session_directory}/artifacts/manifest.jsonl" | tr -d ' ')" = 3
grep -Fq '"category":"network"' "${session_directory}/events.jsonl"
grep -Fq '"kind":"wasm"' "${session_directory}/artifacts/manifest.jsonl"
grep -Fxq -- '--artifacts' "${open_arguments}"
grep -Fxq -- "${session_directory}/artifacts" "${open_arguments}"
grep -Fq 'accepted=3' "${session_directory}/artifact-receiver.log"
test ! -e "/tmp/origin-trace-${UID}-$(basename "${session_directory}").sock"
test ! -e "/tmp/origin-trace-${UID}-$(basename "${session_directory}")-artifacts.sock"

test_succeeded=true
echo "live_session_test passed"
