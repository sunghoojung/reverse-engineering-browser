#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly broker_binary="${repository_root}/build/reb-event-broker"
readonly origin_trace_app="${repository_root}/build/Origin Trace.app"
readonly session_directory="${repository_root}/build/sessions/live"
readonly store_path="${session_directory}/events.jsonl"
readonly token_path="${session_directory}/broker.token"
readonly profile_path="${repository_root}/build/brave-profile"

mkdir -p "${session_directory}" "${profile_path}"

session_id="$(od -An -N8 -tu8 /dev/urandom | tr -d '[:space:]')"
if [[ -z "${session_id}" || "${session_id}" == 0 ]]; then
  session_id=1
fi
readonly session_id
readonly socket_path="/tmp/origin-trace-${UID}-${session_id}.sock"
readonly broker_log="${session_directory}/broker.log"

brave_binary="${REB_BRAVE_BINARY:-}"
if [[ -z "${brave_binary}" ]]; then
  readonly brave_output="${REB_BRAVE_OUTPUT_DIRECTORY:-${repository_root}/browser/worktree/src/out/Component_arm64}"
  readonly candidates=(
    "${brave_output}/Brave Browser.app/Contents/MacOS/Brave Browser"
    "${brave_output}/Brave Browser Dev.app/Contents/MacOS/Brave Browser Dev"
    "${brave_output}/Brave Browser Beta.app/Contents/MacOS/Brave Browser Beta"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "${candidate}" ]]; then
      brave_binary="${candidate}"
      break
    fi
  done
fi

if [[ ! -x "${broker_binary}" ]]; then
  echo "Event broker is missing. Run: make broker" >&2
  exit 1
fi
if [[ ! -d "${origin_trace_app}" ]]; then
  echo "Origin Trace is missing. Run: make app-build" >&2
  exit 1
fi
if [[ -z "${brave_binary}" || ! -x "${brave_binary}" ]]; then
  echo "A complete Brave app build is required." >&2
  echo "Build Brave, or set REB_BRAVE_BINARY to the custom Brave executable." >&2
  exit 1
fi

broker_pid=""
cleanup() {
  if [[ -n "${broker_pid}" ]] && kill -0 "${broker_pid}" 2>/dev/null; then
    kill "${broker_pid}" 2>/dev/null || true
    wait "${broker_pid}" 2>/dev/null || true
  fi
  if [[ -S "${socket_path}" ]]; then
    rm -f "${socket_path}"
  fi
}
trap cleanup EXIT INT TERM

"${broker_binary}" --store "${store_path}" --socket "${socket_path}" \
  --token-file "${token_path}" --session-id "${session_id}" \
  >"${broker_log}" 2>&1 &
broker_pid=$!

for _ in {1..100}; do
  if [[ -S "${socket_path}" && -f "${token_path}" ]]; then
    break
  fi
  if ! kill -0 "${broker_pid}" 2>/dev/null; then
    echo "Event broker stopped during startup. See: ${broker_log}" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -S "${socket_path}" ]]; then
  echo "Event broker socket did not become ready. See: ${broker_log}" >&2
  exit 1
fi

open -n "${origin_trace_app}" --args --store "${store_path}" \
  --broker-socket "${socket_path}"

echo "Origin Trace live session ${session_id}"
echo "Evidence store: ${store_path}"
echo "Close Brave to stop this capture session."

"${brave_binary}" \
  --user-data-dir="${profile_path}" \
  --reb-broker-socket="${socket_path}" \
  --reb-broker-token-file="${token_path}" \
  --reb-session-id="${session_id}"

wait "${broker_pid}"
broker_pid=""
