#!/usr/bin/env bash

set -euo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly broker_binary="${REB_BROKER_BINARY:-${repository_root}/build/reb-event-broker}"
readonly artifact_receiver_binary="${REB_ARTIFACT_RECEIVER_BINARY:-${repository_root}/build/reb-artifact-receiver}"
readonly debugger_transport_binary="${REB_DEBUGGER_TRANSPORT_BINARY:-${repository_root}/build/reb-debugger-transport}"
readonly heap_snapshot_binary="${REB_HEAP_SNAPSHOT_BINARY:-${repository_root}/build/reb-heap-snapshot}"
readonly decoder_binary="${REB_DECODER_BINARY:-${repository_root}/build/reb-decoder}"
readonly research_ui_server="${REB_RESEARCH_UI_SERVER:-${repository_root}/apps/research-ui/server.py}"
readonly vm_analyzer="${REB_VM_ANALYZER:-${repository_root}/apps/research-ui/vm_analyzer.py}"
readonly origin_trace_app="${REB_ORIGIN_TRACE_APP:-${repository_root}/build/Origin Trace.app}"
session_id="$(od -An -N8 -tu8 /dev/urandom | tr -d '[:space:]')"
if [[ -z "${session_id}" || "${session_id}" == 0 ]]; then
  session_id=1
fi
readonly session_id
readonly live_session_root="${REB_LIVE_SESSION_ROOT:-${repository_root}/build/sessions/live}"
readonly session_directory="${live_session_root}/${session_id}"
readonly store_path="${session_directory}/events.jsonl"
readonly trace_store_path="${session_directory}/origin-trace.jsonl"
readonly signal_store_path="${session_directory}/request-signals.jsonl"
readonly artifact_store_path="${session_directory}/artifacts"
readonly token_path="${session_directory}/broker.token"
readonly profile_path="${REB_BRAVE_PROFILE:-${session_directory}/brave-profile}"
readonly category_mask="${REB_CAPTURE_CATEGORY_MASK:-4095}"
readonly duration_seconds="${REB_CAPTURE_DURATION_SECONDS:-3600}"
readonly open_command="${REB_OPEN_COMMAND:-open}"
readonly native_quiet_mode="${REB_NATIVE_QUIET_MODE:-0}"
readonly cdp_network_capture="${REB_CDP_NETWORK_CAPTURE:-0}"
readonly capture_canvas_images="${REB_CAPTURE_CANVAS_IMAGES:-0}"
readonly embedded_session="${REB_EMBEDDED_SESSION:-0}"
readonly session_handshake="${REB_SESSION_HANDSHAKE:-}"
readonly session_owner_pid="${REB_SESSION_OWNER_PID:-}"
readonly python_binary="${REB_PYTHON_BINARY:-python3}"
readonly api_collection_store="${REB_API_COLLECTION_STORE:-${live_session_root}/../api-collection-v1.json}"
readonly local_analyst_store="${REB_LOCAL_ANALYST_STORE:-${live_session_root}/../local-analyst-workspace-v1.json}"

if [[ "${native_quiet_mode}" != 0 && "${native_quiet_mode}" != 1 ]]; then
  echo "REB_NATIVE_QUIET_MODE must be 0 or 1." >&2
  exit 2
fi
if [[ "${cdp_network_capture}" != 0 && "${cdp_network_capture}" != 1 ]]; then
  echo "REB_CDP_NETWORK_CAPTURE must be 0 or 1." >&2
  exit 2
fi
if [[ "${capture_canvas_images}" != 0 && "${capture_canvas_images}" != 1 ]]; then
  echo "REB_CAPTURE_CANVAS_IMAGES must be 0 or 1." >&2
  exit 2
fi
if [[ "${embedded_session}" != 0 && "${embedded_session}" != 1 ]]; then
  echo "REB_EMBEDDED_SESSION must be 0 or 1." >&2
  exit 2
fi
if [[ "${embedded_session}" == 1 ]]; then
  if [[ -z "${session_handshake}" || -z "${session_owner_pid}" ]] ||
     ! [[ "${session_owner_pid}" =~ ^[1-9][0-9]*$ ]]; then
    echo "Embedded sessions require REB_SESSION_HANDSHAKE and a valid REB_SESSION_OWNER_PID." >&2
    exit 2
  fi
fi
if [[ "${capture_canvas_images}" == 1 ]] &&
   (( (category_mask & 1) == 0 || (category_mask & 1024) == 0 )); then
  echo "REB_CAPTURE_CANVAS_IMAGES requires Canvas and Artifact category bits (mask 1025)." >&2
  exit 2
fi
if [[ "${native_quiet_mode}" == 1 && "${cdp_network_capture}" == 1 ]]; then
  echo "REB_CDP_NETWORK_CAPTURE requires the live debugger." >&2
  exit 2
fi

mkdir -p "${session_directory}" "${artifact_store_path}" "${profile_path}"
chmod 700 "${session_directory}" "${artifact_store_path}" "${profile_path}"

readonly socket_path="/tmp/origin-trace-${UID}-${session_id}.sock"
readonly artifact_socket_path="/tmp/origin-trace-${UID}-${session_id}-artifacts.sock"
readonly broker_log="${session_directory}/broker.log"
readonly artifact_receiver_log="${session_directory}/artifact-receiver.log"
readonly ui_log="${session_directory}/research-ui.log"
readonly ui_endpoint_path="${session_directory}/research-ui.endpoint"
readonly devtools_active_port="${profile_path}/DevToolsActivePort"

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
if [[ ! -x "${artifact_receiver_binary}" ]]; then
  echo "Artifact receiver is missing. Run: make artifact-receiver" >&2
  exit 1
fi
if [[ "${native_quiet_mode}" == 0 && ! -x "${debugger_transport_binary}" ]]; then
  echo "Debugger transport is missing. Run: make debugger-transport" >&2
  exit 1
fi
if [[ ! -x "${heap_snapshot_binary}" ]]; then
  echo "Heap snapshot helper is missing. Run: make heap-snapshot" >&2
  exit 1
fi
if [[ ! -x "${decoder_binary}" ]]; then
  echo "Decoder is missing. Run: make decoder" >&2
  exit 1
fi
if [[ ! -f "${research_ui_server}" ]]; then
  echo "Research UI server is missing: ${research_ui_server}" >&2
  exit 1
fi
if ! command -v "${python_binary}" >/dev/null 2>&1; then
  echo "Python 3 is required to run the live research UI." >&2
  exit 1
fi
if [[ "${embedded_session}" == 0 && ! -d "${origin_trace_app}" ]]; then
  echo "Origin Trace is missing. Run: make app-build" >&2
  exit 1
fi
if [[ -z "${brave_binary}" || ! -x "${brave_binary}" ]]; then
  echo "A complete Brave app build is required." >&2
  echo "Build Brave, or set REB_BRAVE_BINARY to the custom Brave executable." >&2
  exit 1
fi

broker_pid=""
artifact_receiver_pid=""
analyzer_pid=""
ui_pid=""
brave_pid=""
stop_artifact_receiver() {
  if [[ -z "${artifact_receiver_pid}" ]]; then
    return
  fi
  if kill -0 "${artifact_receiver_pid}" 2>/dev/null; then
    kill -TERM "${artifact_receiver_pid}" 2>/dev/null || true
  fi
  wait "${artifact_receiver_pid}" 2>/dev/null || true
  artifact_receiver_pid=""
}

cleanup() {
  if [[ -n "${brave_pid}" ]] && kill -0 "${brave_pid}" 2>/dev/null; then
    kill -TERM "${brave_pid}" 2>/dev/null || true
    wait "${brave_pid}" 2>/dev/null || true
  fi
  if [[ -n "${analyzer_pid}" ]] && kill -0 "${analyzer_pid}" 2>/dev/null; then
    kill "${analyzer_pid}" 2>/dev/null || true
    wait "${analyzer_pid}" 2>/dev/null || true
  fi
  if [[ -n "${broker_pid}" ]] && kill -0 "${broker_pid}" 2>/dev/null; then
    kill "${broker_pid}" 2>/dev/null || true
    wait "${broker_pid}" 2>/dev/null || true
  fi
  stop_artifact_receiver
  if [[ -n "${ui_pid}" ]] && kill -0 "${ui_pid}" 2>/dev/null; then
    kill "${ui_pid}" 2>/dev/null || true
    wait "${ui_pid}" 2>/dev/null || true
  fi
  if [[ -S "${socket_path}" ]]; then
    rm -f "${socket_path}"
  fi
  if [[ -S "${artifact_socket_path}" ]]; then
    rm -f "${artifact_socket_path}"
  fi
  if [[ "${embedded_session}" == 1 && -n "${session_handshake}" ]]; then
    rm -f "${session_handshake}"
  fi
}
trap cleanup EXIT INT TERM

"${broker_binary}" --store "${store_path}" --trace-store "${trace_store_path}" \
  --signal-store "${signal_store_path}" \
  --socket "${socket_path}" \
  --token-file "${token_path}" --session-id "${session_id}" \
  --category-mask "${category_mask}" --duration-seconds "${duration_seconds}" \
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

if ((category_mask & 1024)); then
  artifact_receiver_arguments=(
    --store "${artifact_store_path}"
    --socket "${artifact_socket_path}"
    --token-file "${token_path}"
    --session-id "${session_id}"
  )
  if [[ "${capture_canvas_images}" == 1 ]]; then
    artifact_receiver_arguments+=(--allow-sensitive)
  fi
  "${artifact_receiver_binary}" "${artifact_receiver_arguments[@]}" \
    >"${artifact_receiver_log}" 2>&1 &
  artifact_receiver_pid=$!
  for _ in {1..100}; do
    if [[ -S "${artifact_socket_path}" ]]; then
      break
    fi
    if ! kill -0 "${artifact_receiver_pid}" 2>/dev/null; then
      echo "Artifact receiver stopped during startup. See: ${artifact_receiver_log}" >&2
      exit 1
    fi
    sleep 0.05
  done
  if [[ ! -S "${artifact_socket_path}" ]]; then
    echo "Artifact receiver socket did not become ready. See: ${artifact_receiver_log}" >&2
    exit 1
  fi
fi

analyzer_log="${session_directory}/vm-analyzer.log"
analyze_captured_artifacts() {
  local previous_signature="initial"
  local current_signature=""
  local worker_pid=""
  # shellcheck disable=SC2317,SC2329  # Invoked by the signal trap below.
  stop_analyzer_worker() {
    trap - INT TERM
    if [[ -n "${worker_pid}" ]] && kill -0 "${worker_pid}" 2>/dev/null; then
      kill "${worker_pid}" 2>/dev/null || true
      wait "${worker_pid}" 2>/dev/null || true
    fi
    exit 0
  }
  trap stop_analyzer_worker INT TERM
  while true; do
    if [[ -f "${artifact_store_path}/manifest.jsonl" ]]; then
      current_signature="$(stat -f '%m:%z' "${artifact_store_path}/manifest.jsonl")"
    else
      current_signature="missing"
    fi
    if [[ "${current_signature}" != "${previous_signature}" ]]; then
      "${python_binary}" "${vm_analyzer}" --artifacts "${artifact_store_path}" --events "${store_path}" >>"${analyzer_log}" 2>&1 &
      worker_pid=$!
      if ! wait "${worker_pid}"; then
        echo "VM analysis failed for input state ${current_signature}" >>"${analyzer_log}"
      fi
      worker_pid=""
      previous_signature="${current_signature}"
    fi
    sleep 1 &
    worker_pid=$!
    wait "${worker_pid}"
    worker_pid=""
  done
}
analyze_captured_artifacts &
analyzer_pid=$!

ui_arguments=(
  --host 127.0.0.1 --port 0 --endpoint-file "${ui_endpoint_path}" \
  --store "${store_path}" --trace-store "${trace_store_path}" \
  --signal-store "${signal_store_path}" --artifacts "${artifact_store_path}" \
  --api-collection "${api_collection_store}" --local-analyst "${local_analyst_store}" \
  --decoder "${decoder_binary}" --heap-snapshot "${heap_snapshot_binary}" \
  --socket "${socket_path}" --artifact-socket "${artifact_socket_path}"
  --broker-pid "${broker_pid}"
)
if [[ "${native_quiet_mode}" == 0 ]]; then
  ui_arguments+=(
    --devtools-active-port "${devtools_active_port}"
    --debugger-transport "${debugger_transport_binary}"
  )
  if [[ "${cdp_network_capture}" == 1 ]]; then
    ui_arguments+=(--capture-network-content)
  fi
fi
"${python_binary}" -u "${research_ui_server}" \
  "${ui_arguments[@]}" \
  >"${ui_log}" 2>&1 &
ui_pid=$!
# App-build CI can be CPU constrained immediately after compilation. Give the
# UI the same bounded startup window as a normal application launch.
for _ in {1..300}; do
  if [[ -s "${ui_endpoint_path}" ]]; then
    break
  fi
  if ! kill -0 "${ui_pid}" 2>/dev/null; then
    echo "Research UI stopped during startup. See: ${ui_log}" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -s "${ui_endpoint_path}" ]]; then
  echo "Research UI endpoint did not become ready. See: ${ui_log}" >&2
  exit 1
fi
ui_endpoint="$(tr -d '\r\n' < "${ui_endpoint_path}")"
readonly ui_endpoint
readonly live_ui_url="${ui_endpoint}/?native=1&canvas_images=${capture_canvas_images}"

if [[ "${embedded_session}" == 1 ]]; then
  handshake_temporary="${session_handshake}.tmp.$$"
  printf '%s\n' "${live_ui_url}" >"${handshake_temporary}"
  chmod 600 "${handshake_temporary}"
  mv "${handshake_temporary}" "${session_handshake}"
else
  "${open_command}" -n "${origin_trace_app}" --args --store "${store_path}" \
    --trace-store "${trace_store_path}" --signal-store "${signal_store_path}" \
    --artifacts "${artifact_store_path}" \
    --broker-socket "${socket_path}" \
    --ui-url "${live_ui_url}"
fi

echo "Origin Trace live session ${session_id}"
echo "Evidence store: ${store_path}"
echo "Origin trace store: ${trace_store_path}"
echo "Request signal profile store: ${signal_store_path}"
echo "Artifact store: ${artifact_store_path}"
echo "Category mask: ${category_mask}; expires after ${duration_seconds} seconds"
if [[ "${capture_canvas_images}" == 1 ]]; then
  echo "Canvas image capture: enabled for this session; outputs may contain sensitive page content"
else
  echo "Canvas image capture: disabled; set REB_CAPTURE_CANVAS_IMAGES=1 to enable it for one session"
fi
if [[ "${native_quiet_mode}" == 1 ]]; then
  echo "Live debugger: disabled (native quiet mode)"
else
  echo "Live debugger: ${ui_endpoint}"
  if [[ "${cdp_network_capture}" == 1 ]]; then
    echo "CDP network content: enabled for this session; sensitive headers are redacted and bodies are limited to 128 KiB"
  else
    echo "CDP network content: disabled; set REB_CDP_NETWORK_CAPTURE=1 to enable it for one session"
  fi
fi
echo "Close Brave to stop this capture session."

brave_arguments=(
  --user-data-dir="${profile_path}" \
  --reb-broker-socket="${socket_path}" \
  --reb-artifact-socket="${artifact_socket_path}" \
  --reb-broker-token-file="${token_path}" \
  --reb-session-id="${session_id}" \
  --reb-category-mask="${category_mask}" \
  --reb-duration-seconds="${duration_seconds}"
)
if [[ "${native_quiet_mode}" == 1 ]]; then
  brave_arguments+=(--js-flags=--reb-ignore-debugger-statements)
else
  brave_arguments+=(--remote-debugging-port=0)
fi
if [[ "${capture_canvas_images}" == 1 ]]; then
  brave_arguments+=(--reb-capture-canvas-images)
fi
if [[ "${embedded_session}" == 1 ]]; then
  "${brave_binary}" "${brave_arguments[@]}" &
  brave_pid=$!
  while kill -0 "${session_owner_pid}" 2>/dev/null; do
    sleep 1
  done
else
  "${brave_binary}" "${brave_arguments[@]}"
  stop_artifact_receiver
  wait "${broker_pid}"
  broker_pid=""
fi
