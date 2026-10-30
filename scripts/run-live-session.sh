#!/usr/bin/env bash

set -euo pipefail
umask 077

# The native coordinator selects this explicit cause even when Bash or cleanup
# writes later diagnostics. Helpers keep their detailed output in separate logs.
fail_live_session() {
  local status="$1"
  shift
  printf 'REB_LIVE_SESSION_FAILURE: %s\n' "$*" >&2
  exit "${status}"
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly broker_binary="${REB_BROKER_BINARY:-${repository_root}/build/reb-event-broker}"
readonly artifact_receiver_binary="${REB_ARTIFACT_RECEIVER_BINARY:-${repository_root}/build/reb-artifact-receiver}"
readonly heap_snapshot_binary="${REB_HEAP_SNAPSHOT_BINARY:-${repository_root}/build/reb-heap-snapshot}"
readonly decoder_binary="${REB_DECODER_BINARY:-${repository_root}/build/reb-decoder}"
readonly research_ui_server="${REB_ORIGIN_TRACE_BACKEND:-${repository_root}/apps/origin-trace-backend/target/debug/origin-trace-backend}"
readonly vm_analyzer="${REB_VM_ANALYZER:-${repository_root}/apps/origin-trace-backend/target/debug/origin-trace-vm}"
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
readonly native_console_directory="${session_directory}/native-console"
readonly brave_cache_root="${REB_BRAVE_CACHE_ROOT:-}"
readonly category_mask="${REB_CAPTURE_CATEGORY_MASK:-4095}"
readonly duration_seconds="${REB_CAPTURE_DURATION_SECONDS:-3600}"
readonly open_command="${REB_OPEN_COMMAND:-open}"
readonly native_quiet_mode="${REB_NATIVE_QUIET_MODE:-0}"
readonly native_wasm_dispatch="${REB_NATIVE_WASM_DISPATCH:-0}"
readonly native_wasm_call_indirect="${REB_NATIVE_WASM_CALL_INDIRECT:-0}"
readonly native_guest_adapter="${REB_NATIVE_WASM_GUEST_ADAPTER:-}"
readonly native_js_dispatch_sites="${REB_NATIVE_JS_DISPATCH_SITES:-}"
readonly capture_canvas_images="${REB_CAPTURE_CANVAS_IMAGES:-0}"
readonly use_system_keychain="${REB_USE_SYSTEM_KEYCHAIN:-1}"
readonly localhost_only="${REB_LOCALHOST_ONLY:-0}"
readonly embedded_session="${REB_EMBEDDED_SESSION:-0}"
readonly session_handshake="${REB_SESSION_HANDSHAKE:-}"
readonly session_owner_pid="${REB_SESSION_OWNER_PID:-}"
readonly api_collection_store="${REB_API_COLLECTION_STORE:-${live_session_root}/../api-collection-v1.json}"
readonly local_analyst_store="${REB_LOCAL_ANALYST_STORE:-${live_session_root}/../local-analyst-workspace-v1.json}"
readonly active_endpoint_file="${REB_ACTIVE_ENDPOINT_FILE:-${HOME:?HOME is required}/.config/origin-trace/reb-api.endpoint}"

if [[ "${native_quiet_mode}" != 0 && "${native_quiet_mode}" != 1 ]]; then
  fail_live_session 2 "REB_NATIVE_QUIET_MODE must be 0 or 1."
fi
if [[ "${native_wasm_dispatch}" != 0 && "${native_wasm_dispatch}" != 1 ]]; then
  fail_live_session 2 "REB_NATIVE_WASM_DISPATCH must be 0 or 1."
fi
if [[ "${native_wasm_dispatch}" == 1 ]] &&
   (( (category_mask & 512) == 0 || (category_mask & 1024) == 0 )); then
  fail_live_session 2 "REB_NATIVE_WASM_DISPATCH requires VM and Artifact capture categories."
fi
if [[ "${native_wasm_call_indirect}" != 0 && "${native_wasm_call_indirect}" != 1 ]]; then
  fail_live_session 2 "REB_NATIVE_WASM_CALL_INDIRECT must be 0 or 1."
fi
if [[ "${native_wasm_call_indirect}" == 1 ]] &&
   (( (category_mask & 512) == 0 || (category_mask & 1024) == 0 )); then
  fail_live_session 2 "REB_NATIVE_WASM_CALL_INDIRECT requires VM and Artifact capture categories."
fi
if [[ -n "${native_guest_adapter}" ]]; then
  if [[ "${native_wasm_dispatch}" != 1 ]]; then
    fail_live_session 2 "REB_NATIVE_WASM_GUEST_ADAPTER requires REB_NATIVE_WASM_DISPATCH=1."
  fi
  if [[ "${native_guest_adapter}" != /* || ! -f "${native_guest_adapter}" || ! -r "${native_guest_adapter}" ]]; then
    fail_live_session 2 "REB_NATIVE_WASM_GUEST_ADAPTER must name a readable absolute regular file."
  fi
  adapter_bytes="$(wc -c < "${native_guest_adapter}")"
  if (( adapter_bytes == 0 || adapter_bytes > 8192 )); then
    fail_live_session 2 "REB_NATIVE_WASM_GUEST_ADAPTER must contain between 1 and 8192 bytes."
  fi
fi
if [[ -n "${native_js_dispatch_sites}" ]]; then
  if (( (category_mask & 512) == 0 )); then
    fail_live_session 2 "REB_NATIVE_JS_DISPATCH_SITES requires the VM capture category."
  fi
  if [[ "${native_js_dispatch_sites}" != /* || ! -f "${native_js_dispatch_sites}" ||
        ! -r "${native_js_dispatch_sites}" ]]; then
    fail_live_session 2 "REB_NATIVE_JS_DISPATCH_SITES must name a readable absolute regular file."
  fi
  js_sites_bytes="$(wc -c < "${native_js_dispatch_sites}")"
  if (( js_sites_bytes == 0 || js_sites_bytes > 4096 )); then
    fail_live_session 2 "REB_NATIVE_JS_DISPATCH_SITES must contain between 1 and 4096 bytes."
  fi
fi
if [[ "${REB_CDP_NETWORK_CAPTURE:-0}" != 0 || -n "${REB_DEBUGGER_TRANSPORT_BINARY:-}" ]]; then
  fail_live_session 2 "CDP capture and debugger transport were removed; use native Brave capture."
fi
if [[ "${capture_canvas_images}" != 0 && "${capture_canvas_images}" != 1 ]]; then
  fail_live_session 2 "REB_CAPTURE_CANVAS_IMAGES must be 0 or 1."
fi
if [[ "${use_system_keychain}" != 0 && "${use_system_keychain}" != 1 ]]; then
  fail_live_session 2 "REB_USE_SYSTEM_KEYCHAIN must be 0 or 1."
fi
if [[ "${localhost_only}" != 0 && "${localhost_only}" != 1 ]]; then
  fail_live_session 2 "REB_LOCALHOST_ONLY must be 0 or 1."
fi
if [[ "${embedded_session}" != 0 && "${embedded_session}" != 1 ]]; then
  fail_live_session 2 "REB_EMBEDDED_SESSION must be 0 or 1."
fi
if [[ "${embedded_session}" == 1 ]]; then
  if [[ -z "${session_handshake}" || -z "${session_owner_pid}" ]] ||
     ! [[ "${session_owner_pid}" =~ ^[1-9][0-9]*$ ]]; then
    fail_live_session 2 "Embedded sessions require REB_SESSION_HANDSHAKE and a valid REB_SESSION_OWNER_PID."
  fi
fi
if [[ "${capture_canvas_images}" == 1 ]] &&
   (( (category_mask & 1) == 0 || (category_mask & 1024) == 0 )); then
  fail_live_session 2 "REB_CAPTURE_CANVAS_IMAGES requires Canvas and Artifact category bits (mask 1025)."
fi

mkdir -p "${session_directory}" "${artifact_store_path}" "${profile_path}" "${native_console_directory}"
chmod 700 "${session_directory}" "${artifact_store_path}" "${profile_path}" "${native_console_directory}"
if [[ -n "${brave_cache_root}" ]]; then
  readonly brave_cache_profile="${brave_cache_root}/${session_id}/brave-profile"
  mkdir -p "${brave_cache_profile}"
  chmod 700 "${brave_cache_root}" "${brave_cache_root}/${session_id}" "${brave_cache_profile}"
fi

readonly socket_path="/tmp/origin-trace-${UID}-${session_id}.sock"
readonly artifact_socket_path="/tmp/origin-trace-${UID}-${session_id}-artifacts.sock"
readonly broker_log="${session_directory}/broker.log"
readonly artifact_receiver_log="${session_directory}/artifact-receiver.log"
readonly ui_log="${session_directory}/research-ui.log"
readonly brave_log="${session_directory}/brave.log"
readonly ui_endpoint_path="${session_directory}/research-ui.endpoint"
touch "${brave_log}"
chmod 600 "${brave_log}"

brave_binary="${REB_BRAVE_BINARY:-}"
if [[ -z "${brave_binary}" ]]; then
  readonly brave_output="${REB_BRAVE_OUTPUT_DIRECTORY:-${repository_root}/browser/worktree/src/out/Component_arm64}"
  readonly candidates=(
    "${brave_output}/Brave Browser Development.app/Contents/MacOS/Brave Browser Development"
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
  fail_live_session 1 "Event broker is missing. Run: make broker"
fi
if [[ ! -x "${artifact_receiver_binary}" ]]; then
  fail_live_session 1 "Artifact receiver is missing. Run: make artifact-receiver"
fi
if [[ ! -x "${heap_snapshot_binary}" ]]; then
  fail_live_session 1 "Heap snapshot helper is missing. Run: make heap-snapshot"
fi
if [[ ! -x "${decoder_binary}" ]]; then
  fail_live_session 1 "Decoder is missing. Run: make decoder"
fi
if [[ ! -x "${research_ui_server}" || ! -x "${vm_analyzer}" ]]; then
  fail_live_session 1 "Research UI server is missing: ${research_ui_server}"
fi
if [[ "${embedded_session}" == 0 && ! -d "${origin_trace_app}" ]]; then
  fail_live_session 1 "Origin Trace is missing. Run: make app-build"
fi
if [[ -z "${brave_binary}" || ! -x "${brave_binary}" ]]; then
  fail_live_session 1 "A complete Brave app build is required. Build Brave, or set REB_BRAVE_BINARY to the custom Brave executable."
fi

broker_pid=""
artifact_receiver_pid=""
analyzer_pid=""
ui_pid=""
brave_pid=""
# An open native UI can keep HTTP event streams alive during graceful shutdown.
# Signal every owned child before waiting so one blocked helper cannot postpone
# shutdown of the others. All children share one bounded grace period.
stop_processes() {
  local attempts="$1"
  shift
  local child_pid
  local attempt
  local pending
  for child_pid in "$@"; do
    if [[ -n "${child_pid}" ]] && kill -0 "${child_pid}" 2>/dev/null; then
      kill -TERM "${child_pid}" 2>/dev/null || true
    fi
  done
  for ((attempt = 0; attempt < attempts; attempt++)); do
    pending=0
    for child_pid in "$@"; do
      if [[ -n "${child_pid}" ]] && kill -0 "${child_pid}" 2>/dev/null; then
        pending=1
      fi
    done
    if [[ "${pending}" == 0 ]]; then
      break
    fi
    sleep 0.05
  done
  for child_pid in "$@"; do
    if [[ -n "${child_pid}" ]] && kill -0 "${child_pid}" 2>/dev/null; then
      echo "Live session cleanup: forcing owned child ${child_pid} to stop." >&2
      kill -KILL "${child_pid}" 2>/dev/null || true
    fi
  done
  for child_pid in "$@"; do
    if [[ -n "${child_pid}" ]]; then
      wait "${child_pid}" 2>/dev/null || true
    fi
  done
}

stop_artifact_receiver() {
  if [[ -z "${artifact_receiver_pid}" ]]; then
    return
  fi
  stop_processes 100 "${artifact_receiver_pid}"
  artifact_receiver_pid=""
}

cleanup() {
  echo "Live session cleanup started: browser=${brave_pid:-none} analyzer=${analyzer_pid:-none} broker=${broker_pid:-none} artifacts=${artifact_receiver_pid:-none} backend=${ui_pid:-none}" >&2
  stop_processes 100 "${brave_pid}" "${analyzer_pid}" "${broker_pid}" \
    "${artifact_receiver_pid}" "${ui_pid}"
  artifact_receiver_pid=""
  if [[ -S "${socket_path}" ]]; then
    rm -f "${socket_path}"
  fi
  if [[ -S "${artifact_socket_path}" ]]; then
    rm -f "${artifact_socket_path}"
  fi
  if [[ "${embedded_session}" == 1 && -n "${session_handshake}" ]]; then
    rm -f "${session_handshake}"
  fi
  echo "Live session cleanup complete." >&2
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
    fail_live_session 1 "Event broker stopped during startup. See: ${broker_log}"
  fi
  sleep 0.05
done
if [[ ! -S "${socket_path}" ]]; then
  fail_live_session 1 "Event broker socket did not become ready. See: ${broker_log}"
fi

if ((category_mask & (512 | 1024))); then
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
      fail_live_session 1 "Artifact receiver stopped during startup. See: ${artifact_receiver_log}"
    fi
    sleep 0.05
  done
  if [[ ! -S "${artifact_socket_path}" ]]; then
    fail_live_session 1 "Artifact receiver socket did not become ready. See: ${artifact_receiver_log}"
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
    # Finish the worker's two-second grace before the coordinator's shared
    # five-second deadline can kill this shell and orphan its active worker.
    stop_processes 40 "${worker_pid}"
    exit 0
  }
  trap stop_analyzer_worker INT TERM
  while true; do
    if [[ -f "${artifact_store_path}/manifest.jsonl" ]]; then
      current_signature="$(stat -f '%m:%z' "${artifact_store_path}/manifest.jsonl")"
    else
      current_signature="missing"
    fi
    if [[ -f "${artifact_store_path}/capture-provenance-v1.json" ]]; then
      current_signature+=":$(stat -f '%m:%z' "${artifact_store_path}/capture-provenance-v1.json")"
    else
      current_signature+=":provenance-missing"
    fi
    if [[ "${current_signature}" != "${previous_signature}" ]]; then
      "${vm_analyzer}" --artifacts "${artifact_store_path}" --events "${store_path}" >>"${analyzer_log}" 2>&1 &
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
  --active-endpoint-file "${active_endpoint_file}" \
  --store "${store_path}" --trace-store "${trace_store_path}" \
  --signal-store "${signal_store_path}" --artifacts "${artifact_store_path}" \
  --api-collection "${api_collection_store}" --local-analyst "${local_analyst_store}" \
  --decoder "${decoder_binary}" --heap-snapshot "${heap_snapshot_binary}" \
  --socket "${socket_path}" --artifact-socket "${artifact_socket_path}" \
  --capture-session-id "${session_id}"
  --broker-pid "${broker_pid}"
)

ui_arguments+=(--native-console-live-directory "${native_console_directory}")
"${research_ui_server}" \
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
    fail_live_session 1 "Research UI stopped during startup. See: ${ui_log}"
  fi
  sleep 0.05
done
if [[ ! -s "${ui_endpoint_path}" ]]; then
  fail_live_session 1 "Research UI endpoint did not become ready. See: ${ui_log}"
fi
ui_endpoint="$(tr -d '\r\n' < "${ui_endpoint_path}")"
readonly ui_endpoint
readonly live_ui_url="${ui_endpoint}/?native=1&canvas_images=${capture_canvas_images}"

# The backend writes this after the console socket is listening. Absence is not
# fatal: capture still starts, and no second browser profile is launched.
native_console_session_id=""
native_console_socket=""
native_console_token=""
native_console_binding="${native_console_directory}/binding"
for _ in {1..400}; do
  if [[ -f "${native_console_binding}" || -f "${native_console_directory}/binding.absent" ]]; then
    break
  fi
  sleep 0.05
done
if [[ -f "${native_console_binding}" ]]; then
  {
    IFS= read -r native_console_session_id || true
    IFS= read -r native_console_socket || true
    IFS= read -r native_console_token || true
  } < "${native_console_binding}"
fi

brave_arguments=(
  --user-data-dir="${profile_path}" \
  --disable-background-networking \
  --disable-component-update \
  --disable-sync \
  --no-default-browser-check \
  --no-first-run \
  --reb-broker-socket="${socket_path}" \
  --reb-artifact-socket="${artifact_socket_path}" \
  --reb-broker-token-file="${token_path}" \
  --reb-session-id="${session_id}" \
  --reb-category-mask="${category_mask}" \
  --reb-duration-seconds="${duration_seconds}"
)
native_js_flags=()
if [[ "${native_quiet_mode}" == 1 ]]; then
  native_js_flags+=(--reb-ignore-debugger-statements)
fi
if [[ "${native_wasm_dispatch}" == 1 ]]; then
  native_js_flags+=(--reb-wasm-br-table-dispatch)
fi
if [[ "${native_wasm_call_indirect}" == 1 ]]; then
  native_js_flags+=(--reb-wasm-call-indirect-dispatch)
fi
# Per-function-entry frame hooks cost a runtime call on every Wasm call, so
# they are compiled in only when a guest adapter actually needs them.
if [[ -n "${native_guest_adapter}" ]]; then
  native_js_flags+=(--reb-wasm-guest-capture)
fi
# JavaScript dispatch capture turns off code caching, streaming and the
# compilation cache browser-wide, so it is added only with a site file.
if [[ -n "${native_js_dispatch_sites:-}" ]]; then
  native_js_flags+=(--reb-js-dispatch-capture)
fi
if [[ ${#native_js_flags[@]} -gt 0 ]]; then
  brave_arguments+=("--js-flags=${native_js_flags[*]}")
fi
if [[ -n "${native_guest_adapter}" ]]; then
  brave_arguments+=("--reb-wasm-guest-adapter=${native_guest_adapter}")
fi
if [[ -n "${native_js_dispatch_sites:-}" ]]; then
  brave_arguments+=("--reb-js-dispatch-sites=${native_js_dispatch_sites}")
fi
if [[ "${capture_canvas_images}" == 1 ]]; then
  brave_arguments+=(--reb-capture-canvas-images)
fi
if [[ "${use_system_keychain}" == 0 ]]; then
  brave_arguments+=(--use-mock-keychain)
fi
if [[ "${localhost_only}" == 1 ]]; then
  # Preserve Chromium's own sandbox. A nested sandbox-exec prevents its children
  # from initializing their sandbox on macOS. Route non-loopback traffic to an
  # unused local proxy and block external DNS for deterministic local fixtures.
  brave_arguments+=(
    --proxy-server=http://127.0.0.1:9
    '--proxy-bypass-list=localhost;127.0.0.1;[::1]'
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1, EXCLUDE [::1]'
  )
fi

if [[ "${native_console_session_id}" =~ ^[1-9][0-9]{0,19}$ && -S "${native_console_socket}" && -f "${native_console_token}" ]]; then
  brave_arguments+=(
    --reb-native-console
    --reb-native-console-live-binding
    "--reb-native-console-socket=${native_console_socket}"
    "--reb-native-console-token-file=${native_console_token}"
    "--reb-native-console-session-id=${native_console_session_id}"
  )
fi

"${brave_binary}" "${brave_arguments[@]}" >"${brave_log}" 2>&1 &
brave_pid=$!

sleep 0.25
if ! kill -0 "${brave_pid}" 2>/dev/null; then
  fail_live_session 1 "Brave stopped during native startup. See: ${brave_log}"
fi

# This launch never opens a DevTools transport. Preserve the existing native
# provenance value; it is not a promise that instrumentation is undetectable.
vm_capture_mode="native-stealth"
provenance_temporary="${artifact_store_path}/capture-provenance-v1.json.tmp.$$"
printf '{"contract_version":1,"sessions":[{"session_id":"%s","capture_mode":"%s"}]}\n' \
  "${session_id}" "${vm_capture_mode}" >"${provenance_temporary}"
chmod 600 "${provenance_temporary}"
mv "${provenance_temporary}" "${artifact_store_path}/capture-provenance-v1.json"

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
echo "Brave log: ${brave_log}"
echo "Category mask: ${category_mask}; expires after ${duration_seconds} seconds"
if [[ "${capture_canvas_images}" == 1 ]]; then
  echo "Canvas image capture: enabled for this session; outputs may contain sensitive page content"
else
  echo "Canvas image capture: disabled; set REB_CAPTURE_CANVAS_IMAGES=1 to enable it for one session"
fi
echo "Capture transport: native only"
echo "Close Brave to stop this capture session."

if [[ "${embedded_session}" == 1 ]]; then
  while kill -0 "${session_owner_pid}" 2>/dev/null; do
    if ! kill -0 "${brave_pid}" 2>/dev/null; then
      fail_live_session 1 "Brave stopped; the live capture connection has closed. See: ${brave_log}"
    fi
    for dependency in "${broker_pid}" "${artifact_receiver_pid}" "${ui_pid}"; do
      if [[ -n "${dependency}" ]] && ! kill -0 "${dependency}" 2>/dev/null; then
        fail_live_session 1 "A live capture helper stopped; the session has closed. See: ${session_directory}"
      fi
    done
    sleep 1
  done
else
  wait "${brave_pid}"
  brave_pid=""
  stop_artifact_receiver
  wait "${broker_pid}"
  broker_pid=""
fi
