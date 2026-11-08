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
readonly category_mask_setting="${REB_CAPTURE_CATEGORY_MASK:-4095}"
readonly duration_seconds="${REB_CAPTURE_DURATION_SECONDS:-3600}"
readonly open_command="${REB_OPEN_COMMAND:-open}"
readonly native_quiet_mode="${REB_NATIVE_QUIET_MODE:-0}"
readonly native_wasm_dispatch="${REB_NATIVE_WASM_DISPATCH:-0}"
readonly native_wasm_call_indirect="${REB_NATIVE_WASM_CALL_INDIRECT:-0}"
readonly native_wasm_samples_per_function="${REB_NATIVE_WASM_SAMPLES_PER_FUNCTION:-}"
readonly native_wasm_samples_per_indirect_site="${REB_NATIVE_WASM_SAMPLES_PER_INDIRECT_SITE:-}"
readonly native_wasm_function_allow="${REB_NATIVE_WASM_FUNCTION_ALLOW:-}"
readonly native_wasm_function_deny="${REB_NATIVE_WASM_FUNCTION_DENY:-}"
readonly native_wasm_module_allowlist="${REB_NATIVE_WASM_MODULE_ALLOWLIST:-}"
readonly native_guest_adapter="${REB_NATIVE_WASM_GUEST_ADAPTER:-}"
readonly native_js_dispatch_sites="${REB_NATIVE_JS_DISPATCH_SITES:-}"
readonly native_js_invocation_sites="${REB_NATIVE_JS_INVOCATION_SITES:-}"
readonly native_js_invocation_digests="${REB_NATIVE_JS_INVOCATION_DIGESTS:-0}"
# The packaged app sets this for the saved sites it arms in every capture: a
# Brave without invocation capture then starts without them instead of failing.
readonly native_js_invocation_if_supported="${REB_NATIVE_JS_INVOCATION_IF_SUPPORTED:-0}"
readonly console_document_start="${REB_CONSOLE_DOCUMENT_START:-0}"
readonly capture_canvas_images="${REB_CAPTURE_CANVAS_IMAGES:-0}"
# Raw request paths, queries and bounded request bodies (native-network-v2.md).
# Body length, type and digest are recorded whenever Network capture is on.
readonly capture_request_content="${REB_CAPTURE_REQUEST_CONTENT:-0}"
# Unique body and full-target bytes one content session retains.
readonly request_content_budget_mib="${REB_REQUEST_CONTENT_BUDGET_MIB:-256}"
# Content sessions also retain response bodies (native-network-v3.md): unique
# bytes per session, and whether element images, audio, video and fonts count.
readonly response_body_budget_mib="${REB_RESPONSE_BODY_BUDGET_MIB:-512}"
readonly capture_response_media="${REB_CAPTURE_RESPONSE_MEDIA:-0}"
readonly use_system_keychain="${REB_USE_SYSTEM_KEYCHAIN:-1}"
readonly localhost_only="${REB_LOCALHOST_ONLY:-0}"
readonly embedded_session="${REB_EMBEDDED_SESSION:-0}"
readonly session_handshake="${REB_SESSION_HANDSHAKE:-}"
readonly session_owner_pid="${REB_SESSION_OWNER_PID:-}"
readonly api_collection_store="${REB_API_COLLECTION_STORE:-${live_session_root}/../api-collection-v1.json}"
readonly local_analyst_store="${REB_LOCAL_ANALYST_STORE:-${live_session_root}/../local-analyst-workspace-v1.json}"
# The saved invocation sites the backend lists and edits. Saving one arms
# nothing in this session; the app passes the set to its next capture.
readonly js_invocation_site_store="${REB_JS_INVOCATION_SITE_STORE:-${live_session_root}/../js-invocation-sites-v1.json}"
readonly active_endpoint_file="${REB_ACTIVE_ENDPOINT_FILE:-${HOME:?HOME is required}/.config/origin-trace/reb-api.endpoint}"

# One category mask grammar, shared with LiveSessionCoordinator.categoryMask in
# the packaged app: 1 to 10 decimal digits, or 0x and 1 to 8 hex digits, naming
# only known categories (1 to 4095). It is parsed here once, never by Bash
# arithmetic on the raw text, and the broker and Brave, which read decimal
# only, receive the normalized value. The classes list ASCII digits: in a
# UTF-8 locale Bash's [0-9] and [a-f] ranges follow collation and match
# fullwidth digits, and $((10#...)) then aborts under set -e.
if [[ "${category_mask_setting}" =~ ^[0123456789]{1,10}$ ]]; then
  category_mask=$((10#${category_mask_setting}))
elif [[ "${category_mask_setting}" =~ ^0[xX][0123456789abcdefABCDEF]{1,8}$ ]]; then
  category_mask=$((16#${category_mask_setting:2}))
else
  category_mask=0
fi
if (( category_mask < 1 || category_mask > 4095 )); then
  fail_live_session 2 "REB_CAPTURE_CATEGORY_MASK must be a category mask from 1 to 4095, written as up to 10 decimal digits or 0x and up to 8 hex digits."
fi
readonly category_mask

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
if [[ "${console_document_start}" != 0 && "${console_document_start}" != 1 ]]; then
  fail_live_session 2 "REB_CONSOLE_DOCUMENT_START must be 0 or 1."
fi
if [[ "${native_wasm_call_indirect}" != 0 && "${native_wasm_call_indirect}" != 1 ]]; then
  fail_live_session 2 "REB_NATIVE_WASM_CALL_INDIRECT must be 0 or 1."
fi
if [[ "${native_wasm_call_indirect}" == 1 ]] &&
   (( (category_mask & 512) == 0 || (category_mask & 1024) == 0 )); then
  fail_live_session 2 "REB_NATIVE_WASM_CALL_INDIRECT requires VM and Artifact capture categories."
fi
validate_wasm_count() {
  local name="$1" text="$2"
  if [[ -z "${text}" ]]; then
    return 0
  fi
  if [[ ! "${text}" =~ ^[0-9]+$ ]] || (( ${#text} > 2 || 10#${text} < 1 || 10#${text} > 16 )); then
    fail_live_session 2 "${name} must be from 1 to 16."
  fi
}
validate_wasm_function_list() {
  local name="$1" text="$2"
  if [[ -z "${text}" ]]; then
    return 0
  fi
  if [[ ! "${text}" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
    fail_live_session 2 "${name} must be a comma-separated list of function indexes."
  fi
  local IFS=','
  local -a items=()
  read -r -a items <<< "${text}"
  if (( ${#items[@]} > 32 )); then
    fail_live_session 2 "${name} accepts at most 32 function indexes."
  fi
  local seen="|" item value
  for item in "${items[@]}"; do
    if (( ${#item} > 8 )); then
      fail_live_session 2 "${name} indexes must be below 16777216."
    fi
    value=$((10#${item}))
    if (( value >= 16777216 )); then
      fail_live_session 2 "${name} indexes must be below 16777216."
    fi
    if [[ "${seen}" == *"|${value}|"* ]]; then
      fail_live_session 2 "${name} indexes must be unique."
    fi
    seen+="${value}|"
  done
}
validate_wasm_count "REB_NATIVE_WASM_SAMPLES_PER_FUNCTION" "${native_wasm_samples_per_function}"
validate_wasm_count "REB_NATIVE_WASM_SAMPLES_PER_INDIRECT_SITE" "${native_wasm_samples_per_indirect_site}"
validate_wasm_function_list "REB_NATIVE_WASM_FUNCTION_ALLOW" "${native_wasm_function_allow}"
validate_wasm_function_list "REB_NATIVE_WASM_FUNCTION_DENY" "${native_wasm_function_deny}"
if [[ -n "${native_wasm_module_allowlist}" ]]; then
  if [[ "${native_wasm_module_allowlist}" != /* || ! -f "${native_wasm_module_allowlist}" ||
        ! -r "${native_wasm_module_allowlist}" ]]; then
    fail_live_session 2 "REB_NATIVE_WASM_MODULE_ALLOWLIST must name a readable absolute regular file."
  fi
  module_allowlist_bytes="$(wc -c < "${native_wasm_module_allowlist}")"
  if (( module_allowlist_bytes < 1 || module_allowlist_bytes > 1024 )); then
    fail_live_session 2 "REB_NATIVE_WASM_MODULE_ALLOWLIST must contain between 1 and 1024 bytes."
  fi
fi
if [[ -n "${native_wasm_samples_per_function}${native_wasm_samples_per_indirect_site}${native_wasm_function_allow}${native_wasm_function_deny}${native_wasm_module_allowlist}" ]] &&
   [[ "${native_wasm_dispatch}" != 1 && "${native_wasm_call_indirect}" != 1 ]]; then
  fail_live_session 2 "Wasm sample budget options require REB_NATIVE_WASM_DISPATCH=1 or REB_NATIVE_WASM_CALL_INDIRECT=1."
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
if [[ -n "${native_js_invocation_sites}" ]]; then
  if (( (category_mask & 512) == 0 )); then
    fail_live_session 2 "REB_NATIVE_JS_INVOCATION_SITES requires the VM capture category."
  fi
  if [[ "${native_js_invocation_sites}" != /* || ! -f "${native_js_invocation_sites}" ||
        ! -r "${native_js_invocation_sites}" ]]; then
    fail_live_session 2 "REB_NATIVE_JS_INVOCATION_SITES must name a readable absolute regular file."
  fi
  invocation_sites_bytes="$(wc -c < "${native_js_invocation_sites}")"
  if (( invocation_sites_bytes == 0 || invocation_sites_bytes > 4096 )); then
    fail_live_session 2 "REB_NATIVE_JS_INVOCATION_SITES must contain between 1 and 4096 bytes."
  fi
fi
if [[ "${native_js_invocation_digests}" != 0 && "${native_js_invocation_digests}" != 1 ]]; then
  fail_live_session 2 "REB_NATIVE_JS_INVOCATION_DIGESTS must be 0 or 1."
fi
if [[ "${native_js_invocation_if_supported}" != 0 && "${native_js_invocation_if_supported}" != 1 ]]; then
  fail_live_session 2 "REB_NATIVE_JS_INVOCATION_IF_SUPPORTED must be 0 or 1."
fi
# Settled-value digests are a sensitive capture path: they exist only for an
# armed invocation session and are labeled when the session starts.
if [[ "${native_js_invocation_digests}" == 1 && -z "${native_js_invocation_sites}" ]]; then
  fail_live_session 2 "REB_NATIVE_JS_INVOCATION_DIGESTS=1 requires REB_NATIVE_JS_INVOCATION_SITES."
fi
if [[ "${REB_CDP_NETWORK_CAPTURE:-0}" != 0 || -n "${REB_DEBUGGER_TRANSPORT_BINARY:-}" ]]; then
  fail_live_session 2 "CDP capture and debugger transport were removed; use native Brave capture."
fi
if [[ "${capture_canvas_images}" != 0 && "${capture_canvas_images}" != 1 ]]; then
  fail_live_session 2 "REB_CAPTURE_CANVAS_IMAGES must be 0 or 1."
fi
if [[ "${capture_request_content}" != 0 && "${capture_request_content}" != 1 ]]; then
  fail_live_session 2 "REB_CAPTURE_REQUEST_CONTENT must be 0 or 1."
fi
if ! [[ "${request_content_budget_mib}" =~ ^[1-9][0-9]{0,3}$ ]] || ((request_content_budget_mib > 4096)); then
  fail_live_session 2 "REB_REQUEST_CONTENT_BUDGET_MIB must be an integer from 1 to 4096."
fi
if ! [[ "${response_body_budget_mib}" =~ ^[1-9][0-9]{0,4}$ ]] || ((response_body_budget_mib > 16384)); then
  fail_live_session 2 "REB_RESPONSE_BODY_BUDGET_MIB must be an integer from 1 to 16384."
fi
if [[ "${capture_response_media}" != 0 && "${capture_response_media}" != 1 ]]; then
  fail_live_session 2 "REB_CAPTURE_RESPONSE_MEDIA must be 0 or 1."
fi
if [[ "${capture_response_media}" == 1 && "${capture_request_content}" != 1 ]]; then
  fail_live_session 2 "REB_CAPTURE_RESPONSE_MEDIA requires REB_CAPTURE_REQUEST_CONTENT=1."
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
if [[ "${capture_request_content}" == 1 ]] &&
   (( (category_mask & 256) == 0 || (category_mask & 1024) == 0 )); then
  fail_live_session 2 "REB_CAPTURE_REQUEST_CONTENT requires Network and Artifact category bits (mask 1280)."
fi

mkdir -p "${session_directory}" "${artifact_store_path}" "${profile_path}" "${native_console_directory}"
chmod 700 "${session_directory}" "${artifact_store_path}" "${profile_path}" "${native_console_directory}"
readonly wasm_budget_reset_file="${session_directory}/wasm-sample-budget-reset"
printf '0\n' > "${wasm_budget_reset_file}"
chmod 600 "${wasm_budget_reset_file}"
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

# Chromium's loader finds its framework relative to the path it was started
# from, so the launcher checks and starts the real file, not a symlink to it.
resolve_physical_path() {
  local path="$1"
  local link
  local hops=0
  while [[ -L "${path}" ]]; do
    if (( hops++ >= 32 )); then
      return 1
    fi
    link="$(readlink "${path}")"
    if [[ "${link}" != /* ]]; then
      link="$(dirname "${path}")/${link}"
    fi
    path="${link}"
  done
  # With an exported CDPATH, cd prints a directory it finds, which would land in
  # this result.
  printf '%s/%s\n' "$(CDPATH='' cd -P -- "$(dirname "${path}")" && pwd -P)" "$(basename "${path}")"
}
if ! brave_binary="$(resolve_physical_path "${brave_binary}")"; then
  fail_live_session 1 "Could not resolve the Brave executable path. Set REB_BRAVE_BINARY to the executable inside a complete Brave build."
fi
readonly brave_binary

# The project V8 flags are assembled before any helper starts, so a build that
# cannot honor them is refused with nothing to stop and no window opened. Each
# flag keeps the setting that requested it and the setting that turns it off.
native_js_flags=()
native_js_flag_settings=()
native_js_flag_opt_outs=()
add_native_js_flag() {
  native_js_flags+=("$1")
  native_js_flag_settings+=("$2")
  native_js_flag_opt_outs+=("$3")
}
if [[ "${native_quiet_mode}" == 1 ]]; then
  add_native_js_flag --reb-ignore-debugger-statements \
    REB_NATIVE_QUIET_MODE=1 REB_NATIVE_QUIET_MODE=0
fi
if [[ "${native_wasm_dispatch}" == 1 ]]; then
  add_native_js_flag --reb-wasm-br-table-dispatch \
    REB_NATIVE_WASM_DISPATCH=1 REB_NATIVE_WASM_DISPATCH=0
fi
if [[ "${native_wasm_call_indirect}" == 1 ]]; then
  add_native_js_flag --reb-wasm-call-indirect-dispatch \
    REB_NATIVE_WASM_CALL_INDIRECT=1 REB_NATIVE_WASM_CALL_INDIRECT=0
fi
# Per-function-entry frame hooks cost a runtime call on every Wasm call, so
# they are compiled in only when a guest adapter actually needs them.
if [[ -n "${native_guest_adapter}" ]]; then
  add_native_js_flag --reb-wasm-guest-capture \
    REB_NATIVE_WASM_GUEST_ADAPTER "unset REB_NATIVE_WASM_GUEST_ADAPTER"
fi
# JavaScript dispatch capture turns off code caching, streaming and the
# compilation cache browser-wide, so it is added only with a site file.
if [[ -n "${native_js_dispatch_sites:-}" ]]; then
  add_native_js_flag --reb-js-dispatch-capture \
    REB_NATIVE_JS_DISPATCH_SITES "unset REB_NATIVE_JS_DISPATCH_SITES"
fi

# Print the one file that holds the V8 flag table Brave will load.
# chrome/app/chrome_exe_main_mac.cc dlopens a path compiled into the executable,
# ../Frameworks/<product> Framework.framework/Versions/<version>/<product> Framework,
# relative to the executable. Versions/Current can point at another version, so
# that literal is read from the small executable itself.
# In a component build that framework re-exports @rpath/libchrome_dll.dylib
# (chrome/BUILD.gn) or links @rpath/libv8.dylib, both resolved from the output
# directory beside the app, and V8 is libv8.dylib there. Load commands sit at
# the start of the Mach-O, so the first MiB decides which kind of build this is.
locate_brave_v8_image() {
  local executable="$1"
  local bundle="${executable%/Contents/MacOS/*}"
  local loader_path
  local framework
  if [[ "${bundle}" != *.app || "${executable}" != "${bundle}/Contents/MacOS/${executable##*/}" ]]; then
    return 1
  fi
  # A universal executable repeats the literal once per architecture slice.
  if ! loader_path="$(LC_ALL=C grep -a -o -e \
       '\.\./Frameworks/[^[:cntrl:]/]* Framework\.framework/Versions/[^[:cntrl:]/]*/[^[:cntrl:]/]* Framework' \
       "${executable}" | LC_ALL=C sort -u)" || [[ "${loader_path}" == *$'\n'* ]]; then
    return 1
  fi
  framework="${bundle}/Contents/${loader_path#../}"
  if [[ ! -f "${framework}" ]]; then
    return 1
  fi
  # Keep -c: with -q, grep exits at the first match, head dies of SIGPIPE,
  # and pipefail would report a component build as a release build.
  if head -c 1048576 "${framework}" |
     LC_ALL=C grep -a -c -F -e '@rpath/libchrome_dll.dylib' -e '@rpath/libv8.dylib' >/dev/null; then
    if [[ ! -f "${bundle%/*}/libv8.dylib" ]]; then
      return 1
    fi
    printf '%s\n' "${bundle%/*}/libv8.dylib"
  else
    printf '%s\n' "${framework}"
  fi
}

# A stopped launcher must not leave readers behind. No helper has started yet,
# so every background job is a scan, and the job table already holds a reader
# whose PID the loop below had not yet recorded when the signal arrived.
stop_brave_v8_scans() {
  local readers
  readers="$(jobs -p)"
  if [[ -n "${readers}" ]]; then
    # shellcheck disable=SC2086  # One PID per word.
    kill -TERM ${readers} 2>/dev/null || true
  fi
  wait 2>/dev/null || true
}

# V8 stops parsing --js-flags at the first name it does not define and ignores
# every later entry, so a stale Brave would run a healthy-looking session with
# no evidence from the requested modes. V8 keeps each defined flag name, with
# underscores, as a string in its flag table. A miss reads the whole 600+ MB
# release framework, so the per-flag scans of that one file run concurrently.
require_brave_v8_flags() {
  local image
  local flag
  local status
  local index=0
  local missing=""
  local missing_count=0
  local missing_noun="flags"
  local first_missing="the first of them"
  local opt_outs=""
  local uninspected=0
  local scan_pids=()
  if ! image="$(locate_brave_v8_image "${brave_binary}")"; then
    for flag in "${native_js_flag_opt_outs[@]}"; do
      opt_outs+="${opt_outs:+, }${flag}"
    done
    fail_live_session 1 "Cannot locate the V8 library of Brave at ${brave_binary}, so its native V8 flags cannot be checked. Set REB_BRAVE_BINARY to <App>.app/Contents/MacOS/<executable> inside a complete Brave build, not a wrapper script or an app copied away from its build output, or turn that capture off with ${opt_outs}."
  fi
  # No TERM or INT trap exists before this point; the launcher's own traps
  # are installed later, so the default disposition is restored below.
  trap 'stop_brave_v8_scans; exit 143' TERM
  trap 'stop_brave_v8_scans; exit 130' INT
  for flag in "${native_js_flags[@]}"; do
    flag="${flag#--}"
    LC_ALL=C grep -a -q -F -e "${flag//-/_}" "${image}" &
    scan_pids+=($!)
  done
  # Reap every scan before deciding, keeping each status: 1 is an absent
  # name, anything else means the file could not be read.
  for flag in "${native_js_flags[@]}"; do
    status=0
    wait "${scan_pids[index]}" || status=$?
    if (( status == 1 )); then
      missing+="${missing:+, }${flag} (from ${native_js_flag_settings[index]})"
      opt_outs+="${opt_outs:+, }${native_js_flag_opt_outs[index]}"
      missing_count=$((missing_count + 1))
    elif (( status != 0 )); then
      uninspected=1
    fi
    index=$((index + 1))
  done
  trap - TERM INT
  if (( uninspected )); then
    fail_live_session 1 "Could not inspect ${image}, the V8 library of Brave at ${brave_binary}, for the requested native V8 flags. Check that the file is readable."
  fi
  if (( missing_count > 0 )); then
    if (( missing_count == 1 )); then
      missing_noun="flag"
      first_missing="it"
    fi
    fail_live_session 1 "Brave at ${brave_binary} does not define the requested V8 ${missing_noun} ${missing} in ${image}. V8 would stop at ${first_missing} and ignore every later --js-flags entry, so that evidence would be silently missing. Use the Brave Browser Development build released with this Origin Trace, or rebuild Brave from this checkout, or turn that capture off with ${opt_outs}."
  fi
}
# Invocation identity arms function entries at bytecode generation and takes
# the dispatch flag's compile-path settings by implication. Sites the packaged
# app saved are asked for only if this Brave defines the flag: one built before
# invocation capture starts without them and says so, instead of refusing the
# whole session below. Explicit sites keep the strict check.
js_invocation_session_state=""
if [[ -n "${native_js_invocation_sites:-}" ]]; then
  js_invocation_session_state=armed
  if [[ "${native_js_invocation_if_supported:-0}" == 1 ]] &&
     invocation_image="$(locate_brave_v8_image "${brave_binary}")"; then
    trap 'stop_brave_v8_scans; exit 143' TERM
    trap 'stop_brave_v8_scans; exit 130' INT
    LC_ALL=C grep -a -q -F -e reb_js_invocation_capture "${invocation_image}" &
    invocation_scan_status=0
    wait "$!" || invocation_scan_status=$?
    trap - TERM INT
    # 1 is an absent name; an unreadable image is left to the check below.
    if (( invocation_scan_status == 1 )); then
      js_invocation_session_state=browser_unsupported
    fi
  fi
fi
readonly js_invocation_session_state
if [[ "${js_invocation_session_state}" == armed ]]; then
  add_native_js_flag --reb-js-invocation-capture \
    REB_NATIVE_JS_INVOCATION_SITES "unset REB_NATIVE_JS_INVOCATION_SITES"
fi
if [[ ${#native_js_flags[@]} -gt 0 ]]; then
  require_brave_v8_flags
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
  local job_pid
  local unrecorded=()
  echo "Live session cleanup started: browser=${brave_pid:-none} analyzer=${analyzer_pid:-none} broker=${broker_pid:-none} artifacts=${artifact_receiver_pid:-none} backend=${ui_pid:-none}" >&2
  # A signal can arrive after a helper starts but before its PID is saved. The
  # job table already holds that helper, so stop every unrecorded job as well.
  for job_pid in $(jobs -p); do
    case " ${brave_pid} ${analyzer_pid} ${broker_pid} ${artifact_receiver_pid} ${ui_pid} " in
      *" ${job_pid} "*) ;;
      *) unrecorded+=("${job_pid}") ;;
    esac
  done
  stop_processes 100 "${brave_pid}" "${analyzer_pid}" "${broker_pid}" \
    "${artifact_receiver_pid}" "${ui_pid}" ${unrecorded[@]+"${unrecorded[@]}"}
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
  # Canvas images and request bodies are sensitive artifact kinds; the default
  # receiver refuses both.
  if [[ "${capture_canvas_images}" == 1 || "${capture_request_content}" == 1 ]]; then
    artifact_receiver_arguments+=(--allow-sensitive)
  fi
  # Request content is bounded by its byte budget, not a count, so the store
  # grows by that budget and admits small bodies past the default 4,096 items.
  if [[ "${capture_request_content}" == 1 ]]; then
    artifact_receiver_arguments+=(
      --max-store-bytes "$(((256 + request_content_budget_mib + response_body_budget_mib) * 1048576))"
      --max-artifacts 65536
      --max-manifest-bytes 268435456
    )
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
  --js-invocation-site-store "${js_invocation_site_store}" \
  --decoder "${decoder_binary}" --heap-snapshot "${heap_snapshot_binary}" \
  --socket "${socket_path}" --artifact-socket "${artifact_socket_path}" \
  --capture-session-id "${session_id}"
  --broker-pid "${broker_pid}"
  # session_action open_url hands a URL to this browser through its profile,
  # and end asks this launcher, the backend's parent, to stop the session.
  --brave-binary "${brave_binary}"
  --brave-profile "${profile_path}"
  --launcher-pid "$$"
  --wasm-budget-reset-file "${wasm_budget_reset_file}"
)

ui_arguments+=(--native-console-live-directory "${native_console_directory}")
# Labels for the session context; they enable nothing in the backend.
if [[ "${capture_request_content}" == 1 ]]; then
  ui_arguments+=(--session-request-content)
fi
if [[ "${capture_canvas_images}" == 1 ]]; then
  ui_arguments+=(--session-canvas-images)
fi
if [[ "${console_document_start}" == 1 ]]; then
  ui_arguments+=(--session-document-start)
fi
# The session header says which functions this capture tracks, or why not.
if [[ -n "${js_invocation_session_state}" ]]; then
  ui_arguments+=(--js-invocation-session-sites "${native_js_invocation_sites}"
    --js-invocation-session-state "${js_invocation_session_state}")
  if [[ "${js_invocation_session_state}" == armed && "${native_js_invocation_digests}" == 1 ]]; then
    ui_arguments+=(--js-invocation-session-digests)
  fi
fi
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
# The UI labels the session from these; they describe what this launch passed
# to Brave and grant nothing.
readonly live_ui_url="${ui_endpoint}/?native=1&canvas_images=${capture_canvas_images}&request_content=${capture_request_content}"

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
if [[ ${#native_js_flags[@]} -gt 0 ]]; then
  brave_arguments+=("--js-flags=${native_js_flags[*]}")
fi
if [[ -n "${native_guest_adapter}" ]]; then
  brave_arguments+=("--reb-wasm-guest-adapter=${native_guest_adapter}")
fi
# Absent options are unset in the extracted launch slice, which runs under
# set -u. An empty value is the historical unrestricted budget.
if [[ -n "${native_wasm_samples_per_function:-}" ]]; then
  brave_arguments+=("--reb-wasm-samples-per-function=${native_wasm_samples_per_function}")
fi
if [[ -n "${native_wasm_samples_per_indirect_site:-}" ]]; then
  brave_arguments+=("--reb-wasm-samples-per-indirect-site=${native_wasm_samples_per_indirect_site}")
fi
if [[ -n "${native_wasm_function_allow:-}" ]]; then
  brave_arguments+=("--reb-wasm-function-allow=${native_wasm_function_allow}")
fi
if [[ -n "${native_wasm_function_deny:-}" ]]; then
  brave_arguments+=("--reb-wasm-function-deny=${native_wasm_function_deny}")
fi
if [[ -n "${native_wasm_module_allowlist:-}" ]]; then
  brave_arguments+=("--reb-wasm-module-allowlist=${native_wasm_module_allowlist}")
fi
if [[ -n "${wasm_budget_reset_file:-}" ]]; then
  brave_arguments+=("--reb-wasm-budget-reset-file=${wasm_budget_reset_file}")
fi
if [[ -n "${native_js_dispatch_sites:-}" ]]; then
  brave_arguments+=("--reb-js-dispatch-sites=${native_js_dispatch_sites}")
fi
if [[ "${js_invocation_session_state:-}" == armed ]]; then
  brave_arguments+=("--reb-js-invocation-sites=${native_js_invocation_sites}")
  if [[ "${native_js_invocation_digests:-0}" == 1 ]]; then
    brave_arguments+=(--reb-js-invocation-digests)
  fi
fi
if [[ "${capture_canvas_images}" == 1 ]]; then
  brave_arguments+=(--reb-capture-canvas-images)
fi
if [[ "${capture_request_content}" == 1 ]]; then
  brave_arguments+=(--reb-capture-request-content
    "--reb-request-content-budget-bytes=$((request_content_budget_mib * 1048576))"
    "--reb-response-body-budget-bytes=$((response_body_budget_mib * 1048576))")
  if [[ "${capture_response_media}" == 1 ]]; then
    brave_arguments+=(--reb-capture-response-media)
  fi
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

native_console_bound=0
if [[ "${native_console_session_id}" =~ ^[1-9][0-9]{0,19}$ && -S "${native_console_socket}" && -f "${native_console_token}" ]]; then
  native_console_bound=1
  brave_arguments+=(
    --reb-native-console
    --reb-native-console-live-binding
    "--reb-native-console-socket=${native_console_socket}"
    "--reb-native-console-token-file=${native_console_token}"
    "--reb-native-console-session-id=${native_console_session_id}"
  )
  # Permission only, and only for this capture browser's own lifetime. The
  # switch arms nothing: a snippet still needs an explicit confirmed action in
  # an authorized live Console connection. There is no way to add it later.
  if [[ "${console_document_start}" == 1 ]]; then
    brave_arguments+=(--reb-native-console-document-start)
  fi
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
echo "Brave executable: ${brave_binary}"
echo "Brave log: ${brave_log}"
echo "Category mask: ${category_mask}; expires after ${duration_seconds} seconds"
if [[ "${capture_canvas_images}" == 1 ]]; then
  echo "Canvas image capture: enabled for this session; outputs may contain sensitive page content"
else
  echo "Canvas image capture: disabled; set REB_CAPTURE_CANVAS_IMAGES=1 to enable it for one session"
fi
if [[ "${capture_request_content}" == 1 ]]; then
  echo "Request content capture: enabled for this session; request paths, queries and bodies are retained locally, at most ${request_content_budget_mib} MiB of unique content"
  echo "Response body capture: enabled for this session; at most ${response_body_budget_mib} MiB of unique response bytes, element media $([[ "${capture_response_media}" == 1 ]] && echo retained || echo skipped)"
else
  echo "Request content capture: disabled; hosts and body length, type and digest only. Set REB_CAPTURE_REQUEST_CONTENT=1 to retain paths, request bodies and response bodies"
fi
if [[ "${console_document_start}" == 1 && "${native_console_bound}" == 1 ]]; then
  echo "Console document-start scripts: permitted for this capture browser; nothing runs until a live Console connection arms a confirmed rule"
elif [[ "${console_document_start}" == 1 ]]; then
  echo "Console document-start scripts: requested, but the live Console binding is unavailable, so Brave did not receive the permission"
else
  echo "Console document-start scripts: not permitted; set REB_CONSOLE_DOCUMENT_START=1 to permit them for one session"
fi
echo "Native switches: quiet=${native_quiet_mode} wasm_br_table=${native_wasm_dispatch} wasm_call_indirect=${native_wasm_call_indirect} wasm_guest=$([[ -n "${native_guest_adapter}" ]] && echo 1 || echo 0) js_dispatch=$([[ -n "${native_js_dispatch_sites}" ]] && echo 1 || echo 0) js_invocation=$([[ "${js_invocation_session_state}" == armed ]] && echo 1 || echo 0)"
echo "Wasm sample budgets: per_function=${native_wasm_samples_per_function:-unset} per_indirect_site=${native_wasm_samples_per_indirect_site:-unset} function_allow=${native_wasm_function_allow:-unset} function_deny=${native_wasm_function_deny:-unset} module_allowlist=$([[ -n "${native_wasm_module_allowlist:-}" ]] && echo 1 || echo 0) reset_file=${wasm_budget_reset_file:-unset}"
if [[ "${js_invocation_session_state}" == browser_unsupported ]]; then
  echo "JavaScript invocation tracking: unavailable; Brave at ${brave_binary} does not define --reb-js-invocation-capture, so this session started without the saved invocation sites and records no invocation evidence"
elif [[ "${js_invocation_session_state}" == armed && "${native_js_invocation_digests}" == 1 ]]; then
  echo "JavaScript invocation value digests: enabled for this session; settled values of armed calls are hashed (sensitive capture)"
fi
echo "Capture transport: native only"
echo "Close Brave to stop this capture session."

if [[ "${embedded_session}" == 1 ]]; then
  # A PID is reused once its process exits, so the owner is the process with
  # this PID and this start time.
  session_owner_started="$(/bin/ps -o lstart= -p "${session_owner_pid}" 2>/dev/null || true)"
  while [[ -n "${session_owner_started}" &&
           "$(/bin/ps -o lstart= -p "${session_owner_pid}" 2>/dev/null || true)" == "${session_owner_started}" ]]; do
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
  # The broker accepts one browser connection and finishes when it closes. A
  # Brave that exits without connecting, for example after handing this launch
  # to a Brave already running with the same profile, would leave the broker
  # waiting for the whole capture duration. A connected broker drains well
  # within this bound; one still waiting is asked to stop.
  for _ in {1..200}; do
    if ! kill -0 "${broker_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  if kill -0 "${broker_pid}" 2>/dev/null; then
    kill -USR1 "${broker_pid}" 2>/dev/null || true
    wait "${broker_pid}" || true
    broker_pid=""
    fail_live_session 1 "Brave exited, but the event broker was still waiting for its capture connection, so this session recorded no browser evidence. A Brave already running with this profile may have taken the launch; quit it or use a separate REB_BRAVE_PROFILE. See: ${brave_log}"
  fi
  wait "${broker_pid}"
  broker_pid=""
fi
