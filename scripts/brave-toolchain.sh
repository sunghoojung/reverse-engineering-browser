#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly brave_directory="${REB_BRAVE_DIRECTORY:-${repository_root}/browser/worktree/src/brave}"
chromium_directory="$(cd "${brave_directory}/.." 2>/dev/null && pwd)" || chromium_directory=""
readonly chromium_directory
readonly output_directory="${REB_BRAVE_OUTPUT_DIRECTORY:-out/Component_arm64}"
readonly brave_jobs="${REB_BRAVE_JOBS:-}"
readonly probe_objects=(
  "obj/brave/components/reverse_engineering_browser/queue/native_probe_queue.o"
  "obj/brave/components/reverse_engineering_browser/renderer_sink/native_probe_sink.o"
  "obj/brave/components/reverse_engineering_browser/renderer/native_probe_transport.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_local_ipc_client.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_network_capture_sink.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_probe_host.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_probe_session.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_probe_socket_client.o"
  "obj/brave/browser/core/brave_proxying_url_loader_factory.o"
  "obj/brave/browser/core/brave_content_browser_client.o"
  "obj/chrome/renderer/renderer/brave_content_renderer_client.o"
  "obj/third_party/blink/renderer/core/core/html_canvas_element.o"
  "obj/third_party/blink/renderer/core/core/use_counter_callback.o"
  "obj/third_party/blink/renderer/modules/canvas/canvas/base_rendering_context_2d.o"
  "obj/third_party/blink/renderer/modules/canvas/canvas/canvas_2d_recorder_context.o"
  "obj/third_party/blink/renderer/modules/canvas/canvas/canvas_path.o"
  "obj/third_party/blink/renderer/modules/webgl/webgl/webgl_rendering_context_base.o"
  "obj/third_party/blink/renderer/core/core/v8_initializer.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_canvas_rendering_context_2d.o"
  "obj/third_party/blink/renderer/bindings/core/v8/v8/v8_element.o"
  "obj/third_party/blink/renderer/bindings/core/v8/v8/v8_performance.o"
  "obj/third_party/blink/renderer/bindings/core/v8/v8/v8_svg_graphics_element.o"
  "obj/third_party/blink/renderer/bindings/core/v8/v8/v8_window.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_gpu.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_gpu_adapter_info.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_gpu_supported_limits.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_html_iframe_element.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_media_recorder.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_media_device_info.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_media_source.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_navigator.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_permissions.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_rtc_peer_connection.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_screen.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_storage.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_speech_synthesis_voice.o"
  "obj/third_party/blink/renderer/bindings/modules/v8/v8/v8_webgl_rendering_context.o"
  "obj/third_party/blink/renderer/platform/loader/loader/resource_request_sender.o"
  "obj/v8/v8_base_without_compiler/api.o"
  "obj/v8/v8_base_without_compiler/isolate.o"
  "obj/v8/v8_base_without_compiler/wasm-js.o"
  "obj/v8/v8_initializers/builtins-date-gen.o"
  "obj/v8/torque_generated_definitions/math-tq.o"
  "obj/v8/torque_generated_initializers/math-tq-csa.o"
)
readonly web_audio_objects=(
  "obj/third_party/blink/renderer/modules/webaudio/webaudio/audio_buffer.o"
  "obj/third_party/blink/renderer/modules/webaudio/webaudio/audio_node.o"
  "obj/third_party/blink/renderer/modules/webaudio/webaudio/audio_scheduled_source_node.o"
  "obj/third_party/blink/renderer/modules/webaudio/webaudio/base_audio_context.o"
  "obj/third_party/blink/renderer/modules/webaudio/webaudio/offline_audio_context.o"
  "obj/third_party/blink/renderer/modules/webaudio/webaudio/analyser_node.o"
)

usage() {
  echo "Usage: $0 <doctor|gen|probe-check|build|start> [arguments...]"
}

configure_xcode() {
  if [[ -z "${DEVELOPER_DIR:-}" ]] &&
     [[ -d /Applications/Xcode.app/Contents/Developer ]]; then
    export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
  fi

  if ! xcodebuild -version >/dev/null 2>&1; then
    echo "Full Xcode is required. Install it at /Applications/Xcode.app or set DEVELOPER_DIR." >&2
    exit 1
  fi
  if ! xcodebuild -license check >/dev/null 2>&1; then
    echo "The Xcode license has not been accepted." >&2
    exit 1
  fi
}

configure_node() {
  local node_version
  local node_major
  local node_minor
  local candidate
  local candidates=()

  if [[ -n "${REB_NODE_DIRECTORY:-}" ]]; then
    candidates+=("${REB_NODE_DIRECTORY}/bin")
  fi
  candidates+=(/opt/homebrew/opt/node@24/bin /usr/local/opt/node@24/bin)

  node_version="$(node -p 'process.versions.node' 2>/dev/null || true)"
  IFS=. read -r node_major node_minor _ <<< "${node_version}"
  if [[ "${node_major:-}" == 24 && "${node_minor:-0}" =~ ^[0-9]+$ &&
        "${node_minor}" -ge 16 ]]; then
    return
  fi

  for candidate in "${candidates[@]}"; do
    if [[ -x "${candidate}/node" && -x "${candidate}/npm" ]]; then
      export PATH="${candidate}:${PATH}"
      node_version="$(node -p 'process.versions.node')"
      IFS=. read -r node_major node_minor _ <<< "${node_version}"
      if [[ "${node_major}" == 24 && "${node_minor}" =~ ^[0-9]+$ &&
            "${node_minor}" -ge 16 ]]; then
        return
      fi
    fi
  done

  echo "Brave requires Node.js >=24.16.0 and <25. Set REB_NODE_DIRECTORY or install node@24." >&2
  exit 1
}

configure_brave_python() {
  local candidate
  local candidates=()
  shopt -s nullglob
  candidates=(
    "${brave_directory}"/vendor/depot_tools/bootstrap-*_bin/python3/bin
  )
  shopt -u nullglob

  for candidate in "${candidates[@]}"; do
    if [[ -x "${candidate}/python3" ]]; then
      export PATH="${candidate}:${brave_directory}/vendor/depot_tools:${PATH}"
      export PYTHONPATH="${brave_directory}/script${PYTHONPATH:+:${PYTHONPATH}}"
      return
    fi
  done

  echo "Brave's bundled Python is missing. Run ./scripts/bootstrap-brave.sh --init first." >&2
  exit 1
}

touch_brave_overrides() {
  local override_path
  local relative_path
  local siso_config="${chromium_directory}/build/config/siso/brave_siso_config.star"
  local redirect_config_is_newer=0
  while IFS= read -r -d '' override_path; do
    relative_path="${override_path#chromium_src/}"
    if [[ -f "${chromium_directory}/${relative_path}" &&
          -f "${siso_config}" &&
          "${siso_config}" -nt "${chromium_directory}/${relative_path}" ]]; then
      redirect_config_is_newer=1
      break
    fi
  done < <(git -C "${brave_directory}" ls-files -z --cached --others --exclude-standard -- chromium_src)

  if ((redirect_config_is_newer == 1)); then
    echo "Siso redirect config changed; refreshing Brave override timestamps."
    force_touch_brave_overrides
    return
  fi

  while IFS= read -r -d '' override_path; do
    relative_path="${override_path#chromium_src/}"
    if [[ -f "${brave_directory}/${override_path}" ]] &&
       { [[ ! -f "${chromium_directory}/${relative_path}" ]] ||
         [[ "${brave_directory}/${override_path}" -nt "${chromium_directory}/${relative_path}" ]]; }; then
      (
        cd "${brave_directory}"
        node --input-type=module -e \
          "import util from './build/commands/lib/util.js'; util.touchOverriddenFiles()"
      )
      return
    fi
  done < <(git -C "${brave_directory}" ls-files -z --cached --others --exclude-standard -- chromium_src)

  echo "Brave override targets are current."
}

force_touch_brave_overrides() {
  local override_path
  local relative_path
  (
    cd "${brave_directory}"
    node --input-type=module -e \
      "import util from './build/commands/lib/util.js'; util.touchOverriddenFiles()"

    # Brave's helper only touches Chromium sources when the override mtime is
    # newer. A newly enabled Siso redirect can otherwise leave an older object
    # built from the Chromium source, so make the redirected source inputs
    # newer once after the redirect configuration changes.
    while IFS= read -r -d '' override_path; do
      relative_path="${override_path#chromium_src/}"
      if [[ -f "${chromium_directory}/${relative_path}" ]]; then
        touch "${chromium_directory}/${relative_path}"
      fi
    done < <(find chromium_src -type f -print0)
  )
}

run_pnpm() {
  if command -v corepack >/dev/null 2>&1; then
    corepack pnpm "$@"
  elif command -v pnpm >/dev/null 2>&1; then
    pnpm "$@"
  else
    echo "Corepack or pnpm is required." >&2
    exit 1
  fi
}

generated_probe_present() {
  local generated_file="$1"
  local operation="$2"
  awk -v operation="\"${operation}\"" '
    index($0, "NativeProbeSink::Get().Record") && index($0, operation) {
      found = 1
    }
    END { exit found ? 0 : 1 }
  ' "${generated_file}"
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

readonly command_name="$1"
shift

if [[ ! -d "${brave_directory}" ]]; then
  echo "Brave checkout is missing: ${brave_directory}" >&2
  echo "Run ./scripts/bootstrap-brave.sh first." >&2
  exit 1
fi

configure_xcode
configure_node

case "${command_name}" in
  doctor)
    echo "Developer directory: ${DEVELOPER_DIR:-$(xcode-select -p)}"
    xcodebuild -version
    if command -v node >/dev/null 2>&1; then
      echo "Node.js: $(node --version)"
    fi
    run_pnpm --version
    ;;
  gen)
    "${repository_root}/scripts/sync-browser-integration.sh"
    configure_brave_python
    touch_brave_overrides
    (
      cd "${chromium_directory}"
      buildtools/mac/gn gen "${output_directory}"
    )
    ;;
  probe-check)
    "${repository_root}/scripts/sync-browser-integration.sh"
    configure_brave_python
    touch_brave_overrides
    (
      cd "${chromium_directory}"
      buildtools/mac/gn gen "${output_directory}"
      autoninja_arguments=(-C "${output_directory}")
      if [[ -n "${brave_jobs}" ]]; then
        if [[ ! "${brave_jobs}" =~ ^[1-9][0-9]*$ ]]; then
          echo "REB_BRAVE_JOBS must be a positive integer." >&2
          exit 2
        fi
        autoninja_arguments+=("-j${brave_jobs}")
      fi
      autoninja "${autoninja_arguments[@]}" "${probe_objects[@]}" \
        "${web_audio_objects[@]}" \
        brave/components/reverse_engineering_browser:native_artifact_body_tee_unittests \
        brave/components/reverse_engineering_browser:native_probe_sink_unittests
      generated_bindings="${output_directory}/gen/third_party/blink/renderer/bindings/modules/v8"
      generated_core_bindings="${output_directory}/gen/third_party/blink/renderer/bindings/core/v8"
      declare -a generated_probe_expectations=(
        "v8_gpu_adapter_info.cc:GPUAdapterInfo.vendor"
        "v8_gpu_supported_limits.cc:GPUSupportedLimits.maxTextureDimension2D"
        "v8_html_iframe_element.cc:HTMLIFrameElement.contentWindow"
        "v8_media_device_info.cc:MediaDeviceInfo.deviceId"
        "v8_navigator.cc:Navigator.userAgent"
        "v8_permissions.cc:Permissions.query"
        "v8_rtc_peer_connection.cc:RTCPeerConnection.getStats"
        "v8_screen.cc:Screen.width"
        "v8_storage.cc:Storage.getItem"
        "v8_speech_synthesis_voice.cc:SpeechSynthesisVoice.voiceURI"
        "v8_webgl_rendering_context.cc:WebGLRenderingContext.getSupportedExtensions"
        "v8_window.cc:Window.devicePixelRatio"
      )
      for expectation in "${generated_probe_expectations[@]}"; do
        generated_file="${expectation%%:*}"
        operation="${expectation#*:}"
        if ! generated_probe_present "${generated_bindings}/${generated_file}" "${operation}"; then
          echo "Generated fingerprint probe is missing: ${operation}" >&2
          exit 1
        fi
      done
      declare -a generated_core_probe_expectations=(
        "v8_element.cc:Element.getBoundingClientRect"
        "v8_performance.cc:Performance.now"
        "v8_svg_graphics_element.cc:SVGGraphicsElement.getBBox"
      )
      for expectation in "${generated_core_probe_expectations[@]}"; do
        generated_file="${expectation%%:*}"
        operation="${expectation#*:}"
        if ! generated_probe_present "${generated_core_bindings}/${generated_file}" "${operation}"; then
          echo "Generated fingerprint probe is missing: ${operation}" >&2
          exit 1
        fi
      done
      declare -a excluded_core_probe_expectations=(
        "v8_document.cc:Document.createElement"
        "v8_element.cc:Element.classList"
        "v8_html_element.cc:HTMLElement.style"
        "v8_window.cc:Window.performance"
      )
      for expectation in "${excluded_core_probe_expectations[@]}"; do
        generated_file="${expectation%%:*}"
        operation="${expectation#*:}"
        if generated_probe_present "${generated_core_bindings}/${generated_file}" "${operation}"; then
          echo "Routine DOM operation was incorrectly generated as a fingerprint probe: ${operation}" >&2
          exit 1
        fi
      done
      if ! generated_probe_present "${generated_bindings}/v8_gpu.cc" 'GPU.requestAdapter'; then
        echo "Generated fingerprint probe is missing: GPU.requestAdapter" >&2
        exit 1
      fi
      if ! grep -Fq 'kRebMathAcos' "${chromium_directory}/v8/src/builtins/math.tq"; then
        echo "V8 Math fingerprint probes are missing." >&2
        exit 1
      fi
      "${output_directory}/native_artifact_body_tee_unittests"
      "${output_directory}/native_probe_sink_unittests"
    )
    ;;
  build|start)
    (
      cd "${brave_directory}"
      run_pnpm run "${command_name}" "$@"
    )
    ;;
  *)
    echo "Unknown command: ${command_name}" >&2
    usage >&2
    exit 2
    ;;
esac
