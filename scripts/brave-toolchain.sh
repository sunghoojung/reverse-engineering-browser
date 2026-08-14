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
readonly probe_objects=(
  "obj/brave/components/reverse_engineering_browser/renderer/native_probe_sink.o"
  "obj/brave/components/reverse_engineering_browser/renderer/native_probe_transport.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_network_capture_sink.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_probe_host.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_probe_session.o"
  "obj/brave/components/reverse_engineering_browser/browser/native_probe_socket_client.o"
  "obj/brave/browser/core/brave_proxying_url_loader_factory.o"
  "obj/brave/browser/core/brave_content_browser_client.o"
  "obj/chrome/renderer/renderer/brave_content_renderer_client.o"
  "obj/third_party/blink/renderer/platform/loader/loader/resource_request_sender.o"
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
    (
      cd "${chromium_directory}"
      buildtools/mac/gn gen "${output_directory}"
    )
    ;;
  probe-check)
    "${repository_root}/scripts/sync-browser-integration.sh"
    configure_brave_python
    (
      cd "${chromium_directory}"
      buildtools/mac/gn gen "${output_directory}"
      autoninja -C "${output_directory}" "${probe_objects[@]}"
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
