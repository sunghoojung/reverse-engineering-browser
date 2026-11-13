#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Origin Trace application builds currently require macOS" >&2
  exit 1
fi

# The native smoke checks run by default. REB_APP_SMOKE_CHECKS=0 builds the
# same bundle without them; CI's rendered-UI job uses it because the
# macos-package job of the same run executes every one on the same source.
# The agent CLI stand-in is always built: the rendered UI runs it as Claude.
smoke_checks="${REB_APP_SMOKE_CHECKS:-1}"
case "${smoke_checks}" in
  0 | 1) ;;
  *)
    echo "REB_APP_SMOKE_CHECKS must be 0 or 1, not ${smoke_checks}" >&2
    exit 2
    ;;
esac
smoke() {
  if [[ "${smoke_checks}" == 1 ]]; then
    "$@"
  fi
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
final_app_path="${repo_root}/build/Origin Trace.app"
# Assemble and sign a private copy, then replace the bundle in one rename. A
# failed or interrupted build leaves the previous complete bundle, never an
# unsigned partial one that only looks like an app.
mkdir -p "${repo_root}/build"
staging_root="$(mktemp -d "${repo_root}/build/.origin-trace-app.XXXXXX")"
trap 'rm -rf "${staging_root}"' EXIT
app_path="${staging_root}/Origin Trace.app"
contents_path="${app_path}/Contents"
macos_path="${contents_path}/MacOS"
resources_path="${contents_path}/Resources"
swift_source="${repo_root}/apps/research-ui/macos/OriginTraceApp.swift"
stored_event_window_source="${repo_root}/apps/research-ui/macos/StoredEventWindow.swift"
stored_evidence_backend_source="${repo_root}/apps/research-ui/macos/StoredEvidenceBackend.swift"
trace_document_source="${repo_root}/apps/research-ui/macos/OriginTraceDocument.swift"
workspace_lease_source="${repo_root}/apps/research-ui/macos/NativeWorkspaceLease.swift"
analyst_runner_source="${repo_root}/apps/research-ui/macos/AnalystRunner.swift"
close_smoke_source="${repo_root}/apps/research-ui/macos/NativeCloseGuardSmoke.swift"
close_guard_source="${repo_root}/apps/research-ui/macos/NativeCloseGuard.swift"
client_project_export_source="${repo_root}/apps/research-ui/macos/ClientProjectExport.swift"
client_project_smoke_source="${repo_root}/apps/research-ui/macos/ClientProjectExportSmoke.swift"
live_session_source="${repo_root}/apps/research-ui/macos/LiveSessionCoordinator.swift"
decoder_service_source="${repo_root}/apps/research-ui/macos/DecoderService.swift"
decoder_binary="${repo_root}/build/reb-decoder"
deobfuscation_service_source="${repo_root}/apps/research-ui/macos/DeobfuscationService.swift"
wasm_service_source="${repo_root}/apps/research-ui/macos/WasmService.swift"
agent_core_source="${repo_root}/apps/research-ui/macos/AgentCore.swift"
agent_bridge_source="${repo_root}/apps/research-ui/macos/AgentBridge.swift"
session_panel_source="${repo_root}/apps/research-ui/macos/SessionPanel.swift"
agent_cli_source="${repo_root}/apps/research-ui/macos/AgentCLI.swift"
agent_chatgpt_source="${repo_root}/apps/research-ui/macos/AgentChatGPTAuth.swift"
cargo build --locked --release --manifest-path "${repo_root}/apps/deobfuscator-worker/Cargo.toml"
deobfuscation_binary="${repo_root}/apps/deobfuscator-worker/target/release/reb-deobfuscator-worker"
icon_source="${repo_root}/apps/research-ui/macos/assets/origin-trace-icon.png"
iconset_path="${repo_root}/build/OriginTrace.iconset"
research_ui_resources="${resources_path}/research-ui"

mkdir -p "${macos_path}" "${resources_path}"
cp "${repo_root}/apps/research-ui/macos/Info.plist" "${contents_path}/Info.plist"
# Remember a reused local browser output without copying its source or bundle.
# This optional hint never substitutes for the runtime bundle/executable checks.
REB_PACKAGE_REPOSITORY="${repo_root}" REB_PACKAGE_RESOURCES="${resources_path}" \
  REB_PACKAGE_HEAD="$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || echo unknown)" python3 - <<'PY'
import json
import os
from pathlib import Path
import plistlib

root = Path(os.environ["REB_PACKAGE_REPOSITORY"])
brave = os.environ.get("REB_BRAVE_DIRECTORY")
receipt = root / "build/integrated-brave-state.json"
if not brave and receipt.is_file():
    state = json.loads(receipt.read_text())
    brave = state.get("brave")
    head = os.environ["REB_PACKAGE_HEAD"]
    if state.get("integration") != head:
        # Only a location hint; the launcher's own checks still govern the browser.
        print(f"Note: BraveBuild.plist names the Brave checkout recorded for integration "
              f"{state.get('integration')}, not this source {head}; rebuild Brave to pair them.")
output = os.environ.get("REB_BRAVE_OUTPUT_DIRECTORY")
if not output:
    output = Path(brave).parent / "out/Component_arm64" if brave else root / "browser/worktree/src/out/Component_arm64"
application = Path(output) / "Brave Browser Development.app"
if application.is_dir():
    configuration = Path(os.environ["REB_PACKAGE_RESOURCES"]) / "BraveBuild.plist"
    with configuration.open("wb") as destination:
        plistlib.dump({"ApplicationPath": str(application.resolve())}, destination)
PY
mkdir -p "${research_ui_resources}"
# One explicit packaged copy serves both the native scheme and live HTTP UI.
for asset in index.html app.css block_graph.css block_graph.js block_graph_layout.js graph_layout_client.js flow_graph.css flow_graph.js flow_graph_layout.js flow_timeline.js flow_workspace.css flow_workspace.js entropy_map.css entropy_map.js command_palette.js app_state.js evidence_models.js evidence_package.js float32_inspector.js evidence_comparison.js source_syntax.js source_format.js code_view.js source_facts.js source_search.js source_tree.js traffic_view.js traffic_payload.js traffic_index.js traffic_filter.js traffic_columns.js traffic_overview.js network_scope.js request_tabs.js traffic_response.js traffic_headers.js traffic_cookies.js captured_client.js captured_export_formats.js vm_debugger.js vm_static.js vm_static_view.js vm_contextual.js vm_contextual_evidence.js vm_contextual_view.js vm_analysis_packs.js vm_opcode_ledger.js vm_opcode_ledger_view.js vm_semantics.js pane_layout.js native_console_completion.js native_console.js investigation_navigation.js investigation_notebook.js evidence_names.js wasm_function_names.js invocation_sites.js request_stack.js app.js agent_panel.js agent_panel.css session_panel.js session_panel.css vm_program_workspace.js xrefs_view.js xrefs_view.css wasm_runner.js wasm_runner.css debugger_sidebar.js debugger_sidebar.css debugger_pause.js debugger_pause.css analyst_runner_core.js analyst_runner_node.js; do
  cp "${repo_root}/apps/research-ui/${asset}" "${research_ui_resources}/${asset}"
done
# The agent dock's LangGraph loop: one browser bundle per provider, built from
# the lockfile and loaded from these resources only when the agent is turned on.
"${repo_root}/scripts/build-agent-runtime.sh" "${repo_root}/build/agent-runtime"
for provider in claude chatgpt; do
  cp "${repo_root}/build/agent-runtime/agent_runtime_${provider}.js" "${research_ui_resources}/agent_runtime_${provider}.js"
done
cp "${repo_root}/build/agent-runtime/agent_runtime.LICENSES.txt" "${resources_path}/AgentRuntimeLicenses.txt"
node "${repo_root}/tools/check-agent-runtime.mjs" \
  "${research_ui_resources}/agent_runtime_claude.js" "${research_ui_resources}/agent_runtime_chatgpt.js"
cargo build --locked --release --manifest-path "${repo_root}/apps/origin-trace-backend/Cargo.toml"
# The backend links the vendored Triskel (MPL-2.0) and {fmt} (MIT) graph layout
# code. Ship both notices and where Triskel's source is; see
# apps/origin-trace-backend/vendor/README.md.
graph_layout_vendor="${repo_root}/apps/origin-trace-backend/vendor"
triskel_revision="196ba112eba992c1460af3097c038defcf7a7e45"
{
  echo "OriginTraceBackend includes these projects, unmodified, for graph layout."
  echo
  echo "Triskel, commit ${triskel_revision}, under the Mozilla Public License 2.0."
  echo "Source: https://github.com/triskellib/triskel/tree/${triskel_revision}"
  echo "The compiled files are lib/include and lib/src without lib/src/renderer and"
  echo "lib/src/llvm, also in this application's source at"
  echo "apps/origin-trace-backend/vendor/triskel."
  echo
  cat "${graph_layout_vendor}/triskel/LICENSE"
  echo
  echo "{fmt} 12.2.0, header only, under the MIT license."
  echo "Source: https://github.com/fmtlib/fmt/tree/12.2.0"
  echo
  cat "${graph_layout_vendor}/fmt/LICENSE"
} > "${resources_path}/GraphLayoutLicenses.txt"
cp "${repo_root}/apps/origin-trace-backend/target/release/origin-trace-backend" "${macos_path}/OriginTraceBackend"
cp "${repo_root}/apps/origin-trace-backend/target/release/origin-trace-vm" "${macos_path}/OriginTraceVMAnalyzer"
cp "${repo_root}/apps/origin-trace-backend/target/release/reb-api" "${macos_path}/OriginTraceAPI"
cp "${repo_root}/apps/origin-trace-backend/target/release/origin-trace-wasm" "${macos_path}/OriginTraceWasmInspector"
chmod 755 "${macos_path}/OriginTraceWasmInspector"
chmod 755 "${macos_path}/OriginTraceBackend" "${macos_path}/OriginTraceVMAnalyzer" "${macos_path}/OriginTraceAPI"
cp "${repo_root}/scripts/run-live-session.sh" "${resources_path}/run-live-session.sh"
chmod 755 "${resources_path}/run-live-session.sh"
cp "${decoder_binary}" "${macos_path}/OriginTraceDecoder"
chmod 755 "${macos_path}/OriginTraceDecoder"
cp "${repo_root}/build/reb-event-broker" "${macos_path}/OriginTraceEventBroker"
cp "${repo_root}/build/reb-artifact-receiver" "${macos_path}/OriginTraceArtifactReceiver"
# Never retain a retired transport in an incrementally rebuilt app bundle.
rm -f "${macos_path}/OriginTraceDebuggerTransport"
cp "${repo_root}/build/reb-native-vm-fixture" "${macos_path}/OriginTraceOwnedVmFixture"
chmod 755 "${macos_path}/OriginTraceOwnedVmFixture"
cp "${repo_root}/build/reb-console" "${macos_path}/OriginTraceNativeConsole"
chmod 755 "${macos_path}/OriginTraceNativeConsole"
cp "${repo_root}/build/reb-heap-snapshot" "${macos_path}/OriginTraceHeapSnapshot"
chmod 755 \
  "${macos_path}/OriginTraceEventBroker" \
  "${macos_path}/OriginTraceArtifactReceiver" \
  "${macos_path}/OriginTraceHeapSnapshot"
cp "${deobfuscation_binary}" "${macos_path}/OriginTraceDeobfuscator"
chmod 755 "${macos_path}/OriginTraceDeobfuscator"
rm -rf "${iconset_path}"
mkdir -p "${iconset_path}"

render_icon() {
  local pixels="$1"
  local filename="$2"
  sips -z "${pixels}" "${pixels}" "${icon_source}" \
    --out "${iconset_path}/${filename}" >/dev/null
}

render_icon 16 icon_16x16.png
render_icon 32 icon_16x16@2x.png
render_icon 32 icon_32x32.png
render_icon 64 icon_32x32@2x.png
render_icon 128 icon_128x128.png
render_icon 256 icon_128x128@2x.png
render_icon 256 icon_256x256.png
render_icon 512 icon_256x256@2x.png
render_icon 512 icon_512x512.png
render_icon 1024 icon_512x512@2x.png
xcrun iconutil -c icns "${iconset_path}" -o "${resources_path}/OriginTrace.icns"

if [[ "${smoke_checks}" == 0 ]]; then
  echo "Skipping the native smoke checks (REB_APP_SMOKE_CHECKS=0)."
fi

smoke xcrun swiftc -parse-as-library \
  "${workspace_lease_source}" "${repo_root}/apps/research-ui/macos/NativeWorkspaceLeaseChecks.swift" \
  -o "${repo_root}/build/check-native-workspace-lease"
smoke "${repo_root}/build/check-native-workspace-lease"
smoke env REB_WORKSPACE_LEASE_TEST_HELPER="${repo_root}/build/check-native-workspace-lease" \
  cargo test --locked --manifest-path "${repo_root}/apps/origin-trace-backend/Cargo.toml" \
  workspace_native_lock_interoperability -- --ignored

smoke xcrun swiftc -parse-as-library \
  "${trace_document_source}" "${repo_root}/tools/check-origin-trace-gaps.swift" \
  -o "${repo_root}/build/check-origin-trace-gaps"
smoke "${repo_root}/build/check-origin-trace-gaps" \
  "${repo_root}/apps/origin-trace-backend/assets/origin-trace-gap-cases.json" \
  "${repo_root}/apps/origin-trace-backend/assets/origin-trace-invocation-cases.json"

smoke xcrun swiftc -parse-as-library \
  "${live_session_source}" "${repo_root}/tools/check-live-session-failure.swift" \
  -o "${repo_root}/build/check-live-session-failure"
smoke "${repo_root}/build/check-live-session-failure"

xcrun swiftc -parse-as-library \
  "${agent_core_source}" "${agent_cli_source}" "${agent_chatgpt_source}" "${repo_root}/tools/check-agent-core.swift" \
  "${repo_root}/tools/check-agent-subscriptions.swift" "${repo_root}/tools/agent-cli-stand-in.swift" \
  -o "${repo_root}/build/check-agent-core"
smoke "${repo_root}/build/check-agent-core" "${repo_root}/apps/origin-trace-backend/target/release/reb-api"

smoke node "${repo_root}/tools/check-captured-client-project.mjs"
smoke xcrun swiftc -parse-as-library -framework Cocoa -framework WebKit \
  "${client_project_export_source}" "${repo_root}/tools/check-client-project-export.swift" \
  -o "${repo_root}/build/check-client-project-export"
smoke "${repo_root}/build/check-client-project-export" \
  "${repo_root}/build/client-project-qa/authored-example.zip"

smoke xcrun swiftc -parse-as-library \
  "${stored_event_window_source}" "${repo_root}/tools/check-stored-event-window.swift" \
  -o "${repo_root}/build/check-stored-event-window"
smoke "${repo_root}/build/check-stored-event-window"

smoke xcrun swiftc -parse-as-library \
  "${stored_evidence_backend_source}" "${repo_root}/tools/check-stored-evidence-backend.swift" \
  -o "${repo_root}/build/check-stored-evidence-backend"
smoke "${repo_root}/build/check-stored-evidence-backend" "${macos_path}/OriginTraceBackend"

xcrun swiftc \
  -parse-as-library \
  -framework Cocoa \
  -framework WebKit \
  -framework Security \
  "${swift_source}" "${stored_event_window_source}" "${stored_evidence_backend_source}" "${trace_document_source}" "${workspace_lease_source}" "${decoder_service_source}" "${deobfuscation_service_source}" "${wasm_service_source}" "${agent_core_source}" "${agent_cli_source}" "${agent_chatgpt_source}" "${agent_bridge_source}" "${session_panel_source}" "${live_session_source}" "${close_guard_source}" "${close_smoke_source}" "${client_project_export_source}" "${client_project_smoke_source}" \
  -o "${macos_path}/OriginTrace"

"${macos_path}/OriginTrace" --check-native-ui-url

xcrun swiftc \
  -parse-as-library \
  -framework JavaScriptCore \
  "${analyst_runner_source}" \
  -o "${macos_path}/OriginTraceAnalystRunner"

codesign --force --deep --sign - "${app_path}" >/dev/null
rm -rf "${final_app_path}"
mv "${app_path}" "${final_app_path}"
echo "Built ${final_app_path}"
