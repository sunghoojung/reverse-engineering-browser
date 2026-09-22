#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Origin Trace application builds currently require macOS" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app_path="${repo_root}/build/Origin Trace.app"
contents_path="${app_path}/Contents"
macos_path="${contents_path}/MacOS"
resources_path="${contents_path}/Resources"
swift_source="${repo_root}/apps/research-ui/macos/OriginTraceApp.swift"
trace_document_source="${repo_root}/apps/research-ui/macos/OriginTraceDocument.swift"
analyst_runner_source="${repo_root}/apps/research-ui/macos/AnalystRunner.swift"
analyst_runner_core="${repo_root}/apps/research-ui/analyst_runner_core.js"
live_session_source="${repo_root}/apps/research-ui/macos/LiveSessionCoordinator.swift"
decoder_service_source="${repo_root}/apps/research-ui/macos/DecoderService.swift"
decoder_binary="${repo_root}/build/reb-decoder"
deobfuscation_service_source="${repo_root}/apps/research-ui/macos/DeobfuscationService.swift"
cargo build --locked --release --manifest-path "${repo_root}/apps/deobfuscator-worker/Cargo.toml"
deobfuscation_binary="${repo_root}/apps/deobfuscator-worker/target/release/reb-deobfuscator-worker"
icon_source="${repo_root}/apps/research-ui/macos/assets/origin-trace-icon.png"
iconset_path="${repo_root}/build/OriginTrace.iconset"
research_ui_resources="${resources_path}/research-ui"

if [[ -e "${app_path}" ]]; then
  rm -rf "${app_path}"
fi

mkdir -p "${macos_path}" "${resources_path}"
cp "${repo_root}/apps/research-ui/macos/Info.plist" "${contents_path}/Info.plist"
for asset in index.html app.css app_state.js evidence_models.js source_syntax.js traffic_view.js app.js; do
  cp "${repo_root}/apps/research-ui/${asset}" "${resources_path}/${asset}"
done
mkdir -p "${research_ui_resources}/debugger"
find "${repo_root}/apps/research-ui" -maxdepth 1 -type f \
  \( -name '*.py' -o -name '*.js' -o -name '*.html' -o -name '*.css' \) \
  -exec cp {} "${research_ui_resources}/" \;
find "${repo_root}/apps/research-ui/debugger" -maxdepth 1 -type f -name '*.py' \
  -exec cp {} "${research_ui_resources}/debugger/" \;
cp "${repo_root}/scripts/run-live-session.sh" "${resources_path}/run-live-session.sh"
chmod 755 "${resources_path}/run-live-session.sh"
cp "${analyst_runner_core}" "${resources_path}/analyst_runner_core.js"
cp "${decoder_binary}" "${macos_path}/OriginTraceDecoder"
chmod 755 "${macos_path}/OriginTraceDecoder"
cp "${repo_root}/build/reb-event-broker" "${macos_path}/OriginTraceEventBroker"
cp "${repo_root}/build/reb-artifact-receiver" "${macos_path}/OriginTraceArtifactReceiver"
cp "${repo_root}/build/reb-debugger-transport" "${macos_path}/OriginTraceDebuggerTransport"
cp "${repo_root}/build/reb-heap-snapshot" "${macos_path}/OriginTraceHeapSnapshot"
chmod 755 \
  "${macos_path}/OriginTraceEventBroker" \
  "${macos_path}/OriginTraceArtifactReceiver" \
  "${macos_path}/OriginTraceDebuggerTransport" \
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

xcrun swiftc \
  -parse-as-library \
  -framework Cocoa \
  -framework WebKit \
  "${swift_source}" "${trace_document_source}" "${decoder_service_source}" "${deobfuscation_service_source}" "${live_session_source}" \
  -o "${macos_path}/OriginTrace"

xcrun swiftc \
  -parse-as-library \
  -framework JavaScriptCore \
  "${analyst_runner_source}" \
  -o "${macos_path}/OriginTraceAnalystRunner"

codesign --force --deep --sign - "${app_path}" >/dev/null
echo "Built ${app_path}"
