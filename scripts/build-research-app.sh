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
decoder_service_source="${repo_root}/apps/research-ui/macos/DecoderService.swift"
decoder_binary="${repo_root}/build/reb-decoder"
icon_source="${repo_root}/apps/research-ui/macos/assets/origin-trace-icon.png"
event_store="${repo_root}/build/sessions/demo.jsonl"
trace_store="${repo_root}/build/sessions/origin-trace.jsonl"
signal_store="${repo_root}/build/sessions/request-signals.jsonl"
artifact_store="${repo_root}/build/sessions/artifacts"
iconset_path="${repo_root}/build/OriginTrace.iconset"

if [[ -e "${app_path}" ]]; then
  rm -rf "${app_path}"
fi

mkdir -p "${macos_path}" "${resources_path}"
cp "${repo_root}/apps/research-ui/macos/Info.plist" "${contents_path}/Info.plist"
cp "${repo_root}/apps/research-ui/index.html" "${resources_path}/index.html"
cp "${analyst_runner_core}" "${resources_path}/analyst_runner_core.js"
cp "${decoder_binary}" "${macos_path}/OriginTraceDecoder"
chmod 755 "${macos_path}/OriginTraceDecoder"
cp "${event_store}" "${resources_path}/demo.jsonl"
cp "${trace_store}" "${resources_path}/origin-trace.jsonl"
cp "${signal_store}" "${resources_path}/request-signals.jsonl"
cp -R "${artifact_store}" "${resources_path}/artifacts"

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
  "${swift_source}" "${trace_document_source}" "${decoder_service_source}" \
  -o "${macos_path}/OriginTrace"

xcrun swiftc \
  -parse-as-library \
  -framework JavaScriptCore \
  "${analyst_runner_source}" \
  -o "${macos_path}/OriginTraceAnalystRunner"

codesign --force --deep --sign - "${app_path}" >/dev/null
echo "Built ${app_path}"
