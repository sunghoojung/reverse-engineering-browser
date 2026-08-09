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
event_store="${repo_root}/build/sessions/demo.jsonl"

if [[ -e "${app_path}" ]]; then
  rm -rf "${app_path}"
fi

mkdir -p "${macos_path}" "${resources_path}"
cp "${repo_root}/apps/research-ui/macos/Info.plist" "${contents_path}/Info.plist"
cp "${repo_root}/apps/research-ui/index.html" "${resources_path}/index.html"
cp "${event_store}" "${resources_path}/demo.jsonl"

xcrun swiftc \
  -parse-as-library \
  -framework Cocoa \
  -framework WebKit \
  "${swift_source}" \
  -o "${macos_path}/OriginTrace"

codesign --force --deep --sign - "${app_path}" >/dev/null
echo "Built ${app_path}"
