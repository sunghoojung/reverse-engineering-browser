#!/usr/bin/env bash
# Actual sink/lifecycle/queue, narrow pinned Chromium type boundaries only.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly root
build="$(mktemp -d)"
readonly build
trap 'rm -rf "$build"' EXIT
fixture="$root/tools/native-network-capture"
readonly fixture
mkdir -p "$build/include"
ln -s "$root/browser/integration/brave/overlay" "$build/include/brave"
headers=(
  build/build_config.h base/containers/span.h base/no_destructor.h
  base/files/file_path.h base/process/process_handle.h base/threading/platform_thread.h
  base/time/time.h content/public/browser/browser_context.h net/http/http_response_headers.h
  net/url_request/redirect_info.h services/network/public/cpp/resource_request.h
  services/network/public/cpp/url_loader_completion_status.h
  services/network/public/mojom/url_response_head.mojom.h
  brave/components/reverse_engineering_browser/browser/native_probe_session.h
)
for header in "${headers[@]}"; do
  mkdir -p "$build/stubs/$(dirname "$header")"
  printf '#include "chromium_stubs.h"\n' >"$build/stubs/$header"
done
flags=(-std=c++20 -O2 -g -pthread -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror)
if [[ -n "${REB_PROBE_TEST_SANITIZERS:-}" ]]; then
  flags+=(-O1 "-fsanitize=${REB_PROBE_TEST_SANITIZERS}" -fno-omit-frame-pointer)
fi
sources="$root/browser/integration/brave/overlay/components/reverse_engineering_browser"
readonly sources
"${CXX:-c++}" "${flags[@]}" -I"$fixture" -I"$build/stubs" -I"$build/include" \
  "$fixture/main.cc" "$sources/browser/native_network_capture_sink.cc" \
  "$sources/common/native_probe_queue.cc" -o "$build/native-network-capture"
"$build/native-network-capture"

"${CXX:-c++}" "${flags[@]}" -I"$fixture" -I"$build/stubs" -I"$build/include" \
  "$fixture/ipc.cc" "$sources/browser/native_local_ipc_client.cc" -o "$build/native-network-ipc"
"$build/native-network-ipc" "$build"
