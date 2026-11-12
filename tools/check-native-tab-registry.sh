#!/usr/bin/env bash
# The production tab registry, factory scope and owner hook against narrow
# pinned content API stand-ins (tools/native-tab-registry/chromium_stubs.h).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly root
build="$(mktemp -d)"
readonly build
trap 'rm -rf "$build"' EXIT
fixture="$root/tools/native-tab-registry"
readonly fixture
mkdir -p "$build/include"
ln -s "$root/browser/integration/brave/overlay" "$build/include/brave"
headers=(
  base/command_line.h base/component_export.h base/no_destructor.h base/unguessable_token.h
  content/public/browser/browser_context.h content/public/browser/child_process_security_policy.h
  content/public/browser/dedicated_worker_service.h content/public/browser/render_frame_host.h
  content/public/browser/service_worker_context.h
  content/public/browser/service_worker_context_observer.h
  content/public/browser/service_worker_running_info.h content/public/browser/shared_worker_service.h
  content/public/browser/storage_partition.h content/public/browser/web_contents.h
  url/gurl.h url/origin.h
  brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h
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
"${CXX:-c++}" "${flags[@]}" -I"$fixture" -I"$build/stubs" -I"$build/include" "$fixture/main.cc" \
  "$sources/browser/native_tab_registry.cc" "$sources/browser/native_factory_scope.cc" \
  "$sources/browser/native_tab_resolver.cc" "$sources/common/native_factory_owner_hook.cc" \
  -o "$build/native-tab-registry"
"$build/native-tab-registry"
