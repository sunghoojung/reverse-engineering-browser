#!/usr/bin/env bash
# Compile real overlay sink/transport/queue against narrow Chromium boundaries.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly root
build="$(mktemp -d)"
readonly build
trap 'rm -rf "$build"' EXIT
fixture="$root/tools/native-probe-admission"
readonly fixture
mkdir -p "$build/include"
ln -s "$root/browser/integration/brave/overlay" "$build/include/brave"
headers=(
  base/component_export.h base/compiler_specific.h base/process/process_handle.h
  base/threading/platform_thread.h base/time/time.h
  base/memory/shared_memory_mapping.h base/memory/unsafe_shared_memory_region.h
  base/no_destructor.h base/threading/thread_local.h base/functional/bind.h
  base/task/sequenced_task_runner.h mojo/public/cpp/base/big_buffer.h
  mojo/public/cpp/bindings/receiver.h mojo/public/cpp/bindings/shared_remote.h
  third_party/blink/public/web/web_local_frame.h
  brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h
)
for header in "${headers[@]}"; do
  mkdir -p "$build/stubs/$(dirname "$header")"
  printf '#include "chromium_stubs.h"\n' >"$build/stubs/$header"
done
# JSON is a Chromium boundary; this suite tests explicit typed native policies.
cat >"$build/stubs/brave/components/reverse_engineering_browser/common/native_wasm_guest_adapter.h" <<'STUB'
#include <memory>
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest.h"
namespace reb { inline std::shared_ptr<const NativeWasmGuestAdapter> ParseNativeWasmGuestAdapter(std::string_view) { return {}; } }
STUB
flags=(-std=c++20 -O2 -g -pthread -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror)
if [[ -n "${REB_PROBE_TEST_SANITIZERS:-}" ]]; then
  flags+=(-O1 "-fsanitize=${REB_PROBE_TEST_SANITIZERS}" -fno-omit-frame-pointer)
fi
sources="$root/browser/integration/brave/overlay/components/reverse_engineering_browser"
readonly sources
"${CXX:-c++}" "${flags[@]}" -I"$fixture" -I"$build/stubs" -I"$build/include" -I"$root/include" \
  "$fixture/main.cc" "$sources/renderer/native_probe_sink.cc" \
  "$sources/renderer/native_probe_transport.cc" "$sources/common/native_probe_queue.cc" \
  "$root/src/analysis/owned_vm_guest_sampler.cpp" \
  "$root/src/analysis/owned_vm_fixture.cpp" \
  "$root/src/analysis/native_vm_recorder.cpp" \
  -o "$build/native-probe-admission"
"$build/native-probe-admission"
