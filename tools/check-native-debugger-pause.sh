#!/usr/bin/env bash
# The pausing debugger overlay, compiled on the host against stand-in
# declarations of the pinned Chromium, Blink and Mojo types. No machine in
# this project can build Brave, and three rounds of review each found code
# here that a compiler would have refused, so this is where name lookup,
# overload resolution, conversions and const-correctness get checked.
# Compile-only: the stand-ins declare without defining, and the result is
# never run.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly root
build="$(mktemp -d)"
readonly build
trap 'rm -rf "$build"' EXIT
fixture="$root/tools/native-debugger-pause"
readonly fixture
overlay="$root/browser/integration/brave/overlay"
readonly overlay
sources="$overlay/components/reverse_engineering_browser"
readonly sources

mkdir -p "$build/include"
ln -s "$overlay" "$build/include/brave"

# Each pinned header the overlay includes resolves to the stand-ins.
headers=(
  build/build_config.h
  base/command_line.h base/files/file_path.h base/files/scoped_file.h
  base/functional/bind.h base/functional/callback.h base/functional/callback_forward.h
  base/functional/callback_helpers.h base/memory/ref_counted.h
  base/json/json_reader.h base/json/json_writer.h
  base/memory/raw_ptr.h base/memory/ref_counted.h base/memory/scoped_refptr.h
  base/memory/weak_ptr.h base/no_destructor.h base/posix/eintr_wrapper.h
  base/strings/string_number_conversions.h base/strings/string_util.h
  base/synchronization/waitable_event.h base/task/bind_post_task.h
  base/task/single_thread_task_runner.h base/task/single_thread_task_runner_thread_mode.h
  base/task/thread_pool.h base/threading/platform_thread.h base/time/time.h
  base/timer/timer.h base/unguessable_token.h base/values.h
  base/component_export.h base/containers/span.h base/check.h base/check_op.h
  content/public/browser/browser_thread.h content/public/browser/render_frame_host.h
  content/public/browser/render_process_host.h content/public/renderer/render_frame.h
  content/public/renderer/render_frame_observer.h
  mojo/public/cpp/bindings/associated_receiver.h mojo/public/cpp/bindings/associated_remote.h
  mojo/public/cpp/bindings/receiver.h mojo/public/cpp/bindings/remote.h
  third_party/blink/public/common/associated_interfaces/associated_interface_provider.h
  third_party/blink/public/common/associated_interfaces/associated_interface_registry.h
  third_party/blink/public/platform/platform.h third_party/blink/public/platform/web_common.h
  third_party/blink/public/web/web_document.h third_party/blink/public/web/web_local_frame.h
  third_party/blink/public/web/web_local_frame_client.h
  brave/components/reverse_engineering_browser/browser/native_console_session.h
  brave/components/reverse_engineering_browser/common/native_console_io.h
  brave/components/reverse_engineering_browser/common/native_probe_event.h
  brave/components/reverse_engineering_browser/renderer/native_debugger_observation.h
  brave/components/reverse_engineering_browser/renderer/native_request_stack.h
  brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h
)
for header in "${headers[@]}"; do
  mkdir -p "$build/stubs/$(dirname "$header")"
  printf '#include "chromium_stubs.h"\n' >"$build/stubs/$header"
done

# The overlay's own stand-ins: what the mojom generator would emit, and the
# pieces of sibling overlay headers these files use.
mkdir -p "$build/stubs/brave/components/reverse_engineering_browser/common"
printf '#include "mojom_stubs.h"\n' \
  >"$build/stubs/brave/components/reverse_engineering_browser/common/native_debugger_pause.mojom.h"
printf '#include "overlay_stubs.h"\n' \
  >"$build/stubs/brave/components/reverse_engineering_browser/common/native_probe_event.h"
printf '#include "overlay_stubs.h"\n' \
  >"$build/stubs/brave/components/reverse_engineering_browser/common/native_console_io.h"
printf '#include "overlay_stubs.h"\n' \
  >"$build/stubs/brave/components/reverse_engineering_browser/browser/native_console_session.h"
printf '#include "overlay_stubs.h"\n' \
  >"$build/stubs/brave/components/reverse_engineering_browser/renderer/native_request_stack.h"
printf '#include "overlay_stubs.h"\n' \
  >"$build/stubs/brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h"
printf '#include "overlay_stubs.h"\n' \
  >"$build/stubs/brave/components/reverse_engineering_browser/renderer/native_debugger_observation.h"

# Patch 0050's new public header is the real one: it is extracted from the
# patch, so the overlay is compiled against exactly the declarations the
# patch adds rather than a copy of them that could drift.
mkdir -p "$build/stubs/third_party/blink/public/web"
python3 - "$root/browser/integration/brave/patches/chromium/0050-attach-an-in-process-inspector-session.patch" \
  "$build/stubs/third_party/blink/public/web/web_native_debugger.h" <<'PY'
import sys

patch, out = sys.argv[1], sys.argv[2]
want = "+++ b/third_party/blink/public/web/web_native_debugger.h"
lines = open(patch, encoding="utf-8").read().split("\n")
try:
    start = lines.index(want)
except ValueError:
    sys.exit("patch 0050 no longer adds web_native_debugger.h")
body = []
for line in lines[start + 1:]:
    if line.startswith("diff --git "):
        break
    if line.startswith("@@"):
        continue
    if line.startswith("+"):
        body.append(line[1:])
if not body:
    sys.exit("extracted no web_native_debugger.h body from patch 0050")
open(out, "w", encoding="utf-8").write("\n".join(body) + "\n")
PY

# The repository's own strict set, less the one warning Chromium's build
# disables: unused parameters are ordinary in an interface implementation, and
# this harness checks what a Chromium build checks.
flags=(-std=c++20 -O1 -g -pthread -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
  -Wshadow -Wno-unused-parameter -Werror -fsyntax-only)
"${CXX:-c++}" "${flags[@]}" -I"$fixture" -I"$build/stubs" -I"$build/include" -I"$root/include" \
  "$fixture/main.cc" \
  "$sources/renderer/native_debugger_pause_session.cc" \
  "$sources/renderer/native_debugger_pause_agent.cc" \
  "$sources/browser/native_debugger_pause_host.cc"
echo "PASS native debugger pause overlay compiles against the pinned declarations (compile-only; no Chromium available)"
