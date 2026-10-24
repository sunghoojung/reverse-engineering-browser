// Component integration, not a browser capture: actual renderer admission,
// browser-assigned script parent, and production event/artifact wire records.
#include "chromium_stubs.h"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_transport.h"

namespace {
constexpr std::uint64_t kSession = 42;
constexpr auto kVmMask = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm);
constexpr auto kForever = std::numeric_limits<std::uint64_t>::max();
reb::NativeProbeQueue renderer_queue;
std::vector<reb::NativeProbeEvent> browser_events;
unsigned artifact_calls = 0;
bool reconfigure_after_accept = false;
bool reconfigure_after_artifact = false;
void Configure();
auto& renderer = reb::NativeProbeSink::Get();
auto& browser = reb::NativeArtifactCaptureSink::Get();
auto& socket = reb::NativeArtifactSocketClient::Get();

bool EmitEvent(const reb::NativeProbeEvent& event, std::uint64_t generation) noexcept {
  const bool accepted = renderer.CanAdmitEvent(event, generation) && renderer_queue.TryPush(event);
  if (accepted && reconfigure_after_accept) {
    reconfigure_after_accept = false;
    Configure();
  }
  return accepted;
}
void EmitBrowserEvent(const reb::NativeProbeEvent& event) noexcept {
  browser_events.push_back(event);
}
void EmitArtifact(reb::NativeArtifactKind kind,
                  reb::NativeArtifactCaptureOrigin origin,
                  std::uint64_t creator,
                  std::uint64_t context,
                  std::uint64_t frame,
                  std::string_view url,
                  std::span<const std::uint8_t> bytes,
                  const reb::NativeRuntimeScript& script) noexcept {
  assert(kind == reb::NativeArtifactKind::kBytecodeBuffer);
  assert(origin == reb::NativeArtifactCaptureOrigin::kRuntimeTypedArray);
  ++artifact_calls;
  // This adapter substitutes only Mojo delivery. Browser parent assignment and
  // validation below are the real product implementation, not fixture authorship.
  base::test_process_id = 202;
  browser.CaptureRuntimeTypedArray(
      101, script.session_id, script.script_id, script.is_eval, creator, context, frame, url,
      mojo_base::BigBuffer(script.source), mojo_base::BigBuffer(bytes));
  base::test_process_id = 101;
  if (reconfigure_after_artifact) {
    reconfigure_after_artifact = false;
    Configure();
  }
}
void Configure() {
  browser.SetEmitter(&EmitBrowserEvent, kSession, kVmMask, kForever);
  renderer.SetEmitters(&EmitEvent, &EmitArtifact, kSession, kVmMask, kForever);
}
void Write(std::ofstream& output, const void* data, std::size_t size) {
  output.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
  assert(output.good());
}
}  // namespace

// The production transport is not linked: its Mojo queue and shared-memory
// mapping stay in the browser. Dispatch samples that reach EmitStatus are
// rejected instead of reported as admitted.
reb::NativeProbeEmitStatus reb::NativeProbeTransport::EmitStatus(const reb::NativeProbeEvent&,
                                                                 std::uint64_t) noexcept {
  return reb::NativeProbeEmitStatus::kRejected;
}

int main(int argc, char* argv[]) {
  assert(argc == 4);  // OUTPUT SOURCE MODE
  const std::filesystem::path output(argv[1]);
  std::ifstream input(argv[2], std::ios::binary);
  assert(input.good());
  const std::string source{std::istreambuf_iterator<char>(input), {}};
  assert(!source.empty());
  const auto source_bytes =
      std::span(reinterpret_cast<const std::uint8_t*>(source.data()), source.size());
  const std::string mode(argv[3]);
  Configure();
  std::array<std::uint8_t, 32> bytes{1, 7, 2, 3, 0};
  reb::NativeRuntimeScript script{9, false, source_bytes};
  auto capture = [&] { renderer.CaptureRuntimeTypedArray(7, 8, "", bytes, script); };

  if (mode == "after-emitter") {
    reconfigure_after_artifact = true;
    capture();
    assert(artifact_calls == 1 && socket.transfers.size() == 2);
    assert(renderer.RuntimeScriptSourceNeeded(7, 9));
    for (unsigned index = 0; index < 16; ++index)
      capture();
    assert(socket.transfers.size() == 19);
  } else if (mode == "reconfigured") {
    reconfigure_after_accept = true;
    capture();
    assert(artifact_calls == 0 && socket.transfers.empty());
    assert(renderer.RuntimeScriptSourceNeeded(7, 9));
    for (unsigned index = 0; index < 16; ++index)
      capture();
    assert(socket.transfers.size() == 17);
  } else if (mode == "full-ring") {
    for (std::size_t index = 0; index < reb::kNativeProbeQueueCapacity; ++index)
      assert(renderer_queue.TryPush({}));
    capture();
    assert(artifact_calls == 0 && socket.transfers.empty());
    assert(renderer.RuntimeScriptSourceNeeded(7, 9));
    reb::NativeProbeEvent discarded;
    while (renderer_queue.TryPop(discarded)) {
    }
    capture();
    assert(artifact_calls == 1 && socket.transfers.size() == 2);
  } else if (mode == "accepted") {
    capture();
    assert(socket.transfers.size() == 2);
    assert(!renderer.RuntimeScriptSourceNeeded(7, 9));
    script.source = {};
    bytes[1] = 19;
    capture();
    assert(socket.transfers.size() == 3);
    assert(socket.transfers[1]->header.parent_artifact_id ==
           socket.transfers[0]->header.artifact_id);
    assert(socket.transfers[2]->header.parent_artifact_id ==
           socket.transfers[0]->header.artifact_id);
  } else if (mode == "scope") {
    capture();
    base::test_process_id = 202;
    // Same URL and numeric script ID must not borrow another renderer/context/frame's parent.
    for (const auto scope : {std::array<std::uint64_t, 3>{102, 7, 8}, {101, 77, 8}, {101, 7, 88}}) {
      const auto before = socket.transfers.size();
      browser.CaptureRuntimeTypedArray(static_cast<int>(scope[0]), kSession, 9, false, 1, scope[1],
                                       scope[2], "script://9", mojo_base::BigBuffer({}),
                                       mojo_base::BigBuffer(bytes));
      assert(socket.transfers.size() == before);
      browser.CaptureRuntimeTypedArray(static_cast<int>(scope[0]), kSession, 9, false, 1, scope[1],
                                       scope[2], "script://9", mojo_base::BigBuffer(source_bytes),
                                       mojo_base::BigBuffer(bytes));
      assert(socket.transfers.size() == before + 2);
      assert(socket.transfers.back()->header.parent_artifact_id ==
             socket.transfers[before]->header.artifact_id);
      assert(socket.transfers.back()->header.parent_artifact_id !=
             socket.transfers[0]->header.artifact_id);
    }
  } else if (mode == "parent-rejected") {
    socket.reject_next = true;
    capture();
    assert(socket.transfers.empty());
    assert(browser_events.size() == 2);
    for (const auto& failed : browser_events)
      assert(failed.header.type == reb::NativeProbeType::kArtifactCaptureFailed);
  } else if (mode == "browser-stale") {
    browser.CaptureRuntimeTypedArray(101, kSession + 1, 9, false, 1, 7, 8, "script://9",
                                     mojo_base::BigBuffer(source_bytes),
                                     mojo_base::BigBuffer(bytes));
    assert(socket.transfers.empty());
  } else if (mode == "disabled" || mode == "expired" || mode == "stale" ||
             mode == "missing-source") {
    if (mode == "disabled")
      renderer.SetEmitters(nullptr, nullptr, 0, 0, 0);
    if (mode == "expired")
      base::test_now_ns = std::numeric_limits<std::int64_t>::max();
    if (mode == "expired")
      renderer.SetEmitters(&EmitEvent, &EmitArtifact, kSession, kVmMask, 101);
    if (mode == "stale") {
      script.capture_generation = renderer.RuntimeCaptureGeneration();
      Configure();
    }
    if (mode == "missing-source")
      script.source = {};
    capture();
    assert(artifact_calls == 0 && socket.transfers.empty());
  } else {
    std::cerr << "unknown case: " << mode << '\n';
    return 2;
  }
  // A test adapter writes unchanged queued records; production receiver/broker
  // parsing, hashing, manifest assignment and analyzer run in the Python driver.
  std::filesystem::create_directories(output);
  std::ofstream events(output / "events.bin", std::ios::binary);
  reb::NativeProbeEvent event;
  while (renderer_queue.TryPop(event))
    Write(events, &event, sizeof(event));
  for (const auto& value : browser_events)
    Write(events, &value, sizeof(value));
  std::ofstream artifacts(output / "artifacts.bin", std::ios::binary);
  for (const auto& transfer : socket.transfers) {
    Write(artifacts, &transfer->header, sizeof(transfer->header));
    Write(artifacts, transfer->url.data(), transfer->url.size());
    Write(artifacts, transfer->mime_type.data(), transfer->mime_type.size());
    Write(artifacts, transfer->content.data(), transfer->content.size());
  }
  std::cout << "PASS component pipeline " << mode << '\n';
}
