// Component regression: real renderer sink, transport and queue. Chromium base,
// frame lookup, mapping and Mojo notification boundaries are narrow test stubs.
#include "chromium_stubs.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/common/native_runtime_snapshot_queue.h"
#include "brave/components/reverse_engineering_browser/common/runtime_buffer_frame.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_transport.h"
#include "reb/owned_vm_guest_sampler.hpp"
// clang-format off
// Leave these headers outside the sorted common-header block above.
#include "brave/components/reverse_engineering_browser/common/native_vm_finding.h"
#include "brave/components/reverse_engineering_browser/common/page_guest_dispatch.h"
// clang-format on

std::atomic<std::uint64_t> allocations{0};
void* operator new(std::size_t size) {
  ++allocations;
  if (void* value = std::malloc(size)) {
    return value;
  }
  std::abort();
}
void operator delete(void* value) noexcept {
  std::free(value);
}
void operator delete(void* value, std::size_t) noexcept {
  std::free(value);
}

namespace {
using reb::NativeProbeEvent;
using reb::NativeProbeQueue;
constexpr auto kRuntime = reb::NativeProbeCategory::kRuntime;
constexpr auto kForever = std::numeric_limits<std::uint64_t>::max();
auto& sink = reb::NativeProbeSink::Get();
auto& transport = reb::NativeProbeTransport::Get();

void Configure(NativeProbeQueue& queue,
               std::uint64_t session = 42,
               std::uint64_t expires = kForever,
               std::uint64_t mask = reb::kAllNativeProbeCategoryMask) {
  transport.Configure(session, mask, expires, false, {&queue, sizeof(queue)});
}
void Record(std::atomic<std::uint64_t>& observed) {
  sink.RecordApiCallOnce(kRuntime, "Math.acos", observed);
}
void Fill(NativeProbeQueue& queue) {
  for (std::size_t index = 0; index < reb::kNativeProbeQueueCapacity; ++index) {
    assert(queue.TryPush({}));
  }
}
std::size_t Drain(NativeProbeQueue& queue) {
  NativeProbeEvent event;
  std::size_t count = 0;
  while (queue.TryPop(event)) {
    ++count;
  }
  return count;
}
NativeProbeEvent One(NativeProbeQueue& queue) {
  NativeProbeEvent event;
  assert(queue.TryPop(event));
  NativeProbeEvent extra;
  assert(!queue.TryPop(extra));
  return event;
}

void QueueMappingAndCanvasBurst() {
  NativeProbeQueue queue;
  constexpr std::size_t kOldQueueBytes = 393536;
  static_assert(sizeof(NativeProbeQueue) == 3146048);
  static_assert(reb::kNativeProbeQueueCapacity == 8192);
  assert(queue.IsValid());
  for (const std::size_t bytes : {kOldQueueBytes, sizeof(queue) - 1, sizeof(queue) + 64}) {
    transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, false, {&queue, bytes});
    sink.RecordApiCall(reb::NativeProbeCategory::kCanvas, "canvas.getImageData");
    assert(Drain(queue) == 0 && queue.DroppedCount() == 0);
  }
  Configure(queue);
  constexpr std::size_t kSyntheticBurst = 4096;
  for (std::size_t index = 0; index < kSyntheticBurst; ++index) {
    sink.RecordApiCall(reb::NativeProbeCategory::kCanvas, "canvas.getImageData");
  }
  assert(queue.DroppedCount() == 0);
  NativeProbeEvent event;
  std::size_t accepted = 0;
  while (queue.TryPop(event)) {
    assert(event.header.category == reb::NativeProbeCategory::kCanvas);
    assert(event.header.type == reb::NativeProbeType::kApiCall);
    ++accepted;
  }
  assert(accepted == kSyntheticBurst);  // Canvas counts are not coalesced.
  transport.Disable();
  std::cout << "PASS exact queue mapping rejects legacy/wrong size; 4096 synthetic canvas calls "
               "retained\n";
}

void RecoveryAndSaturation() {
  NativeProbeQueue queue;
  Configure(queue);
  std::atomic<std::uint64_t> first{0};
  const auto notifications = reb::mojom::NativeProbeHost::notifications.load();
  Record(first);
  assert(reb::mojom::NativeProbeHost::notifications == notifications + 1);
  const auto initial = One(queue).header.sequence_number;
  Fill(queue);
  std::atomic<std::uint64_t> observed{0};
  constexpr unsigned kRejected = 10000;
  for (unsigned index = 0; index < kRejected; ++index) {
    Record(observed);
  }
  assert(queue.DroppedCount() == kRejected);
  assert((observed.load() & 1U) == 1);  // Failure watermark, eligible to retry.
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  Record(observed);
  const auto recovered = One(queue);
  assert(recovered.header.sequence_number == initial + kRejected + 1);
  assert(recovered.header.session_id == 42);
  assert(sink.CanAdmitEvent(recovered, observed.load()));
  auto wrong_session = recovered;
  ++wrong_session.header.session_id;
  assert(!sink.CanAdmitEvent(wrong_session, observed.load()));
  assert(!sink.CanAdmitEvent(recovered, observed.load() - 1));
  assert(!sink.CanAdmitEvent(recovered, observed.load() - 2));
  auto wrong_category = recovered;
  wrong_category.header.category = reb::NativeProbeCategory::kUnknown;
  assert(!sink.CanAdmitEvent(wrong_category, observed.load()));
  for (unsigned index = 0; index < kRejected; ++index) {
    Record(observed);
  }
  assert(Drain(queue) == 0 && queue.DroppedCount() == kRejected);
  // Admission also succeeds with the existing coalesced notification pending.
  std::atomic<std::uint64_t> another{0};
  Record(another);
  Record(another);
  One(queue);
  assert(reb::mojom::NativeProbeHost::notifications == notifications + 1);
  queue.ClearNotificationPending();
  std::atomic<std::uint64_t> after_clear{0};
  Record(after_clear);
  One(queue);
  assert(reb::mojom::NativeProbeHost::notifications == notifications + 2);
  transport.Disable();
  std::cout << "PASS full ring: 10000 counted drops, sequence gap, recovery and dedup\n";
}

void ConcurrentSameSite() {
  NativeProbeQueue queue;
  Configure(queue);
  std::atomic<std::uint64_t> observed{0};
  auto run = [&] {
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    for (unsigned index = 0; index < 16; ++index) {
      threads.emplace_back([&] {
        while (!start.load()) {
          std::this_thread::yield();
        }
        for (unsigned call = 0; call < 4000; ++call) {
          Record(observed);
        }
      });
    }
    start = true;
    for (auto& thread : threads) {
      thread.join();
    }
  };
  run();
  One(queue);
  assert(queue.DroppedCount() == 0);
  // New configuration permits a fresh claim, even with the same session ID.
  Configure(queue);
  Fill(queue);
  run();
  assert(queue.DroppedCount() > 0 && queue.DroppedCount() <= 64000);
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  run();
  One(queue);
  transport.Disable();
  std::cout << "PASS 16 concurrent same-site callers, empty/full/recovered rings\n";
}

std::atomic<bool> entered{false};
std::atomic<bool> resume{false};
void PauseAtFrame() {
  entered = true;
  while (!resume.load()) {
    std::this_thread::yield();
  }
}
void ExpireAtFrame() {
  base::test_now_ns = 1000;
}

void ConfigurationRaces() {
  for (unsigned mode = 0; mode < 4; ++mode) {
    NativeProbeQueue old_queue;
    NativeProbeQueue new_queue;
    Configure(old_queue);
    std::atomic<std::uint64_t> observed{0};
    entered = false;
    resume = false;
    std::thread old([&] {
      blink::test_frame_hook = &PauseAtFrame;
      Record(observed);
    });
    while (!entered.load()) {
      std::this_thread::yield();
    }
    transport.Disable();
    const auto old_claim = observed.load();
    std::uint64_t new_claim = 0;
    if (mode != 0) {
      Configure(new_queue, mode == 3 ? 43 : 42);
      if (mode == 2) {
        Fill(new_queue);
      }
      Record(observed);
      new_claim = observed.load();
      assert(new_claim > old_claim);
    }
    resume = true;
    old.join();
    assert(Drain(old_queue) == 0 && old_queue.DroppedCount() == 0);
    if (mode == 0) {
      assert(observed == old_claim - 1);
      Configure(new_queue);
      Record(observed);
      One(new_queue);
    } else {
      // The rejected old call cannot erase a newer accepted or failed claim.
      assert(observed == new_claim);
      if (mode == 2) {
        assert(new_queue.DroppedCount() == 1);
        assert(Drain(new_queue) == reb::kNativeProbeQueueCapacity);
        Record(observed);
      }
      const auto event = One(new_queue);
      assert(event.header.session_id == (mode == 3 ? 43U : 42U));
      Record(observed);
      assert(Drain(new_queue) == 0);
    }
    transport.Disable();
  }
  std::cout << "PASS paused claim races: disable, same/new session, newer failed claim\n";
}

void CanvasCreatorAdmission() {
  NativeProbeQueue queue;
  transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, true,
                      {&queue, sizeof(queue)});
  Fill(queue);
  const auto before = reb::mojom::NativeProbeHost::artifacts.load();
  sink.RecordCanvasToDataUrl("data:image/png;base64,AAAA");
  assert(queue.DroppedCount() == 1);
  assert(reb::mojom::NativeProbeHost::artifacts == before);
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  sink.RecordCanvasToDataUrl("data:image/png;base64,AAAA");
  assert(One(queue).header.category == reb::NativeProbeCategory::kCanvas);
  assert(reb::mojom::NativeProbeHost::artifacts == before + 1);
  transport.Disable();
  std::cout << "PASS Canvas artifact requires admitted creator metadata\n";
}

void RuntimeCreatorAdmission() {
  NativeProbeQueue queue;
  Configure(queue);
  std::array<std::uint8_t, 32> bytes{};
  const std::string_view text = "function vm(){while(pc<n){switch(op){case 1:return;}}}";
  const std::vector<std::uint8_t> source(text.begin(), text.end());
  const reb::NativeRuntimeScript script{9, false, source};
  const auto before = reb::mojom::NativeProbeHost::artifacts.load();
  Fill(queue);
  for (unsigned index = 0; index < 32; ++index) {
    sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/vm.js", bytes, script);
  }
  assert(queue.DroppedCount() == 32);
  assert(reb::mojom::NativeProbeHost::artifacts == before);
  assert(sink.RuntimeScriptSourceNeeded(7, 9));
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  for (unsigned index = 0; index < 16; ++index) {
    sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/vm.js", bytes, script);
    assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  }
  assert(reb::mojom::NativeProbeHost::artifacts == before + 16);
  assert(!sink.RuntimeScriptSourceNeeded(7, 9));
  sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/vm.js", bytes, script);
  assert(One(queue).header.type == reb::NativeProbeType::kArtifactCaptureFailed);
  assert(reb::mojom::NativeProbeHost::artifacts == before + 16);
  transport.Disable();
  std::cout << "PASS runtime artifact requires creator admission; full-ring retries preserve "
               "source and snapshot budgets\n";
}

void RuntimeScriptProvenance() {
  NativeProbeQueue queue;
  Configure(queue);
  std::array<std::uint8_t, 32> bytes{};
  constexpr std::array<std::uint8_t, 4> source{'v', 'm', '(', ')'};
  const auto before = reb::mojom::NativeProbeHost::artifacts.load();
  sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/script.js", bytes, {});
  const auto failed = One(queue);
  assert(failed.header.type == reb::NativeProbeType::kArtifactCaptureFailed);
  const std::string reason(reinterpret_cast<const char*>(failed.inline_payload.data()),
                           failed.header.payload_size);
  assert(reason == "allocating_script_unavailable");
  assert(reb::mojom::NativeProbeHost::artifacts == before);
  reb::NativeRuntimeScript script{9, true, source};
  assert(sink.RuntimeScriptSourceNeeded(7, 9));
  sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/script.js", bytes, script);
  assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  assert(reb::mojom::NativeProbeHost::artifacts == before + 1);
  assert(!sink.RuntimeScriptSourceNeeded(7, 9));
  assert(sink.RuntimeScriptSourceNeeded(10, 9));
  script.source = {};
  sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/script.js", bytes, script);
  One(queue);
  assert(reb::mojom::NativeProbeHost::artifacts == before + 2);
  Configure(queue, 43);
  assert(sink.RuntimeScriptSourceNeeded(7, 9));
  script.capture_generation = sink.RuntimeCaptureGeneration();
  Configure(queue, 44);
  script.source = source;
  sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/script.js", bytes, script);
  assert(Drain(queue) == 0);
  transport.Disable();
  const auto allocation_count = allocations.load();
  const auto clock_reads = base::test_clock_reads.load();
  assert(sink.RuntimeCaptureGeneration() == 0);
  assert(base::test_clock_reads == clock_reads);
  sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/script.js", bytes, script);
  assert(allocations == allocation_count && Drain(queue) == 0);
  std::cout << "PASS runtime script provenance, missing source, context/session isolation and "
               "inactive path\n";
}

std::string captured_runtime_url;
void CaptureRuntimeMetadata(reb::NativeArtifactKind,
                            reb::NativeArtifactCaptureOrigin,
                            std::uint64_t,
                            std::uint64_t,
                            std::uint64_t,
                            std::string_view url,
                            std::span<const std::uint8_t>,
                            const reb::NativeRuntimeScript&) noexcept {
  captured_runtime_url = url;
}
reb::NativeProbeEmitStatus AcceptRuntimeEvent(const NativeProbeEvent&, std::uint64_t) noexcept {
  return reb::NativeProbeEmitStatus::kAdmitted;
}

void RuntimeKeepList() {
  using Observation = reb::NativeRuntimeScriptObservation;
  NativeProbeQueue queue;
  Configure(queue);
  const auto generation = sink.RuntimeCaptureGeneration();
  std::array<std::uint8_t, 256> bytes{};
  constexpr std::array<std::uint8_t, 4> source{'v', 'm', '(', ')'};
  reb::NativeRuntimeScript script{11, false, source};
  const auto before = reb::mojom::NativeProbeHost::artifacts.load();
  const auto capture = [&](std::size_t size = 32) {
    sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/script.js", std::span(bytes).first(size),
                                  script);
  };
  // A large allocation alone is not evidence; rejected values do not use the cap.
  for (unsigned i = 0; i < 32; ++i)
    capture(256);
  const auto rejected = One(queue);
  assert(rejected.header.type == reb::NativeProbeType::kArtifactCaptureFailed);
  assert(std::string(reinterpret_cast<const char*>(rejected.inline_payload.data()),
                     rejected.header.payload_size) == "runtime_buffer_no_vm_signal");
  assert(reb::mojom::NativeProbeHost::artifacts == before);
  assert(
      sink.RegisterRuntimeScriptObservation(generation, 7, 11, Observation::kCapturedVmCandidate));
  capture(31);
  assert(Drain(queue) == 0);
  capture();
  One(queue);
  script.script_id = 12;
  assert(sink.RegisterRuntimeScriptObservation(generation, 7, 12, Observation::kCapturedLikelyVm));
  capture();
  One(queue);
  script.script_id = 13;
  script.is_eval = true;
  capture();
  One(queue);
  script.script_id = 14;
  script.is_eval = false;
  assert(
      sink.RegisterRuntimeScriptObservation(generation, 7, 14, Observation::kStaticDispatchLoop));
  capture(255);
  assert(Drain(queue) == 0);
  capture(256);
  One(queue);
  // Same numeric script in another context is not the observed script.
  sink.CaptureRuntimeTypedArray(99, 8, "fixture://owned/script.js", bytes, script);
  assert(Drain(queue) == 0);
  for (unsigned i = 4; i < 16; ++i)
    capture(256);
  assert(Drain(queue) == 12);
  capture(256);
  const auto limited = One(queue);
  assert(std::string(reinterpret_cast<const char*>(limited.inline_payload.data()),
                     limited.header.payload_size) == "runtime_typed_array_session_limit");
  assert(reb::mojom::NativeProbeHost::artifacts == before + 16);
  Configure(queue, 43);
  assert(
      !sink.RegisterRuntimeScriptObservation(generation, 7, 14, Observation::kStaticDispatchLoop));
  capture(256);
  assert(Drain(queue) == 1);
  script.is_eval = true;
  sink.SetEmitters(&AcceptRuntimeEvent, &CaptureRuntimeMetadata, 44,
                   reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm), kForever);
  captured_runtime_url.clear();
  sink.CaptureRuntimeTypedArray(7, 8, "", bytes, script);
  assert(captured_runtime_url == "script://14");
  sink.CaptureRuntimeTypedArray(7, 8, "https://user:password@owned.test/vm.js?token=secret#private",
                                bytes, script);
  assert(captured_runtime_url == "https://owned.test/vm.js");
  captured_runtime_url.clear();
  sink.CaptureRuntimeTypedArray(7, 8, "blob:https://user:password@host/id?token=1#private", bytes,
                                script);
  assert(captured_runtime_url == "blob:https://host/id");
  captured_runtime_url.clear();
  sink.CaptureRuntimeTypedArray(7, 8, "BLOB:http://host/worker.js", bytes, script);
  assert(captured_runtime_url == "blob:http://host/worker.js");
  for (const std::string_view unsafe :
       {"DATA:text/javascript,secret", "JAVASCRIPT:secret", "//user:password@host/path",
        "https:user:password@host/path", "data://source-code", "blob:file://host/id",
        "blob:blob:https://host/id", "script://source-text", "script://14/extra"}) {
    captured_runtime_url.clear();
    sink.CaptureRuntimeTypedArray(7, 8, unsafe, bytes, script);
    assert(captured_runtime_url.empty());
  }
  const auto active_generation = sink.RuntimeCaptureGeneration();
  for (std::uint64_t i = 1; i <= 64; ++i) {
    assert(sink.RegisterRuntimeScriptObservation(active_generation, 7, i,
                                                 Observation::kStaticDispatchLoop));
  }
  assert(!sink.RegisterRuntimeScriptObservation(active_generation, 7, 65,
                                                Observation::kStaticDispatchLoop));
  transport.Disable();
  assert(sink.RuntimeCaptureGeneration() == 0);
  assert(!sink.RegisterRuntimeScriptObservation(active_generation, 7, 1,
                                                Observation::kCapturedVmCandidate));
  std::cout << "PASS runtime keep-list three rows, floor, cap, exact scope, stale observations and "
               "sanitized URL\n";
}

reb::RuntimeBufferFrameFact Fact(const bool builtin,
                                 const bool javascript,
                                 const bool script,
                                 const bool source_is_string,
                                 const int script_id) {
  return {builtin, javascript, script, source_is_string, script_id};
}

void RuntimeBufferFrameSelection() {
  const auto authored = Fact(false, true, true, true, 9);
  const auto builtin = Fact(true, true, true, true, 1);
  const auto wasm = Fact(false, false, false, false, 0);
  const auto bare = Fact(false, true, false, false, 4);
  const auto empty_source = Fact(false, true, true, false, 5);
  const auto zero_id = Fact(false, true, true, true, 0);

  const reb::RuntimeBufferFrameFact constructor_then_caller[] = {builtin, authored};
  const std::uint8_t two_frames[] = {1, 1};
  const auto caller = reb::SelectRuntimeBufferFrame(constructor_then_caller, two_frames);
  assert(caller.found() && caller.frame == 1 && caller.summary == 0);

  const reb::RuntimeBufferFrameFact inlined[] = {builtin, authored};
  const std::uint8_t one_frame[] = {2};
  const auto outer = reb::SelectRuntimeBufferFrame(inlined, one_frame);
  assert(outer.found() && outer.frame == 0 && outer.summary == 1);

  const reb::RuntimeBufferFrameFact skipped[] = {wasm, bare, empty_source, zero_id, authored};
  const std::uint8_t five[] = {1, 1, 1, 1, 1};
  const auto fifth = reb::SelectRuntimeBufferFrame(skipped, five);
  assert(fifth.found() && fifth.frame == 4 && fifth.summary == 0);

  std::array<reb::RuntimeBufferFrameFact, 33> deep{};
  std::array<std::uint8_t, 33> counts{};
  counts.fill(1);
  deep[31] = authored;
  const auto at_limit =
      reb::SelectRuntimeBufferFrame(deep, std::span(counts).first(reb::kRuntimeBufferFrameLimit));
  assert(at_limit.found() && at_limit.frame == 31 && at_limit.summary == 0);
  deep[31] = {};
  deep[32] = authored;
  const auto past_limit = reb::SelectRuntimeBufferFrame(deep, counts);
  assert(!past_limit.found());

  std::array<reb::RuntimeBufferFrameFact, 33> inlines{};
  inlines[32] = authored;
  const std::uint8_t wide[] = {33};
  const auto outermost = reb::SelectRuntimeBufferFrame(inlines, wide);
  assert(outermost.found() && outermost.frame == 0 && outermost.summary == 32);

  const reb::RuntimeBufferFrameFact one[] = {authored};
  const std::uint8_t broken[] = {2};
  assert(!reb::SelectRuntimeBufferFrame(one, broken).found());
  std::cout << "PASS runtime buffer frame selection for builtins, outer summaries and the 32-frame "
               "limit\n";
}

void RuntimeSourceFeed() {
  NativeProbeQueue queue;
  Configure(queue, 77);
  std::array<std::uint8_t, 256> buffer{};
  const auto before = reb::mojom::NativeProbeHost::artifacts.load();
  std::uint64_t script_id = 30;
  const auto capture = [&](const std::string_view source, const std::size_t size) {
    const std::vector<std::uint8_t> owned(source.begin(), source.end());
    const reb::NativeRuntimeScript script{script_id, false, owned};
    sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/script.js", std::span(buffer).first(size),
                                  script);
    ++script_id;
  };
  const auto payload = [](const NativeProbeEvent& event) {
    return std::string(reinterpret_cast<const char*>(event.inline_payload.data()),
                       event.header.payload_size);
  };

  capture("var hidden=\"while(i<n){switch(op){}}\";", 256);
  const auto rejected = One(queue);
  assert(rejected.header.type == reb::NativeProbeType::kArtifactCaptureFailed);
  assert(payload(rejected) == "runtime_buffer_no_vm_signal");
  assert(reb::mojom::NativeProbeHost::artifacts == before);

  std::string overflow =
      "function vm(){var pc=0;while(pc<program.length){switch(program[pc++]){case "
      "1:stack.push(1);return;}}}";
  for (unsigned index = 0; index < 256; ++index) {
    overflow += "function p(){return 1;}";
  }
  capture(overflow, 32);
  assert(Drain(queue) == 0);
  capture("function broken(){while(i<n){switch(op){}}", 32);
  capture("function add(a,b){return a+b;}", 256);
  capture("function a(){while(false){}} function b(){switch(0){default:break;}}", 256);
  capture("function commented(){/* while(i<n){switch(op){}} */ return 1;}", 256);
  assert(Drain(queue) == 0);
  assert(reb::mojom::NativeProbeHost::artifacts == before);

  capture("instructionPointer++;", 32);
  assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  capture("while(i<n){switch(op){}}", 32);
  assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  capture(
      "function vm(){var pc=0;while(pc<program.length){switch(program[pc++]){case "
      "1:stack.push(1);return;}}}",
      32);
  assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  const auto likely_id = script_id - 1U;
  reb::NativeRuntimeScript again{likely_id, false, {}};
  sink.CaptureRuntimeTypedArray(7, 8, "fixture://owned/script.js", std::span(buffer).first(32),
                                again);
  assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  capture(
      "var vm=(pc)=>{while(pc<program.length){switch(program[pc++]){case "
      "1:stack.push(1);return;}}};",
      32);
  assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  capture(
      "var vm=pc=>{while(pc<program.length){switch(program[pc++]){case 1:stack.push(1);return;}}};",
      32);
  assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  capture(
      "function vm(op){const n=program.length/2;const re=/[{]/;"
      "while(n<op){switch(op){case 1:stack=1;return 1;}}}",
      32);
  assert(One(queue).header.type == reb::NativeProbeType::kApiCall);
  const std::string_view unrelated{"function add(a,b){return a+b;}"};
  const std::vector<std::uint8_t> unrelated_bytes(unrelated.begin(), unrelated.end());
  const reb::NativeRuntimeScript other_context{likely_id, false, unrelated_bytes};
  sink.CaptureRuntimeTypedArray(99, 8, "fixture://owned/script.js", std::span(buffer).first(32),
                                other_context);
  assert(Drain(queue) == 0);
  assert(reb::mojom::NativeProbeHost::artifacts == before + 7);

  const auto generation = sink.RuntimeCaptureGeneration();
  const std::string_view regex_source =
      "function vm(op){const n=program.length/2;const re=/[{]/;"
      "while(n<op){switch(op){case 1:stack=1;return 1;}}}";
  const std::vector<std::uint8_t> regex_bytes(regex_source.begin(), regex_source.end());
  assert(!sink.RuntimeScriptSourceNoted(generation, 7, 90));
  assert(sink.NoteRuntimeScriptSource(generation, 7, 90, regex_bytes));
  assert(sink.RuntimeScriptSourceNoted(generation, 7, 90));
  assert(sink.NoteRuntimeScriptSource(generation, 7, 90, regex_bytes));
  assert(sink.RuntimeBufferHasSignal(generation, 7, 8, 32, 90, false));
  assert(!sink.RuntimeScriptNoteAccepts(generation, 7, 90));
  assert(Drain(queue) == 0);

  const std::string_view plain{"function add(a,b){return a+b;}"};
  const std::vector<std::uint8_t> plain_bytes(plain.begin(), plain.end());
  assert(!sink.NoteRuntimeScriptSource(generation, 7, 91, plain_bytes));
  assert(sink.RuntimeScriptSourceNoted(generation, 7, 91));
  assert(!sink.NoteRuntimeScriptSource(generation, 7, 91, plain_bytes));
  assert(!sink.RuntimeBufferHasSignal(generation, 7, 8, 32, 91, false));
  // This generation already reported the missing signal. A later plain script
  // stays rejected without a second failure event or artifact.
  assert(Drain(queue) == 0);
  assert(reb::mojom::NativeProbeHost::artifacts == before + 7);

  const std::string_view cut_source =
      "function vm(){while(pc<program.length){switch(program[pc++]){case "
      "1:stack.push(1);return;}}} function rest(){";
  const std::vector<std::uint8_t> cut_bytes(cut_source.begin(), cut_source.end());
  assert(!sink.NoteRuntimeScriptSource(generation, 7, 92, cut_bytes, false));
  assert(sink.RuntimeScriptSourceNoted(generation, 7, 92));
  assert(!sink.RuntimeBufferHasSignal(generation, 7, 8, 32, 92, false));
  assert(sink.NoteRuntimeScriptSource(generation, 7, 93, cut_bytes, true));
  assert(sink.RuntimeBufferHasSignal(generation, 7, 8, 32, 93, false));

  const auto admit = [&](const std::uint64_t id, const std::string_view source) {
    const std::vector<std::uint8_t> bytes(source.begin(), source.end());
    assert(sink.NoteRuntimeScriptSource(generation, 7, id, bytes));
    assert(sink.RuntimeBufferHasSignal(generation, 7, 8, 32, id, false));
  };
  admit(94, "function vm(){if(ok)/[{]/;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(95, "function vm(){const n=pc++ /2;while(n<op){switch(op){case 1:stack=1;return 1;}}}");
  admit(
      96,
      "function vm(){const n=function(){return 1} /2;while(n<op){switch(op){case 1:stack=1;return "
      "1;}}}");
  admit(98, "function vm(){const n=pc + /[{]/;while(n<op){switch(op){case 1:stack=1;return 1;}}}");
  admit(99, "function vm(){return + /[{]/;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(100, "function vm(){const n=(a+b)/2;while(n<op){switch(op){case 1:stack=1;return 1;}}}");
  admit(101,
        "function vm(){const n='8' / 2;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(102,
        "function vm(){const n=`8` / 2;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(103, "function vm(){if(ok){} /[{]/;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(104,
        "function vm(){const n=({value:8}) / 2;while(pc<n){switch(op){case "
        "1:stack.push(1);return;}}}");
  admit(105,
        "function vm(){const n=obj.return / 2;while(pc<n){switch(op){case "
        "1:stack.push(1);return;}}}");
  admit(106,
        "function vm(){const n=/[\\/{}]/.test('x');while(pc<n){switch(op){case "
        "1:stack.push(1);return;}}}");
  admit(107,
        "function vm(){const n=pc - /[{]/;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(108,
        "function vm(){const n=8 / /* /[{]/ */ 2;while(pc<n){switch(op){case "
        "1:stack.push(1);return;}}}");
  admit(
      109,
      "function vm(){const n=class {} / 2;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(110,
        "function vm(){try{} catch{} /[{]/;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(111,
        "function vm(){async function a(){} /[{]/;while(pc<n){switch(op){case "
        "1:stack.push(1);return;}}}");
  admit(112, "function vm(){label:{} /[{]/;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  admit(113,
        "function vm(){const n=class extends (class {}){} / 2;while(pc<n){switch(op){case "
        "1:stack.push(1);return;}}}");
  admit(114,
        "function vm(){const n=class extends (function(){return class {}})(){} / "
        "2;while(pc<n){switch(op){case 1:stack.push(1);return;}}}");
  assert(Drain(queue) == 0);
  assert(reb::mojom::NativeProbeHost::artifacts == before + 7);

  // VM-looking text in non-code tokens must not create a signal either.
  const std::array<std::string_view, 4> lexical_negatives = {
      "const re=/instructionPointer/;",
      "function plain(){const n=pc + /instructionPointer/;}",
      "function plain(){if(ok){} /instructionPointer/;}",
      "function plain(){const n=`instructionPointer`;}",
  };
  std::uint64_t negative_id = 200;
  for (const auto source : lexical_negatives) {
    const std::vector<std::uint8_t> bytes(source.begin(), source.end());
    assert(!sink.NoteRuntimeScriptSource(generation, 7, negative_id, bytes));
    assert(!sink.RuntimeBufferHasSignal(generation, 7, 8, 32, negative_id, false));
    ++negative_id;
  }
  assert(Drain(queue) == 0);

  assert(sink.RuntimeScriptNoteAccepts(generation, 7, 97));
  assert(!sink.RememberRuntimeScriptMiss(generation, 7, 97));
  assert(sink.RuntimeScriptSourceNoted(generation, 7, 97));
  assert(!sink.RuntimeScriptNoteAccepts(generation, 7, 97));
  assert(!sink.RuntimeBufferHasSignal(generation, 7, 8, 32, 97, false));

  assert(payload(One(queue)) == "runtime_script_classification_unavailable");

  Configure(queue, 79);
  const auto fresh = sink.RuntimeCaptureGeneration();
  const std::vector<std::uint8_t> closed{'v', 'a', 'r', ' ', 'x', '=', '1', ';'};
  for (std::uint64_t id = 1; id <= 64; ++id) {
    assert(sink.RuntimeScriptNoteAccepts(fresh, 7, id));
    assert(!sink.NoteRuntimeScriptSource(fresh, 7, id, closed));
    assert(sink.RuntimeScriptSourceNoted(fresh, 7, id));
    assert(!sink.RuntimeScriptNoteAccepts(fresh, 7, id));
    // A retained negative never reconverts or rescans, nor spends scan budget.
    for (unsigned repeat = 0; repeat < 8; ++repeat) {
      assert(!sink.NoteRuntimeScriptSource(fresh, 7, id, regex_bytes));
    }
  }
  // A later real VM must not be starved by the first 64 unrelated scripts.
  assert(sink.RuntimeScriptNoteAccepts(fresh, 7, 65));
  assert(sink.NoteRuntimeScriptSource(fresh, 7, 65, regex_bytes));
  assert(sink.RuntimeBufferHasSignal(fresh, 7, 8, 32, 65, false));
  assert(!sink.RuntimeScriptSourceNoted(fresh, 7, 1));
  for (std::uint64_t id = 66; id <= 256; ++id) {
    assert(sink.RuntimeScriptNoteAccepts(fresh, 7, id));
    assert(!sink.NoteRuntimeScriptSource(fresh, 7, id, closed));
  }
  assert(sink.RuntimeScriptSourceNoted(fresh, 7, 65));
  assert(sink.RuntimeBufferHasSignal(fresh, 7, 8, 32, 65, false));
  // Neither a new script nor an evicted negative can bypass the work budget.
  for (const std::uint64_t id : {1U, 257U}) {
    assert(!sink.RuntimeScriptNoteAccepts(fresh, 7, id));
    assert(!sink.NoteRuntimeScriptSource(fresh, 7, id, regex_bytes));
    assert(!sink.RuntimeScriptSourceNoted(fresh, 7, id));
  }
  Fill(queue);
  assert(!sink.RuntimeBufferHasSignal(fresh, 7, 8, 32, 257, false));
  assert(queue.DroppedCount() == 1);
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  assert(!sink.RuntimeBufferHasSignal(fresh, 7, 8, 32, 257, false));
  const auto missed = One(queue);
  assert(missed.header.type == reb::NativeProbeType::kArtifactCaptureFailed);
  assert(payload(missed) == "runtime_script_classification_limit");
  assert(!sink.RuntimeBufferHasSignal(fresh, 7, 8, 32, 258, false));
  assert(Drain(queue) == 0);
  // A known negative is distinct from an unexamined script after exhaustion.
  assert(!sink.RuntimeBufferHasSignal(fresh, 7, 8, 32, 256, false));
  assert(payload(One(queue)) == "runtime_buffer_no_vm_signal");

  Configure(queue, 79);  // Reusing a session still replaces the generation.
  const auto reset = sink.RuntimeCaptureGeneration();
  assert(reset != fresh);
  assert(!sink.RuntimeScriptNoteAccepts(fresh, 7, 257));
  assert(!sink.NoteRuntimeScriptSource(fresh, 7, 257, regex_bytes));
  assert(sink.RuntimeScriptNoteAccepts(reset, 7, 257));
  assert(sink.NoteRuntimeScriptSource(reset, 7, 257, regex_bytes));
  assert(!sink.RuntimeScriptSourceNoted(reset, 7, 65));
  assert(!sink.RuntimeBufferHasSignal(reset, 99, 8, 32, 257, false));
  assert(payload(One(queue)) == "runtime_script_classification_unavailable");
  // Trusted observations stay pinned even when every table entry is positive.
  for (std::uint64_t id = 1; id <= 63; ++id) {
    assert(sink.RegisterRuntimeScriptObservation(
        reset, 7, id, reb::NativeRuntimeScriptObservation::kCapturedVmCandidate));
  }
  assert(!sink.RuntimeScriptNoteAccepts(reset, 7, 258));
  assert(!sink.NoteRuntimeScriptSource(reset, 7, 258, regex_bytes));
  assert(!sink.RuntimeBufferHasSignal(reset, 7, 8, 32, 258, false));
  assert(payload(One(queue)) == "runtime_script_classification_limit");
  assert(sink.RuntimeBufferHasSignal(reset, 7, 8, 32, 257, false));
  assert(reb::mojom::NativeProbeHost::artifacts == before + 7);
  std::cout << "PASS runtime source feed: valid regex/division, late VM admission, pinned signals, "
               "bounded scans, generation reset and explicit omissions\n";
}

void RuntimeCheckpointQueue() {
  struct Snapshot {
    std::uint64_t generation;
    std::uint64_t allocator_script;
    std::shared_ptr<std::array<std::uint8_t, 32>> bytes;
    bool detached = false;
  };
  reb::NativeRuntimeSnapshotQueue<Snapshot> pending;
  NativeProbeQueue events;
  Configure(events);
  const auto generation = sink.RuntimeCaptureGeneration();
  auto bytes = std::make_shared<std::array<std::uint8_t, 32>>();
  std::weak_ptr<std::array<std::uint8_t, 32>> retained = bytes;
  assert(pending.Push({generation, 100, bytes}, 32));
  // Script A allocated the zero-filled array. Script B writes synchronously;
  // the queued native payload retains A and observes the later byte contents.
  for (std::size_t i = 0; i < bytes->size(); ++i)
    (*bytes)[i] = static_cast<std::uint8_t>(i ^ 0x5a);
  unsigned copies = 0;
  pending.Drain([&](Snapshot item) {
    assert(item.allocator_script == 100);
    assert(item.generation == sink.RuntimeCaptureGeneration());
    assert((*item.bytes)[1] == (1 ^ 0x5a));
    ++copies;
  });
  assert(copies == 1 && pending.size() == 0 && pending.bytes() == 0);
  assert(pending.Push({generation, 100, bytes}, 32));
  transport.Disable();
  pending.Drain([&](Snapshot item) {
    if (item.generation == sink.RuntimeCaptureGeneration())
      ++copies;
  });
  assert(copies == 1);
  Configure(events, 98, 200);
  const auto expiring = sink.RuntimeCaptureGeneration();
  assert(pending.Push({expiring, 100, bytes}, 32));
  base::test_now_ns = 200;
  pending.Drain([&](Snapshot item) {
    if (item.generation == sink.RuntimeCaptureGeneration())
      ++copies;
  });
  base::test_now_ns = 100;
  assert(copies == 1);
  Configure(events, 99);
  assert(pending.Push({generation, 100, bytes}, 32));
  pending.Drain([&](Snapshot item) {
    if (item.generation == sink.RuntimeCaptureGeneration())
      ++copies;
  });
  assert(copies == 1);
  const auto current = sink.RuntimeCaptureGeneration();
  assert(pending.Push({current, 100, bytes, true}, 32));
  pending.Drain([&](Snapshot item) {
    if (item.detached) {
      sink.RecordRuntimeBufferOmission(item.generation, 8, "runtime_buffer_checkpoint_invalid");
      return;
    }
    ++copies;
  });
  assert(One(events).header.type == reb::NativeProbeType::kArtifactCaptureFailed && copies == 1);
  for (unsigned i = 0; i < 16; ++i)
    assert(pending.Push({current, 100, bytes}, 32));
  assert(!pending.Push({current, 100, bytes}, 32));
  // No checkpoint before teardown: omit, release all retained owners, no copy.
  bytes.reset();
  pending.Drain([&](Snapshot item) {
    sink.RecordRuntimeBufferOmission(item.generation, 8, "runtime_buffer_checkpoint_unavailable");
  });
  assert(Drain(events) == 16 && retained.expired() && copies == 1);
  assert(pending.Push({current, 100, {}}, pending.kMaxBytes));
  assert(!pending.Push({current, 100, {}}, 1));
  pending.Drain([](Snapshot) {});
  transport.Disable();
  std::cout << "PASS native checkpoint queue: later writes, allocator identity, disable/session, "
               "detach, teardown and independent limits\n";
}

void DisabledExpiredAndMalformed() {
  transport.Disable();
  std::atomic<std::uint64_t> observed{0};
  const auto before = allocations.load();
  for (unsigned index = 0; index < 10000; ++index) {
    Record(observed);
    sink.RecordRequestInitiated(1, "GET", "example.test");
  }
  assert(allocations == before && observed == 0);
  NativeProbeQueue queue;
  Configure(queue, 42, 100);  // Expired at Configure.
  Record(observed);
  assert(observed == 0 && Drain(queue) == 0);
  Configure(queue, 42, kForever, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas));
  Record(observed);
  assert(observed == 0 && Drain(queue) == 0);
  Configure(queue, 42, 1000);
  sink.RecordApiCallOnce(kRuntime, "", observed);
  sink.RecordApiCallOnce(reb::NativeProbeCategory::kUnknown, "invalid", observed);
  assert(observed == 0);
  blink::test_frame_hook = &ExpireAtFrame;
  Record(observed);  // Valid in sink, expired before transport admission.
  blink::test_frame_hook = nullptr;
  assert((observed.load() & 1U) == 1);
  assert(Drain(queue) == 0 && queue.DroppedCount() == 0);
  base::test_now_ns = 100;
  Configure(queue);
  Record(observed);
  const auto event = One(queue);
  // Test an expired admission policy directly, independently of the sink guard.
  Configure(queue, 42, 1000);
  Record(observed);
  const auto expiring = One(queue);
  base::test_now_ns = 1000;
  assert(!sink.CanAdmitEvent(expiring, observed.load()));
  base::test_now_ns = 100;
  Configure(queue);
  assert(!sink.CanAdmitEvent(event, observed.load()));
  // Property and network paths use the same explicit admission contract.
  std::atomic<std::uint64_t> property{0};
  sink.RecordPropertyReadOnce(kRuntime, "Intl.locale", property);
  sink.RecordPropertyReadOnce(kRuntime, "Intl.locale", property);
  assert(One(queue).header.type == reb::NativeProbeType::kPropertyRead);
  sink.RecordRequestInitiated(1, "GET", "example.test");
  assert(One(queue).header.type == reb::NativeProbeType::kRequestInitiated);
  transport.Disable();
  std::cout << "PASS disabled allocation-free, expired/masked/malformed and other emit paths\n";
}
}  // namespace

void DispatchSampleAdmission() {
  NativeProbeQueue queue;
  reb::NativeVmDispatchSamplePayload sample;
  sample.finding_id = 1;
  sample.investigation_id = 2;
  sample.interpreter_artifact_id = 3;
  Configure(queue, 70, kForever, reb::NativeProbeCategoryMask(kRuntime));
  sink.RecordVmDispatchSample(sample);
  assert(Drain(queue) == 0);
  for (std::uint64_t session : {71U, 72U}) {
    Configure(queue, session);
    auto invalid = sample;
    invalid.finding_id = 0;
    sink.RecordVmDispatchSample(invalid);
    for (std::uint32_t index = 0; index < 32; ++index) {
      sink.RecordVmDispatchSample(sample);
    }
    sink.PublishVmDispatchBudgetGap();
    NativeProbeEvent event;
    std::size_t samples = 0;
    std::size_t gaps = 0;
    std::uint64_t omitted = 0;
    while (queue.TryPop(event)) {
      assert(event.header.session_id == session);
      assert(event.header.category == reb::NativeProbeCategory::kVm);
      if (event.header.type == reb::NativeProbeType::kVmDispatchSample) {
        ++samples;
        continue;
      }
      assert(event.header.type == reb::NativeProbeType::kGap);
      assert(event.header.artifact_id == sample.interpreter_artifact_id);
      omitted += reb::NativeProbeDropWeight(event);
      ++gaps;
    }
    assert(samples == reb::kNativeVmDispatchSampleBudget);
    assert(gaps == 1);
    assert(omitted == 32 - reb::kNativeVmDispatchSampleBudget);
  }
  std::cout << "PASS dispatch sink/transport quota, category rejection, malformed rejection, "
               "visible budget gap and replacement configuration\n";
}

void DispatchEmitFailureReleasesBudget() {
  NativeProbeQueue queue;
  Configure(queue, 73);
  Fill(queue);
  reb::NativeVmDispatchSamplePayload sample;
  sample.finding_id = 1;
  sample.investigation_id = 2;
  sample.interpreter_artifact_id = 3;
  for (std::uint32_t index = 0; index < reb::kNativeVmDispatchSampleBudget; ++index) {
    sink.RecordVmDispatchSample(sample);
  }
  assert(queue.DroppedCount() == reb::kNativeVmDispatchSampleBudget);
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  for (std::uint32_t index = 0; index < reb::kNativeVmDispatchSampleBudget; ++index) {
    sink.RecordVmDispatchSample(sample);
  }
  NativeProbeEvent event;
  std::size_t samples = 0;
  while (queue.TryPop(event)) {
    assert(event.header.type == reb::NativeProbeType::kVmDispatchSample);
    assert(event.header.session_id == 73);
    ++samples;
  }
  assert(samples == reb::kNativeVmDispatchSampleBudget);
  assert(queue.DroppedCount() == reb::kNativeVmDispatchSampleBudget);
  sink.PublishVmDispatchBudgetGap();
  assert(Drain(queue) == 0);
  std::cout << "PASS failed dispatch emit returns the budget slot and keeps the queue drop\n";
}

void OwnedRegisterSamplerAdmission() {
  NativeProbeQueue queue;
  Configure(queue, 90);
  const auto before = allocations.load();
  sink.IngestOwnedRegisterInvocation(1);
  sink.IngestOwnedRegisterStep(0, 1, 1, 0);
  const auto disabled = reb::SampleOwnedRegisterInvocation(1, nullptr);
  assert(disabled.halted && disabled.executed == 9 && disabled.submitted == 0);
  assert(allocations == before);
  assert(Drain(queue) == 0);
  reb::OwnedRegisterSamplePolicy missing{};
  assert(!sink.EnableOwnedRegisterSampling(missing));
  Configure(queue, 90, kForever, reb::NativeProbeCategoryMask(kRuntime));
  reb::OwnedRegisterSamplePolicy policy{105, 106, 107, 108};
  assert(!sink.EnableOwnedRegisterSampling(policy));
  Configure(queue, 90);
  assert(sink.EnableOwnedRegisterSampling(policy));
  Configure(queue, 90);
  const reb::OwnedRegisterSamplerBinding binding{&reb::IngestOwnedRegisterInvocationThunk,
                                                 &reb::IngestOwnedRegisterStepThunk, &sink};
  const auto cleared = reb::SampleOwnedRegisterInvocation(201, &binding);
  assert(cleared.halted && cleared.submitted == 9);
  assert(Drain(queue) == 0);

  assert(sink.EnableOwnedRegisterSampling(policy));
  constexpr std::uint32_t kPcs[] = {0, 1, 2, 3, 4, 5, 6, 8, 10};
  constexpr std::uint32_t kOpcodes[] = {1, 1, 2, 3, 4, 5, 6, 7, 8};
  for (const std::uint64_t invocation : {201U, 202U}) {
    const auto run = reb::SampleOwnedRegisterInvocation(invocation, &binding);
    assert(run.halted && run.executed == 9 && run.submitted == 9);
  }
  sink.PublishVmDispatchBudgetGap();
  constexpr std::uint32_t kProgramSteps = 9;
  constexpr std::uint32_t kRetained = reb::kNativeVmDispatchSampleBudget;
  std::uint32_t samples = 0;
  std::uint32_t findings = 0;
  std::uint32_t gaps = 0;
  std::uint64_t omitted = 0;
  std::uint64_t invocations[2]{};
  NativeProbeEvent event;
  while (queue.TryPop(event)) {
    assert(event.header.session_id == 90);
    assert(event.header.category == reb::NativeProbeCategory::kVm);
    assert(event.header.artifact_id == policy.interpreter_artifact_id);
    if (event.header.type == reb::NativeProbeType::kVmFinding) {
      const auto finding = std::bit_cast<reb::NativeVmFindingPayload>(event.inline_payload);
      assert(finding.kind == reb::NativeVmFindingKind::kInvocation);
      assert(finding.confidence == reb::NativeVmFindingConfidence::kObserved);
      assert(finding.flags == static_cast<std::uint8_t>(reb::NativeVmFindingFlag::kDynamic));
      assert(finding.finding_id == policy.finding_id);
      assert(finding.investigation_id == policy.investigation_id);
      assert(finding.related_subject_id == policy.bytecode_artifact_id);
      constexpr char kLabel[] = "owned-register-v1";
      assert(finding.label_size == sizeof(kLabel) - 1);
      assert(std::memcmp(finding.label.data(), kLabel, finding.label_size) == 0);
      assert(findings < 2);
      invocations[findings] = finding.subject_id;
      ++findings;
      continue;
    }
    if (event.header.type == reb::NativeProbeType::kGap) {
      omitted += reb::NativeProbeDropWeight(event);
      ++gaps;
      continue;
    }
    assert(event.header.type == reb::NativeProbeType::kVmDispatchSample);
    const auto sample = std::bit_cast<reb::NativeVmDispatchSamplePayload>(event.inline_payload);
    const std::uint32_t program_index = samples < kProgramSteps ? samples : samples - kProgramSteps;
    assert(program_index < kProgramSteps);
    assert(sample.instruction_pointer == kPcs[program_index]);
    assert(sample.opcode == kOpcodes[program_index]);
    assert(sample.handler_index == kOpcodes[program_index]);
    assert(sample.sample_index == program_index);
    assert(sample.interpreter_artifact_id == policy.interpreter_artifact_id);
    assert(sample.bytecode_artifact_id == policy.bytecode_artifact_id);
    ++samples;
  }
  assert(findings == 2);
  assert(invocations[0] == 201 && invocations[1] == 202);
  assert(samples == kRetained);
  assert(gaps == 1);
  assert(omitted == (2 * kProgramSteps) - kRetained);

  Configure(queue, 91);
  assert(sink.EnableOwnedRegisterSampling(policy));
  Fill(queue);
  const auto dropped = reb::SampleOwnedRegisterInvocation(301, &binding);
  assert(dropped.submitted == kProgramSteps);
  assert(queue.DroppedCount() == kProgramSteps + 1);
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  const auto recovered = reb::SampleOwnedRegisterInvocation(302, &binding);
  assert(recovered.submitted == kProgramSteps);
  std::uint32_t recovered_samples = 0;
  std::uint32_t recovered_findings = 0;
  while (queue.TryPop(event)) {
    if (event.header.type == reb::NativeProbeType::kVmFinding) {
      const auto finding = std::bit_cast<reb::NativeVmFindingPayload>(event.inline_payload);
      assert(finding.subject_id == 302);
      ++recovered_findings;
      continue;
    }
    assert(event.header.type == reb::NativeProbeType::kVmDispatchSample);
    const auto sample = std::bit_cast<reb::NativeVmDispatchSamplePayload>(event.inline_payload);
    assert(sample.instruction_pointer == kPcs[recovered_samples]);
    assert(sample.opcode == kOpcodes[recovered_samples]);
    ++recovered_samples;
  }
  assert(recovered_findings == 1);
  assert(recovered_samples == kProgramSteps);
  assert(queue.DroppedCount() == kProgramSteps + 1);
  sink.PublishVmDispatchBudgetGap();
  assert(Drain(queue) == 0);
  std::cout << "PASS owned register sampler opt-in, invocation markers, budget gap and queue "
               "drops\n";
}

std::vector<std::uint8_t> JavaScriptSwitchProgram() {
  std::vector<std::uint8_t> program;
  for (int step = 0; step < 17; ++step) {
    program.insert(program.end(), {16, 0, static_cast<std::uint8_t>(step)});
  }
  program.push_back(19);
  return program;
}

std::vector<std::uint8_t> WasmBrTableModule() {
  std::vector<std::uint8_t> body{0x00};
  body.insert(body.end(), 16, 0x01);
  body.insert(body.end(), {0x41, 0x00, 0x0E, 0x00, 0x00, 0x0B});
  std::vector<std::uint8_t> module{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04,
                                   0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x0A};
  module.push_back(static_cast<std::uint8_t>(body.size() + 2));
  module.push_back(0x01);
  module.push_back(static_cast<std::uint8_t>(body.size()));
  module.insert(module.end(), body.begin(), body.end());
  return module;
}

void ExpectGuestTrace(NativeProbeQueue& queue,
                      const reb::PageGuestSamplePolicy& policy,
                      const reb::PageGuestWalk& walk,
                      const std::string_view label,
                      const reb::NativeVmHostRuntime host) {
  sink.PublishVmDispatchBudgetGap();
  std::size_t findings = 0;
  std::size_t samples = 0;
  std::size_t gaps = 0;
  std::uint64_t gap_weight = 0;
  NativeProbeEvent event;
  while (queue.TryPop(event)) {
    assert(event.header.category == reb::NativeProbeCategory::kVm);
    assert(event.header.session_id != 0);
    assert(event.header.artifact_id == policy.interpreter_artifact_id);
    if (event.header.type == reb::NativeProbeType::kVmFinding) {
      const auto finding = std::bit_cast<reb::NativeVmFindingPayload>(event.inline_payload);
      assert(finding.kind == reb::NativeVmFindingKind::kInvocation);
      assert(finding.host_runtime == host);
      assert(finding.confidence == reb::NativeVmFindingConfidence::kObserved);
      assert(finding.flags == static_cast<std::uint8_t>(reb::NativeVmFindingFlag::kDynamic));
      assert(finding.finding_id == policy.finding_id);
      assert(finding.investigation_id == policy.investigation_id);
      assert(finding.related_subject_id == policy.bytecode_artifact_id);
      assert(finding.subject_id != 0);
      assert(finding.label_size == label.size());
      assert(std::memcmp(finding.label.data(), label.data(), label.size()) == 0);
      ++findings;
    } else if (event.header.type == reb::NativeProbeType::kVmDispatchSample) {
      const auto sample = std::bit_cast<reb::NativeVmDispatchSamplePayload>(event.inline_payload);
      assert(samples < reb::kNativeVmDispatchSampleBudget);
      assert(sample.instruction_pointer == walk.steps[samples].instruction_pointer);
      assert(sample.opcode == walk.steps[samples].opcode);
      assert(sample.handler_index == walk.steps[samples].opcode);
      assert(sample.operand_count == walk.steps[samples].operand_count);
      assert(sample.sample_index == static_cast<std::uint32_t>(samples));
      assert(sample.interpreter_artifact_id == policy.interpreter_artifact_id);
      assert(sample.bytecode_artifact_id == policy.bytecode_artifact_id);
      ++samples;
    } else if (event.header.type == reb::NativeProbeType::kGap) {
      ++gaps;
      gap_weight += reb::NativeProbeDropWeight(event);
    } else {
      assert(false);
    }
  }
  const auto retained = std::min(walk.submitted, reb::kNativeVmDispatchSampleBudget);
  const std::uint32_t omitted = walk.submitted - retained + (walk.truncated ? 1U : 0U);
  assert(findings == 1);
  assert(samples == retained);
  assert(gaps == (omitted == 0 ? 0U : 1U));
  assert(gap_weight == omitted);
}

void PageGuestSamplerAdmission() {
  NativeProbeQueue queue;
  Configure(queue, 92);
  const auto before = allocations.load();
  const std::array<std::uint8_t, 4> short_program{16, 0, 1, 19};
  sink.ObserveCapturedJavaScriptSwitchProgram(short_program);
  sink.ObserveCapturedWasmModule({});
  sink.CaptureRuntimeTypedArray(1, 1, "https://owned.example/guest", short_program, {});
  assert(allocations == before);
  assert(Drain(queue) == 0);
  reb::PageGuestSamplePolicy missing{};
  assert(!sink.EnableJavaScriptSwitchSampling(missing));
  assert(!sink.EnableWasmBrTableSampling(missing));
  Configure(queue, 92, kForever, reb::NativeProbeCategoryMask(kRuntime));
  const reb::PageGuestSamplePolicy javascript_policy{211, 212, 213, 214};
  const reb::PageGuestSamplePolicy wasm_policy{311, 312, 313, 314};
  assert(!sink.EnableJavaScriptSwitchSampling(javascript_policy));
  assert(!sink.EnableWasmBrTableSampling(wasm_policy));

  Configure(queue, 92);
  assert(sink.EnableJavaScriptSwitchSampling(javascript_policy));
  Configure(queue, 92);
  const auto program = JavaScriptSwitchProgram();
  sink.ObserveCapturedJavaScriptSwitchProgram(program);
  assert(Drain(queue) == 0);
  assert(sink.EnableJavaScriptSwitchSampling(javascript_policy));
  const std::array<std::uint8_t, 1> unsupported{0x02};
  sink.ObserveCapturedJavaScriptSwitchProgram(unsupported);
  assert(Drain(queue) == 0);
  const auto short_walk = reb::WalkJavaScriptSwitchDispatch(short_program);
  sink.CaptureRuntimeTypedArray(7, 8, "https://owned.example/switch", short_program, {});
  ExpectGuestTrace(queue, javascript_policy, short_walk, "javascript-switch-dispatch-v1",
                   reb::NativeVmHostRuntime::kJavaScript);
  Configure(queue, 92);
  assert(sink.EnableJavaScriptSwitchSampling(javascript_policy));
  const auto javascript = reb::WalkJavaScriptSwitchDispatch(program);
  sink.ObserveCapturedJavaScriptSwitchProgram(program);
  ExpectGuestTrace(queue, javascript_policy, javascript, "javascript-switch-dispatch-v1",
                   reb::NativeVmHostRuntime::kJavaScript);

  Configure(queue, 93);
  assert(sink.EnableJavaScriptSwitchSampling(javascript_policy));
  Fill(queue);
  sink.ObserveCapturedJavaScriptSwitchProgram(program);
  assert(queue.DroppedCount() == javascript.submitted + 1);
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  sink.ObserveCapturedJavaScriptSwitchProgram(program);
  std::size_t recovered_findings = 0;
  std::size_t recovered_samples = 0;
  NativeProbeEvent event;
  while (queue.TryPop(event)) {
    if (event.header.type == reb::NativeProbeType::kVmFinding) {
      ++recovered_findings;
    } else if (event.header.type == reb::NativeProbeType::kVmDispatchSample) {
      const auto sample = std::bit_cast<reb::NativeVmDispatchSamplePayload>(event.inline_payload);
      assert(sample.instruction_pointer == javascript.steps[recovered_samples].instruction_pointer);
      assert(sample.opcode == javascript.steps[recovered_samples].opcode);
      ++recovered_samples;
    }
  }
  assert(recovered_findings == 1);
  assert(recovered_samples == reb::kNativeVmDispatchSampleBudget);
  assert(queue.DroppedCount() == javascript.submitted + 1);
  sink.PublishVmDispatchBudgetGap();
  assert(Drain(queue) == 1);

  Configure(queue, 94);
  assert(sink.EnableWasmBrTableSampling(wasm_policy));
  const std::array<std::uint8_t, 4> not_wasm{0x00, 0x61, 0x73, 0x6D};
  sink.ObserveCapturedWasmModule(not_wasm);
  assert(Drain(queue) == 0);
  const auto module = WasmBrTableModule();
  const auto wasm = reb::WalkWasmBrTableDispatch(module);
  sink.ObserveCapturedWasmModule(module);
  ExpectGuestTrace(queue, wasm_policy, wasm, "wasm-br-table-dispatch-v1",
                   reb::NativeVmHostRuntime::kWebAssembly);
  std::cout
      << "PASS page javascript and wasm opt-in, program counters, budget gap and queue drops\n";
}

// Actual callback-input admission only; this does not execute V8.
std::size_t native_wasm_frame_lookups = 0;
std::uint64_t NativeWasmFrameLookup() noexcept {
  ++native_wasm_frame_lookups;
  return 8;
}
std::size_t native_wasm_retained = 0;
bool native_wasm_accept = true;
bool CaptureNativeWasm(const reb::NativeWasmDispatchObservation& observation,
                       std::uint64_t generation) noexcept {
  assert(generation != 0);
  assert(observation.header.type == reb::NativeProbeType::kWasmDispatchObservation);
  assert(observation.header.artifact_id == 0 && observation.header.parent_event_id == 0);
  assert(observation.execution_context_id == 7 && observation.header.frame_id == 8);
  assert(observation.document_token_high == 9 && observation.document_token_low == 10);
  assert(observation.module_byte_offset == 8 && observation.selector == UINT32_MAX);
  assert(observation.table_count == 2 && observation.sample_index == native_wasm_retained);
  if (!native_wasm_accept)
    return false;
  ++native_wasm_retained;
  return true;
}
void NativeWasmRuntimeAdmission() {
  NativeProbeQueue queue;
  constexpr std::array<std::uint8_t, 12> module{0, 97, 115, 109, 1, 0, 0, 0, 0x0e, 2, 0, 0};
  reb::NativeWasmDispatchObservation input;
  input.header.frame_id = 8;
  input.execution_context_id = 7;
  input.document_token_high = 9;
  input.source_url = "https://owned.test/module.wasm";
  input.module_bytes = module;
  input.module_byte_offset = 8;
  input.table_count = 2;
  assert(reb::IsValidNativeWasmDispatchInput(input));
  input.table_count = 3;
  assert(!reb::IsValidNativeWasmDispatchInput(input));
  input.table_count = 2;
  input.module_byte_offset = UINT32_MAX;
  assert(!reb::IsValidNativeWasmDispatchInput(input));
  input.module_byte_offset = 8;
  input.source_url = "";
  assert(!reb::IsValidNativeWasmDispatchInput(input));
  input.source_url = "https://owned.test/module.wasm";
  std::vector<std::uint8_t> oversized(reb::kNativeArtifactMaxContentBytes + 1);
  input.module_bytes = oversized;
  assert(!reb::IsValidNativeWasmDispatchInput(input));
  input.module_bytes = std::span(module).first(9);
  assert(!reb::IsValidNativeWasmDispatchInput(input));
  const auto record = [&] {
    sink.RecordNativeWasmDispatch(7, 8, "https://owned.test/module.wasm", module, 0, 8, UINT32_MAX,
                                  2, 9, 10);
  };
  transport.Disable();
  sink.SetNativeWasmDispatchEmitter(&CaptureNativeWasm);
  const auto before = allocations.load();
  assert(!sink.IsNativeWasmDispatchEnabled());
  record();
  assert(allocations.load() == before && native_wasm_retained == 0);
  Configure(queue, 42, kForever, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm));
  assert(!sink.IsNativeWasmDispatchEnabled());
  Configure(queue, 42, 0);
  assert(!sink.IsNativeWasmDispatchEnabled());
  Configure(queue);
  sink.SetNativeWasmDispatchEmitter(&CaptureNativeWasm);
  assert(sink.IsNativeWasmDispatchEnabled());
  sink.RecordNativeWasmDispatch(7, 8, "https://owned.test/module.wasm", module, 0, 8, 0, 2, 0, 0);
  assert(One(queue).header.type == reb::NativeProbeType::kGap);
  assert(native_wasm_retained == 0);
  native_wasm_accept = false;
  record();
  assert(One(queue).header.type == reb::NativeProbeType::kGap);
  native_wasm_accept = true;
  for (unsigned i = 0; i < 16; ++i)
    record();
  const auto initial_drain = Drain(queue);
  assert(native_wasm_retained == 16 && initial_drain == 0);
  Fill(queue);
  record();  // A full ring must NOT permanently suppress the cap omission.
  assert(sink.IsNativeWasmDispatchEnabled());
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  record();
  const auto gap = One(queue);
  assert(std::string_view(reinterpret_cast<const char*>(gap.inline_payload.data()),
                          gap.header.payload_size) == "native_wasm_dispatch_budget_incomplete");
  assert(!sink.IsNativeWasmDispatchEnabled());
  record();
  assert(native_wasm_retained == 16 && Drain(queue) == 0);
  Configure(queue);
  sink.SetNativeWasmDispatchEmitter(&CaptureNativeWasm);  // Same session, fresh policy generation.
  native_wasm_retained = 0;
  assert(sink.IsNativeWasmDispatchEnabled());
  record();
  assert(native_wasm_retained == 1);
  sink.SetEmitters(&AcceptRuntimeEvent, &CaptureRuntimeMetadata, 42,
                   reb::kAllNativeProbeCategoryMask, kForever, false, &NativeWasmFrameLookup);
  assert(sink.IsNativeWasmDispatchEnabled());
  assert(native_wasm_frame_lookups == 0);  // Enabled callback must not re-enter V8.
  sink.SetNativeWasmDispatchEmitter(nullptr);
  assert(!sink.IsNativeWasmDispatchEnabled());
  transport.Disable();
  std::cout << "PASS native Wasm runtime-input admission; scoped bounds, unsigned selector, "
               "transport retry and full-ring cap retry\n";
}

std::size_t native_indirect_retained = 0;
bool native_indirect_accept = true;
bool CaptureNativeIndirect(const reb::NativeWasmIndirectObservation& observation,
                           std::uint64_t generation) noexcept {
  assert(generation != 0);
  assert(observation.header.type == reb::NativeProbeType::kWasmIndirectObservation);
  assert(observation.header.artifact_id == 0 && observation.header.parent_event_id == 0);
  assert(observation.execution_context_id == 7 && observation.header.frame_id == 8);
  assert(observation.document_token_high == 9 && observation.document_token_low == 10);
  assert(observation.module_byte_offset == 8 && observation.table_index == 0);
  assert(observation.slot == UINT32_MAX && observation.callee_function_index == 0);
  assert(observation.resolution == reb::NativeWasmIndirectResolution::kOutOfBounds);
  assert(observation.sample_index == native_indirect_retained);
  if (!native_indirect_accept)
    return false;
  ++native_indirect_retained;
  return true;
}
void NativeWasmIndirectAdmission() {
  // Heap-held: main inlines each test, and two rings would overflow its stack.
  const auto owned_queue = std::make_unique<NativeProbeQueue>();
  NativeProbeQueue& queue = *owned_queue;
  // call_indirect type 0, table 0, then return_call_indirect type 0, table 1.
  constexpr std::array<std::uint8_t, 14> module{0, 97,   115, 109, 1,    0, 0,
                                                0, 0x11, 0,   0,   0x13, 0, 1};
  reb::NativeWasmIndirectObservation input;
  input.header.frame_id = 8;
  input.execution_context_id = 7;
  input.document_token_high = 9;
  input.document_token_low = 10;
  input.source_url = "https://owned.test/module.wasm";
  input.module_bytes = module;
  input.module_byte_offset = 8;
  input.slot = UINT32_MAX;
  input.resolution = reb::NativeWasmIndirectResolution::kOutOfBounds;
  assert(reb::IsValidNativeWasmIndirectInput(input));
  input.table_index = 1;
  assert(!reb::IsValidNativeWasmIndirectInput(input));
  input.module_byte_offset = 11;
  assert(reb::IsValidNativeWasmIndirectInput(input));
  input.module_byte_offset = 9;
  assert(!reb::IsValidNativeWasmIndirectInput(input));
  input.module_byte_offset = 8;
  input.table_index = 0;
  input.callee_function_index = 3;
  assert(!reb::IsValidNativeWasmIndirectInput(input));
  input.resolution = reb::NativeWasmIndirectResolution::kResolved;
  assert(reb::IsValidNativeWasmIndirectInput(input));
  input.resolution = static_cast<reb::NativeWasmIndirectResolution>(5);
  input.callee_function_index = 0;
  assert(!reb::IsValidNativeWasmIndirectInput(input));
  input.resolution = reb::NativeWasmIndirectResolution::kOutOfBounds;
  input.module_bytes = std::span(module).first(10);
  assert(!reb::IsValidNativeWasmIndirectInput(input));
  input.module_bytes = module;
  input.sample_index = 16;
  assert(!reb::IsValidNativeWasmIndirectInput(input));
  input.sample_index = 0;
  const auto record = [&] { sink.RecordNativeWasmIndirect(input); };
  transport.Disable();
  sink.SetNativeWasmIndirectEmitter(&CaptureNativeIndirect);
  const auto before = allocations.load();
  assert(!sink.IsNativeWasmIndirectEnabled());
  record();
  assert(allocations.load() == before && native_indirect_retained == 0);
  Configure(queue, 42, kForever, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm));
  assert(!sink.IsNativeWasmIndirectEnabled());
  Configure(queue, 42, 0);  // Expired.
  assert(!sink.IsNativeWasmIndirectEnabled());
  record();
  assert(native_indirect_retained == 0 && Drain(queue) == 0);
  Configure(queue);
  sink.SetNativeWasmIndirectEmitter(&CaptureNativeIndirect);
  assert(sink.IsNativeWasmIndirectEnabled());
  auto malformed = input;
  malformed.module_byte_offset = 9;
  sink.RecordNativeWasmIndirect(malformed);
  auto gap = One(queue);
  assert(gap.header.type == reb::NativeProbeType::kGap);
  assert(std::string_view(reinterpret_cast<const char*>(gap.inline_payload.data()),
                          gap.header.payload_size) == "native_wasm_indirect_input_unavailable");
  assert(native_indirect_retained == 0);
  native_indirect_accept = false;
  record();
  gap = One(queue);
  assert(std::string_view(reinterpret_cast<const char*>(gap.inline_payload.data()),
                          gap.header.payload_size) == "native_wasm_indirect_transport_unavailable");
  native_indirect_accept = true;
  // The br_table budget is independent: exhausting it leaves this stream open.
  for (unsigned i = 0; i < 16; ++i)
    record();
  const auto initial_drain = Drain(queue);
  assert(native_indirect_retained == 16 && initial_drain == 0);
  Fill(queue);
  record();  // A full ring must NOT permanently suppress the cap omission.
  assert(sink.IsNativeWasmIndirectEnabled());
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  record();
  gap = One(queue);
  assert(std::string_view(reinterpret_cast<const char*>(gap.inline_payload.data()),
                          gap.header.payload_size) == "native_wasm_indirect_budget_incomplete");
  assert(!sink.IsNativeWasmIndirectEnabled());
  record();
  assert(native_indirect_retained == 16 && Drain(queue) == 0);
  Configure(queue);
  sink.SetNativeWasmIndirectEmitter(&CaptureNativeIndirect);  // Fresh policy generation.
  native_indirect_retained = 0;
  assert(sink.IsNativeWasmIndirectEnabled());
  record();
  assert(native_indirect_retained == 1);
  sink.SetEmitters(&AcceptRuntimeEvent, &CaptureRuntimeMetadata, 42,
                   reb::kAllNativeProbeCategoryMask, kForever, false, &NativeWasmFrameLookup);
  native_wasm_frame_lookups = 0;
  assert(sink.IsNativeWasmIndirectEnabled());
  assert(native_wasm_frame_lookups == 0);  // Enabled callback must not re-enter V8.
  sink.SetNativeWasmIndirectEmitter(nullptr);
  assert(!sink.IsNativeWasmIndirectEnabled());
  transport.Disable();
  std::cout << "PASS native Wasm call_indirect admission; disabled, expired, input, transport, "
               "separate 16-record budget and full-ring cap retry\n";
}

#include "guest_sampler_tests.h"

// Each test keeps a multi-megabyte ring on its own stack. Inlining every test
// into main can exceed the default 8 MiB main-thread stack, so each runs in
// its own frame.
template <auto Test>
[[gnu::noinline]] void Run() {
  Test();
}

int main() {
  reb::mojom::NativeProbeHost host;
  transport.Connect(mojo::PendingRemote<reb::mojom::NativeProbeHost>(&host));
  Run<&NativeGuestAdmission>();
  Run<&NativeGuestModuleVerdictsAndHostBudget>();
  Run<&NativeGuestParentDispatch>();
  Run<&NativeGuestTwoSiteNesting>();
  Run<&NativeWasmRuntimeAdmission>();
  Run<&NativeWasmIndirectAdmission>();
  Run<&DispatchSampleAdmission>();
  Run<&DispatchEmitFailureReleasesBudget>();
  Run<&OwnedRegisterSamplerAdmission>();
  Run<&PageGuestSamplerAdmission>();
  Run<&QueueMappingAndCanvasBurst>();
  Run<&RecoveryAndSaturation>();
  Run<&ConcurrentSameSite>();
  Run<&ConfigurationRaces>();
  Run<&DisabledExpiredAndMalformed>();
  Run<&CanvasCreatorAdmission>();
  Run<&RuntimeCreatorAdmission>();
  Run<&RuntimeScriptProvenance>();
  Run<&RuntimeKeepList>();
  Run<&RuntimeBufferFrameSelection>();
  Run<&RuntimeSourceFeed>();
  Run<&RuntimeCheckpointQueue>();
  std::cout << "Renderer ring admission only; no full Chromium/Mojo/runtime validation.\n";
}
