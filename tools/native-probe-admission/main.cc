// Component regression: real renderer sink, transport and queue. Chromium base,
// frame lookup, mapping and Mojo notification boundaries are narrow test stubs.
#include "chromium_stubs.h"

#include <array>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/common/native_runtime_snapshot_queue.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_transport.h"

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
bool AcceptRuntimeEvent(const NativeProbeEvent&, std::uint64_t) noexcept {
  return true;
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
  sink.CaptureRuntimeTypedArray(7, 8, "", bytes, script);
  const auto missing = One(queue);
  assert(std::string(reinterpret_cast<const char*>(missing.inline_payload.data()),
                     missing.header.payload_size) == "allocating_script_url_unavailable");
  sink.SetEmitters(&AcceptRuntimeEvent, &CaptureRuntimeMetadata, 44,
                   reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm), kForever);
  sink.CaptureRuntimeTypedArray(7, 8, "https://user:password@owned.test/vm.js?token=secret#private",
                                bytes, script);
  assert(captured_runtime_url == "https://owned.test/vm.js");
  for (const std::string_view unsafe :
       {"DATA:text/javascript,secret", "JAVASCRIPT:secret", "//user:password@host/path",
        "https:user:password@host/path", "data://source-code",
        "blob:https://user:password@host/id"}) {
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
  const std::string_view unrelated{"function add(a,b){return a+b;}"};
  const std::vector<std::uint8_t> unrelated_bytes(unrelated.begin(), unrelated.end());
  const reb::NativeRuntimeScript other_context{likely_id, false, unrelated_bytes};
  sink.CaptureRuntimeTypedArray(99, 8, "fixture://owned/script.js", std::span(buffer).first(32),
                                other_context);
  assert(Drain(queue) == 0);
  assert(reb::mojom::NativeProbeHost::artifacts == before + 6);
  std::cout << "PASS runtime source feed for candidate, likely-VM, dispatch and closed failures\n";
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

int main() {
  reb::mojom::NativeProbeHost host;
  transport.Connect(mojo::PendingRemote<reb::mojom::NativeProbeHost>(&host));
  QueueMappingAndCanvasBurst();
  RecoveryAndSaturation();
  ConcurrentSameSite();
  ConfigurationRaces();
  DisabledExpiredAndMalformed();
  CanvasCreatorAdmission();
  RuntimeScriptProvenance();
  RuntimeKeepList();
  RuntimeSourceFeed();
  RuntimeCheckpointQueue();
  std::cout << "Renderer ring admission only; no full Chromium/Mojo/runtime validation.\n";
}
