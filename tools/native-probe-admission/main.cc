// Component regression: real renderer sink, transport and queue. Chromium base,
// frame lookup, mapping and Mojo notification boundaries are narrow test stubs.
#include "chromium_stubs.h"

#include <array>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <thread>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
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
  RecoveryAndSaturation();
  ConcurrentSameSite();
  ConfigurationRaces();
  DisabledExpiredAndMalformed();
  CanvasCreatorAdmission();
  std::cout << "Renderer ring admission only; no full Chromium/Mojo/runtime validation.\n";
}
