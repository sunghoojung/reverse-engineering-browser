#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <thread>

#include "reb/event.hpp"
#include "reb/spsc_ring.hpp"

namespace {

constexpr std::uint64_t kSessionId = 1;
constexpr std::uint64_t kEventCount = 100'000;

std::uint64_t MonotonicTimeNs() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch())
                                        .count());
}

}  // namespace

int main() {
  reb::SpscRing<reb::EventRecord, 1024> ring;
  std::atomic<bool> producer_done{false};
  std::uint64_t consumed = 0;

  std::thread producer([&ring, &producer_done] {
    for (std::uint64_t sequence = 1; sequence <= kEventCount; ++sequence) {
      const reb::EventRecord event =
          reb::MakeEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall, sequence,
                         MonotonicTimeNs(), kSessionId);
      static_cast<void>(ring.TryPush(event));
    }
    producer_done.store(true, std::memory_order_release);
  });

  reb::EventRecord event{};
  while (!producer_done.load(std::memory_order_acquire) || ring.SizeApprox() != 0) {
    if (ring.TryPop(event)) {
      ++consumed;
    } else {
      std::this_thread::yield();
    }
  }

  producer.join();

  std::cout << "Reverse Engineering Browser event demo\n"
            << "Produced: " << kEventCount << '\n'
            << "Consumed: " << consumed << '\n'
            << "Dropped:  " << ring.DroppedCount() << '\n'
            << "Category: " << reb::EventCategoryName(event.header.category) << '\n'
            << "Type:     " << reb::EventTypeName(event.header.type) << '\n';

  if (consumed + ring.DroppedCount() != kEventCount) {
    std::cerr << "Event accounting mismatch\n";
    return 1;
  }

  return 0;
}
