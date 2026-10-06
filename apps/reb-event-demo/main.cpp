#include <array>
#include <atomic>
#include <barrier>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <thread>

#include "components/reverse_engineering_browser/common/native_probe_queue.h"
#include "reb/event.hpp"
#include "reb/spsc_ring.hpp"

namespace {

constexpr std::uint64_t kSessionId = 1;
constexpr std::uint64_t kEventCount = 100'000;
constexpr std::uint64_t kDefaultQueueIterations = 500'000;

std::uint64_t MonotonicTimeNs() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch())
                                        .count());
}

bool RunEventDemo() {
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
    return false;
  }

  return true;
}

bool CheckNativeQueueLimits() {
  reb::NativeProbeQueue queue;
  reb::NativeProbeEvent event;
  for (std::uint64_t sequence = 1; sequence <= reb::kNativeProbeQueueCapacity; ++sequence) {
    event.header.sequence_number = sequence;
    if (!queue.TryPush(event)) {
      return false;
    }
  }
  const reb::NativeProbeEvent gap = reb::MakeNativeProbeGapEvent(event, 23);
  if (queue.TryPush(event) || queue.TryPush(gap, reb::NativeProbeDropWeight(gap)) ||
      queue.DroppedCount() != 24) {
    return false;
  }
  for (std::uint64_t sequence = 1; sequence <= reb::kNativeProbeQueueCapacity; ++sequence) {
    if (!queue.TryPop(event) || event.header.sequence_number != sequence) {
      return false;
    }
  }
  if (!queue.Empty() || queue.TryPop(event) || !queue.TryPush(event) || !queue.TryPop(event) ||
      queue.DroppedCount() != 24) {
    return false;
  }
  for (std::size_t index = 0; index < reb::kNativeProbeQueueCapacity; ++index) {
    if (!queue.TryPush(event)) {
      return false;
    }
  }
  const reb::NativeProbeEvent saturated_gap =
      reb::MakeNativeProbeGapEvent(event, std::numeric_limits<std::uint64_t>::max());
  if (queue.TryPush(saturated_gap, reb::NativeProbeDropWeight(saturated_gap)) ||
      queue.TryPush(event) || queue.DroppedCount() != std::numeric_limits<std::uint64_t>::max()) {
    return false;
  }
  std::cout << "Native queue limits: capacity=" << reb::kNativeProbeQueueCapacity
            << " bytes=" << sizeof(queue) << " weighted_drops=24 saturation=passed\n";
  return true;
}

bool CheckNativeQueueNotifications(const std::uint64_t iterations) {
  reb::NativeProbeQueue queue;
  std::barrier iteration_barrier(2);
  // The end barrier publishes these results; the next start barrier prevents
  // the producer from changing them until the consumer has inspected them.
  bool producer_pushed = false;
  bool producer_notified = false;
  std::thread producer([&] {
    reb::NativeProbeEvent event;
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
      event.header.sequence_number = iteration + 1;
      iteration_barrier.arrive_and_wait();
      producer_pushed = queue.TryPush(event);
      producer_notified = producer_pushed && queue.MarkNotificationPending();
      iteration_barrier.arrive_and_wait();
    }
  });

  std::uint64_t stranded = 0;
  std::uint64_t invalid = 0;
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    // Model an existing wake-up after Drain has removed the previous batch.
    static_cast<void>(queue.MarkNotificationPending());
    iteration_barrier.arrive_and_wait();
    queue.ClearNotificationPending();
    const bool saw_empty = queue.Empty();
    if (!saw_empty) {
      static_cast<void>(queue.MarkNotificationPending());
    }
    iteration_barrier.arrive_and_wait();
    if (saw_empty && producer_pushed && !producer_notified) {
      ++stranded;
    }
    reb::NativeProbeEvent event;
    if (!producer_pushed || !queue.TryPop(event) || event.header.sequence_number != iteration + 1 ||
        !queue.Empty()) {
      ++invalid;
    }
    queue.ClearNotificationPending();
  }
  producer.join();
  std::cout << "Native queue handoffs: iterations=" << iterations << " stranded=" << stranded
            << " invalid=" << invalid << " dropped=" << queue.DroppedCount() << '\n';
  return stranded == 0 && invalid == 0 && queue.DroppedCount() == 0;
}

bool CheckNativeQueueProducers() {
  reb::NativeProbeQueue queue;
  constexpr std::size_t kProducerCount = 4;
  constexpr std::uint64_t kEventsPerProducer = 100'000;
  std::atomic<std::size_t> producers_done{0};
  std::array<std::thread, kProducerCount> producers;
  for (std::size_t index = 0; index < producers.size(); ++index) {
    producers[index] = std::thread([&, index] {
      reb::NativeProbeEvent event;
      event.header.thread_id = static_cast<std::uint32_t>(index);
      for (std::uint64_t sequence = 1; sequence <= kEventsPerProducer; ++sequence) {
        event.header.sequence_number = sequence;
        if (queue.TryPush(event)) {
          static_cast<void>(queue.MarkNotificationPending());
        }
      }
      producers_done.fetch_add(1, std::memory_order_release);
    });
  }
  std::uint64_t consumed = 0;
  std::uint64_t invalid = 0;
  std::array<std::uint64_t, kProducerCount> last_sequences{};
  while (producers_done.load(std::memory_order_acquire) != kProducerCount || !queue.Empty()) {
    reb::NativeProbeEvent event;
    if (!queue.TryPop(event)) {
      queue.ClearNotificationPending();
      std::this_thread::yield();
      continue;
    }
    ++consumed;
    if (event.header.thread_id >= kProducerCount ||
        event.header.sequence_number <= last_sequences[event.header.thread_id]) {
      ++invalid;
    } else {
      last_sequences[event.header.thread_id] = event.header.sequence_number;
    }
  }
  for (std::thread& producer : producers) {
    producer.join();
  }
  const std::uint64_t attempted = kEventsPerProducer * kProducerCount;
  std::cout << "Native queue producers: attempted=" << attempted << " consumed=" << consumed
            << " dropped=" << queue.DroppedCount() << " invalid=" << invalid << '\n';
  return invalid == 0 && consumed + queue.DroppedCount() == attempted && queue.Empty();
}

bool MeasureNativeQueueReuse(const std::uint64_t iterations) {
  reb::NativeProbeQueue queue;
  reb::NativeProbeEvent event;
  constexpr std::uint64_t kBatchSize = 32;
  std::uint64_t produced = 0;
  std::uint64_t consumed = 0;
  std::uint64_t notifications = 0;
  const auto start = std::chrono::steady_clock::now();
  while (produced < iterations) {
    for (std::uint64_t index = 0; index < kBatchSize && produced < iterations; ++index) {
      event.header.sequence_number = ++produced;
      if (!queue.TryPush(event)) {
        return false;
      }
      if (queue.MarkNotificationPending()) {
        ++notifications;
      }
    }
    while (queue.TryPop(event)) {
      if (event.header.sequence_number != ++consumed) {
        return false;
      }
    }
    queue.ClearNotificationPending();
  }
  const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start);
  std::cout << "Native queue bounded batches: produced=" << produced << " consumed=" << consumed
            << " dropped=" << queue.DroppedCount() << " notifications=" << notifications
            << " ns_per_event=" << elapsed.count() * 1'000'000'000.0 / static_cast<double>(consumed)
            << '\n';
  const std::uint64_t expected_notifications =
      iterations / kBatchSize + (iterations % kBatchSize != 0 ? 1U : 0U);
  return consumed == iterations && queue.DroppedCount() == 0 && queue.Empty() &&
         notifications == expected_notifications;
}

bool ParseIterations(const int argc, char* argv[], std::uint64_t& iterations) {
  if (argc == 1) {
    return true;
  }
  if (argc != 3 || std::string_view(argv[1]) != "--queue-iterations") {
    return false;
  }
  const std::string_view value(argv[2]);
  const auto result = std::from_chars(value.data(), value.data() + value.size(), iterations);
  return result.ec == std::errc{} && result.ptr == value.data() + value.size() && iterations != 0;
}

}  // namespace

int main(const int argc, char* argv[]) {
  std::uint64_t iterations = kDefaultQueueIterations;
  if (!ParseIterations(argc, argv, iterations)) {
    std::cerr << "Usage: " << argv[0] << " [--queue-iterations COUNT]\n";
    return 2;
  }
  if (!RunEventDemo() || !CheckNativeQueueLimits() || !CheckNativeQueueProducers() ||
      !MeasureNativeQueueReuse(iterations) || !CheckNativeQueueNotifications(iterations)) {
    std::cerr << "Native event queue validation failed\n";
    return 1;
  }
  return 0;
}
