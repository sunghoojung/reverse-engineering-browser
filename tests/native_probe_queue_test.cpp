#include <atomic>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <thread>
#include <vector>

#include "reb/event_broker.hpp"

#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_queue.h"

namespace {

constexpr std::uint64_t kProducerCount = 4;
constexpr std::uint64_t kEventsPerProducer = 20000;

reb::NativeProbeEvent Event(const std::uint64_t producer, const std::uint64_t sequence) {
  reb::NativeProbeEvent event;
  event.header.process_id = static_cast<std::uint32_t>(producer + 1);
  event.header.sequence_number = sequence + 1;
  return event;
}

bool TestLayoutAndBoundedDrop() {
  reb::NativeProbeQueue queue;
  if (!queue.IsValid() || !queue.Empty() || queue.DroppedCount() != 0) {
    return false;
  }

  for (std::uint64_t index = 0; index < reb::kNativeProbeQueueCapacity; ++index) {
    if (!queue.TryPush(Event(0, index))) {
      return false;
    }
  }

  if (queue.TryPush(Event(0, reb::kNativeProbeQueueCapacity)) || queue.DroppedCount() != 1) {
    return false;
  }

  reb::NativeProbeEvent event;
  for (std::uint64_t index = 0; index < reb::kNativeProbeQueueCapacity; ++index) {
    if (!queue.TryPop(event) || event.header.sequence_number != index + 1) {
      return false;
    }
  }
  return queue.Empty() && !queue.TryPop(event);
}

bool TestNotificationCoalescing() {
  reb::NativeProbeQueue queue;
  if (!queue.MarkNotificationPending() || queue.MarkNotificationPending()) {
    return false;
  }
  queue.ClearNotificationPending();
  return queue.MarkNotificationPending();
}

bool TestGapMarker() {
  reb::NativeProbeEvent reference = Event(2, 99);
  reference.header.category = reb::NativeProbeCategory::kNetwork;
  reference.header.monotonic_time_ns = 1234;
  reference.header.session_id = 55;
  const reb::NativeProbeEvent gap =
      reb::MakeNativeProbeGapEvent(reference, 18446744073709551615ULL);
  const std::string_view payload(reinterpret_cast<const char*>(gap.inline_payload.data()),
                                 gap.header.payload_size);
  return gap.header.category == reb::NativeProbeCategory::kNetwork &&
         gap.header.type == reb::NativeProbeType::kGap &&
         gap.header.sequence_number == reference.header.sequence_number &&
         gap.header.monotonic_time_ns == 1234 && gap.header.session_id == 55 &&
         gap.header.process_id == reference.header.process_id && payload == "18446744073709551615";
}

bool TestCategoryMasks() {
  const std::uint64_t canvas = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas);
  const std::uint64_t network = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork);
  const std::uint64_t vm = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm);
  return canvas == 1 && network == (std::uint64_t{1} << 8U) && vm == (std::uint64_t{1} << 9U) &&
         canvas == reb::EventCategoryMask(reb::EventCategory::kCanvas) &&
         network == reb::EventCategoryMask(reb::EventCategory::kNetwork) &&
         vm == reb::EventCategoryMask(reb::EventCategory::kVm) &&
         reb::kAllNativeProbeCategoryMask == reb::kAllEventCategoryMask &&
         reb::IsValidNativeProbeCategoryMask(canvas | network | vm) &&
         !reb::IsValidNativeProbeCategoryMask(0) &&
         !reb::IsValidNativeProbeCategoryMask(std::uint64_t{1} << 63U);
}

bool TestConcurrentProducers() {
  reb::NativeProbeQueue queue;
  std::atomic<bool> start{false};
  std::atomic<std::uint64_t> producers_done{0};
  std::vector<std::thread> producers;
  producers.reserve(kProducerCount);

  for (std::uint64_t producer = 0; producer < kProducerCount; ++producer) {
    producers.emplace_back([&queue, &start, &producers_done, producer] {
      while (!start.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      for (std::uint64_t sequence = 0; sequence < kEventsPerProducer; ++sequence) {
        while (!queue.TryPush(Event(producer, sequence))) {
          std::this_thread::yield();
        }
      }
      producers_done.fetch_add(1, std::memory_order_release);
    });
  }

  std::array<std::uint64_t, kProducerCount> expected_sequences{};
  std::uint64_t consumed = 0;
  bool ordered = true;
  start.store(true, std::memory_order_release);

  while (producers_done.load(std::memory_order_acquire) != kProducerCount || !queue.Empty()) {
    reb::NativeProbeEvent event;
    if (!queue.TryPop(event)) {
      std::this_thread::yield();
      continue;
    }
    const std::size_t producer = event.header.process_id - 1;
    if (producer >= expected_sequences.size() ||
        event.header.sequence_number != expected_sequences[producer] + 1) {
      ordered = false;
      continue;
    }
    ++expected_sequences[producer];
    ++consumed;
  }

  for (auto& producer : producers) {
    producer.join();
  }

  if (!ordered || consumed != kProducerCount * kEventsPerProducer) {
    return false;
  }
  for (const std::uint64_t sequence : expected_sequences) {
    if (sequence != kEventsPerProducer) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
  if (!TestLayoutAndBoundedDrop() || !TestNotificationCoalescing() || !TestGapMarker() ||
      !TestCategoryMasks() || !TestConcurrentProducers()) {
    std::cerr << "native_probe_queue_test failed\n";
    return 1;
  }
  std::cout << "native_probe_queue_test passed\n";
  return 0;
}
