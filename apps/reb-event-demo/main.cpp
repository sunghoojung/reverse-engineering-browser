#include <array>
#include <atomic>
#include <barrier>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>

#include "components/reverse_engineering_browser/common/native_console_messages.h"
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

bool CheckEventJson() {
  reb::EventRecord event = reb::MakeEvent(reb::EventCategory::kRuntime, reb::EventType::kApiCall,
                                          std::numeric_limits<std::uint64_t>::max(),
                                          std::numeric_limits<std::uint64_t>::max(),
                                          std::numeric_limits<std::uint64_t>::max());
  event.header.process_id = std::numeric_limits<std::uint32_t>::max();
  event.header.thread_id = std::numeric_limits<std::uint32_t>::max();
  event.header.tab_id = std::numeric_limits<std::uint32_t>::max();
  event.header.navigation_id = std::numeric_limits<std::uint64_t>::max();
  event.header.frame_id = std::numeric_limits<std::uint64_t>::max();
  event.header.artifact_id = std::numeric_limits<std::uint64_t>::max();
  event.header.parent_event_id = std::numeric_limits<std::uint64_t>::max();
  event.header.request_id = std::numeric_limits<std::uint64_t>::max();
  event.header.browser_context_id_high = std::numeric_limits<std::uint64_t>::max();
  event.header.browser_context_id_low = std::numeric_limits<std::uint64_t>::max();
  event.header.encoded_data_length = std::numeric_limits<std::int64_t>::min();
  event.header.decoded_body_length = std::numeric_limits<std::int64_t>::max();
  event.header.status_code = std::numeric_limits<std::int32_t>::max();
  event.header.error_code = std::numeric_limits<std::int32_t>::min();
  event.header.resource_type = std::numeric_limits<std::uint16_t>::max();
  event.header.flags = 7;
  event.header.initiator_request_id = std::numeric_limits<std::uint32_t>::max();
  event.header.initiator_process_id = std::numeric_limits<std::uint32_t>::max();
  constexpr std::string_view kPrefix =
      "{\"protocol_version\":3,\"session_id\":\"18446744073709551615\","
      "\"sequence_number\":\"18446744073709551615\",\"monotonic_time_ns\":\"18446744073709551615\","
      "\"process_id\":4294967295,\"thread_id\":4294967295,\"tab_id\":4294967295,"
      "\"navigation_id\":\"18446744073709551615\",\"frame_id\":\"18446744073709551615\","
      "\"artifact_id\":\"18446744073709551615\",\"parent_event_id\":\"18446744073709551615\","
      "\"request_id\":\"18446744073709551615\",\"browser_context_id_high\":"
      "\"18446744073709551615\","
      "\"browser_context_id_low\":\"18446744073709551615\","
      "\"encoded_data_length\":\"-9223372036854775808\",\"decoded_body_length\":"
      "\"9223372036854775807\","
      "\"status_code\":2147483647,\"error_code\":-2147483648,\"resource_type\":65535,\"flags\":7,"
      "\"initiator_request_id\":4294967295,\"initiator_process_id\":4294967295,"
      "\"payload_truncated\":true,\"category\":\"runtime\",\"type\":\"api_call\",\"payload_size\":";
  constexpr std::string_view kHex = "0123456789abcdef";
  std::size_t checked = 0;
  for (unsigned offset = 0; offset < 256; ++offset) {
    for (std::size_t index = 0; index < event.inline_payload.size(); ++index) {
      event.inline_payload[index] = static_cast<std::byte>((offset + index) % 256);
    }
    std::string expected_payload;
    for (std::size_t size = 0; size <= event.inline_payload.size(); ++size) {
      event.header.payload_size = static_cast<std::uint32_t>(size);
      const auto matches_json = [&] {
        const std::string expected =
            std::string(kPrefix) + std::to_string(event.header.payload_size) +
            ",\"payload_encoding\":\"hex\",\"payload\":\"" + expected_payload + "\"}";
        return reb::EventToJson(event) == expected;
      };
      if (!reb::IsValidEvent(event) || !matches_json()) {
        return false;
      }
      ++checked;
      if (size == event.inline_payload.size()) {
        // Invalid lengths remain rejected, and direct callers still encode only
        // the bounded inline bytes without overflowing the output size.
        for (const std::uint32_t invalid_size :
             {static_cast<std::uint32_t>(reb::kInlinePayloadSize + 1),
              std::numeric_limits<std::uint32_t>::max()}) {
          event.header.payload_size = invalid_size;
          if (reb::IsValidEvent(event) || !matches_json()) {
            return false;
          }
          ++checked;
        }
        break;
      }
      const unsigned value = std::to_integer<unsigned>(event.inline_payload[size]);
      expected_payload.push_back(kHex[value / 16]);
      expected_payload.push_back(kHex[value % 16]);
    }
  }
  std::cout << "Event JSON: checked=" << checked
            << " all_payload_sizes=passed all_byte_values=passed oversized=passed\n";
  return true;
}

bool CheckNativeConsoleMessages() {
  // Queue counters and their owned strings must never acquire separate owners.
  static_assert(!std::is_copy_constructible_v<reb::NativeConsoleMessages>);
  static_assert(!std::is_copy_assignable_v<reb::NativeConsoleMessages>);
  static_assert(!std::is_move_constructible_v<reb::NativeConsoleMessages>);
  static_assert(!std::is_move_assignable_v<reb::NativeConsoleMessages>);
  reb::NativeConsoleMessages queue;
  constexpr std::string_view kEmpty = "{\"status\":\"ok\",\"messages\":[],\"dropped\":0}";
  const auto reply = [](std::string_view records, std::uint32_t dropped) {
    return "{\"status\":\"ok\",\"messages\":[" + std::string(records) +
           "],\"dropped\":" + std::to_string(dropped) + "}";
  };
  if (queue.Poll() != kEmpty)
    return false;

  // The former raw-text accounting accepted 16 x 2048 control bytes, then
  // drained them before rejecting the ~192 KiB JSON response. Charge the actual
  // encoded records instead; retain the newest whole records and report loss.
  std::string controls = "{\"text\":\"";
  for (unsigned i = 0; i < 2048; ++i)
    controls += "\\u0001";
  controls += "\"}";
  for (unsigned i = 0; i < 16; ++i)
    queue.Push(controls);
  const auto bounded = queue.Poll();
  if (bounded != reply(controls + "," + controls, 14) ||
      bounded.size() > reb::kNativeConsolePayloadLimit || queue.Poll() != kEmpty)
    return false;

  // Count pressure, repeated wraparound and FIFO order are independent of the
  // encoded-byte limit. Quoted controls and UTF-8 remain serialized inert text.
  for (unsigned pass = 0; pass < 64; ++pass) {
    std::string expected;
    for (unsigned i = 0; i < 40; ++i) {
      const auto record = "{\"text\":\"雪\\n\\\"\\\\\",\"id\":" + std::to_string(i) + "}";
      queue.Push(record);
      if (i >= 8) {
        if (!expected.empty())
          expected += ',';
        expected += record;
      }
    }
    if (queue.Poll() != reply(expected, 8))
      return false;
  }

  const std::string exact =
      "{\"text\":\"" + std::string(reb::NativeConsoleMessages::kByteLimit - 11, 'x') + "\"}";
  queue.Push(exact);
  if (queue.Poll() != reply(exact, 0))
    return false;
  queue.Push(exact);
  queue.Push("{}");
  if (queue.Poll() != reply("{}", 1))
    return false;

  queue.Push("{}");
  queue.Push(std::string(reb::NativeConsoleMessages::kByteLimit + 1, 'x'));
  queue.Push("");
  if (queue.Poll() != reply("{}", 2))
    return false;
  queue.Drop(std::numeric_limits<std::uint32_t>::max());
  queue.Drop();
  if (queue.Poll() != reply("", reb::NativeConsoleMessages::kDropLimit))
    return false;
  queue.Push(controls);
  queue.Drop();
  queue.Reset();
  if (queue.Poll() != kEmpty)
    return false;

  std::cout << "Native console messages: escaping=passed count_limit=passed byte_limit=passed "
               "fifo_wraparound=passed rejected_record=passed drop_saturation=passed "
               "reset=passed\n";
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
  if (!RunEventDemo() || !CheckEventJson() || !CheckNativeConsoleMessages() ||
      !CheckNativeQueueLimits() || !CheckNativeQueueProducers() ||
      !MeasureNativeQueueReuse(iterations) || !CheckNativeQueueNotifications(iterations)) {
    std::cerr << "Native event/console queue validation failed\n";
    return 1;
  }
  return 0;
}
