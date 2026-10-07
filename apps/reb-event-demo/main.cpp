#include <array>
#include <atomic>
#include <barrier>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "components/reverse_engineering_browser/browser/native_worker_transfer_gate.h"
#include "components/reverse_engineering_browser/common/native_probe_queue.h"
#include "components/reverse_engineering_browser/common/native_worker_observation.h"
#include "components/reverse_engineering_browser/common/native_worker_source.h"
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

bool CheckNativeWorkerSources() {
  using Status = reb::NativeWorkerCaptureStatus;
  using Kind = reb::NativeWorkerKind;
  using Source = reb::NativeWorkerSourceKind;
  reb::NativeWorkerSourceQueue queue;
  const reb::NativeWorkerToken worker{0x1234, 0x5678};
  const reb::NativeWorkerToken parent{0x1122, 0x3344};
  reb::NativeWorkerCaptureTicket ticket;
  reb::NativeWorkerSourcePolicy policy{17, 1, 100, {11, 12}, {13, 14}, worker, false};
  const auto latin = [](const std::string_view value) {
    return reb::NativeWorkerText{
        std::span(reinterpret_cast<const std::uint8_t*>(value.data()), value.size()), {}};
  };
  const auto capture = [&](const reb::NativeWorkerText source,
                           const std::string_view url =
                               "https://user:secret@fixture.invalid/a.js?q=secret#secret") {
    return queue.Capture(ticket, parent, Source::kClassic, source, latin(url), 2);
  };
  const auto output = std::make_unique<std::uint8_t[]>(reb::kNativeWorkerSourceMaxBytes);
  const std::span<std::uint8_t> output_span(output.get(), reb::kNativeWorkerSourceMaxBytes);
  std::array<char, reb::kNativeWorkerSourceMaxUrlBytes> url{};
  reb::NativeWorkerSourceHeader header;
  if (queue.IsEnabled() || queue.Begin(Kind::kDedicated, worker, 1, ticket) != Status::kDisabled ||
      capture(latin("disabled")) != Status::kDisabled || queue.Stats().attempted != 0 ||
      queue.Configure(policy, 1) != Status::kInvalid || queue.IsEnabled()) {
    return false;
  }
  policy.sensitive_source_approved = true;
  if (queue.Configure(policy, 1) != Status::kAccepted ||
      queue.Begin(Kind::kShared, worker, 1, ticket) != Status::kUnsupportedWorker ||
      queue.Begin(Kind::kService, worker, 1, ticket) != Status::kUnsupportedWorker ||
      queue.Begin(Kind::kDedicated, {worker.high + 1, worker.low}, 1, ticket) !=
          Status::kWrongWorker ||
      queue.Begin(Kind::kDedicated, worker, 100, ticket) != Status::kExpired ||
      queue.Begin(Kind::kDedicated, worker, 1, ticket) != Status::kAccepted ||
      capture(latin("a\xe9")) != Status::kAccepted ||
      queue.Take(header, {}, url, 3) != Status::kOutputTooSmall ||
      queue.Take(header, output_span, url, 3) != Status::kAccepted || header.worker != worker ||
      header.parent_context != parent || header.browser_context != policy.browser_context ||
      header.renderer_instance != policy.renderer_instance || header.session_id != 17 ||
      header.generation != 1 || header.sequence != 1 || header.sensitive != 1 ||
      header.source_size != 3 || header.source_code_units != 2 ||
      std::string_view(reinterpret_cast<const char*>(output.get()), header.source_size) !=
          "a\xc3\xa9" ||
      std::string_view(url.data(), header.url_size) != "https://fixture.invalid/a.js" ||
      header.url_status != reb::NativeWorkerUrlStatus::kSanitized) {
    return false;
  }
  const std::u16string utf16 = u"\u00e9\U0001f642";
  if (capture({{}, utf16}, "blob:https://fixture.invalid/private-id") != Status::kAccepted ||
      queue.Take(header, output_span, url, 3) != Status::kAccepted || header.source_size != 6 ||
      header.source_code_units != 3 || header.url_size != 0 ||
      header.url_status != reb::NativeWorkerUrlStatus::kOpaqueOmitted ||
      std::string_view(reinterpret_cast<const char*>(output.get()), header.source_size) !=
          "\xc3\xa9\xf0\x9f\x99\x82") {
    return false;
  }
  const std::array<char16_t, 1> malformed{0xd800};
  const std::string too_large(reb::kNativeWorkerSourceMaxBytes + 1, 'x');
  if (capture({{}, malformed}) != Status::kInvalid ||
      capture(latin(too_large)) != Status::kTooLarge ||
      capture({{}, {}, true}) != Status::kSourceUnavailable || capture({}) != Status::kAccepted ||
      queue.Take(header, output_span, url, 3) != Status::kAccepted || header.source_size != 0 ||
      header.dropped_before != 3 || header.sequence != 6) {
    return false;
  }
  for (std::size_t index = 0; index < reb::kNativeWorkerSourceCapacity; ++index) {
    if (capture(latin("queued")) != Status::kAccepted) {
      return false;
    }
  }
  if (capture(latin("dropped")) != Status::kFull || queue.Stats().pending_gap != 1 ||
      queue.Take(header, output_span, url, 3) != Status::kAccepted ||
      capture(latin("after gap")) != Status::kAccepted) {
    return false;
  }
  for (std::size_t index = 0; index < reb::kNativeWorkerSourceCapacity; ++index) {
    if (queue.Take(header, output_span, url, 3) != Status::kAccepted) {
      return false;
    }
  }
  if (header.dropped_before != 1 || queue.Stats().dropped != 4 ||
      queue.Take(header, output_span, url, 3) != Status::kEmpty) {
    return false;
  }
  const auto stale_ticket = ticket;
  policy.generation = 2;
  policy.session_id = 18;
  if (capture(latin("retire on reconfigure")) != Status::kAccepted ||
      queue.Configure(policy, 1) != Status::kAccepted || queue.Stats().retired != 1 ||
      queue.Capture(stale_ticket, parent, Source::kClassic, latin("stale"), {}, 2) !=
          Status::kStaleGeneration ||
      queue.Stats().stale != 1 ||
      queue.Begin(Kind::kDedicated, worker, 1, ticket) != Status::kAccepted ||
      capture(latin("must disappear on teardown")) != Status::kAccepted) {
    return false;
  }
  queue.RetireWorker({worker.high + 1, worker.low});
  if (!queue.IsEnabled()) {
    return false;
  }
  queue.RetireWorker(worker);
  if (queue.IsEnabled() || queue.Take(header, output_span, url, 3) != Status::kDisabled ||
      queue.Stats().retired != 2 || queue.Configure(policy, 1) != Status::kInvalid) {
    return false;
  }
  policy.generation = 3;
  if (queue.Configure(policy, 1) != Status::kAccepted ||
      queue.Begin(Kind::kDedicated, worker, 1, ticket) != Status::kAccepted ||
      capture(latin(std::string_view(too_large).substr(0, reb::kNativeWorkerSourceMaxBytes))) !=
          Status::kAccepted ||
      queue.Take(header, output_span, url, 100) != Status::kExpired || queue.Stats().queued != 0 ||
      queue.Stats().retired != 3) {
    return false;
  }
  queue.Disable();
  std::cout << "Native worker source foundation: disabled=passed exact_worker=passed "
               "shared_service=unsupported utf8=passed redaction=passed limits=passed "
               "gaps=passed stale=passed teardown=passed expiration=passed\n";
  return true;
}

bool CheckNativeWorkerSourceUrls() {
  using Status = reb::NativeWorkerCaptureStatus;
  using UrlStatus = reb::NativeWorkerUrlStatus;
  struct UrlCase final {
    std::string_view input;
    std::string_view expected;
    UrlStatus status;
  };
  const std::string max_label(63, 'a');
  const std::string max_label_url = "https://" + max_label + ".invalid/a.js";
  const std::string over_label_url = "https://a" + max_label + ".invalid/a.js";
  const std::string max_host =
      max_label + "." + max_label + "." + max_label + "." + std::string(61, 'b');
  const std::string max_host_url = "https://" + max_host + "./a.js";
  const std::string over_host_url = "https://" + max_host + "b/a.js";
  const std::array cases{
      UrlCase{max_label_url, max_label_url, UrlStatus::kSanitized},
      UrlCase{over_label_url, "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{max_host_url, max_host_url, UrlStatus::kSanitized},
      UrlCase{over_host_url, "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://fixture.invalid/private.js", "https://fixture.invalid/private.js",
              UrlStatus::kSanitized},
      UrlCase{"https://fixture.invalid", "https://fixture.invalid", UrlStatus::kSanitized},
      UrlCase{"http://localhost:0/worker.js", "http://localhost:0/worker.js",
              UrlStatus::kSanitized},
      UrlCase{"http://127.0.0.1:65535/a.js?q=secret#secret", "http://127.0.0.1:65535/a.js",
              UrlStatus::kSanitized},
      UrlCase{"https://fixture.invalid:00065535/a.js", "https://fixture.invalid:00065535/a.js",
              UrlStatus::kSanitized},
      UrlCase{"https://user:secret@fixture.invalid:443/a.js?q=secret#secret",
              "https://fixture.invalid:443/a.js", UrlStatus::kSanitized},
      UrlCase{"https://UPPER.fixture.invalid./a.js", "https://UPPER.fixture.invalid./a.js",
              UrlStatus::kSanitized},
      // Redaction is deliberately not a full numeric-address/URL validator.
      UrlCase{"https://999.999.999.999/a.js", "https://999.999.999.999/a.js",
              UrlStatus::kSanitized},
      UrlCase{"https://:443/private.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://[::1/private.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid:65536/private.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid:999999999999999999999/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid:-1/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid:+1/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid:port/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid:/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https:///a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://user:secret@/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://[]/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://[[::1]]/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid]/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://[::1]extra/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://::1/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://[::1]:65536/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid\\private/a.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://fixture.invalid/\na.js", "", UrlStatus::kInvalidOmitted},
      UrlCase{"https://[::1]:443/a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://[not-an-ip]/a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://user:secret@[::1]/a.js?q=secret#secret", "",
              UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://name_with_underscore/a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://-fixture.invalid/a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://fixture-.invalid/a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://fixture..invalid/a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://fixture.invalid../a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://%66ixture.invalid/a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"https://m\xfcnich.invalid/a.js", "", UrlStatus::kUnsupportedAuthorityOmitted},
      UrlCase{"data:text/javascript,secret", "", UrlStatus::kOpaqueOmitted},
      UrlCase{"blob:https://fixture.invalid/private-id", "", UrlStatus::kOpaqueOmitted},
      UrlCase{"", "", UrlStatus::kAbsent},
  };
  reb::NativeWorkerSourceQueue queue;
  const reb::NativeWorkerToken worker{101, 102};
  const reb::NativeWorkerSourcePolicy policy{103, 1, 100, {104, 105}, {106, 107}, worker, true};
  reb::NativeWorkerCaptureTicket ticket;
  if (queue.Configure(policy, 1) != Status::kAccepted ||
      queue.Begin(reb::NativeWorkerKind::kDedicated, worker, 1, ticket) != Status::kAccepted) {
    return false;
  }
  constexpr std::array<std::uint8_t, 1> kSource{'x'};
  std::array<std::uint8_t, 1> output{};
  std::array<char, reb::kNativeWorkerSourceMaxUrlBytes> url{};
  for (const auto& test : cases) {
    const reb::NativeWorkerText input{
        std::span(reinterpret_cast<const std::uint8_t*>(test.input.data()), test.input.size()), {}};
    reb::NativeWorkerSourceHeader header;
    if (queue.Capture(ticket, {}, reb::NativeWorkerSourceKind::kClassic, {kSource, {}}, input, 2) !=
            Status::kAccepted ||
        queue.Take(header, output, url, 3) != Status::kAccepted ||
        header.url_status != test.status ||
        std::string_view(url.data(), header.url_size) != test.expected ||
        header.source_size != kSource.size() || output != kSource || header.sensitive != 1) {
      return false;
    }
  }
  if (queue.Stats().dropped != 0) {
    return false;
  }
  std::cout << "Native worker URL metadata: vectors=" << cases.size()
            << " authority_subset=passed redaction=passed omissions=passed "
               "full_url_validation=not_claimed\n";
  return true;
}

bool CheckNativeWorkerSourceConcurrency() {
  using Status = reb::NativeWorkerCaptureStatus;
  reb::NativeWorkerSourceQueue queue;
  const reb::NativeWorkerToken worker{71, 72};
  const reb::NativeWorkerSourcePolicy policy{81, 1, 100, {91, 92}, {93, 94}, worker, true};
  reb::NativeWorkerCaptureTicket ticket;
  if (queue.Configure(policy, 1) != Status::kAccepted ||
      queue.Begin(reb::NativeWorkerKind::kDedicated, worker, 1, ticket) != Status::kAccepted) {
    return false;
  }
  constexpr std::uint64_t kAttempts = 20'000;
  std::atomic<bool> done{false};
  std::atomic<bool> valid{true};
  std::thread producer([&] {
    constexpr std::array<std::uint8_t, 3> kText{'a', 'b', 'c'};
    for (std::uint64_t index = 0; index < kAttempts; ++index) {
      const auto status =
          queue.Capture(ticket, {}, reb::NativeWorkerSourceKind::kModule, {kText, {}}, {}, 2);
      if (status != Status::kAccepted && status != Status::kFull && status != Status::kBusy) {
        valid.store(false);
      }
    }
    done.store(true, std::memory_order_release);
  });
  std::uint64_t taken = 0;
  std::uint64_t last = 0;
  std::array<std::uint8_t, 3> source{};
  while (!done.load(std::memory_order_acquire) || queue.Stats().queued != 0) {
    reb::NativeWorkerSourceHeader header;
    const auto status = queue.Take(header, source, {}, 3);
    if (status == Status::kAccepted) {
      ++taken;
      if (header.sequence <= last || source != std::array<std::uint8_t, 3>{'a', 'b', 'c'}) {
        valid.store(false);
      }
      last = header.sequence;
    } else if (status != Status::kBusy && status != Status::kEmpty) {
      valid.store(false);
    }
  }
  producer.join();
  const auto stats = queue.Stats();
  std::cout << "Native worker source concurrency: attempts=" << kAttempts << " taken=" << taken
            << " dropped=" << stats.dropped << " contended=" << stats.contended << '\n';
  return valid.load() && stats.attempted + stats.contended == kAttempts &&
         taken + stats.dropped == stats.attempted && stats.queued == 0;
}

bool CheckNativeWorkerObservations() {
  using Status = reb::NativeWorkerCaptureStatus;
  using Operation = reb::NativeWorkerOperation;
  using Direction = reb::NativeWorkerDirection;
  reb::NativeWorkerObservationQueue queue;
  reb::NativeWorkerObservationProjection projection;
  reb::NativeWorkerObservationPolicy policy{71, 1, 1000, {1, 2}, {3, 4}, {5, 6}, {7, 8}};
  reb::NativeWorkerCaptureTicket ticket;
  reb::NativeWorkerObservation record;
  const auto begin = [&] {
    return queue.Begin(reb::NativeWorkerKind::kDedicated, policy.worker, policy.creator,
                       policy.creator_kind, 1, ticket);
  };
  const auto emit = [&](reb::NativeWorkerObservationInput input) {
    return queue.Capture(ticket, input, 2);
  };
  const auto project = [&] {
    return queue.Take(record, 3) == Status::kAccepted && projection.Apply(record, 3);
  };
  if (begin() != Status::kDisabled || queue.Take(record, 1) != Status::kDisabled ||
      queue.Configure({}, 1) != Status::kInvalid || queue.IsEnabled() ||
      queue.Configure(policy, 1) != Status::kAccepted || !projection.Reset(policy) ||
      queue.Begin(reb::NativeWorkerKind::kShared, policy.worker, policy.creator,
                  policy.creator_kind, 1, ticket) != Status::kUnsupportedWorker ||
      queue.Begin(reb::NativeWorkerKind::kService, policy.worker, policy.creator,
                  policy.creator_kind, 1, ticket) != Status::kUnsupportedWorker ||
      queue.Begin(reb::NativeWorkerKind::kDedicated, {99, 6}, policy.creator, policy.creator_kind,
                  1, ticket) != Status::kWrongWorker ||
      queue.Begin(reb::NativeWorkerKind::kDedicated, policy.worker, {99, 8}, policy.creator_kind, 1,
                  ticket) != Status::kWrongWorker ||
      queue.Begin(reb::NativeWorkerKind::kDedicated, policy.worker, policy.creator,
                  reb::NativeWorkerCreatorKind::kDedicatedWorker, 1,
                  ticket) != Status::kWrongWorker ||
      begin() != Status::kAccepted) {
    return false;
  }
  for (const auto operation : {Operation::kObjectCreated, Operation::kGlobalScopeStarted,
                               Operation::kTerminateRequested, Operation::kGlobalScopeDisposed}) {
    if (emit({operation}) != Status::kAccepted || !project()) {
      return false;
    }
  }
  reb::NativeWorkerMessageTag send_tag;
  const auto receive = [&](Direction direction, std::uint64_t native_id,
                           reb::NativeWorkerMessageTag tag, bool error = false) {
    return emit({error ? Operation::kMessageError : Operation::kMessageReceived, direction,
                 native_id, 0, reb::NativeWorkerSourceKind::kClassic, tag});
  };
  if (queue.Capture(ticket, {Operation::kMessageSent, Direction::kToWorker, 0}, 2, &send_tag) !=
          Status::kAccepted ||
      send_tag.send_sequence == 0 || !project() || projection.messages()[0].observed() ||
      receive(Direction::kToWorker, 0, send_tag) != Status::kAccepted || !project() ||
      !projection.messages()[0].observed() ||
      queue.Capture(ticket, {Operation::kMessageSent, Direction::kToCreator, 0}, 2, &send_tag) !=
          Status::kAccepted ||
      !project() || receive(Direction::kToCreator, 0, send_tag, true) != Status::kAccepted ||
      !project() || !projection.messages()[1].observed() ||
      !projection.messages()[1].receive_error ||
      receive(Direction::kToCreator, 0, send_tag) != Status::kAccepted || !project() ||
      projection.messages()[1].observed() || !projection.messages()[1].ambiguous ||
      receive(Direction::kToWorker, 999, {}) != Status::kAccepted || !project() ||
      projection.stats().untagged_receives != 1 ||
      emit({Operation::kScriptCompiled, Direction::kNone, 0, 19,
            reb::NativeWorkerSourceKind::kModule}) != Status::kAccepted ||
      !project() || projection.scripts()[0].script_id != 19 ||
      emit({Operation::kScriptCompiled, Direction::kNone, 0, 19}) != Status::kAccepted ||
      !project() || !projection.scripts()[0].ambiguous || projection.stats().ambiguous_ids != 2) {
    return false;
  }
  // Reject copied records from different epochs/contexts or malformed ABI.
  const auto valid = record;
  for (int mutation = 0; mutation < 12; ++mutation) {
    auto forged = valid;
    ++forged.sequence;
    switch (mutation) {
      case 0:
        ++forged.session_id;
        break;
      case 1:
        ++forged.generation;
        break;
      case 2:
        ++forged.worker.high;
        break;
      case 3:
        ++forged.creator.high;
        break;
      case 4:
        ++forged.browser_context.high;
        break;
      case 5:
        ++forged.renderer_instance.high;
        break;
      case 6:
        ++forged.version;
        break;
      case 7:
        ++forged.record_size;
        break;
      case 8:
        forged.reserved[0] = std::byte{1};
        break;
      case 9:
        forged.worker_kind = reb::NativeWorkerKind::kService;
        break;
      case 10:
        forged.creator_kind = reb::NativeWorkerCreatorKind::kDedicatedWorker;
        break;
      case 11:
        forged.monotonic_time_ns = 4;
        break;
    }
    if (projection.Apply(forged, 3)) {
      return false;
    }
  }
  if (projection.Apply(valid, 3) || projection.stats().out_of_order != 1 ||
      emit({Operation::kMessageSent, Direction::kNone, 1}) != Status::kInvalid ||
      emit({Operation::kScriptCompiled}) != Status::kInvalid ||
      emit({static_cast<Operation>(999)}) != Status::kInvalid ||
      emit({Operation::kObjectCreated}) != Status::kAccepted || !project() ||
      record.dropped_before != 3 || projection.stats().missing_sequences != 3 ||
      projection.stats().reported_drops != 3) {
    return false;
  }
  for (std::size_t index = 0; index < reb::kNativeWorkerObservationCapacity; ++index) {
    if (emit({Operation::kObjectCreated}) != Status::kAccepted) {
      return false;
    }
  }
  if (emit({Operation::kObjectCreated}) != Status::kFull || !project() ||
      emit({Operation::kObjectCreated}) != Status::kAccepted) {
    return false;
  }
  while (queue.Stats().queued != 0) {
    if (!project()) {
      return false;
    }
  }
  if (record.dropped_before != 1 || queue.Stats().dropped != 4) {
    return false;
  }
  const auto old_ticket = ticket;
  ++policy.generation;
  if (queue.Configure(policy, 1) != Status::kAccepted || !projection.Reset(policy) ||
      queue.Capture(old_ticket, {}, 2) != Status::kStaleGeneration ||
      begin() != Status::kAccepted) {
    return false;
  }
  queue.Retire(old_ticket);
  auto wrong_ticket = ticket;
  ++wrong_ticket.worker.high;
  queue.Retire(wrong_ticket);
  if (!queue.IsEnabled()) {
    return false;
  }
  // Never evict a completed key and accidentally pair a later reuse.
  reb::NativeWorkerMessageTag retained_send_tag;
  for (std::uint64_t id = 0; id < reb::kNativeWorkerProjectionCapacity; ++id) {
    if (emit({Operation::kMessageSent, Direction::kToWorker, id}) != Status::kAccepted ||
        !project()) {
      return false;
    }
    if (id == 1) {
      retained_send_tag = {record.session_id, record.generation, record.send_sequence};
    }
  }
  if (emit({Operation::kMessageSent, Direction::kToWorker, 999}) != Status::kAccepted ||
      project() || projection.stats().capacity_drops != 1 ||
      receive(Direction::kToWorker, 999,
              {record.session_id, record.generation, record.send_sequence}) != Status::kAccepted ||
      project() || projection.stats().capacity_drops != 2 ||
      receive(Direction::kToWorker, 1, retained_send_tag) != Status::kAccepted || !project() ||
      !projection.messages()[1].observed() ||
      emit({Operation::kObjectCreated}) != Status::kAccepted) {
    return false;
  }
  queue.Retire(ticket);
  if (queue.IsEnabled() || queue.Stats().queued != 1 || queue.Stats().retired != 0 ||
      queue.Capture(ticket, {}, 2) != Status::kDisabled ||
      queue.Take(record, 3) != Status::kAccepted || record.operation != Operation::kObjectCreated ||
      queue.Take(record, 3) != Status::kEmpty || queue.Configure(policy, 1) != Status::kInvalid) {
    return false;
  }
  ++policy.generation;
  if (queue.Configure(policy, 1) != Status::kAccepted || begin() != Status::kAccepted ||
      emit({}) != Status::kAccepted || queue.Capture(ticket, {}, 1000) != Status::kExpired ||
      queue.Take(record, 1000) != Status::kDisabled || queue.Stats().queued != 0 ||
      queue.Stats().retired != 1 || (!projection.Expire(1000)) || !projection.messages().empty() ||
      projection.Reset({}) || projection.Apply(valid, 3) || !projection.messages().empty() ||
      !projection.scripts().empty()) {
    return false;
  }
  queue.Disable();
  std::cout << "Native worker metadata: identity=passed lifecycle=passed zero_trace_id=passed "
               "message_error=passed ambiguity=passed bounded_projection=passed gaps=passed "
               "retirement=passed expiry=passed no_payload_fields=passed\n";
  return true;
}

bool CheckNativeWorkerMessageTags() {
  using Status = reb::NativeWorkerCaptureStatus;
  using Operation = reb::NativeWorkerOperation;
  using Direction = reb::NativeWorkerDirection;
  reb::NativeWorkerObservationQueue queue;
  reb::NativeWorkerObservationProjection projection;
  reb::NativeWorkerObservationPolicy policy{71, 1, 1000, {1, 2}, {3, 4}, {5, 6}, {7, 8}};
  reb::NativeWorkerCaptureTicket ticket;
  reb::NativeWorkerObservation record;
  reb::NativeWorkerMessageTag first, second;
  const auto project = [&] {
    return queue.Take(record, 3) == Status::kAccepted && projection.Apply(record, 3);
  };
  const auto receive = [&](reb::NativeWorkerMessageTag tag,
                           Direction direction = Direction::kToWorker) {
    return queue.Capture(
        ticket,
        {Operation::kMessageReceived, direction, 0, 0, reb::NativeWorkerSourceKind::kClassic, tag},
        2);
  };
  if (queue.Configure(policy, 1) != Status::kAccepted || !projection.Reset(policy) ||
      queue.Begin(reb::NativeWorkerKind::kDedicated, policy.worker, policy.creator,
                  policy.creator_kind, 1, ticket) != Status::kAccepted ||
      queue.Capture(ticket, {Operation::kMessageSent, Direction::kToWorker, 0}, 2, &first) !=
          Status::kAccepted ||
      !project() || queue.Capture(ticket, {Operation::kObjectCreated}, 2) != Status::kAccepted ||
      !project()) {
    return false;
  }
  // A tag naming a lifecycle observation must never pair with an unrelated send
  // merely because both upstream trace IDs are zero.
  auto absent = first;
  ++absent.send_sequence;
  if (receive(absent) != Status::kAccepted || !project() || projection.messages().size() != 2 ||
      projection.messages()[0].observed() || projection.messages()[1].observed() ||
      receive(first) != Status::kAccepted || !project() || !projection.messages()[0].observed() ||
      queue.Capture(ticket, {Operation::kMessageSent, Direction::kToWorker, 0}, 2, &second) !=
          Status::kAccepted ||
      !project() || receive(second) != Status::kAccepted || !project() ||
      projection.messages().size() != 3 || !projection.messages()[2].observed()) {
    return false;
  }
  for (int mutation = 0; mutation < 4; ++mutation) {
    auto stale = second;
    if (mutation == 0)
      ++stale.session_id;
    if (mutation == 1)
      ++stale.generation;
    if (mutation == 2)
      stale.send_sequence = 0;
    if (mutation == 3)
      stale.send_sequence = std::numeric_limits<std::uint64_t>::max();
    if (receive(stale) != Status::kInvalid)
      return false;
  }
  if (receive(second, Direction::kToCreator) != Status::kAccepted || !project() ||
      projection.messages()[2].observed() || !projection.messages()[2].ambiguous ||
      record.dropped_before != 4 ||
      queue.Capture(ticket, {Operation::kGlobalScopeDisposed}, 2) != Status::kAccepted) {
    return false;
  }
  queue.Retire(ticket);
  if (queue.IsEnabled() || !project() || record.operation != Operation::kGlobalScopeDisposed ||
      queue.Take(record, 3) != Status::kEmpty ||
      queue.Capture(ticket, {}, 2, &second) != Status::kDisabled || second.send_sequence != 0) {
    return false;
  }
  projection.Retire();
  if (!projection.messages().empty() || projection.stats().retired_entries != 3 ||
      projection.Apply(record, 3))
    return false;
  ++policy.generation;
  if (queue.Configure(policy, 1) != Status::kAccepted ||
      queue.Begin(reb::NativeWorkerKind::kDedicated, policy.worker, policy.creator,
                  policy.creator_kind, 1, ticket) != Status::kAccepted ||
      queue.Capture(ticket, {}, 2) != Status::kAccepted)
    return false;
  queue.Disable();
  if (queue.Stats().retired != 1 || queue.Take(record, 3) != Status::kDisabled)
    return false;
  std::cout
      << "Native worker tags: full_epoch=passed reused_zero_trace=passed false_pair=prevented "
         "direction_mismatch=ambiguous dispose_drain=passed explicit_revoke=passed\n";
  return true;
}

bool CheckNativeWorkerObservationConcurrency() {
  using Status = reb::NativeWorkerCaptureStatus;
  reb::NativeWorkerObservationQueue queue;
  reb::NativeWorkerObservationPolicy policy{71, 1, 1000, {1, 2}, {3, 4}, {5, 6}, {7, 8}};
  reb::NativeWorkerCaptureTicket ticket;
  if (queue.Configure(policy, 1) != Status::kAccepted ||
      queue.Begin(reb::NativeWorkerKind::kDedicated, policy.worker, policy.creator,
                  policy.creator_kind, 1, ticket) != Status::kAccepted) {
    return false;
  }
  constexpr std::uint64_t kAttempts = 20000;
  std::atomic<bool> done{false};
  std::atomic<bool> valid{true};
  std::thread producer([&] {
    for (std::uint64_t index = 0; index < kAttempts; ++index) {
      const auto status = queue.Capture(ticket, {}, 2);
      if (status != Status::kAccepted && status != Status::kFull && status != Status::kBusy) {
        valid.store(false);
      }
    }
    done.store(true, std::memory_order_release);
  });
  std::uint64_t taken = 0;
  std::uint64_t last = 0;
  while (!done.load(std::memory_order_acquire) || queue.Stats().queued != 0) {
    reb::NativeWorkerObservation record;
    const auto status = queue.Take(record, 3);
    if (status == Status::kAccepted) {
      ++taken;
      if (record.sequence <= last) {
        valid.store(false);
      }
      last = record.sequence;
    } else if (status != Status::kBusy && status != Status::kEmpty) {
      valid.store(false);
    }
  }
  producer.join();
  const auto stats = queue.Stats();
  std::cout << "Native worker metadata concurrency: attempts=" << kAttempts << " taken=" << taken
            << " dropped=" << stats.dropped << " contended=" << stats.contended << '\n';
  return valid.load() && stats.attempted + stats.contended == kAttempts &&
         taken + stats.dropped == stats.attempted && stats.queued == 0;
}

bool WorkerCheck(const bool condition, const std::string_view description) {
  if (!condition) {
    std::cerr << "Native worker transport: " << description << '\n';
  }
  return condition;
}

struct WorkerTransferFixture final {
  static constexpr std::uint64_t kNow = 100;
  reb::NativeWorkerAuthorityScope scope{1,      71,     1,      100'000'000'000ULL,
                                        {1, 2}, {3, 4}, {5, 6}, {7, 8}};
  reb::NativeWorkerOwner owner{{9, 10},
                               {11, 12},
                               scope.selected_frame,
                               reb::NativeWorkerCreatorKind::kDocument,
                               scope.selected_document,
                               scope.document_generation};
  reb::NativeWorkerAuthority authority;
  reb::NativeWorkerObservationQueue queue;
  reb::NativeWorkerTransferSender sender{queue};
  reb::NativeWorkerTransferReceiver receiver{authority};
  reb::NativeWorkerLease lease;
  reb::NativeWorkerCaptureTicket ticket;

  bool Configure() {
    return authority.Reset(scope, kNow) &&
           authority.Created(scope.observer_epoch, owner, kNow) ==
               reb::NativeWorkerAuthorityStatus::kRecorded &&
           authority.Issue(owner.worker, {13, 14}, kNow, lease) ==
               reb::NativeWorkerAuthorityStatus::kAllowed &&
           sender.Configure(lease, kNow) == reb::NativeWorkerTransferStatus::kConfigured &&
           receiver.Configure(lease, kNow) &&
           queue.Begin(reb::NativeWorkerKind::kDedicated, owner.worker, owner.creator,
                       owner.creator_kind, kNow,
                       ticket) == reb::NativeWorkerCaptureStatus::kAccepted;
  }
  bool Capture(const reb::NativeWorkerObservationInput input = {}) {
    return queue.Capture(ticket, input, kNow) == reb::NativeWorkerCaptureStatus::kAccepted;
  }
};
static_assert(!std::is_copy_constructible_v<reb::NativeWorkerTransferSender>);
static_assert(!std::is_move_constructible_v<reb::NativeWorkerTransferSender>);
static_assert(!std::is_copy_constructible_v<reb::NativeWorkerTransferReceiver>);
static_assert(!std::is_move_constructible_v<reb::NativeWorkerAuthority>);

bool CheckNativeWorkerAuthority() {
  using Status = reb::NativeWorkerAuthorityStatus;
  using Creator = reb::NativeWorkerCreatorKind;
  WorkerTransferFixture fixture;
  auto& authority = fixture.authority;
  auto scope = fixture.scope;
  const auto root = fixture.owner;
  reb::NativeWorkerOwner child{{20, 21}, {22, 23}, root.worker, Creator::kDedicatedWorker, {}, 0};
  reb::NativeWorkerLease lease;
  if (!WorkerCheck(
          authority.Resolve(root.worker, 100) == Status::kDisabled && authority.Reset(scope, 100) &&
              authority.Created(1, child, 100) == Status::kRecorded &&
              authority.Resolve(child.worker, 100) == Status::kUnresolvedParent &&
              authority.Issue(child.worker, {30, 31}, 100, lease) == Status::kUnresolvedParent &&
              lease == reb::NativeWorkerLease{} &&
              authority.Created(1, root, 100) == Status::kRecorded &&
              authority.Created(1, root, 100) == Status::kDuplicate &&
              authority.Resolve(child.worker, 100) == Status::kAllowed &&
              authority.Issue(child.worker, {30, 31}, 100, lease) == Status::kAllowed &&
              authority.IsCurrent(lease, 100),
          "out-of-order browser ancestry and exact duplicate ownership")) {
    return false;
  }
  const auto old_lease = lease;
  if (!WorkerCheck(authority.Issue(root.worker, {32, 33}, 100, lease) == Status::kAllowed &&
                       !authority.IsCurrent(old_lease, 100) && authority.IsCurrent(lease, 100),
                   "new lease revokes prior worker/connection")) {
    return false;
  }
  for (unsigned field = 0; field < 13; ++field) {
    auto forged = lease;
    switch (field) {
      case 0:
        ++forged.policy.browser_context.high;
        break;
      case 1:
        ++forged.storage_partition.high;
        break;
      case 2:
        ++forged.policy.renderer_instance.high;
        break;
      case 3:
        ++forged.selected_frame.high;
        break;
      case 4:
        ++forged.selected_document.high;
        break;
      case 5:
        ++forged.document_generation;
        break;
      case 6:
        ++forged.observer_epoch;
        break;
      case 7:
        ++forged.connection.high;
        break;
      case 8:
        ++forged.policy.worker.high;
        break;
      case 9:
        ++forged.policy.creator.high;
        break;
      case 10:
        ++forged.policy.session_id;
        break;
      case 11:
        ++forged.policy.generation;
        break;
      case 12:
        ++forged.policy.expires_at_monotonic_ns;
        break;
    }
    if (!WorkerCheck(!authority.IsCurrent(forged, 100), "forged lease rejected")) {
      return false;
    }
  }
  auto conflict = root;
  ++conflict.renderer_instance.high;
  if (!WorkerCheck(authority.Created(1, conflict, 100) == Status::kAmbiguous &&
                       authority.Resolve(child.worker, 100) == Status::kAmbiguous &&
                       !authority.IsCurrent(lease, 100),
                   "conflicting ownership fails closed")) {
    return false;
  }
  ++scope.observer_epoch;
  if (!authority.Reset(scope, 100)) {
    return false;
  }
  auto wrong_document = root;
  ++wrong_document.creator_document.high;
  if (!WorkerCheck(authority.Created(2, wrong_document, 100) == Status::kRecorded &&
                       authority.Resolve(root.worker, 100) == Status::kWrongDocument &&
                       authority.Created(1, child, 100) == Status::kStaleEpoch &&
                       !authority.DocumentDestroyed(1, scope.selected_document, 1) &&
                       !authority.DocumentDestroyed(2, scope.selected_document, 2),
                   "document token/generation and observer epoch are mandatory")) {
    return false;
  }
  ++scope.observer_epoch;
  if (!authority.Reset(scope, 100)) {
    return false;
  }
  auto cycle = root;
  cycle.creator = child.worker;
  cycle.creator_kind = Creator::kDedicatedWorker;
  cycle.creator_document = {};
  cycle.document_generation = 0;
  if (!WorkerCheck(authority.Created(3, cycle, 100) == Status::kRecorded &&
                       authority.Created(3, child, 100) == Status::kRecorded &&
                       authority.Resolve(child.worker, 100) == Status::kCycle,
                   "cycles never establish ancestry")) {
    return false;
  }
  ++scope.observer_epoch;
  if (!authority.Reset(scope, 100)) {
    return false;
  }
  if (!WorkerCheck(authority.Destroyed(4, root.worker) == Status::kRecorded &&
                       authority.Created(4, root, 100) == Status::kRetired &&
                       authority.Created(4, child, 100) == Status::kRecorded &&
                       authority.Resolve(child.worker, 100) == Status::kRetired,
                   "out-of-order teardown tombstones cannot be reused")) {
    return false;
  }
  ++scope.observer_epoch;
  if (!authority.Reset(scope, 100)) {
    return false;
  }
  if (!WorkerCheck(authority.RendererDestroyed(5, root.renderer_instance) == Status::kRecorded &&
                       authority.Created(5, root, 100) == Status::kRetired &&
                       authority.RendererDestroyed(5, root.renderer_instance) == Status::kDuplicate,
                   "renderer incarnation tombstones reject late creation")) {
    return false;
  }
  ++scope.observer_epoch;
  if (!authority.Reset(scope, 100) || authority.Created(6, root, 100) != Status::kRecorded ||
      authority.Created(6, child, 100) != Status::kRecorded ||
      authority.Issue(child.worker, {30, 31}, 100, lease) != Status::kAllowed ||
      authority.RendererDestroyed(6, root.renderer_instance) != Status::kRecorded ||
      !WorkerCheck(!authority.IsCurrent(lease, 100) &&
                       authority.Resolve(child.worker, 100) == Status::kRetired,
                   "parent renderer death revokes descendant lease")) {
    return false;
  }
  ++scope.observer_epoch;
  if (!authority.Reset(scope, 100)) {
    return false;
  }
  for (std::size_t index = 0; index < reb::kNativeWorkerAuthorityCapacity; ++index) {
    auto owner = root;
    owner.worker = {1000 + index, 1};
    if (authority.Created(7, owner, 100) != Status::kRecorded ||
        authority.RendererDestroyed(7, {2000 + index, 1}) != Status::kRecorded) {
      return false;
    }
  }
  if (!WorkerCheck(authority.Created(7, root, 100) == Status::kFull &&
                       authority.RendererDestroyed(7, root.renderer_instance) == Status::kFull &&
                       authority.Resolve({1000, 1}, 100) == Status::kDisabled &&
                       authority.stats().capacity_drops == 2,
                   "fixed ownership and retirement bounds report loss and fail closed")) {
    return false;
  }
  ++scope.observer_epoch;
  if (!authority.Reset(scope, 100) || authority.Created(8, root, 100) != Status::kRecorded ||
      authority.Issue(root.worker, {30, 31}, 100, lease) != Status::kAllowed ||
      !WorkerCheck(!authority.IsCurrent(lease, scope.expires_at_ns) &&
                       authority.Resolve(root.worker, scope.expires_at_ns) == Status::kExpired &&
                       authority.DocumentDestroyed(8, scope.selected_document, 1) &&
                       authority.Resolve(root.worker, 100) == Status::kDisabled,
                   "absolute expiry and exact document teardown")) {
    return false;
  }
  std::cout << "Native worker authority: ancestry=passed tombstones=passed cycles=passed "
               "document_partition_lease=passed stale_epoch=passed bounds=passed\n";
  return true;
}

bool CheckNativeWorkerTransfer() {
  using Status = reb::NativeWorkerTransferStatus;
  using Capture = reb::NativeWorkerCaptureStatus;
  WorkerTransferFixture fixture;
  if (!fixture.Configure()) {
    return false;
  }
  reb::NativeWorkerPull request;
  constexpr auto kNow = WorkerTransferFixture::kNow;
  constexpr auto kNext = kNow + reb::kNativeWorkerMinPollIntervalNs;
  if (!WorkerCheck(
          fixture.receiver.Request(kNow, request) == Status::kRequestReady &&
              fixture.receiver.Receive(fixture.sender.Pull(request, kNow), kNow) == Status::kIdle &&
              fixture.receiver.Request(kNext - 1, request) == Status::kBusy,
          "empty polling respects bounded request cadence")) {
    return false;
  }
  reb::NativeWorkerMessageTag tag;
  using Operation = reb::NativeWorkerOperation;
  using Direction = reb::NativeWorkerDirection;
  if (fixture.queue.Capture(fixture.ticket, {Operation::kMessageSent, Direction::kToWorker, 0},
                            kNow, &tag) != Capture::kAccepted ||
      !fixture.Capture({Operation::kMessageReceived, Direction::kToWorker, 0, 0,
                        reb::NativeWorkerSourceKind::kClassic, tag}) ||
      !fixture.Capture({Operation::kScriptCompiled, Direction::kNone, 0, 7,
                        reb::NativeWorkerSourceKind::kModule}) ||
      fixture.receiver.Request(kNext, request) != Status::kRequestReady) {
    return false;
  }
  const auto reply = fixture.sender.Pull(request, kNext);
  if (!WorkerCheck(reply.status == Status::kBatch && reply.batch.count == 3 &&
                       fixture.sender.stats().acknowledged_records == 0 &&
                       fixture.receiver.Receive(reply, kNext) == Status::kBatch &&
                       fixture.receiver.Request(kNext, request) == Status::kBusy,
                   "drain retains credit until downstream acceptance")) {
    return false;
  }
  const auto* pending = fixture.receiver.PendingForPublication(kNext);
  reb::NativeWorkerObservationProjection projection;
  if (!pending || !projection.Reset(fixture.lease.policy)) {
    return false;
  }
  for (std::size_t index = 0; index < pending->count; ++index) {
    if (!projection.Apply(pending->records[index], kNext)) {
      return false;
    }
  }
  const reb::NativeWorkerBatchAck ack{pending->epoch, pending->batch_id};
  auto wrong_ack = ack;
  ++wrong_ack.batch_id;
  if (!WorkerCheck(projection.messages().size() == 1 && projection.messages()[0].observed() &&
                       projection.scripts().size() == 1 &&
                       !fixture.receiver.AcknowledgePublished(wrong_ack, kNext) &&
                       fixture.receiver.PendingForPublication(kNext) &&
                       fixture.receiver.AcknowledgePublished(ack, kNext) &&
                       !fixture.receiver.PendingForPublication(kNext) &&
                       !fixture.receiver.AcknowledgePublished(ack, kNext),
                   "exact carried tag survives transfer; ack is exact and single-use")) {
    return false;
  }
  const auto now = kNext + reb::kNativeWorkerMinPollIntervalNs;
  if (fixture.receiver.Request(now, request) != Status::kRequestReady ||
      fixture.receiver.Receive(fixture.sender.Pull(request, now), now) != Status::kIdle ||
      !WorkerCheck(fixture.sender.stats().acknowledged_records == 3 &&
                       fixture.sender.stats().acknowledged_batches == 1,
                   "next pull acknowledges complete batch")) {
    return false;
  }
  fixture.receiver.Revoke();
  if (!WorkerCheck(!fixture.receiver.Configure(fixture.lease, now),
                   "revoked receiver cannot reset sequence state in the same lease")) {
    return false;
  }
  std::cout << "Native worker transfer: bounded_poll=passed exact_tag_projection=passed "
               "downstream_credit=passed acknowledgment=passed lease_replay=passed\n";
  return true;
}

bool CheckNativeWorkerTransferPressure() {
  using Status = reb::NativeWorkerTransferStatus;
  WorkerTransferFixture fixture;
  if (!fixture.Configure()) {
    return false;
  }
  for (std::size_t index = 0; index < reb::kNativeWorkerObservationCapacity; ++index) {
    if (!fixture.Capture()) {
      return false;
    }
  }
  if (fixture.queue.Capture(fixture.ticket, {}, 100) != reb::NativeWorkerCaptureStatus::kFull) {
    return false;
  }
  fixture.queue.Retire(fixture.ticket);
  std::uint64_t now = WorkerTransferFixture::kNow;
  for (std::size_t index = 0; index < 8; ++index) {
    reb::NativeWorkerPull request;
    if (fixture.receiver.Request(now, request) != Status::kRequestReady) {
      return false;
    }
    const auto reply = fixture.sender.Pull(request, now);
    if (fixture.receiver.Receive(reply, now) != Status::kBatch ||
        !WorkerCheck(
            reply.batch.count == reb::kNativeWorkerBatchCapacity &&
                reply.batch.capture_stats.dropped == 1 && reply.batch.worker_retired &&
                reply.batch.capture_stats.queued == (7 - index) * reb::kNativeWorkerBatchCapacity &&
                fixture.receiver.AcknowledgePublished({reply.epoch, reply.batch.batch_id}, now),
            "retired queue drains in fixed batches with terminal drop accounting")) {
      return false;
    }
    now += reb::kNativeWorkerMinPollIntervalNs;
  }
  reb::NativeWorkerPull request;
  if (fixture.receiver.Request(now, request) != Status::kRequestReady ||
      fixture.receiver.Receive(fixture.sender.Pull(request, now), now) != Status::kIdle ||
      fixture.sender.stats().acknowledged_records != reb::kNativeWorkerObservationCapacity ||
      fixture.sender.stats().batches != 8 || fixture.queue.Stats().retired != 0) {
    return false;
  }
  std::cout << "Native worker transfer pressure: batches=8 records=128 overflow=reported "
               "retired_drain=passed terminal_loss=passed\n";
  return true;
}

bool CheckNativeWorkerTransferRejection() {
  using Status = reb::NativeWorkerTransferStatus;
  constexpr auto kNow = WorkerTransferFixture::kNow;
  for (unsigned field = 0; field < 16; ++field) {
    WorkerTransferFixture fixture;
    reb::NativeWorkerPull request;
    if (!fixture.Configure() || !fixture.Capture() || !fixture.Capture() ||
        fixture.receiver.Request(kNow, request) != Status::kRequestReady) {
      return false;
    }
    auto reply = fixture.sender.Pull(request, kNow);
    switch (field) {
      case 0:
        ++reply.batch.version;
        break;
      case 1:
        ++reply.batch.reserved;
        break;
      case 2:
        reply.batch.count = 17;
        break;
      case 3:
        ++reply.batch.epoch.connection.high;
        break;
      case 4:
        reply.batch.batch_id = 0;
        break;
      case 5:
        reply.batch.acknowledgment_deadline_ns = kNow;
        break;
      case 6:
        ++reply.batch.acknowledgment_deadline_ns;
        break;
      case 7:
        reply.batch.capture_stats.queued = 129;
        break;
      case 8:
        ++reply.batch.records[0].worker.high;
        break;
      case 9:
        reply.batch.records[0].reserved[0] = std::byte{1};
        break;
      case 10:
        reply.batch.records[0].monotonic_time_ns = kNow - 1;
        break;
      case 11:
        reply.batch.records[0].monotonic_time_ns = kNow + 1;
        break;
      case 12:
        reply.batch.records[1].sequence = reply.batch.records[0].sequence;
        break;
      case 13:
        reply.batch.records[2] = reply.batch.records[0];
        break;
      case 14:
        reply.status = Status::kIdle;
        break;
      case 15:
        reply.status = static_cast<Status>(65535);
        break;
    }
    if (!WorkerCheck(fixture.receiver.Receive(reply, kNow) == Status::kInvalid &&
                         !fixture.receiver.PendingForPublication(kNow),
                     "malformed or forged batch rejected before publication")) {
      std::cerr << "Mutation field: " << field << '\n';
      return false;
    }
  }
  WorkerTransferFixture fixture;
  reb::NativeWorkerPull request;
  if (!fixture.Configure() || !fixture.Capture() ||
      fixture.receiver.Request(kNow, request) != Status::kRequestReady) {
    return false;
  }
  const auto reply = fixture.sender.Pull(request, kNow);
  auto stale = reply;
  ++stale.epoch.connection.high;
  if (fixture.receiver.Receive(stale, kNow) != Status::kStaleEpoch ||
      fixture.receiver.Receive(reply, kNow) != Status::kBatch ||
      fixture.receiver.Receive(reply, kNow) != Status::kStaleEpoch) {
    return false;
  }
  ++request.request_id;
  const auto retry = fixture.sender.Pull(request, kNow);
  if (!WorkerCheck(retry.status == Status::kAwaitingAcknowledgment && retry.batch == reply.batch &&
                       fixture.sender.stats().staged_records == 1,
                   "unacknowledged retry cannot drain or mutate staged batch")) {
    return false;
  }
  ++request.request_id;
  request.acknowledged = {reply.epoch, reply.batch.batch_id + 1};
  if (fixture.sender.Pull(request, kNow).status != Status::kInvalidAcknowledgment ||
      fixture.sender.stats().acknowledged_records != 0) {
    return false;
  }
  std::cout << "Native worker transfer rejection: mutations=16 stale_connection=passed "
               "duplicate_reply=passed immutable_retry=passed invalid_ack=passed\n";
  return true;
}

bool CheckNativeWorkerTransferRetirement() {
  using Status = reb::NativeWorkerTransferStatus;
  constexpr auto kNow = WorkerTransferFixture::kNow;
  for (unsigned mode = 0; mode < 5; ++mode) {
    WorkerTransferFixture fixture;
    reb::NativeWorkerPull request;
    if (!fixture.Configure() || !fixture.Capture() ||
        fixture.receiver.Request(kNow, request) != Status::kRequestReady) {
      return false;
    }
    const auto reply = fixture.sender.Pull(request, kNow);
    if (fixture.receiver.Receive(reply, kNow) != Status::kBatch) {
      return false;
    }
    std::uint64_t now = kNow;
    switch (mode) {
      case 0:
        if (!fixture.authority.DocumentDestroyed(1, fixture.scope.selected_document, 1))
          return false;
        break;
      case 1:
        if (fixture.authority.Destroyed(1, fixture.owner.worker) !=
            reb::NativeWorkerAuthorityStatus::kRecorded)
          return false;
        break;
      case 2:
        if (fixture.authority.RendererDestroyed(1, fixture.owner.renderer_instance) !=
            reb::NativeWorkerAuthorityStatus::kRecorded)
          return false;
        break;
      case 3:
        now = fixture.scope.expires_at_ns;
        break;
      case 4:
        now = reply.batch.acknowledgment_deadline_ns;
        break;
    }
    if (!WorkerCheck(
            !fixture.receiver.PendingForPublication(now) &&
                !fixture.receiver.AcknowledgePublished({reply.epoch, reply.batch.batch_id}, now) &&
                fixture.receiver.retired_records() == 1,
            "publication rechecks document, worker, renderer, expiry and ack deadline")) {
      return false;
    }
  }
  WorkerTransferFixture timed;
  reb::NativeWorkerPull request;
  if (!timed.Configure()) {
    return false;
  }
  for (std::size_t index = 0; index < 17; ++index) {
    if (!timed.Capture())
      return false;
  }
  if (timed.receiver.Request(kNow, request) != Status::kRequestReady)
    return false;
  const auto reply = timed.sender.Pull(request, kNow);
  const auto deadline = reply.batch.acknowledgment_deadline_ns;
  if (!WorkerCheck(timed.sender.Tick(deadline).status == Status::kTimedOut &&
                       timed.sender.stats().retired_inflight_records == 16 &&
                       timed.sender.stats().timeouts == 1 && timed.queue.Stats().retired == 1 &&
                       !timed.queue.IsEnabled() &&
                       timed.receiver.Request(deadline, request) == Status::kTimedOut &&
                       timed.receiver.abandoned_requests() == 1,
                   "idle timeout reports queued, inflight and unanswered losses separately")) {
    return false;
  }
  WorkerTransferFixture disconnected;
  if (!disconnected.Configure() || !disconnected.Capture() ||
      disconnected.receiver.Request(kNow, request) != Status::kRequestReady)
    return false;
  const auto staged = disconnected.sender.Pull(request, kNow);
  const auto closed = disconnected.sender.Revoke(staged.epoch, Status::kDisconnected);
  if (!WorkerCheck(closed.status == Status::kDisconnected &&
                       closed.transfer_stats.retired_inflight_records == 1 &&
                       !disconnected.queue.IsEnabled(),
                   "disconnect retires sender credit"))
    return false;
  std::cout << "Native worker transfer retirement: document=passed worker=passed renderer=passed "
               "expiry=passed timeout=passed disconnect=passed losses=reported\n";
  return true;
}

bool CheckNativeWorkerTransferControls() {
  using Status = reb::NativeWorkerTransferStatus;
  constexpr auto kNow = WorkerTransferFixture::kNow;
  WorkerTransferFixture fixture;
  reb::NativeWorkerPull request;
  if (!WorkerCheck(fixture.sender.Tick(kNow).status == Status::kDisabled &&
                       fixture.sender.Pull(request, kNow).status == Status::kDisabled &&
                       fixture.receiver.Request(kNow, request) == Status::kDisabled &&
                       !fixture.receiver.Configure({}, kNow),
                   "unconfigured endpoints stay disabled")) {
    return false;
  }
  if (!fixture.Configure())
    return false;
  // Loss with no accepted event still gets a status-only batch and final ack.
  const reb::NativeWorkerObservationInput invalid{reb::NativeWorkerOperation::kScriptCompiled,
                                                  reb::NativeWorkerDirection::kNone, 0, -1};
  if (fixture.queue.Capture(fixture.ticket, invalid, kNow) !=
          reb::NativeWorkerCaptureStatus::kInvalid ||
      fixture.receiver.Request(kNow, request) != Status::kRequestReady)
    return false;
  const auto loss = fixture.sender.Pull(request, kNow);
  if (!WorkerCheck(
          loss.status == Status::kBatch && loss.batch.count == 0 &&
              loss.batch.capture_stats.dropped == 1 && loss.batch.capture_stats.pending_gap == 1 &&
              fixture.receiver.Receive(loss, kNow) == Status::kBatch &&
              fixture.receiver.AcknowledgePublished({loss.epoch, loss.batch.batch_id}, kNow),
          "stats-only batch exposes loss without a later event"))
    return false;
  const auto next = kNow + reb::kNativeWorkerMinPollIntervalNs;
  fixture.queue.Retire(fixture.ticket);
  if (fixture.receiver.Request(next, request) != Status::kRequestReady)
    return false;
  const auto terminal = fixture.sender.Pull(request, next);
  if (!WorkerCheck(terminal.status == Status::kBatch && terminal.batch.count == 0 &&
                       terminal.batch.worker_retired &&
                       fixture.receiver.Receive(terminal, next) == Status::kBatch &&
                       fixture.receiver.AcknowledgePublished(
                           {terminal.epoch, terminal.batch.batch_id}, next),
                   "idle retirement sends terminal status exactly once"))
    return false;
  const auto later = next + reb::kNativeWorkerMinPollIntervalNs;
  if (fixture.receiver.Request(later, request) != Status::kRequestReady ||
      fixture.receiver.Receive(fixture.sender.Pull(request, later), later) != Status::kIdle)
    return false;
  const auto old_epoch = reb::WorkerTransferEpoch(fixture.lease);
  if (fixture.sender.Revoke(old_epoch, Status::kRevoked).status != Status::kRevoked)
    return false;
  fixture.receiver.Revoke();
  reb::NativeWorkerLease replacement;
  if (fixture.authority.Issue(fixture.owner.worker, {90, 91}, later, replacement) !=
          reb::NativeWorkerAuthorityStatus::kAllowed ||
      fixture.sender.Configure(replacement, later) != Status::kConfigured ||
      !fixture.receiver.Configure(replacement, later))
    return false;
  if (!WorkerCheck(
          fixture.sender.Revoke(old_epoch, Status::kRevoked).status == Status::kStaleEpoch &&
              fixture.queue.IsEnabled() &&
              fixture.receiver.Receive(loss, later) == Status::kStaleEpoch,
          "late old-connection controls cannot retire new capture"))
    return false;
  std::cout << "Native worker controls: disabled=passed stats_only=passed empty_retirement=passed "
               "reconfiguration=passed stale_revoke=passed\n";
  return true;
}

bool CheckNativeWorkerTransferLifetime() {
  reb::NativeWorkerObservationQueue queue;
  reb::NativeWorkerAuthority authority;
  const reb::NativeWorkerAuthorityScope scope{1,      71,     1,      100'000'000'000ULL,
                                              {1, 2}, {3, 4}, {5, 6}, {7, 8}};
  const reb::NativeWorkerOwner owner{{9, 10},
                                     {11, 12},
                                     scope.selected_frame,
                                     reb::NativeWorkerCreatorKind::kDocument,
                                     scope.selected_document,
                                     scope.document_generation};
  reb::NativeWorkerLease lease;
  if (!authority.Reset(scope, 100) ||
      authority.Created(scope.observer_epoch, owner, 100) !=
          reb::NativeWorkerAuthorityStatus::kRecorded ||
      authority.Issue(owner.worker, {13, 14}, 100, lease) !=
          reb::NativeWorkerAuthorityStatus::kAllowed) {
    return false;
  }
  {
    reb::NativeWorkerTransferSender sender(queue);
    if (sender.Configure(lease, 100) != reb::NativeWorkerTransferStatus::kConfigured) {
      return false;
    }
  }
  if (queue.IsEnabled()) {
    std::cerr << "Worker sender destruction left capture enabled\n";
    return false;
  }
  return true;
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
  if (!RunEventDemo() || !CheckEventJson() || !CheckNativeQueueLimits() ||
      !CheckNativeWorkerTransferLifetime() || !CheckNativeWorkerAuthority() ||
      !CheckNativeWorkerTransfer() || !CheckNativeWorkerTransferPressure() ||
      !CheckNativeWorkerTransferRejection() || !CheckNativeWorkerTransferRetirement() ||
      !CheckNativeWorkerTransferControls() || !CheckNativeWorkerObservations() ||
      !CheckNativeWorkerMessageTags() || !CheckNativeWorkerObservationConcurrency() ||
      !CheckNativeWorkerSources() || !CheckNativeWorkerSourceUrls() ||
      !CheckNativeWorkerSourceConcurrency() || !CheckNativeQueueProducers() ||
      !MeasureNativeQueueReuse(iterations) || !CheckNativeQueueNotifications(iterations)) {
    std::cerr << "Native event queue validation failed\n";
    return 1;
  }
  return 0;
}
