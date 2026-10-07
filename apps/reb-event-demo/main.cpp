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

#include "components/reverse_engineering_browser/common/native_probe_queue.h"
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
      !CheckNativeWorkerSources() || !CheckNativeWorkerSourceUrls() ||
      !CheckNativeWorkerSourceConcurrency() || !CheckNativeQueueProducers() ||
      !MeasureNativeQueueReuse(iterations) || !CheckNativeQueueNotifications(iterations)) {
    std::cerr << "Native event queue validation failed\n";
    return 1;
  }
  return 0;
}
