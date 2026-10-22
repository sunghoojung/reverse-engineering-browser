#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "reb/event.hpp"
#include "reb/event_broker.hpp"

namespace {

int failures = 0;

void Expect(const bool condition, const std::string_view message) {
  if (!condition) {
    std::cerr << message << '\n';
    ++failures;
  }
}

reb::EventRecord Make(const reb::EventCategory category,
                      const reb::EventType type,
                      const std::uint64_t sequence) {
  return reb::MakeEvent(category, type, sequence, sequence, 7);
}

bool Accept(reb::EventBroker& broker, const reb::EventRecord& event) {
  return broker.Ingest(event) == reb::IngestStatus::kAccepted;
}

}  // namespace

int main() {
  constexpr std::size_t kWindow = 5000;
  constexpr std::uint64_t kDrops = 280;
  reb::EventBroker broker(kWindow + 16);
  const reb::EventType kRequests[] = {
      reb::EventType::kRequestInitiated,
      reb::EventType::kRequestStarted,
      reb::EventType::kResponseStarted,
      reb::EventType::kRequestCompleted,
  };
  for (std::size_t index = 0; index < 4; ++index) {
    Expect(Accept(broker, Make(reb::EventCategory::kNetwork, kRequests[index], index + 1)),
           "request ingest");
  }
  reb::EventRecord gap = Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 285);
  Expect(reb::SetInlinePayload(gap, "280"), "gap payload");
  Expect(Accept(broker, gap), "gap ingest");
  for (std::uint64_t sequence = 286; sequence <= 5286; ++sequence) {
    Expect(Accept(broker, Make(reb::EventCategory::kCanvas, reb::EventType::kApiCall, sequence)),
           "canvas ingest");
  }

  const reb::BrokerStats stats = broker.Stats();
  Expect(stats.queue_drops == kDrops, "capture-wide queue drops stay 280");
  Expect(!stats.queue_drops_saturated, "queue drops are not saturated");
  Expect(stats.sequence_gaps == kDrops, "capture-wide sequence gaps stay 280");
  Expect(!stats.sequence_gaps_saturated, "sequence gaps are not saturated");

  const std::vector<reb::EventRecord> window = broker.Snapshot(kWindow);
  Expect(window.size() == kWindow, "snapshot keeps the 5000-event cap");
  Expect(window.size() >= 5, "window holds the protected records");
  if (window.size() >= 5) {
    Expect(window[0].header.type == reb::EventType::kRequestInitiated &&
               window[0].header.sequence_number == 1,
           "request_initiated stays in the capped window");
    Expect(window[1].header.type == reb::EventType::kRequestStarted &&
               window[1].header.sequence_number == 2,
           "request_started stays in the capped window");
    Expect(window[2].header.type == reb::EventType::kResponseStarted &&
               window[2].header.sequence_number == 3,
           "response_started stays in the capped window");
    Expect(window[3].header.type == reb::EventType::kRequestCompleted &&
               window[3].header.sequence_number == 4,
           "request_completed stays in the capped window");
    Expect(window[4].header.type == reb::EventType::kGap && window[4].header.sequence_number == 285,
           "earlier gap record stays in the capped window");
    const auto payload = reb::InlinePayload(window[4]);
    Expect(payload.size() == 3 && payload[0] == std::byte{'2'} && payload[1] == std::byte{'8'} &&
               payload[2] == std::byte{'0'},
           "retained gap payload is the decimal count 280");
    Expect(window[5].header.sequence_number == 292,
           "oldest displaced canvas calls leave the window");
  }
  Expect(std::ranges::none_of(
             window,
             [](const reb::EventRecord& event) { return event.header.sequence_number == 286; }),
         "canvas api_call 286 is displaced by the protected records");
  Expect(std::ranges::any_of(
             window,
             [](const reb::EventRecord& event) { return event.header.sequence_number == 5286; }),
         "newest canvas call remains inside the cap");

  reb::EventBroker evicting(4);
  Expect(Accept(evicting, Make(reb::EventCategory::kWebGl, reb::EventType::kApiCall, 1)),
         "prefix ingest");
  reb::EventRecord evicted_gap = Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 282);
  Expect(reb::SetInlinePayload(evicted_gap, "280"), "evicted gap payload");
  Expect(Accept(evicting, evicted_gap), "evicted gap ingest");
  for (std::uint64_t sequence = 283; sequence < 283 + 8; ++sequence) {
    Expect(Accept(evicting, Make(reb::EventCategory::kWebGl, reb::EventType::kApiCall, sequence)),
           "webgl ingest");
  }
  const reb::BrokerStats retained = evicting.Stats();
  Expect(retained.queue_drops == kDrops, "queue drops survive ring eviction");
  Expect(retained.sequence_gaps == kDrops, "sequence gaps survive ring eviction");
  const std::vector<reb::EventRecord> retained_window = evicting.Snapshot(4);
  Expect(retained_window.size() == 4, "evicting ring stays at capacity");
  Expect(std::ranges::none_of(retained_window,
                              [](const reb::EventRecord& event) {
                                return event.header.type == reb::EventType::kGap;
                              }),
         "a full ring of non-canvas events can drop the gap record itself");

  if (failures != 0) {
    std::cerr << failures << " event broker window checks failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "PASS event broker keeps gap and network records in a 5000-event window and "
               "reports 280 capture-wide queue drops\n";
  return EXIT_SUCCESS;
}
