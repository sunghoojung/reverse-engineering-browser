#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
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
  Expect(window.front().header.sequence_number == 287,
         "low-level snapshots remain the newest general suffix");
  Expect(window.back().header.sequence_number == 5286, "newest record stays visible");
  Expect(std::ranges::none_of(window,
                              [](const reb::EventRecord& event) {
                                return event.header.category == reb::EventCategory::kNetwork;
                              }),
         "network retention belongs to the independent disk-backed API window");

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

  for (const std::string_view payload :
       {"", "0", "01", "-1", "+1", " 2", "2 ", "18446744073709551616"}) {
    reb::EventBroker invalid_payload(1);
    reb::EventRecord event = Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 1);
    Expect(reb::SetInlinePayload(event, payload), "bounded malformed count payload");
    Expect(Accept(invalid_payload, event), "gap record envelope remains valid");
    Expect(invalid_payload.Stats().queue_drops == 1, "noncanonical drop count weighs one");
  }
  reb::EventBroker saturating(1);
  reb::EventRecord maximum = Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 1);
  Expect(reb::SetInlinePayload(maximum, "18446744073709551615"), "maximum count payload");
  Expect(Accept(saturating, maximum), "maximum count ingest");
  Expect(Accept(saturating, Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 2)),
         "overflow ingest");
  Expect(saturating.Stats().queue_drops == std::numeric_limits<std::uint64_t>::max(),
         "drop count saturates");
  Expect(saturating.Stats().queue_drops_saturated, "saturation is explicit");

  if (failures != 0) {
    std::cerr << failures << " event broker window checks failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "PASS event broker preserves newest general snapshots and "
               "reports 280 capture-wide queue drops\n";
  return EXIT_SUCCESS;
}
