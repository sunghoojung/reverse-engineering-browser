#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <set>
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

  const auto api = [&](std::uint64_t sequence) {
    return Make(reb::EventCategory::kRuntime, reb::EventType::kApiCall, sequence);
  };
  reb::EventBroker delayed(8);
  Expect(Accept(delayed, api(3)) && Accept(delayed, api(1)), "reverse arrival accepted");
  Expect(delayed.Stats().sequence_gaps == 1, "lower bound exposes one absent ID");
  Expect(Accept(delayed, api(2)) && Accept(delayed, api(2)), "late and duplicate accepted");
  Expect(delayed.Stats().sequence_gaps == 0, "late ID closes hole; duplicate neutral");
  Expect(Accept(delayed, api(8)), "forward gap accepted");
  Expect(delayed.Stats().sequence_gaps == 4, "four IDs missing");
  for (auto sequence : {6U, 4U, 7U, 5U})
    Expect(Accept(delayed, api(sequence)), "split hole fill");
  Expect(delayed.Stats().sequence_gaps == 0, "split holes close despite ring eviction");
  auto other = api(100);
  other.header.process_id = 99;
  Expect(Accept(delayed, other), "independent process accepted");
  Expect(delayed.Stats().sequence_gaps == 0, "unknown process prefix not counted");
  reb::EventBroker bounded(1);
  for (auto sequence : {1U, 3U, 5U})
    Expect(Accept(bounded, api(sequence)), "bounded holes");
  Expect(bounded.Stats().sequence_tracking_evictions == 1, "interval budget eviction explicit");
  Expect(bounded.Stats().sequence_gaps == 0, "evicted uncertainty not permanent loss");
  reb::EventBroker large(8);
  for (std::uint32_t process : {1U, 2U}) {
    auto first = api(1), last = api(std::numeric_limits<std::uint64_t>::max());
    first.header.process_id = last.header.process_id = process;
    Expect(Accept(large, first) && Accept(large, last), "wide bounds");
  }
  Expect(large.Stats().sequence_gaps_saturated, "distinct holes saturate safely");
  reb::EventBroker retract(8);
  Expect(Accept(retract, api(1)) && Accept(retract, api(std::numeric_limits<std::uint64_t>::max())),
         "large interval");
  auto small = api(1);
  small.header.process_id = 88;
  Expect(Accept(retract, small), "second stream");
  small.header.sequence_number = 6;
  Expect(Accept(retract, small), "second hole");
  Expect(retract.Stats().sequence_gaps_saturated, "combined saturation");
  for (auto sequence : {2U, 3U}) {
    small.header.sequence_number = sequence;
    Expect(Accept(retract, small), "late saturation retraction");
  }
  Expect(!retract.Stats().sequence_gaps_saturated &&
             retract.Stats().sequence_gaps == std::numeric_limits<std::uint64_t>::max(),
         "exact maximum unsaturates");
  // Independent set oracle for interleaved, duplicate and out-of-order arrivals.
  reb::EventBroker permutation(128);
  std::map<std::uint32_t, std::set<std::uint64_t>> observed;
  std::uint32_t random = 0x327U;
  for (std::size_t index = 0; index < 1000; ++index) {
    random = random * 1664525U + 1013904223U;
    const auto process = (random >> 16U) % 3U + 1U;
    const std::uint64_t sequence = (random >> 8U) % 64U + 1U;
    auto arrival = api(sequence);
    arrival.header.process_id = process;
    Expect(Accept(permutation, arrival), "interleaved arrival");
    observed[process].insert(sequence);
    std::uint64_t absent = 0;
    for (const auto& [unused, ids] : observed) {
      static_cast<void>(unused);
      absent += *ids.rbegin() - *ids.begin() - static_cast<std::uint64_t>(ids.size() - 1);
    }
    Expect(permutation.Stats().sequence_gaps == absent, "tracker matches independent ID set");
    Expect(permutation.Stats().sequence_tracking_evictions == 0, "property fixture fits budget");
  }

  if (failures != 0) {
    std::cerr << failures << " event broker window checks failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "PASS event broker preserves newest general snapshots and "
               "reports 280 capture-wide queue drops\n";
  return EXIT_SUCCESS;
}
