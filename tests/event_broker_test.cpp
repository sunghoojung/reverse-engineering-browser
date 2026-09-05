#include <algorithm>
#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

#include "reb/event.hpp"
#include "reb/event_broker.hpp"

#define CHECK(condition)                                                                   \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " << #condition \
                << '\n';                                                                   \
      return 1;                                                                            \
    }                                                                                      \
  } while (false)

namespace {

reb::EventRecord Event(const std::uint64_t sequence,
                       const std::uint64_t session = 7,
                       const std::uint32_t process = 1) {
  reb::EventRecord event = reb::MakeEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall,
                                          sequence, 1234 + sequence, session);
  event.header.navigation_id = 11;
  event.header.artifact_id = 12;
  event.header.process_id = process;
  static_cast<void>(reb::SetInlinePayload(event, "canvas.toDataURL"));
  return event;
}

}  // namespace

int main() {
  bool rejected_zero_capacity = false;
  try {
    reb::EventBroker invalid_broker(0);
  } catch (const std::invalid_argument&) {
    rejected_zero_capacity = true;
  }
  CHECK(rejected_zero_capacity);

  bool rejected_empty_policy = false;
  try {
    reb::EventBroker invalid_policy_broker(1, {.category_mask = 0});
  } catch (const std::invalid_argument&) {
    rejected_empty_policy = true;
  }
  CHECK(rejected_empty_policy);

  bool rejected_unknown_category_bit = false;
  try {
    reb::EventBroker invalid_policy_broker(
        1, {.category_mask = reb::kAllEventCategoryMask | (std::uint64_t{1} << 63U)});
  } catch (const std::invalid_argument&) {
    rejected_unknown_category_bit = true;
  }
  CHECK(rejected_unknown_category_bit);

  // Exercise partial, full, and wrapped retention with arbitrary capacities.
  for (const std::size_t capacity : std::array<std::size_t, 4>{1, 2, 3, 17}) {
    reb::EventBroker retention_broker(capacity);
    CHECK(retention_broker.Snapshot(10).empty());
    for (std::uint64_t sequence = 1; sequence <= capacity * 5; ++sequence) {
      CHECK(retention_broker.IngestAt(Event(sequence), 1) == reb::IngestStatus::kAccepted);
      const std::size_t retained = std::min(static_cast<std::size_t>(sequence), capacity);
      CHECK(retention_broker.Size() == retained);
      CHECK(retention_broker.Stats().evicted == sequence - retained);
      for (std::size_t limit = 0; limit <= capacity + 1; ++limit) {
        const auto latest = retention_broker.Snapshot(limit);
        const std::size_t count = std::min(limit, retained);
        CHECK(latest.size() == count);
        for (std::size_t index = 0; index < count; ++index) {
          CHECK(latest[index].header.sequence_number == sequence - count + index + 1);
          CHECK(reb::IsValidEvent(latest[index]));
        }
      }
    }
    reb::EventRecord rejected = Event(999);
    rejected.header.protocol_version = 99;
    CHECK(retention_broker.IngestAt(rejected, 1) == reb::IngestStatus::kInvalid);
    CHECK(retention_broker.Snapshot(1).front().header.sequence_number == capacity * 5);
  }

  reb::EventBroker broker(2);
  CHECK(broker.Ingest(Event(1)) == reb::IngestStatus::kAccepted);
  CHECK(broker.Ingest(Event(3)) == reb::IngestStatus::kAccepted);
  CHECK(broker.Ingest(Event(4)) == reb::IngestStatus::kAccepted);
  CHECK(broker.Size() == 2);

  const reb::BrokerStats stats = broker.Stats();
  CHECK(stats.accepted == 3);
  CHECK(stats.sequence_gaps == 1);
  CHECK(stats.evicted == 1);
  CHECK(stats.invalid == 0);

  const auto snapshot = broker.Snapshot(10);
  CHECK(snapshot.size() == 2);
  CHECK(snapshot[0].header.sequence_number == 3);
  CHECK(snapshot[1].header.sequence_number == 4);

  reb::EventRecord invalid = Event(5);
  invalid.header.protocol_version = 99;
  CHECK(broker.Ingest(invalid) == reb::IngestStatus::kInvalid);
  CHECK(broker.Stats().invalid == 1);

  reb::EventBroker scoped_broker(
      4, {.category_mask = reb::EventCategoryMask(reb::EventCategory::kNetwork),
          .expires_at_monotonic_ns = 100});
  CHECK(scoped_broker.IngestAt(Event(1), 1) == reb::IngestStatus::kCategoryRejected);
  reb::EventRecord network_event = Event(2);
  network_event.header.category = reb::EventCategory::kNetwork;
  network_event.header.type = reb::EventType::kRequestStarted;
  CHECK(scoped_broker.IngestAt(network_event, 99) == reb::IngestStatus::kAccepted);
  CHECK(scoped_broker.IngestAt(network_event, 100) == reb::IngestStatus::kSessionExpired);
  CHECK(scoped_broker.Size() == 1);
  CHECK(scoped_broker.Stats().accepted == 1);
  CHECK(scoped_broker.Stats().category_rejected == 1);
  CHECK(scoped_broker.Stats().expired == 1);
  CHECK(scoped_broker.Stats().sequence_gaps == 0);

  reb::EventBroker interleaved_broker(8);
  CHECK(interleaved_broker.Ingest(Event(1, 10)) == reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Ingest(Event(1, 20)) == reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Ingest(Event(3, 10)) == reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Ingest(Event(2, 20)) == reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Ingest(Event(2, 10)) == reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Stats().sequence_gaps == 1);

  reb::EventBroker multiprocess_broker(8);
  CHECK(multiprocess_broker.Ingest(Event(1, 30, 101)) == reb::IngestStatus::kAccepted);
  CHECK(multiprocess_broker.Ingest(Event(1, 30, 202)) == reb::IngestStatus::kAccepted);
  CHECK(multiprocess_broker.Ingest(Event(2, 30, 101)) == reb::IngestStatus::kAccepted);
  CHECK(multiprocess_broker.Ingest(Event(2, 30, 202)) == reb::IngestStatus::kAccepted);
  CHECK(multiprocess_broker.Stats().sequence_gaps == 0);

  reb::EventBroker bounded_stream_broker(1);
  CHECK(bounded_stream_broker.Ingest(Event(1, 100, 1)) == reb::IngestStatus::kAccepted);
  CHECK(bounded_stream_broker.Ingest(Event(1, 200, 2)) == reb::IngestStatus::kAccepted);
  CHECK(bounded_stream_broker.Ingest(Event(3, 100, 1)) == reb::IngestStatus::kAccepted);
  CHECK(bounded_stream_broker.Size() == 1);
  CHECK(bounded_stream_broker.Stats().sequence_gaps == 0);
  CHECK(bounded_stream_broker.Stats().sequence_tracking_evictions == 2);

  reb::EventBroker deterministic_eviction_broker(2);
  CHECK(deterministic_eviction_broker.Ingest(Event(1, 200, 1)) == reb::IngestStatus::kAccepted);
  CHECK(deterministic_eviction_broker.Ingest(Event(1, 100, 1)) == reb::IngestStatus::kAccepted);
  CHECK(deterministic_eviction_broker.Ingest(Event(3, 100, 1)) == reb::IngestStatus::kAccepted);
  CHECK(deterministic_eviction_broker.Ingest(Event(1, 300, 1)) == reb::IngestStatus::kAccepted);
  CHECK(deterministic_eviction_broker.Ingest(Event(3, 200, 1)) == reb::IngestStatus::kAccepted);
  CHECK(deterministic_eviction_broker.Stats().sequence_gaps == 1);
  CHECK(deterministic_eviction_broker.Stats().sequence_tracking_evictions == 2);

  reb::EventBroker saturating_gap_broker(4);
  CHECK(saturating_gap_broker.Ingest(Event(1, 400, 1)) == reb::IngestStatus::kAccepted);
  CHECK(saturating_gap_broker.Ingest(Event(std::numeric_limits<std::uint64_t>::max(), 400, 1)) ==
        reb::IngestStatus::kAccepted);
  CHECK(saturating_gap_broker.Ingest(Event(1, 500, 1)) == reb::IngestStatus::kAccepted);
  CHECK(saturating_gap_broker.Ingest(Event(std::numeric_limits<std::uint64_t>::max(), 500, 1)) ==
        reb::IngestStatus::kAccepted);
  CHECK(saturating_gap_broker.Stats().sequence_gaps == std::numeric_limits<std::uint64_t>::max());
  CHECK(saturating_gap_broker.Stats().sequence_gaps_saturated);

  const std::string json = reb::EventToJson(snapshot[0]);
  CHECK(json.find("\"category\":\"canvas\"") != std::string::npos);
  CHECK(json.find("\"navigation_id\":\"11\"") != std::string::npos);
  CHECK(json.find("\"request_id\":\"0\"") != std::string::npos);
  CHECK(json.find("\"payload_truncated\":false") != std::string::npos);
  CHECK(json.find("\"payload\":\"63616e7661732e746f4461746155524c\"") != std::string::npos);

  std::cout << "event_broker_test passed\n";
  return 0;
}
