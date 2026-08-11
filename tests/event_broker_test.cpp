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
