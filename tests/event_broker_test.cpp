#include <iostream>
#include <stdexcept>
#include <string>

#include "reb/event.hpp"
#include "reb/event_broker.hpp"

#define CHECK(condition)                                                      \
  do {                                                                        \
    if (!(condition)) {                                                       \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " \
                << #condition << '\n';                                        \
      return 1;                                                               \
    }                                                                         \
  } while (false)

namespace {

reb::EventRecord Event(const std::uint64_t sequence,
                       const std::uint64_t session = 7) {
  reb::EventRecord event = reb::MakeEvent(reb::EventCategory::kCanvas,
                                           reb::EventType::kApiCall, sequence,
                                           1234 + sequence, session);
  event.header.navigation_id = 11;
  event.header.artifact_id = 12;
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
  CHECK(interleaved_broker.Ingest(Event(1, 10)) ==
        reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Ingest(Event(1, 20)) ==
        reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Ingest(Event(3, 10)) ==
        reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Ingest(Event(2, 20)) ==
        reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Ingest(Event(2, 10)) ==
        reb::IngestStatus::kAccepted);
  CHECK(interleaved_broker.Stats().sequence_gaps == 1);

  const std::string json = reb::EventToJson(snapshot[0]);
  CHECK(json.find("\"category\":\"canvas\"") != std::string::npos);
  CHECK(json.find("\"navigation_id\":11") != std::string::npos);
  CHECK(json.find("\"payload\":\"63616e7661732e746f4461746155524c\"") !=
        std::string::npos);

  std::cout << "event_broker_test passed\n";
  return 0;
}
