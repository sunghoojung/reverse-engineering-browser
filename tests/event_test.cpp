#include <cstddef>
#include <iostream>
#include <type_traits>

#include "reb/event.hpp"

#define CHECK(condition)                                                               \
  do {                                                                                 \
    if (!(condition)) {                                                                \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": "          \
                << #condition << '\n';                                                  \
      return 1;                                                                        \
    }                                                                                  \
  } while (false)

int main() {
  CHECK(sizeof(reb::EventHeader) == 80);
  CHECK(sizeof(reb::EventRecord) == 128);
  CHECK(alignof(reb::EventRecord) == 64);
  CHECK(std::is_trivially_copyable_v<reb::EventRecord>);

  const reb::EventRecord event = reb::MakeEvent(
      reb::EventCategory::kCanvas, reb::EventType::kApiCall, 42, 123456, 7);

  CHECK(event.header.protocol_version == reb::kEventProtocolVersion);
  CHECK(event.header.header_size == sizeof(reb::EventHeader));
  CHECK(event.header.category == reb::EventCategory::kCanvas);
  CHECK(event.header.type == reb::EventType::kApiCall);
  CHECK(event.header.sequence_number == 42);
  CHECK(event.header.monotonic_time_ns == 123456);
  CHECK(event.header.session_id == 7);
  CHECK(event.header.payload_size == 0);
  CHECK(reb::EventCategoryName(event.header.category) == "canvas");
  CHECK(reb::EventTypeName(event.header.type) == "api_call");

  std::cout << "event_test passed\n";
  return 0;
}
