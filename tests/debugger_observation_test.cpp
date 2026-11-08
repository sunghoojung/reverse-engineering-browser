#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "reb/debugger_observation.hpp"
#include "reb/event.hpp"

namespace {

int failures = 0;
// Every record below, for the cross-language golden (--golden).
std::vector<std::pair<std::string, reb::EventRecord>> golden;

void Expect(const std::string& name, const reb::EventRecord& event, const bool valid) {
  if (reb::IsValidEvent(event) != valid) {
    std::cerr << "FAIL " << name << '\n';
    ++failures;
  }
  golden.emplace_back(name, event);
}

static_assert(static_cast<std::uint16_t>(reb::EventType::kRequestWatchMatch) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kRequestWatchMatch));
static_assert(static_cast<std::uint16_t>(reb::EventType::kDomMutation) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kDomMutation));

reb::EventRecord Record(const reb::EventType type, const reb::ObservationPayload& payload) {
  const bool request = type == reb::EventType::kRequestWatchMatch;
  reb::EventRecord event = reb::MakeEvent(
      request ? reb::EventCategory::kNetwork : reb::EventCategory::kRuntime, type, 9, 1, 7);
  event.header.payload_size = reb::kInlinePayloadSize;
  event.header.process_id = 42;
  event.header.frame_id = 3;
  if (request) {
    event.header.request_id = 5;
    event.header.parent_event_id = 8;
  }
  std::memcpy(event.inline_payload.data(), &payload, sizeof(payload));
  return event;
}

reb::ObservationPayload NoScript() {
  reb::ObservationPayload payload;
  payload.stack.state = static_cast<std::uint8_t>(reb::RequestStackState::kNoScript);
  return payload;
}

reb::ObservationPayload Captured() {
  reb::ObservationPayload payload;
  auto& stack = payload.stack;
  stack.state = static_cast<std::uint8_t>(reb::RequestStackState::kCaptured);
  stack.total_depth = stack.recorded = 1;
  stack.scripts = 1;
  stack.digest[0] = 1;
  stack.innermost = {1, 0, 0, 11, 40, 12};
  return payload;
}

void Name(reb::ObservationPayload& payload, const std::size_t at, std::string_view text) {
  payload.stack.reserved1[at] = static_cast<std::uint8_t>(text.size());
  std::memcpy(payload.stack.reserved1.data() + at + 1, text.data(), text.size());
}

void ValidRecords() {
  auto listener = NoScript();
  listener.stack.reserved1[1] = 1;
  const reb::StackFrame frame{1, 0, 0, 11, 120, 120};
  std::memcpy(listener.stack.reserved1.data() + 4, &frame, sizeof(frame));
  Name(listener, 20, "click");
  Expect("listener with function position", Record(reb::EventType::kListenerDispatch, listener),
         true);

  auto match = Captured();
  match.stack.reserved1[1] = 1;
  Expect("request match captured stack", Record(reb::EventType::kRequestWatchMatch, match), true);

  auto csp = Captured();
  csp.stack.reserved1[1] = 1;
  Name(csp, 2, "cdn.example");
  Expect("csp violation host only", Record(reb::EventType::kCspViolation, csp), true);

  auto exception = Captured();
  exception.stack.reserved1[0] = 3;
  Expect("unhandled rejection", Record(reb::EventType::kExceptionObservation, exception), true);

  auto attribute = NoScript();
  attribute.stack.reserved1[0] = 1;
  Name(attribute, 4, "class");
  Expect("attribute mutation", Record(reb::EventType::kDomMutation, attribute), true);

  auto timer = Captured();
  timer.stack.reserved1[0] = 1;
  timer.stack.reserved1[1] = 2;
  Expect("scheduled interval", Record(reb::EventType::kTimerObservation, timer), true);
}

void MalformedRecords() {
  auto listener = NoScript();
  listener.stack.reserved1[1] = 1;
  Expect("listener without event type", Record(reb::EventType::kListenerDispatch, listener), false);
  Name(listener, 20, "cl ick");
  Expect("event type with space", Record(reb::EventType::kListenerDispatch, listener), false);

  auto match = Captured();
  match.stack.reserved1[0] = reb::kObservationRequestRules;
  Expect("rule slot past the request rules", Record(reb::EventType::kRequestWatchMatch, match),
         false);

  auto exception = NoScript();
  exception.stack.reserved1[0] = 3;
  exception.stack.digest[0] = 1;
  Expect("no_script with a digest", Record(reb::EventType::kExceptionObservation, exception),
         false);

  auto removal = NoScript();
  removal.stack.reserved1[0] = 3;
  Name(removal, 4, "id");
  Expect("removal naming an attribute", Record(reb::EventType::kDomMutation, removal), false);

  auto unparented = Captured();
  unparented.stack.reserved1[1] = 1;
  auto event = Record(reb::EventType::kRequestWatchMatch, unparented);
  event.header.parent_event_id = 0;
  Expect("request match without parent", event, false);

  auto runtime = NoScript();
  runtime.stack.reserved1[0] = 1;
  runtime.stack.reserved1[1] = 1;
  event = Record(reb::EventType::kTimerObservation, runtime);
  event.header.request_id = 5;
  Expect("runtime observation naming a request", event, false);
}

}  // namespace

int main(int argc, char** argv) {
  ValidRecords();
  MalformedRecords();
  if (argc == 2 && std::string_view(argv[1]) == "--golden") {
    std::string json;
    std::cout << '[';
    for (std::size_t index = 0; index < golden.size(); ++index) {
      reb::WriteEventJson(golden[index].second, json);
      std::cout << (index ? ",\n" : "\n") << "{\"name\":\"" << golden[index].first
                << "\",\"valid\":" << (reb::IsValidEvent(golden[index].second) ? "true" : "false")
                << ",\"event\":" << json << '}';
    }
    std::cout << "\n]\n";
    return failures == 0 ? 0 : 1;
  }
  if (failures != 0) {
    return 1;
  }
  std::cout << "debugger observation records ok\n";
  return 0;
}
