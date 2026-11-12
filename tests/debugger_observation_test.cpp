#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "reb/debugger_observation.hpp"
#include "reb/debugger_pause.hpp"
#include "reb/event.hpp"
#include "reb/event_broker.hpp"
#include "request_child_check.hpp"

namespace {

int failures = 0;
// Every record below, for the cross-language golden (--golden).
std::vector<std::pair<std::string, reb::EventRecord>> golden;

void ExpectTrue(const bool condition, const std::string& name) {
  if (!condition) {
    std::cerr << "FAIL " << name << '\n';
    ++failures;
  }
}

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

// Pause records never name a request and only a resumed record has a parent,
// so they do not share the observation envelope helper below.
reb::EventRecord PauseRecord(const reb::EventType type, const reb::ObservationPayload& payload) {
  reb::EventRecord event = reb::MakeEvent(reb::EventCategory::kRuntime, type, 9, 1, 7);
  event.header.payload_size = reb::kInlinePayloadSize;
  event.header.process_id = 42;
  event.header.frame_id = 3;
  std::memcpy(event.inline_payload.data(), &payload, sizeof(payload));
  return event;
}

void Put32(reb::ObservationPayload& payload, const std::size_t at, const std::uint32_t value) {
  for (std::size_t i = 0; i < 4; ++i) {
    payload.stack.reserved1[at + i] = static_cast<std::uint8_t>(value >> (8U * i));
  }
}

void Put64(reb::ObservationPayload& payload, const std::size_t at, const std::uint64_t value) {
  for (std::size_t i = 0; i < 8; ++i) {
    payload.stack.reserved1[at + i] = static_cast<std::uint8_t>(value >> (8U * i));
  }
}

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
  if (!reb_test::StaysRequestChild(Record(reb::EventType::kRequestWatchMatch, match))) {
    std::cerr << "FAIL request match stays a request child\n";
    ++failures;
  }

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

  // Every envelope field the broker requires, so the offline validator matches it.
  const auto envelope_case = [&](const std::string& name,
                                 const std::function<void(reb::EventRecord&)>& change) {
    auto copy = Record(reb::EventType::kRequestWatchMatch, unparented);
    change(copy);
    Expect(name, copy, false);
  };
  envelope_case("observation flags", [](auto& e) { e.header.flags = 1; });
  envelope_case("observation parent at its own sequence",
                [](auto& e) { e.header.parent_event_id = e.header.sequence_number; });
  envelope_case("observation parent past its sequence",
                [](auto& e) { e.header.parent_event_id = e.header.sequence_number + 1; });
  envelope_case("observation navigation", [](auto& e) { e.header.navigation_id = 1; });
  envelope_case("observation status", [](auto& e) { e.header.status_code = 200; });
  envelope_case("observation error", [](auto& e) { e.header.error_code = 1; });
  envelope_case("observation encoded length", [](auto& e) { e.header.encoded_data_length = 1; });
  envelope_case("observation decoded length", [](auto& e) { e.header.decoded_body_length = 1; });
  envelope_case("observation resource type", [](auto& e) { e.header.resource_type = 1; });
  envelope_case("observation initiator request",
                [](auto& e) { e.header.initiator_request_id = 1; });
  envelope_case("observation initiator process",
                [](auto& e) { e.header.initiator_process_id = 1; });

  auto runtime = NoScript();
  runtime.stack.reserved1[0] = 1;
  runtime.stack.reserved1[1] = 1;
  event = Record(reb::EventType::kTimerObservation, runtime);
  event.header.request_id = 5;
  Expect("runtime observation naming a request", event, false);
}

void PauseRecords() {
  auto attach = NoScript();
  attach.stack.reserved1[0] = reb::kDebuggerAttachPhaseAttach;
  Expect("debugger attached", PauseRecord(reb::EventType::kDebuggerAttached, attach), true);
  attach.stack.reserved1[1] = reb::kDebuggerClearNavigated;
  Expect("attach naming a clear reason", PauseRecord(reb::EventType::kDebuggerAttached, attach),
         false);

  auto detach = NoScript();
  detach.stack.reserved1[0] = reb::kDebuggerAttachPhaseDetach;
  detach.stack.reserved1[1] = reb::kDebuggerClearNavigated;
  Put32(detach, 4, 3);
  Expect("navigation detached and dropped breakpoints",
         PauseRecord(reb::EventType::kDebuggerAttached, detach), true);
  detach.stack.reserved1[1] = reb::kDebuggerClearIdle;
  Expect("an authorization that ended idle", PauseRecord(reb::EventType::kDebuggerAttached, detach),
         true);
  detach.stack.reserved1[1] = reb::kDebuggerClearIdle + 1;
  Expect("detach with an unknown reason", PauseRecord(reb::EventType::kDebuggerAttached, detach),
         false);

  auto paused = Captured();
  paused.stack.reserved1[0] = reb::kDebuggerPauseReasonBreakpoint;
  paused.stack.reserved1[2] = 4;
  Put64(paused, 8, 17);
  Put32(paused, 16, 2);
  Expect("paused at a breakpoint", PauseRecord(reb::EventType::kDebuggerPaused, paused), true);
  paused.stack.reserved1[0] = 3;
  Expect("a step pause naming a breakpoint", PauseRecord(reb::EventType::kDebuggerPaused, paused),
         false);
  Put32(paused, 16, 0);
  Expect("paused by a step", PauseRecord(reb::EventType::kDebuggerPaused, paused), true);
  paused.stack.reserved1[0] = reb::kDebuggerPauseReasonMax + 1;
  Expect("paused for a reason version 1 reserves",
         PauseRecord(reb::EventType::kDebuggerPaused, paused), false);
  paused.stack.reserved1[0] = 5;
  Expect("paused at the page's own debugger statement",
         PauseRecord(reb::EventType::kDebuggerPaused, paused), true);
  Put64(paused, 8, 0);
  Expect("paused without a lease", PauseRecord(reb::EventType::kDebuggerPaused, paused), false);

  auto deep = Captured();
  deep.stack.reserved1[0] = reb::kDebuggerPauseReasonBreakpoint;
  deep.stack.reserved1[1] = reb::kDebuggerPauseFramesTruncated;
  deep.stack.reserved1[2] = 0x01;
  deep.stack.reserved1[3] = 0x04;
  Put64(deep, 8, 1);
  Expect("1025 recorded frames", PauseRecord(reb::EventType::kDebuggerPaused, deep), false);

  auto resumed = NoScript();
  resumed.stack.reserved1[0] = 4;
  Put32(resumed, 4, 60000);
  Put64(resumed, 8, 17);
  Expect("lease expired and resumed", PauseRecord(reb::EventType::kDebuggerResumed, resumed), true);
  // The lease id joins a resume to its pause, so no record names a parent.
  auto parented = PauseRecord(reb::EventType::kDebuggerResumed, resumed);
  parented.header.parent_event_id = 8;
  Expect("a resumed record naming a parent", parented, false);
  Put64(resumed, 8, 0);
  Expect("resumed without a lease", PauseRecord(reb::EventType::kDebuggerResumed, resumed), false);
  Put64(resumed, 8, 17);
  resumed.stack.reserved1[0] = reb::kDebuggerResumeEndMax - 1;
  Expect("a stop in another document of the group, ended at once",
         PauseRecord(reb::EventType::kDebuggerResumed, resumed), true);
  resumed.stack.reserved1[0] = reb::kDebuggerResumeEndMax;
  Expect("a pause something else continued", PauseRecord(reb::EventType::kDebuggerResumed, resumed),
         true);
  resumed.stack.reserved1[0] = reb::kDebuggerResumeEndMax + 1;
  Expect("an end this version has no number for",
         PauseRecord(reb::EventType::kDebuggerResumed, resumed), false);
  resumed.stack.reserved1[0] = 4;

  auto set = NoScript();
  set.stack.reserved1[0] = 1;
  set.stack.reserved1[1] = 2;
  Put32(set, 4, 11);
  Put32(set, 8, 120);
  Put32(set, 12, 1);
  Expect("conditional breakpoint set", PauseRecord(reb::EventType::kDebuggerBreakpoint, set), true);
  set.stack.reserved1[1] = reb::kDebuggerBreakpointKindMax + 1;
  Expect("a breakpoint kind version 1 has no number for",
         PauseRecord(reb::EventType::kDebuggerBreakpoint, set), false);
  set.stack.reserved1[1] = 3;
  Expect("logpoint set", PauseRecord(reb::EventType::kDebuggerBreakpoint, set), true);
  set.stack.reserved1[0] = reb::kDebuggerBreakpointPhaseRefused;
  Expect("a refused breakpoint keeping an id",
         PauseRecord(reb::EventType::kDebuggerBreakpoint, set), false);
  Put32(set, 12, 0);
  Expect("breakpoint refused", PauseRecord(reb::EventType::kDebuggerBreakpoint, set), true);

  // A debugger record is written with no script running, so the frame cannot
  // come from whatever context is entered: it has to be the selected
  // document's own. Without it the validator refuses the record and the
  // broker counts it invalid, which is evidence silently lost.
  auto armed = NoScript();
  armed.stack.reserved1[0] = reb::kDebuggerAttachPhaseAttach;
  auto without_frame = PauseRecord(reb::EventType::kDebuggerAttached, armed);
  without_frame.header.frame_id = 0;
  Expect("an attach record without a frame", without_frame, false);
  {
    reb::EventBroker broker(8);
    const auto carried = PauseRecord(reb::EventType::kDebuggerAttached, armed);
    ExpectTrue(broker.IngestAt(carried, 1) == reb::IngestStatus::kAccepted,
               "a pause record naming its frame reaches the broker");
    auto dropped = carried;
    dropped.header.frame_id = 0;
    dropped.header.sequence_number = carried.header.sequence_number + 1;
    ExpectTrue(broker.IngestAt(dropped, 2) == reb::IngestStatus::kInvalid,
               "one without a frame is counted invalid instead");
    const reb::BrokerStats stats = broker.Stats();
    ExpectTrue(stats.accepted == 1 && stats.invalid == 1, "the broker counts exactly one of each");
  }

  auto named = NoScript();
  named.stack.reserved1[0] = reb::kDebuggerAttachPhaseAttach;
  auto request = PauseRecord(reb::EventType::kDebuggerAttached, named);
  request.header.request_id = 5;
  Expect("a pause record naming a request", request, false);
  auto frameless = PauseRecord(reb::EventType::kDebuggerAttached, named);
  frameless.header.frame_id = 0;
  Expect("a pause record without a frame", frameless, false);
}

}  // namespace

int main(int argc, char** argv) {
  ValidRecords();
  MalformedRecords();
  PauseRecords();
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
