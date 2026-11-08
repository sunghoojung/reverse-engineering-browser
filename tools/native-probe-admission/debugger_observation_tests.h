// Debugger observations through the request stack walker,
// protocol/native-debugger-observation-v1.md. Runs after NativeRequestStacks,
// which installs the fixture provider.
#pragma once

#include "brave/components/reverse_engineering_browser/renderer/native_debugger_observation.h"
#include "brave/components/reverse_engineering_browser/renderer/native_fetch_owner.h"
#include "request_stack_tests.h"

namespace {

std::array<std::uint8_t, 48> ListenerTail() {
  std::array<std::uint8_t, 48> tail{};
  tail[1] = 1;
  tail[20] = 5;
  std::memcpy(tail.data() + 21, "click", 5);
  return tail;
}

NativeRequestStackPayload ObservationPayload(const NativeProbeEvent& event) {
  auto value = std::bit_cast<NativeRequestStackPayload>(event.inline_payload);
  auto prefix = value;
  prefix.reserved1 = {};
  assert(reb::IsValidNativeRequestStackPayload(prefix));
  return value;
}

[[gnu::noinline]] void NativeDebuggerObservations() {
  using reb::NativeProbeType;
  NativeProbeQueue queue;
  Configure(queue, 51);
  transport.Disable();
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kListenerDispatch, 0, 0, 3,
                                            ListenerTail());
  assert(Drain(queue) == 0);

  Configure(queue, 52);
  scenario = {};
  scenario.depth = 2;
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kListenerDispatch, 0, 0, 3,
                                            ListenerTail());
  const auto listener = Pop(queue);
  assert(listener.header.type == NativeProbeType::kListenerDispatch &&
         listener.header.category == reb::NativeProbeCategory::kRuntime &&
         listener.header.request_id == 0 && listener.header.parent_event_id == 0 &&
         listener.header.frame_id == 3);
  const auto captured = ObservationPayload(listener);
  assert(captured.state == 1 && captured.recorded == 2 && captured.reserved1 == ListenerTail());
  Drain(queue);

  const auto initiated =
      sink.RecordRequestInitiated(7, "POST", "https", "api.example.test").initiated_sequence;
  std::array<std::uint8_t, 48> match{};
  match[1] = 1;
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kRequestWatchMatch, 7, initiated, 3,
                                            match);
  assert(Pop(queue).header.sequence_number == initiated);
  const auto request = Pop(queue);
  assert(request.header.type == NativeProbeType::kRequestWatchMatch &&
         request.header.category == reb::NativeProbeCategory::kNetwork &&
         request.header.request_id == 7 && request.header.parent_event_id == initiated);
  assert(ObservationPayload(request).reserved1 == match);
  Drain(queue);

  scenario.result = reb::NativeRequestStackWalkResult::kNoScript;
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kListenerDispatch, 0, 0, 3,
                                            ListenerTail());
  const auto native = ObservationPayload(Pop(queue));
  assert(native.state == 2 && native.reserved1 == ListenerTail());
  assert(Drain(queue) == 0);

  // Arm rules and let the public entry points filter and emit. depth 0 keeps
  // each observation to one record (no stack frames, no script_identity child).
  Configure(queue, 53);
  scenario = {};
  reb::NativeWatchRules rules;
  rules.request_count = 1;
  const std::string_view api = "/api/x";
  std::memcpy(rules.requests[0].url.data(), api.data(), api.size());
  rules.requests[0].url_length = api.size();
  rules.event_count = 1;
  std::memcpy(rules.events[0].data(), "click", 5);
  rules.event_lengths[0] = 5;
  assert(reb::NativeDebuggerWatch::Arm(9, rules));
  assert(reb::NativeDebuggerWatch::Armed(reb::kNativeWatchRequests | reb::kNativeWatchListeners));

  {
    const reb::NativeFetchOwnerScope armed({reb::NativeLoaderKind::kDocument, 9});
    const auto hit =
        sink.RecordRequestInitiated(21, "GET", "https", "api.example.test").initiated_sequence;
    reb::NativeDebuggerWatch::Request(21, hit, "GET", "https://api.example.test/api/x?q=1");
    assert(Pop(queue).header.sequence_number == hit);
    const NativeProbeEvent watched = Pop(queue);
    assert(watched.header.type == NativeProbeType::kRequestWatchMatch &&
           watched.header.frame_id == 9);
    // A URL the rule does not name emits nothing.
    const auto miss =
        sink.RecordRequestInitiated(22, "GET", "https", "api.example.test").initiated_sequence;
    reb::NativeDebuggerWatch::Request(22, miss, "GET", "https://api.example.test/other");
    assert(Pop(queue).header.sequence_number == miss && Drain(queue) == 0);
  }
  // Another frame's or a worker's request never matches the armed document's rule.
  for (const reb::NativeFetchOwner owner :
       {reb::NativeFetchOwner{reb::NativeLoaderKind::kDocument, 10},
        reb::NativeFetchOwner{reb::NativeLoaderKind::kDedicatedWorker, 0x77}}) {
    const reb::NativeFetchOwnerScope other(owner);
    const auto sequence =
        sink.RecordRequestInitiated(24, "GET", "https", "api.example.test").initiated_sequence;
    reb::NativeDebuggerWatch::Request(24, sequence, "GET", "https://api.example.test/api/x");
    assert(Pop(queue).header.sequence_number == sequence && Drain(queue) == 0);
  }

  reb::NativeDebuggerWatch::Listener(9, "click", 1, 1,
                                     reb::NativeDebuggerWatch::FunctionFrame(10, 40));
  assert(Pop(queue).header.type == NativeProbeType::kListenerDispatch);
  // An unwatched event type is dropped.
  reb::NativeDebuggerWatch::Listener(9, "scroll", 1, 1, NativeStackFrame{});
  assert(Drain(queue) == 0);

  reb::NativeDebuggerWatch::Disarm(9);
  assert(!reb::NativeDebuggerWatch::Armed(reb::kNativeWatchRequests));
  reb::NativeDebuggerWatch::Request(
      23, sink.RecordRequestInitiated(23, "GET", "https", "api.example.test").initiated_sequence,
      "GET", "https://api.example.test/api/x");
  Drain(queue);

  transport.Disable();
  scenario = {};
  std::cout << "PASS debugger observations: inactive, captured stack and tail, "
               "request match identity, no-script stack, armed filtering and disarm\n";
}
}  // namespace
