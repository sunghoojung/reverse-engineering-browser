// Debugger observations through the request stack walker,
// protocol/native-debugger-observation-v1.md. Runs after NativeRequestStacks,
// which installs the fixture provider.
#pragma once

#include "brave/components/reverse_engineering_browser/renderer/native_debugger_observation.h"
#include "brave/components/reverse_engineering_browser/renderer/native_fetch_owner.h"
#include "reb/debugger_observation.hpp"
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
  assert(reb::IsValidObservationEvent(std::bit_cast<reb::EventRecord>(event)));
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
  assert(rules.AddRequest("/api/x", "") && rules.AddEvent("click"));
  // Rules the renderer could not hold exactly are refused and add nothing.
  assert(!rules.AddRequest("", "") && !rules.AddRequest("x", "post") &&
         !rules.AddRequest(std::string(257, 'x'), "") &&
         !rules.AddRequest(std::string_view("a\0b", 3), "") &&
         !rules.AddRequest("x", "VERYLONGMETHODNAME"));
  assert(!rules.AddEvent("click") && !rules.AddEvent("cl ick") && !rules.AddEvent("") &&
         !rules.AddEvent(std::string(28, 'e')));
  assert(rules.request_count == 1 && rules.event_count == 1);
  assert(!rules.AddDom(0, true, false, false) && !rules.AddDom(5, false, false, false));
  assert(rules.AddDom(5, true, true, false) && !rules.AddDom(5, false, false, true));
  for (int id = 6; id < 9; ++id) {
    assert(rules.AddDom(id, false, false, true));
  }
  assert(!rules.AddDom(9, true, false, false) && rules.dom_count == 4);
  rules.timers = rules.csp = rules.uncaught = rules.caught = true;
  {
    // Disarmed, every hook is one relaxed load: no walk, no record, no allocation.
    const auto before = allocations.load();
    reb::NativeDebuggerWatch::Listener(9, "click", 1, 1, NativeStackFrame{});
    reb::NativeDebuggerWatch::Timer(9, false, false, false, 1, 0, NativeStackFrame{});
    reb::NativeDebuggerWatch::Csp(9, 20, false, "cdn.example.test");
    reb::NativeDebuggerWatch::Exception(9, 1, NativeStackFrame{});
    reb::NativeDebuggerWatch::Mutation(9, reb::kNativeWatchAttribute,
                                       reb::NativeDebuggerWatch::DomSlot(5, 1), 1, "class");
    assert(allocations.load() == before && scenario.walks == 0 && Drain(queue) == 0);
  }
  assert(!reb::NativeDebuggerWatch::Arm(0, rules));
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
  {
    const auto tail = ObservationPayload(Pop(queue)).reserved1;
    const auto frame = std::bit_cast<NativeStackFrame>(std::array<std::uint8_t, 16>{
        tail[4], tail[5], tail[6], tail[7], tail[8], tail[9], tail[10], tail[11], tail[12],
        tail[13], tail[14], tail[15], tail[16], tail[17], tail[18], tail[19]});
    assert(tail[0] == 0 && tail[1] == 1 && frame.script_id == 10 && frame.position == 40 &&
           frame.detail == 40 && tail[20] == 5);
  }
  // An unwatched event type, another frame and frame 0 are dropped.
  reb::NativeDebuggerWatch::Listener(9, "scroll", 1, 1, NativeStackFrame{});
  reb::NativeDebuggerWatch::Listener(10, "click", 1, 1, NativeStackFrame{});
  reb::NativeDebuggerWatch::Listener(0, "click", 1, 1, NativeStackFrame{});
  assert(Drain(queue) == 0);

  reb::NativeDebuggerWatch::Timer(9, true, true, true, 77, 16, NativeStackFrame{});
  {
    const NativeProbeEvent timer = Pop(queue);
    const auto tail = ObservationPayload(timer).reserved1;
    std::uint32_t id = 0;
    std::memcpy(&id, tail.data() + 4, sizeof(id));
    assert(timer.header.type == NativeProbeType::kTimerObservation && timer.header.frame_id == 9 &&
           tail[0] == 2 && tail[1] == 2 && tail[2] == 1 && id == 77);
  }
  reb::NativeDebuggerWatch::Csp(9, 20, true, "cdn.example.test");
  {
    const auto tail = ObservationPayload(Pop(queue)).reserved1;
    assert(tail[0] == 20 && tail[1] == 2 && tail[2] == 16 &&
           std::string_view(reinterpret_cast<const char*>(tail.data() + 3), 16) ==
               "cdn.example.test");
  }
  // A host that does not fit is left out rather than cut.
  reb::NativeDebuggerWatch::Csp(9, 20, false, std::string(46, 'h'));
  assert(ObservationPayload(Pop(queue)).reserved1[2] == 0);

  for (const std::uint8_t kind : {std::uint8_t{1}, std::uint8_t{2}, std::uint8_t{3}}) {
    reb::NativeDebuggerWatch::Exception(9, kind,
                                        reb::NativeDebuggerWatch::FunctionFrame(11, 5, 30));
    const auto tail = ObservationPayload(Pop(queue)).reserved1;
    assert(tail[0] == kind && tail[4] == 1 && tail[8] == 11 && tail[12] == 30 && tail[16] == 5);
  }
  reb::NativeDebuggerWatch::Exception(9, 4, NativeStackFrame{});
  assert(Drain(queue) == 0);

  // Node 5 watches attributes and subtree; 6 to 8 watch removal only.
  assert(reb::NativeDebuggerWatch::DomSlot(5, reb::kNativeWatchAttribute) == 0 &&
         reb::NativeDebuggerWatch::DomSlot(5, reb::kNativeWatchRemoval) == -1 &&
         reb::NativeDebuggerWatch::DomSlot(7, reb::kNativeWatchRemoval) == 2 &&
         reb::NativeDebuggerWatch::DomSlot(99, reb::kNativeWatchAttribute) == -1);
  reb::NativeDebuggerWatch::Mutation(9, reb::kNativeWatchAttribute, 0, 1, "data-state");
  {
    const auto tail = ObservationPayload(Pop(queue)).reserved1;
    assert(tail[0] == 1 && tail[1] == 0 && tail[2] == 1 && tail[4] == 10);
  }
  reb::NativeDebuggerWatch::Mutation(9, reb::kNativeWatchRemoval, 2, 1, "");
  assert(ObservationPayload(Pop(queue)).reserved1[0] == 3);
  // A kind the slot does not watch, and an attribute without a name, record nothing.
  reb::NativeDebuggerWatch::Mutation(9, reb::kNativeWatchRemoval, 0, 1, "");
  reb::NativeDebuggerWatch::Mutation(9, reb::kNativeWatchAttribute, 0, 1, "");
  assert(Drain(queue) == 0);

  // The 1,024-record budget refuses the next record and leaves one gap.
  {
    assert(reb::NativeDebuggerWatch::Arm(9, rules));
    std::uint32_t admitted = 0;
    while (reb::NativeDebuggerWatch::Wants(9, reb::kNativeWatchTimers)) {
      reb::NativeDebuggerWatch::Timer(9, false, false, false, admitted + 1, 0, NativeStackFrame{});
      const NativeProbeEvent next = Pop(queue);
      if (next.header.type == NativeProbeType::kGap) {
        assert(admitted == reb::kNativeWatchBudget);
        break;
      }
      ++admitted;
    }
    assert(!reb::NativeDebuggerWatch::Wants(9, reb::kNativeWatchTimers));
    reb::NativeDebuggerWatch::Timer(9, false, false, false, 1, 0, NativeStackFrame{});
    assert(Drain(queue) == 0);
  }

  reb::NativeDebuggerWatch::Disarm(9);
  assert(!reb::NativeDebuggerWatch::Armed(reb::kNativeWatchRequests));
  reb::NativeDebuggerWatch::Request(
      23, sink.RecordRequestInitiated(23, "GET", "https", "api.example.test").initiated_sequence,
      "GET", "https://api.example.test/api/x");
  Drain(queue);

  transport.Disable();
  scenario = {};
  std::cout << "PASS debugger observations: inactive, captured stack and tail, request match "
               "identity, no-script stack, rule bounds, disarmed cost, per-hook tails, frame "
               "filtering, budget gap and disarm\n";
}
}  // namespace
