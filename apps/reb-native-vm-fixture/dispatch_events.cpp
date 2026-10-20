#include "dispatch_events.hpp"

#include <unistd.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>

#include "reb/event.hpp"
#include "reb/native_vm_recorder.hpp"
#include "reb/owned_vm_fixture.hpp"
#include "reb/vm_dispatch.hpp"
#include "reb/vm_finding.hpp"

namespace {
struct Options final {
  bool stack = false;
  std::uint64_t session = 0;
  std::uint64_t navigation = 0;
  std::uint64_t frame = 0;
  std::uint64_t invocation = 0;
  std::uint64_t finding = 0;
  std::uint64_t investigation = 0;
  std::uint64_t interpreter = 0;
  std::uint64_t bytecode = 0;
};

bool Parse(int argc, char** argv, Options& options) {
  constexpr std::array names{"--session-id",
                             "--navigation-id",
                             "--frame-id",
                             "--invocation-id",
                             "--finding-id",
                             "--investigation-id",
                             "--interpreter-artifact-id",
                             "--bytecode-artifact-id"};
  const std::array fields{&options.session,     &options.navigation, &options.frame,
                          &options.invocation,  &options.finding,    &options.investigation,
                          &options.interpreter, &options.bytecode};
  std::array<bool, names.size()> seen{};
  bool fixture_seen = false;
  if (argc != 20)
    return false;
  for (int index = 2; index < argc; index += 2) {
    const std::string_view name(argv[index]);
    const std::string_view value(argv[index + 1]);
    if (name == "--fixture") {
      if (fixture_seen || (value != "register" && value != "stack"))
        return false;
      fixture_seen = true;
      options.stack = value == "stack";
      continue;
    }
    std::size_t field = 0;
    while (field < names.size() && name != names[field])
      ++field;
    if (field == names.size() || seen[field] || value.empty() || value.front() == '0')
      return false;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), *fields[field]);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
        *fields[field] == 0)
      return false;
    seen[field] = true;
  }
  for (const bool present : seen) {
    if (!present)
      return false;
  }
  return fixture_seen;
}

reb::EventRecord Event(const Options& options, std::uint64_t sequence) {
  const auto now =
      static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
  auto event = reb::MakeEvent(reb::EventCategory::kVm, reb::EventType::kVmDispatchSample, sequence,
                              now, options.session);
  event.header.process_id = static_cast<std::uint32_t>(getpid());
  event.header.thread_id = event.header.process_id;
  event.header.navigation_id = options.navigation;
  event.header.frame_id = options.frame;
  event.header.artifact_id = options.interpreter;
  return event;
}
}  // namespace

int EmitOwnedVmDispatchEvents(int argc, char** argv, bool observe_owned_clock) {
  Options options;
  if (!Parse(argc, argv, options)) {
    std::cerr
        << "Owned dispatch export requires a fixture and eight unique nonzero identity arguments\n";
    return 2;
  }
  reb::NativeVmRecorder recorder;
  if (!recorder.Enable({options.session, options.frame, options.invocation, 100}, 0))
    return 1;
  reb::OwnedVmFixture fixture(options.stack ? reb::OwnedVmArchitecture::kStack
                                            : reb::OwnedVmArchitecture::kRegister);
  // Fixed event storage is filled at cooperative instruction boundaries; only
  // the final bounded export writes bytes. This never attaches to a browser.
  std::array<reb::EventRecord, reb::kOwnedVmDispatchBudget + 2> events{};
  events[0] = Event(options, 1);
  auto invocation = reb::MakeVmFinding(
      reb::VmFindingKind::kInvocation, reb::VmHostRuntime::kUnknown,
      reb::VmFindingConfidence::kObserved, options.finding, options.investigation,
      options.stack ? "owned-stack-v1" : "owned-register-v1");
  invocation.subject_id = options.invocation;
  invocation.related_subject_id = options.bytecode;
  invocation.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kDynamic);
  if (!reb::SetVmFindingPayload(events[0], invocation))
    return 1;
  std::size_t count = 1;
  bool clock_observed = false;
  for (std::uint64_t tick = 1; !fixture.snapshot().halted && tick <= reb::kOwnedVmDispatchBudget;
       ++tick) {
    const auto result = fixture.ExecuteOne(&recorder, options.frame, recorder.generation(), tick);
    if (result.status != reb::OwnedVmExecuteStatus::kCommitted ||
        result.recorder_result != reb::VmRecordResult::kRecorded) {
      std::cerr << "Owned dispatch capture did not retain every instruction\n";
      return 1;
    }
    const auto& record = recorder.records().back();
    if (record.step.before.pc > std::numeric_limits<std::uint32_t>::max() ||
        record.sequence > std::numeric_limits<std::uint32_t>::max())
      return 1;
    auto& event = events[count];
    event = Event(options, count + 1);
    event.header.parent_event_id = 1;
    const auto sample = reb::MakeVmDispatchSample(
        static_cast<std::uint32_t>(record.step.before.pc), record.step.opcode, record.step.opcode,
        static_cast<std::uint32_t>(record.sequence - 1), options.finding, options.investigation,
        options.interpreter, options.bytecode, record.step.operand_count);
    if (!reb::SetVmDispatchSamplePayload(event, sample))
      return 1;
    ++count;
    if (observe_owned_clock && record.step.before.pc == 2) {
      // Real owned host operation after instruction-index 2. This is a clock
      // callback in this compiled fixture, not a captured browser API call.
      const auto observed_time =
          static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                         std::chrono::steady_clock::now().time_since_epoch())
                                         .count());
      auto& host = events[count];
      host = Event(options, count + 1);
      host.header.category = reb::EventCategory::kRuntime;
      host.header.type = reb::EventType::kApiCall;
      host.header.parent_event_id = event.header.sequence_number;
      host.header.monotonic_time_ns = observed_time;
      if (!reb::SetInlinePayload(host, "owned.monotonic_clock.after_instruction"))
        return 1;
      clock_observed = true;
      ++count;
    }
  }
  if (!fixture.snapshot().halted || recorder.records().size() != fixture.executed_count() ||
      (observe_owned_clock && !clock_observed))
    return 1;
  for (std::size_t index = 0; index < count; ++index)
    std::cout.write(reinterpret_cast<const char*>(&events[index]), sizeof(events[index]));
  if (!std::cout) {
    std::cerr << "Owned dispatch event export failed; delivery is not confirmed\n";
    return 1;
  }
  return 0;
}
