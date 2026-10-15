#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

#include <unistd.h>

#include "owned_vm_helper_protocol.hpp"

#include "reb/native_vm_recorder.hpp"
#include "reb/owned_vm_fixture.hpp"

namespace {
using namespace reb;
VmValue Observed(std::uint64_t value) {
  return {value, VmEvidence::kObserved};
}
constexpr VmScope kScope{1, 2, 3, 100};
void Require(bool condition, const char* name) {
  if (!condition) {
    std::cerr << "FAIL: " << name << '\n';
    std::exit(1);
  }
}
// The legacy batch path still uses deterministic recorder ticks 1 through 9.
VmSnapshot RunFixture(bool stack, NativeVmRecorder* recorder) {
  const auto generation = recorder != nullptr ? recorder->generation() : 0;
  OwnedVmFixture fixture(stack ? OwnedVmArchitecture::kStack : OwnedVmArchitecture::kRegister);
  for (std::uint64_t tick = 1; !fixture.snapshot().halted && tick <= kOwnedVmDispatchBudget;
       ++tick) {
    const auto result = fixture.ExecuteOne(recorder, kScope.document_id, generation, tick);
    Require(result.status == OwnedVmExecuteStatus::kCommitted, "owned fixture instruction");
  }
  Require(fixture.snapshot().halted, "bounded fixture halt");
  return fixture.snapshot();
}

void SerializerSelfTest();
void SelfTest() {
  NativeVmRecorder recorder;
  const auto baseline = RunFixture(false, nullptr);
  Require(RunFixture(false, &recorder) == baseline && recorder.records().empty(),
          "disabled semantics and no retention");
  for (const bool stack : {false, true}) {
    Require(recorder.Enable(kScope, 0), "enable");
    const auto untraced = RunFixture(stack, nullptr);
    Require(RunFixture(stack, &recorder) == untraced, "paired full state semantics");
    Require(recorder.records().size() == 9 && recorder.stats().recorded == 9,
            "all instructions retained");
    Require(untraced.memory[0].value == Observed(12), "fixture result");
    constexpr std::array<std::uint64_t, 9> pcs{0, 1, 2, 3, 4, 5, 6, 8, 10};
    constexpr std::array<std::uint64_t, 9> next_pcs{1, 2, 3, 4, 5, 6, 8, 10, 10};
    for (std::size_t i = 0; i < recorder.records().size(); ++i) {
      const auto& record = recorder.records()[i];
      Require(record.sequence == i + 1 && record.tick == i + 1 && record.step.before.pc == pcs[i] &&
                  record.step.after.pc == next_pcs[i],
              "PC and sequence transitions");
      Require(record.step.opcode_evidence == VmEvidence::kObserved, "opcode provenance");
      if (i > 0)
        Require(recorder.records()[i - 1].step.after == record.step.before, "state continuity");
    }
    const auto& add = recorder.records()[2].step;
    Require(add.operand_count == 2 && add.operands[0].value.bits == 7 &&
                add.operands[1].value.bits == 5 && add.effects[2].value.bits == 12,
            "typed operand read/write effects");
    Require(recorder.records()[3].step.after.memory[0].guest_address == 16, "sparse guest address");
    const auto& untaken = recorder.records()[5].step;
    const auto& jump = recorder.records()[6].step;
    const auto& taken = recorder.records()[7].step;
    const auto& halt = recorder.records()[8].step;
    Require(untaken.opcode == 5 && untaken.operands[0].value == Observed(12) &&
                untaken.operands[1].value == Observed(10) && untaken.effect_count == 1 &&
                untaken.effects[0].access == VmAccess::kRead &&
                untaken.effects[0].value == Observed(12),
            "golden untaken branch inputs");
    Require(jump.opcode == 6 && jump.operand_count == 1 && jump.operands[0].value == Observed(8) &&
                jump.effect_count == 0,
            "golden jump effects");
    Require(taken.opcode == 7 && taken.operands[0].value == Observed(12) &&
                taken.operands[1].value == Observed(10) && taken.effect_count == 1 &&
                taken.effects[0].access == VmAccess::kRead,
            "golden taken branch inputs");
    Require(halt.opcode == 8 && halt.operand_count == 0 && halt.effect_count == 0 &&
                !halt.before.halted && halt.after.halted,
            "golden halt");
    for (std::size_t i = 5; i < 9; ++i) {
      auto expected = recorder.records()[i].step.before;
      expected.pc = next_pcs[i];
      expected.halted = i == 8;
      Require(recorder.records()[i].step.after == expected, "control flow changes only PC or halt");
    }
    NativeVmRecorder bounded(2);
    Require(bounded.Enable(kScope, 0), "bounded enable");
    Require(RunFixture(stack, &bounded) == untraced && bounded.records().size() == 2 &&
                bounded.stats().full == 7 && bounded.stats().attempted == 9,
            "bounded loss preserves semantics");
  }
  VmStep valid = recorder.records()[0].step;
  const auto stale_generation = recorder.generation();
  Require(recorder.Enable({1, 2, 4, 100}, 0), "same document new invocation");
  Require(recorder.Record(2, stale_generation, 200, valid) == VmRecordResult::kStaleGeneration &&
              recorder.records().empty() && recorder.stats().stale_generation == 1,
          "stale invocation cannot record or expire new generation");
  Require(recorder.Record(2, recorder.generation(), 1, valid) == VmRecordResult::kRecorded,
          "current generation admitted");
  const auto old_generation = recorder.generation();
  Require(recorder.Enable(kScope, 0), "same scope new generation");
  Require(recorder.Record(2, old_generation, 1, valid) == VmRecordResult::kStaleGeneration,
          "same scope stale generation rejected");
  Require(recorder.Enable(kScope, 0), "reset");
  Require(recorder.records().empty() && recorder.stats().attempted == 0, "reset retention");
  Require(recorder.Record(9, recorder.generation(), 200, valid) == VmRecordResult::kWrongDocument &&
              recorder.records().empty(),
          "wrong document");
  VmStep malformed = valid;
  malformed.operand_count = 255;
  Require(recorder.Record(2, recorder.generation(), 2, malformed) == VmRecordResult::kMalformed,
          "operand bound");
  malformed = valid;
  malformed.after.stack_count = 255;
  Require(recorder.Record(2, recorder.generation(), 3, malformed) == VmRecordResult::kMalformed,
          "snapshot bound");
  malformed = valid;
  malformed.effects[0].location = static_cast<VmLocation>(255);
  Require(recorder.Record(2, recorder.generation(), 4, malformed) == VmRecordResult::kMalformed,
          "unknown enum");
  malformed = valid;
  malformed.after.memory_count = 2;
  malformed.after.memory[0] = {16, Observed(1)};
  malformed.after.memory[1] = {16, Observed(2)};
  Require(recorder.Record(2, recorder.generation(), 5, malformed) == VmRecordResult::kMalformed,
          "duplicate addresses");
  malformed = valid;
  malformed.after.memory[7] = {9, Observed(1)};
  Require(recorder.Record(2, recorder.generation(), 6, malformed) == VmRecordResult::kMalformed,
          "unused storage");
  malformed = valid;
  malformed.operands[0].value = {99, VmEvidence::kUnknown};
  Require(recorder.Record(2, recorder.generation(), 7, malformed) == VmRecordResult::kMalformed,
          "unknown is no value");
  Require(recorder.Record(2, recorder.generation(), 8, valid) == VmRecordResult::kRecorded &&
              recorder.records()[0].sequence == 7 && recorder.stats().malformed == 6,
          "visible malformed gap");
  valid.partial = true;
  valid.opcode_evidence = VmEvidence::kInferred;
  Require(recorder.Record(2, recorder.generation(), 9, valid) == VmRecordResult::kRecorded &&
              recorder.stats().partial == 1 &&
              recorder.records()[1].step.opcode_evidence == VmEvidence::kInferred,
          "partial and inferred retained");
  Require(recorder.Record(2, recorder.generation(), 100, valid) == VmRecordResult::kExpired,
          "expiry exact boundary");
  Require(recorder.Record(2, recorder.generation(), 10, valid) == VmRecordResult::kDisabled,
          "expiry latches");
  Require(recorder.stats().expired == 1, "expiry visible");
  Require(recorder.Enable(kScope, 10), "reenable");
  Require(recorder.Record(2, recorder.generation(), 9, valid) == VmRecordResult::kExpired,
          "clock rollback fails closed");
  Require(recorder.Enable(kScope, 0), "reenable navigation");
  recorder.InvalidateDocument();
  Require(recorder.Record(2, recorder.generation(), 1, valid) == VmRecordResult::kDisabled,
          "navigation invalidation");
  Require(recorder.Enable(kScope, 0), "reenable disable");
  recorder.Disable();
  Require(recorder.Record(2, recorder.generation(), 1, valid) == VmRecordResult::kDisabled,
          "explicit disable");
  Require(!recorder.Enable({1, 0, 3, 100}, 0), "zero document rejected");
  Require(!recorder.Enable(kScope, 100) && recorder.records().empty(), "expired enable clears");
  NativeVmRecorder zero(0);
  Require(zero.Enable(kScope, 0) &&
              zero.Record(2, zero.generation(), 1, valid) == VmRecordResult::kFull &&
              zero.stats().full == 1,
          "zero capacity explicit loss");
  NativeVmRecorder maximum(1000);
  Require(maximum.Enable(kScope, 0), "clamped capacity");
  for (std::size_t i = 0; i < kNativeVmRecords + 1; ++i) {
    const auto result = maximum.Record(2, maximum.generation(), 1, valid);
    Require(result == (i < kNativeVmRecords ? VmRecordResult::kRecorded : VmRecordResult::kFull),
            "hard capacity");
  }
  SerializerSelfTest();
  std::cout << "Native VM recorder fixture checks passed\n";
}

const char* Evidence(VmEvidence evidence) {
  switch (evidence) {
    case VmEvidence::kObserved:
      return "observed";
    case VmEvidence::kInferred:
      return "inferred";
    case VmEvidence::kUnknown:
      return "unknown";
  }
  return "unknown";
}
const char* Location(VmLocation location) {
  switch (location) {
    case VmLocation::kImmediate:
      return "immediate";
    case VmLocation::kRegister:
      return "register";
    case VmLocation::kStack:
      return "stack";
    case VmLocation::kMemory:
      return "memory";
  }
  return "unknown";
}
void Value(std::ostream& out, const VmValue& value) {
  // Strings preserve the full unsigned 64-bit range in JSON consumers.
  out << "{\"bits\":\"" << value.bits << "\",\"evidence\":\"" << Evidence(value.evidence) << "\"}";
}
void Snapshot(std::ostream& out, const VmSnapshot& state) {
  out << "{\"pc\":\"" << state.pc << "\",\"pc_evidence\":\"" << Evidence(state.pc_evidence)
      << "\",\"partial\":" << state.partial << ",\"halted\":" << state.halted;
  for (const bool stack : {false, true}) {
    out << (stack ? ",\"stack\":[" : ",\"registers\":[");
    const auto count = stack ? state.stack_count : state.register_count;
    for (std::size_t i = 0; i < count; ++i) {
      if (i != 0)
        out << ',';
      Value(out, stack ? state.stack[i] : state.registers[i]);
    }
    out << ']';
  }
  out << ",\"memory\":[";
  for (std::size_t i = 0; i < state.memory_count; ++i) {
    if (i != 0)
      out << ',';
    out << "{\"guest_address\":\"" << state.memory[i].guest_address << "\",\"value\":";
    Value(out, state.memory[i].value);
    out << '}';
  }
  out << "]}";
}
void Record(std::ostream& out, const VmRecordedStep& record) {
  const auto& step = record.step;
  out << "{\"sequence\":\"" << record.sequence << "\",\"tick\":\"" << record.tick
      << "\",\"opcode\":" << step.opcode << ",\"opcode_evidence\":\""
      << Evidence(step.opcode_evidence) << "\",\"partial\":" << step.partial << ",\"operands\":[";
  for (std::size_t i = 0; i < step.operand_count; ++i) {
    if (i != 0)
      out << ',';
    const auto& operand = step.operands[i];
    out << "{\"location\":\"" << Location(operand.location) << "\",\"index\":\"" << operand.index
        << "\",\"value\":";
    Value(out, operand.value);
    out << '}';
  }
  out << "],\"effects\":[";
  for (std::size_t i = 0; i < step.effect_count; ++i) {
    if (i != 0)
      out << ',';
    const auto& effect = step.effects[i];
    out << "{\"access\":\"" << (effect.access == VmAccess::kRead ? "read" : "write")
        << "\",\"location\":\"" << Location(effect.location) << "\",\"index\":\"" << effect.index
        << "\",\"value\":";
    Value(out, effect.value);
    out << '}';
  }
  out << "],\"before\":";
  Snapshot(out, step.before);
  out << ",\"after\":";
  Snapshot(out, step.after);
  out << '}';
}
// Test the serializer's full native schema bounds, independently of the much
// smaller fixed programs. This is reachable only from the existing self-test.
void SerializerSelfTest() {
  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  VmSnapshot snapshot{};
  snapshot.pc = maximum;
  snapshot.pc_evidence = VmEvidence::kObserved;
  snapshot.register_count = kNativeVmSlots;
  snapshot.stack_count = kNativeVmSlots;
  snapshot.memory_count = kNativeVmSlots;
  for (std::size_t i = 0; i < kNativeVmSlots; ++i) {
    snapshot.registers[i] = Observed(maximum);
    snapshot.stack[i] = Observed(maximum);
    snapshot.memory[i] = {maximum - i, Observed(maximum)};
  }
  reb::owned_vm_helper::PayloadBuffer state_buffer;
  std::ostream state_out(&state_buffer);
  state_out << std::boolalpha;
  Snapshot(state_out, snapshot);
  Require(state_out.good() && state_buffer.view().size() == 1808,
          "maximum native snapshot JSON bound");
  VmRecordedStep record{};
  record.sequence = maximum;
  record.tick = maximum;
  record.step.opcode = std::numeric_limits<std::uint32_t>::max();
  record.step.opcode_evidence = VmEvidence::kObserved;
  record.step.operand_count = record.step.operands.size();
  record.step.effect_count = record.step.effects.size();
  record.step.before = snapshot;
  record.step.after = snapshot;
  for (auto& operand : record.step.operands)
    operand = {VmLocation::kMemory, maximum, Observed(maximum)};
  for (auto& effect : record.step.effects)
    effect = {VmAccess::kWrite, VmLocation::kMemory, maximum, Observed(maximum)};
  reb::owned_vm_helper::PayloadBuffer record_buffer;
  std::ostream record_out(&record_buffer);
  record_out << std::boolalpha;
  Record(record_out, record);
  Require(record_out.good() && record_buffer.view().size() == 5306,
          "maximum native record JSON bound");
}
void Export(const NativeVmRecorder& recorder, bool stack) {
  std::cout << std::boolalpha << "{\"schema\":\"reb-owned-vm-fixture-v1\",\"fixture\":\""
            << (stack ? "stack" : "register")
            << "\",\"backend\":\"cooperative-native-fixture\",\"program_id\":\""
            << (stack ? "owned-stack-v1" : "owned-register-v1")
            << "\",\"fixture_revision\":1,\"pc_units\":\"instruction-index\","
               "\"value_semantics\":\"unsigned-64-bit-bits\",\"termination_reason\":\"halt\","
               "\"session_id\":\""
            << recorder.scope().session_id << "\",\"document_id\":\""
            << recorder.scope().document_id << "\",\"invocation_id\":\""
            << recorder.scope().invocation_id << "\",\"expires_at\":\""
            << recorder.scope().expires_at << "\",\"generation\":\"" << recorder.generation()
            << "\",\"records\":[";
  bool first = true;
  for (const auto& record : recorder.records()) {
    if (!first)
      std::cout << ',';
    first = false;
    Record(std::cout, record);
  }
  const auto& stats = recorder.stats();
  std::cout << "],\"loss\":{\"full\":" << stats.full << ",\"malformed\":" << stats.malformed
            << ",\"wrong_document\":" << stats.wrong_document << ",\"expired\":" << stats.expired
            << ",\"stale_generation\":" << stats.stale_generation
            << ",\"exhausted\":" << stats.exhausted << ",\"partial\":" << stats.partial
            << "},\"attempted\":" << stats.attempted << ",\"recorded\":" << stats.recorded << "}\n";
}
namespace helper = reb::owned_vm_helper;
struct ControlOptions final {
  OwnedVmArchitecture architecture = OwnedVmArchitecture::kRegister;
  VmScope scope{};
  std::uint64_t run_generation = 0;
  std::uint64_t lifetime_ms = 0;
};
bool ControlArguments(int argc, char** argv, ControlOptions& options) {
  if (argc != 14)
    return false;
  unsigned fields = 0;
  for (int i = 2; i < argc; i += 2) {
    const std::string_view key(argv[i]);
    const std::string_view value(argv[i + 1]);
    unsigned field = 0;
    std::uint64_t* number = nullptr;
    if (key == "--fixture") {
      field = 1;
      if (value == "register")
        options.architecture = OwnedVmArchitecture::kRegister;
      else if (value == "stack")
        options.architecture = OwnedVmArchitecture::kStack;
      else
        return false;
    } else if (key == "--session-id") {
      field = 2;
      number = &options.scope.session_id;
    } else if (key == "--document-id") {
      field = 4;
      number = &options.scope.document_id;
    } else if (key == "--invocation-id") {
      field = 8;
      number = &options.scope.invocation_id;
    } else if (key == "--run-generation") {
      field = 16;
      number = &options.run_generation;
    } else if (key == "--lifetime-ms") {
      field = 32;
      number = &options.lifetime_ms;
    } else {
      return false;
    }
    if ((fields & field) != 0 ||
        (number != nullptr && (!helper::CanonicalU64(value, *number) || *number == 0)))
      return false;
    fields |= field;
  }
  return fields == 63 && options.lifetime_ms <= helper::kMaxLifetimeMs;
}
std::uint64_t MonotonicNow() {
  const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                       .count();
  return now > 0 ? static_cast<std::uint64_t>(now) : 0;
}
const char* RecorderResult(VmRecordResult result) {
  switch (result) {
    case VmRecordResult::kRecorded:
      return "recorded";
    case VmRecordResult::kStaleGeneration:
      return "stale_generation";
    case VmRecordResult::kExhausted:
      return "exhausted";
    case VmRecordResult::kDisabled:
      return "disabled";
    case VmRecordResult::kExpired:
      return "expired";
    case VmRecordResult::kWrongDocument:
      return "wrong_document";
    case VmRecordResult::kMalformed:
      return "malformed";
    case VmRecordResult::kFull:
      return "full";
  }
  return "malformed";
}
void ControlPayload(std::ostream& out,
                    const ControlOptions& options,
                    const OwnedVmFixture& fixture,
                    const NativeVmRecorder& recorder,
                    const char* state,
                    const VmRecordResult* result) {
  const bool stack = options.architecture == OwnedVmArchitecture::kStack;
  out << std::boolalpha << "{\"schema\":\"reb-owned-vm-helper-v1\",\"fixture\":\""
      << (stack ? "stack" : "register") << "\",\"program_id\":\""
      << (stack ? "owned-stack-v1" : "owned-register-v1")
      << "\",\"fixture_revision\":1,\"session_id\":\"" << options.scope.session_id
      << "\",\"document_id\":\"" << options.scope.document_id << "\",\"invocation_id\":\""
      << options.scope.invocation_id << "\",\"run_generation\":\"" << options.run_generation
      << "\",\"state\":\"" << state << "\",\"executed_count\":\"" << fixture.executed_count()
      << "\",\"retained_count\":\"" << recorder.stats().recorded << "\",\"snapshot\":";
  Snapshot(out, fixture.snapshot());
  out << ",\"transition\":";
  if (result != nullptr && *result == VmRecordResult::kRecorded)
    Record(out, recorder.records().back());
  else
    out << "null";
  out << ",\"recorder_result\":";
  if (result != nullptr)
    out << '"' << RecorderResult(*result) << '"';
  else
    out << "null";
  const auto& stats = recorder.stats();
  out << ",\"stats\":{\"attempted\":\"" << stats.attempted << "\",\"recorded\":\"" << stats.recorded
      << "\",\"full\":\"" << stats.full << "\",\"malformed\":\"" << stats.malformed
      << "\",\"wrong_document\":\"" << stats.wrong_document << "\",\"stale_generation\":\""
      << stats.stale_generation << "\",\"exhausted\":\"" << stats.exhausted << "\",\"expired\":\""
      << stats.expired << "\",\"partial\":\"" << stats.partial
      << "\"},\"tick_units\":\"monotonic-nanoseconds\"}";
}
bool WriteAll(std::span<const std::uint8_t> bytes) {
  while (!bytes.empty()) {
    const auto written = ::write(STDOUT_FILENO, bytes.data(), bytes.size());
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return false;
    bytes = bytes.subspan(static_cast<std::size_t>(written));
  }
  return true;
}
bool Respond(helper::Status status,
             std::uint64_t request_id,
             const ControlOptions& options,
             const OwnedVmFixture& fixture,
             const NativeVmRecorder& recorder,
             const char* state,
             const VmRecordResult* result = nullptr) {
  helper::PayloadBuffer buffer;
  std::ostream out(&buffer);
  ControlPayload(out, options, fixture, recorder, state, result);
  if (!out || buffer.view().size() > helper::kMaxPayloadBytes)
    return false;
  const auto payload = buffer.view();
  const auto header =
      helper::ResponseHeader(status, request_id, static_cast<std::uint32_t>(payload.size()));
  return WriteAll(header) &&
         WriteAll({reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size()});
}
enum class ReadResult { kComplete, kEof, kShort, kError };
ReadResult ReadRequest(std::array<std::uint8_t, helper::kRequestBytes>& bytes) {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count = ::read(STDIN_FILENO, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0)
      return ReadResult::kError;
    if (count == 0)
      return offset == 0 ? ReadResult::kEof : ReadResult::kShort;
    offset += static_cast<std::size_t>(count);
  }
  return ReadResult::kComplete;
}
int ControlMain(int argc, char** argv) {
  ControlOptions options;
  if (!ControlArguments(argc, argv, options)) {
    std::cerr << "Invalid owned fixture control arguments\n";
    return 2;
  }
  // The pipe peer owns process lifetime. No diagnostics contain input values,
  // and a closed output pipe fails the exchange instead of terminating mid-write
  // via SIGPIPE. This does not change the legacy batch CLI's signal handling.
  std::signal(SIGPIPE, SIG_IGN);
  auto last_now = MonotonicNow();
  const auto lifetime_ns = options.lifetime_ms * 1000000;
  if (last_now == 0 || last_now > std::numeric_limits<std::uint64_t>::max() - lifetime_ns)
    return 1;
  options.scope.expires_at = last_now + lifetime_ns;
  OwnedVmFixture fixture(options.architecture);
  NativeVmRecorder recorder;
  if (!recorder.Enable(options.scope, last_now))
    return 1;
  const auto recorder_generation = recorder.generation();
  std::uint64_t last_request_id = 0;
  if (!Respond(helper::Status::kOk, 0, options, fixture, recorder, "paused"))
    return 1;
  for (;;) {
    std::array<std::uint8_t, helper::kRequestBytes> bytes{};
    const auto read = ReadRequest(bytes);
    if (read == ReadResult::kEof)
      return 0;
    if (read != ReadResult::kComplete) {
      std::cerr << "Incomplete owned fixture request frame\n";
      return 2;
    }
    helper::Request request;
    auto status = helper::Status::kOk;
    const char* state = fixture.snapshot().halted ? "halted" : "paused";
    bool terminal = false;
    OwnedVmExecuteResult execution;
    const VmRecordResult* recorded = nullptr;
    if (!helper::DecodeRequest(bytes, request)) {
      status = helper::Status::kMalformed;
      state = "failed";
      terminal = true;
    } else if (request.request_id == 0 || request.request_id <= last_request_id) {
      status = helper::Status::kRequestId;
    } else {
      // Even a well-framed guard rejection consumes its request ID. Reusing it
      // with corrected fields is never a retry grant or a second dispatch.
      last_request_id = request.request_id;
      if (request.generation != options.run_generation) {
        status = helper::Status::kStaleGeneration;
      } else if (request.executed_count != fixture.executed_count()) {
        status = helper::Status::kCountMismatch;
      } else if (request.request_id == std::numeric_limits<std::uint64_t>::max()) {
        status = helper::Status::kResourceLimit;
        state = "failed";
        terminal = true;
      } else {
        // Do not inspect the replacement run's deadline for stale identity or
        // count. Real monotonic expiry is checked immediately before dispatch.
        const auto now = MonotonicNow();
        if (helper::Expired(now, last_now, options.scope.expires_at)) {
          status = helper::Status::kExpired;
          state = "expired";
          terminal = true;
        } else {
          last_now = now;
          if (request.operation == helper::Operation::kClose) {
            status = helper::Status::kClosed;
            state = "stopped";
            terminal = true;
          } else if (request.operation == helper::Operation::kExecuteOne) {
            execution =
                fixture.ExecuteOne(&recorder, options.scope.document_id, recorder_generation, now);
            switch (execution.status) {
              case OwnedVmExecuteStatus::kCommitted:
                recorded = &execution.recorder_result;
                state = fixture.snapshot().halted ? "halted" : "paused";
                break;
              case OwnedVmExecuteStatus::kHalted:
                status = helper::Status::kHalted;
                break;
              case OwnedVmExecuteStatus::kBudget:
                status = helper::Status::kResourceLimit;
                state = "failed";
                terminal = true;
                break;
              case OwnedVmExecuteStatus::kInvalidState:
                status = helper::Status::kFixtureError;
                state = "failed";
                terminal = true;
                break;
            }
          }
        }
      }
    }
    if (!Respond(status, request.request_id, options, fixture, recorder, state, recorded))
      return 1;
    if (terminal)
      return status == helper::Status::kMalformed || status == helper::Status::kFixtureError ? 2
                                                                                             : 0;
  }
}
}  // namespace

int main(int argc, char** argv) {
  if (argc > 1 && std::string_view(argv[1]) == "--control-owned-fixture-v1")
    return ControlMain(argc, argv);
  bool enabled = false;
  bool stack = false;
  for (int i = 1; i < argc; ++i) {
    const std::string_view argument(argv[i]);
    if (argument == "--self-test" && argc == 2) {
      SelfTest();
      return 0;
    }
    if (argument == "--enable-owned-fixture")
      enabled = true;
    else if (argument == "--stack")
      stack = true;
    else {
      std::cerr << "Usage: reb-native-vm-fixture [--enable-owned-fixture] [--stack]\n"
                   "       reb-native-vm-fixture --self-test\n";
      return 2;
    }
  }
  NativeVmRecorder recorder;
  if (enabled && !recorder.Enable(kScope, 0))
    return 1;
  const auto result = RunFixture(stack, &recorder);
  Require(result.memory[0].value == Observed(12), "fixture output");
  Export(recorder, stack);
  return std::cout ? 0 : 1;
}
