#include <cstdlib>
#include <iostream>
#include <string_view>

#include "reb/native_vm_recorder.hpp"

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
void Effect(VmStep& step,
            VmAccess access,
            VmLocation location,
            std::uint64_t index,
            VmValue value) {
  step.effects[step.effect_count++] = {access, location, index, value};
}
void Operand(VmStep& step, VmLocation location, std::uint64_t index, VmValue value) {
  step.operands[step.operand_count++] = {location, index, value};
}

// These two tiny interpreters own their state and explicitly report completed
// instructions. Recording never supplies values back into interpreter execution.
VmSnapshot RunFixture(bool stack, NativeVmRecorder* recorder) {
  const auto generation = recorder != nullptr ? recorder->generation() : 0;
  VmSnapshot state{};
  state.pc_evidence = VmEvidence::kObserved;
  state.register_count = stack ? 0 : 3;
  for (std::uint32_t tick = 1; !state.halted && tick <= 16; ++tick) {
    const auto pc = state.pc;
    auto next_pc = pc + 1;
    VmStep step{};
    step.opcode = static_cast<std::uint32_t>(pc < 2 ? 1 : pc);
    step.opcode_evidence = VmEvidence::kObserved;
    step.before = state;
    const auto location = stack ? VmLocation::kStack : VmLocation::kRegister;
    auto& slots = stack ? state.stack : state.registers;
    if (pc < 2) {
      const auto value = Observed(pc == 0 ? 7 : 5);
      Operand(step, VmLocation::kImmediate, 0, value);
      slots[pc] = value;
      if (stack)
        ++state.stack_count;
      Effect(step, VmAccess::kWrite, location, pc, value);
    } else if (pc == 2) {
      for (std::size_t i = 0; i < 2; ++i) {
        Operand(step, location, i, slots[i]);
        Effect(step, VmAccess::kRead, location, i, slots[i]);
      }
      slots[0] = Observed(slots[0].bits + slots[1].bits);
      Effect(step, VmAccess::kWrite, location, 0, slots[0]);
      if (stack) {
        slots[1] = {};
        state.stack_count = 1;
        Effect(step, VmAccess::kWrite, location, 1, {});
      }
    } else if (pc == 3) {
      Operand(step, location, 0, slots[0]);
      Effect(step, VmAccess::kRead, location, 0, slots[0]);
      state.memory_count = 1;
      state.memory[0] = {16, slots[0]};
      Effect(step, VmAccess::kWrite, VmLocation::kMemory, 16, slots[0]);
      if (stack) {
        slots[0] = {};
        state.stack_count = 0;
        Effect(step, VmAccess::kWrite, location, 0, {});
      }
    } else if (pc == 4) {
      Operand(step, VmLocation::kMemory, 16, state.memory[0].value);
      Effect(step, VmAccess::kRead, VmLocation::kMemory, 16, state.memory[0].value);
      const std::size_t destination = stack ? 0 : 2;
      slots[destination] = state.memory[0].value;
      if (stack)
        state.stack_count = 1;
      Effect(step, VmAccess::kWrite, location, destination, slots[destination]);
    } else if (pc == 5 || pc == 8) {
      step.opcode = pc == 5 ? 5 : 7;
      const std::size_t condition_slot = stack ? 0 : 2;
      Operand(step, location, condition_slot, slots[condition_slot]);
      Effect(step, VmAccess::kRead, location, condition_slot, slots[condition_slot]);
      const std::uint64_t target = 10;
      Operand(step, VmLocation::kImmediate, 0, Observed(target));
      const bool taken =
          pc == 5 ? slots[condition_slot].bits == 0 : slots[condition_slot].bits != 0;
      if (taken)
        next_pc = target;
    } else if (pc == 6) {
      step.opcode = 6;
      Operand(step, VmLocation::kImmediate, 0, Observed(8));
      next_pc = 8;
    } else if (pc == 10) {
      step.opcode = 8;
      state.halted = true;
      next_pc = pc;
    } else {
      Require(false, "unreachable owned fixture instruction");
    }
    state.pc = next_pc;
    step.after = state;
    if (recorder != nullptr) {
      const auto result = recorder->Record(kScope.document_id, generation, tick, step);
      (void)result;  // Loss cannot affect execution; inspect recorder.stats().
    }
  }
  Require(state.halted, "bounded fixture halt");
  return state;
}

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
void Value(const VmValue& value) {
  // Strings preserve the full unsigned 64-bit range in JSON consumers.
  std::cout << "{\"bits\":\"" << value.bits << "\",\"evidence\":\"" << Evidence(value.evidence)
            << "\"}";
}
void Snapshot(const VmSnapshot& state) {
  std::cout << "{\"pc\":\"" << state.pc << "\",\"pc_evidence\":\"" << Evidence(state.pc_evidence)
            << "\",\"partial\":" << state.partial << ",\"halted\":" << state.halted;
  for (const bool stack : {false, true}) {
    std::cout << (stack ? ",\"stack\":[" : ",\"registers\":[");
    const auto count = stack ? state.stack_count : state.register_count;
    for (std::size_t i = 0; i < count; ++i) {
      if (i != 0)
        std::cout << ',';
      Value(stack ? state.stack[i] : state.registers[i]);
    }
    std::cout << ']';
  }
  std::cout << ",\"memory\":[";
  for (std::size_t i = 0; i < state.memory_count; ++i) {
    if (i != 0)
      std::cout << ',';
    std::cout << "{\"guest_address\":\"" << state.memory[i].guest_address << "\",\"value\":";
    Value(state.memory[i].value);
    std::cout << '}';
  }
  std::cout << "]}";
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
    const auto& step = record.step;
    std::cout << "{\"sequence\":\"" << record.sequence << "\",\"tick\":\"" << record.tick
              << "\",\"opcode\":" << step.opcode << ",\"opcode_evidence\":\""
              << Evidence(step.opcode_evidence) << "\",\"partial\":" << step.partial
              << ",\"operands\":[";
    for (std::size_t i = 0; i < step.operand_count; ++i) {
      if (i != 0)
        std::cout << ',';
      const auto& operand = step.operands[i];
      std::cout << "{\"location\":\"" << Location(operand.location) << "\",\"index\":\""
                << operand.index << "\",\"value\":";
      Value(operand.value);
      std::cout << '}';
    }
    std::cout << "],\"effects\":[";
    for (std::size_t i = 0; i < step.effect_count; ++i) {
      if (i != 0)
        std::cout << ',';
      const auto& effect = step.effects[i];
      std::cout << "{\"access\":\"" << (effect.access == VmAccess::kRead ? "read" : "write")
                << "\",\"location\":\"" << Location(effect.location) << "\",\"index\":\""
                << effect.index << "\",\"value\":";
      Value(effect.value);
      std::cout << '}';
    }
    std::cout << "],\"before\":";
    Snapshot(step.before);
    std::cout << ",\"after\":";
    Snapshot(step.after);
    std::cout << '}';
  }
  const auto& stats = recorder.stats();
  std::cout << "],\"loss\":{\"full\":" << stats.full << ",\"malformed\":" << stats.malformed
            << ",\"wrong_document\":" << stats.wrong_document << ",\"expired\":" << stats.expired
            << ",\"stale_generation\":" << stats.stale_generation
            << ",\"exhausted\":" << stats.exhausted << ",\"partial\":" << stats.partial
            << "},\"attempted\":" << stats.attempted << ",\"recorded\":" << stats.recorded << "}\n";
}
}  // namespace

int main(int argc, char** argv) {
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
