#include "reb/owned_vm_fixture.hpp"

#include <array>

namespace reb {
namespace {
VmValue Observed(std::uint64_t value) noexcept {
  return {value, VmEvidence::kObserved};
}
void Effect(VmStep& step,
            VmAccess access,
            VmLocation location,
            std::uint64_t index,
            VmValue value) noexcept {
  step.effects[step.effect_count++] = {access, location, index, value};
}
void Operand(VmStep& step, VmLocation location, std::uint64_t index, VmValue value) noexcept {
  step.operands[step.operand_count++] = {location, index, value};
}
constexpr std::array<std::uint64_t, 10> kPcs{0, 1, 2, 3, 4, 5, 6, 8, 10, 10};
}  // namespace

VmSnapshot OwnedVmFixture::InitialState(OwnedVmArchitecture architecture) noexcept {
  VmSnapshot state{};
  state.pc_evidence = VmEvidence::kObserved;
  state.register_count = architecture == OwnedVmArchitecture::kRegister ? 3 : 0;
  return state;
}
OwnedVmFixture::OwnedVmFixture(OwnedVmArchitecture architecture) noexcept
    : architecture_(architecture), state_(InitialState(architecture)) {}
const VmSnapshot& OwnedVmFixture::snapshot() const noexcept {
  return state_;
}
std::uint64_t OwnedVmFixture::executed_count() const noexcept {
  return executed_count_;
}
bool OwnedVmFixture::ValidState() const noexcept {
  if ((architecture_ != OwnedVmArchitecture::kRegister &&
       architecture_ != OwnedVmArchitecture::kStack) ||
      executed_count_ >= kPcs.size() || state_.pc != kPcs[executed_count_] ||
      state_.pc_evidence != VmEvidence::kObserved || state_.partial ||
      state_.halted != (executed_count_ == 9))
    return false;
  // There are no user inputs or state writes: these are the exact reachable
  // operands and active-slot shapes of the two fixed programs. Validate the
  // whole snapshot before computing a next state, including unused storage.
  auto expected = InitialState(architecture_);
  expected.pc = state_.pc;
  expected.halted = state_.halted;
  if (architecture_ == OwnedVmArchitecture::kRegister) {
    if (executed_count_ >= 1)
      expected.registers[0] = Observed(executed_count_ >= 3 ? 12 : 7);
    if (executed_count_ >= 2)
      expected.registers[1] = Observed(5);
    if (executed_count_ >= 5)
      expected.registers[2] = Observed(12);
  } else {
    if (executed_count_ == 1) {
      expected.stack_count = 1;
      expected.stack[0] = Observed(7);
    } else if (executed_count_ == 2) {
      expected.stack_count = 2;
      expected.stack[0] = Observed(7);
      expected.stack[1] = Observed(5);
    } else if (executed_count_ == 3 || executed_count_ >= 5) {
      expected.stack_count = 1;
      expected.stack[0] = Observed(12);
    }
  }
  if (executed_count_ >= 4) {
    expected.memory_count = 1;
    expected.memory[0] = {16, Observed(12)};
  }
  return state_ == expected;
}
OwnedVmExecuteResult OwnedVmFixture::ExecuteOne(NativeVmRecorder* recorder,
                                                std::uint64_t document_id,
                                                std::uint64_t generation,
                                                std::uint64_t now) noexcept {
  OwnedVmExecuteResult result;
  if (executed_count_ >= kOwnedVmDispatchBudget) {
    result.status = OwnedVmExecuteStatus::kBudget;
    return result;
  }
  if (!ValidState())
    return result;
  if (state_.halted) {
    result.status = OwnedVmExecuteStatus::kHalted;
    return result;
  }
  auto next = state_;
  auto& step = result.transition;
  const auto pc = state_.pc;
  auto next_pc = pc + 1;
  const bool stack = architecture_ == OwnedVmArchitecture::kStack;
  const auto location = stack ? VmLocation::kStack : VmLocation::kRegister;
  auto& slots = stack ? next.stack : next.registers;
  step.before = state_;
  step.opcode = static_cast<std::uint32_t>(pc < 2 ? 1 : pc);
  step.opcode_evidence = VmEvidence::kObserved;
  if (pc < 2) {
    const auto value = Observed(pc == 0 ? 7 : 5);
    Operand(step, VmLocation::kImmediate, 0, value);
    slots[pc] = value;
    if (stack)
      ++next.stack_count;
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
      next.stack_count = 1;
      Effect(step, VmAccess::kWrite, location, 1, {});
    }
  } else if (pc == 3) {
    Operand(step, location, 0, slots[0]);
    Effect(step, VmAccess::kRead, location, 0, slots[0]);
    next.memory_count = 1;
    next.memory[0] = {16, slots[0]};
    Effect(step, VmAccess::kWrite, VmLocation::kMemory, 16, slots[0]);
    if (stack) {
      slots[0] = {};
      next.stack_count = 0;
      Effect(step, VmAccess::kWrite, location, 0, {});
    }
  } else if (pc == 4) {
    Operand(step, VmLocation::kMemory, 16, next.memory[0].value);
    Effect(step, VmAccess::kRead, VmLocation::kMemory, 16, next.memory[0].value);
    const std::size_t destination = stack ? 0 : 2;
    slots[destination] = next.memory[0].value;
    if (stack)
      next.stack_count = 1;
    Effect(step, VmAccess::kWrite, location, destination, slots[destination]);
  } else if (pc == 5 || pc == 8) {
    step.opcode = pc == 5 ? 5 : 7;
    const std::size_t condition_slot = stack ? 0 : 2;
    Operand(step, location, condition_slot, slots[condition_slot]);
    Effect(step, VmAccess::kRead, location, condition_slot, slots[condition_slot]);
    const std::uint64_t target = 10;
    Operand(step, VmLocation::kImmediate, 0, Observed(target));
    const bool taken = pc == 5 ? slots[condition_slot].bits == 0 : slots[condition_slot].bits != 0;
    if (taken)
      next_pc = target;
  } else if (pc == 6) {
    step.opcode = 6;
    Operand(step, VmLocation::kImmediate, 0, Observed(8));
    next_pc = 8;
  } else if (pc == 10) {
    step.opcode = 8;
    next.halted = true;
    next_pc = pc;
  } else {
    return result;
  }
  next.pc = next_pc;
  step.after = next;
  // The only commit point. Rejected operations above cannot mutate either
  // state, execution count, or recorder. The hard budget makes increment safe.
  state_ = next;
  ++executed_count_;
  result.status = OwnedVmExecuteStatus::kCommitted;
  if (recorder != nullptr)
    result.recorder_result = recorder->Record(document_id, generation, now, step);
  return result;
}

}  // namespace reb
