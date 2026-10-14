#include "reb/native_vm_recorder.hpp"

#include <limits>

namespace reb {
namespace {
constexpr bool Advance(std::uint64_t& counter) noexcept {
  if (counter == std::numeric_limits<std::uint64_t>::max())
    return false;
  ++counter;
  return true;
}
static_assert([] {
  auto value = std::numeric_limits<std::uint64_t>::max() - 1;
  return Advance(value) && !Advance(value) && value == std::numeric_limits<std::uint64_t>::max();
}());

bool Valid(VmEvidence evidence) noexcept {
  return evidence == VmEvidence::kUnknown || evidence == VmEvidence::kObserved ||
         evidence == VmEvidence::kInferred;
}
bool Valid(const VmValue& value) noexcept {
  return Valid(value.evidence) && (value.evidence != VmEvidence::kUnknown || value.bits == 0);
}
bool Valid(const VmSnapshot& state) noexcept {
  if (!Valid(state.pc_evidence) || (state.pc_evidence == VmEvidence::kUnknown && state.pc != 0) ||
      state.register_count > kNativeVmSlots || state.stack_count > kNativeVmSlots ||
      state.memory_count > kNativeVmSlots) {
    return false;
  }
  for (std::size_t i = 0; i < kNativeVmSlots; ++i) {
    if (!Valid(state.registers[i]) || !Valid(state.stack[i]) || !Valid(state.memory[i].value))
      return false;
    // Unused storage cannot smuggle values into a retained snapshot.
    if ((i >= state.register_count && state.registers[i] != VmValue{}) ||
        (i >= state.stack_count && state.stack[i] != VmValue{}) ||
        (i >= state.memory_count && state.memory[i] != VmMemoryCell{}))
      return false;
    if (i < state.memory_count) {
      for (std::size_t j = 0; j < i; ++j) {
        if (state.memory[j].guest_address == state.memory[i].guest_address)
          return false;
      }
    }
  }
  return true;
}
bool ValidLocation(VmLocation location, std::uint64_t index) noexcept {
  switch (location) {
    case VmLocation::kImmediate:
      return index == 0;
    case VmLocation::kRegister:
    case VmLocation::kStack:
      return index < kNativeVmSlots;
    case VmLocation::kMemory:
      return true;
  }
  return false;
}
bool Valid(const VmStep& step) noexcept {
  if (!Valid(step.opcode_evidence) ||
      (step.opcode_evidence == VmEvidence::kUnknown && step.opcode != 0) ||
      step.operand_count > step.operands.size() || step.effect_count > step.effects.size() ||
      !Valid(step.before) || !Valid(step.after))
    return false;
  for (std::size_t i = 0; i < step.operands.size(); ++i) {
    const auto& operand = step.operands[i];
    if (!ValidLocation(operand.location, operand.index) || !Valid(operand.value))
      return false;
    if (i >= step.operand_count && (operand.location != VmLocation::kImmediate ||
                                    operand.index != 0 || operand.value != VmValue{}))
      return false;
  }
  for (std::size_t i = 0; i < step.effects.size(); ++i) {
    const auto& effect = step.effects[i];
    if ((effect.access != VmAccess::kRead && effect.access != VmAccess::kWrite) ||
        effect.location == VmLocation::kImmediate ||
        !ValidLocation(effect.location, effect.index) || !Valid(effect.value))
      return false;
    if (i >= step.effect_count &&
        (effect.access != VmAccess::kRead || effect.location != VmLocation::kRegister ||
         effect.index != 0 || effect.value != VmValue{}))
      return false;
  }
  return true;
}
}  // namespace

NativeVmRecorder::NativeVmRecorder(std::size_t capacity) noexcept
    : capacity_(capacity <= kNativeVmRecords ? capacity : kNativeVmRecords) {}

bool NativeVmRecorder::Enable(VmScope scope, std::uint64_t now) noexcept {
  enabled_ = false;
  records_ = {};
  size_ = 0;
  stats_ = {};
  scope_ = {};
  last_tick_ = now;
  if (!Advance(generation_))
    return false;
  if (scope.session_id == 0 || scope.document_id == 0 || scope.invocation_id == 0 ||
      scope.expires_at <= now)
    return false;
  scope_ = scope;
  enabled_ = true;
  return true;
}
void NativeVmRecorder::Disable() noexcept {
  enabled_ = false;
}
void NativeVmRecorder::InvalidateDocument() noexcept {
  Disable();
}

VmRecordResult NativeVmRecorder::Record(std::uint64_t document_id,
                                        std::uint64_t generation,
                                        std::uint64_t now,
                                        const VmStep& step) noexcept {
  if (!enabled_)
    return VmRecordResult::kDisabled;
  if (generation != generation_) {
    Advance(stats_.stale_generation);
    return VmRecordResult::kStaleGeneration;
  }
  if (document_id != scope_.document_id) {
    Advance(stats_.wrong_document);
    return VmRecordResult::kWrongDocument;
  }
  if (now >= scope_.expires_at || now < last_tick_) {
    enabled_ = false;
    Advance(stats_.expired);
    return VmRecordResult::kExpired;
  }
  last_tick_ = now;
  if (!Advance(stats_.attempted)) {
    Advance(stats_.exhausted);
    enabled_ = false;
    return VmRecordResult::kExhausted;
  }
  const auto sequence = stats_.attempted;
  if (!Valid(step)) {
    Advance(stats_.malformed);
    return VmRecordResult::kMalformed;
  }
  if (size_ == capacity_) {
    Advance(stats_.full);
    return VmRecordResult::kFull;
  }
  records_[size_++] = {sequence, now, step};
  Advance(stats_.recorded);
  if (step.partial || step.before.partial || step.after.partial)
    Advance(stats_.partial);
  return VmRecordResult::kRecorded;
}
std::span<const VmRecordedStep> NativeVmRecorder::records() const noexcept {
  return {records_.data(), size_};
}
const VmRecorderStats& NativeVmRecorder::stats() const noexcept {
  return stats_;
}
const VmScope& NativeVmRecorder::scope() const noexcept {
  return scope_;
}
std::uint64_t NativeVmRecorder::generation() const noexcept {
  return generation_;
}
}  // namespace reb
