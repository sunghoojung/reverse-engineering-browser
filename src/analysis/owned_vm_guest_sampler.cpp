#include "reb/owned_vm_guest_sampler.hpp"
#include "reb/owned_vm_fixture.hpp"

#include <cstdint>
#include <limits>

namespace reb {

OwnedRegisterSamplerResult SampleOwnedRegisterInvocation(
    const std::uint64_t invocation_id,
    const OwnedRegisterSamplerBinding* const binding) noexcept {
  OwnedRegisterSamplerResult result;
  OwnedVmFixture fixture(OwnedVmArchitecture::kRegister);
  const bool submit = binding != nullptr && binding->observe_step != nullptr;
  if (submit && binding->begin_invocation != nullptr && invocation_id != 0) {
    binding->begin_invocation(invocation_id, binding->context);
  }
  std::uint32_t sample_index = 0;
  while (!fixture.snapshot().halted) {
    const OwnedVmExecuteResult step = fixture.ExecuteOne();
    if (step.status != OwnedVmExecuteStatus::kCommitted) {
      break;
    }
    const std::uint64_t instruction_pointer = step.transition.before.pc;
    if (submit && instruction_pointer <= std::numeric_limits<std::uint32_t>::max()) {
      binding->observe_step(static_cast<std::uint32_t>(instruction_pointer), step.transition.opcode,
                            step.transition.operand_count, sample_index, binding->context);
      ++sample_index;
    }
  }
  result.executed = fixture.executed_count();
  result.submitted = sample_index;
  result.halted = fixture.snapshot().halted;
  return result;
}

}  // namespace reb
