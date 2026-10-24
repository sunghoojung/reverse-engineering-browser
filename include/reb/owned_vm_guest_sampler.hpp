#ifndef REB_OWNED_VM_GUEST_SAMPLER_HPP_
#define REB_OWNED_VM_GUEST_SAMPLER_HPP_

#include <cstdint>

namespace reb {

// Callbacks for one owned-register invocation. A null binding, or a binding
// whose step callback is null, is the disabled sampler: the fixture still
// runs and no sample is submitted. The step callback receives the committed
// instruction-index program counter. It does not receive operand values.
using OwnedRegisterBeginFn = void (*)(std::uint64_t invocation_id, void* context) noexcept;
using OwnedRegisterStepFn = void (*)(std::uint32_t instruction_pointer,
                                     std::uint32_t opcode,
                                     std::uint8_t operand_count,
                                     std::uint32_t sample_index,
                                     void* context) noexcept;

struct OwnedRegisterSamplerBinding final {
  OwnedRegisterBeginFn begin_invocation = nullptr;
  OwnedRegisterStepFn observe_step = nullptr;
  void* context = nullptr;
};

struct OwnedRegisterSamplerResult final {
  std::uint64_t executed = 0;
  std::uint64_t submitted = 0;
  bool halted = false;
};

// Runs owned-register-v1 to halt. Sample policy when observe_step is set:
// one begin_invocation call when invocation_id is nonzero, then one observe_step
// per committed instruction. sample_index restarts at 0 for each invocation.
// Program counters are instruction indices. Handler selection stays with the
// sink, which copies the fixture opcode. The 16-sample budget is enforced by
// the probe writer, not here. A null binding performs no callback and allocates
// nothing beyond the fixture's fixed stack state.
[[nodiscard]] OwnedRegisterSamplerResult SampleOwnedRegisterInvocation(
    std::uint64_t invocation_id,
    const OwnedRegisterSamplerBinding* binding) noexcept;

}  // namespace reb

#endif  // REB_OWNED_VM_GUEST_SAMPLER_HPP_
