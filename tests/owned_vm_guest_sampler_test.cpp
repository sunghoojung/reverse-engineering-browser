#include <cstdint>
#include <iostream>

#include "reb/owned_vm_guest_sampler.hpp"

namespace {

bool Check(const bool condition, const char* const message) {
  if (!condition) {
    std::cerr << message << '\n';
  }
  return condition;
}

struct Capture final {
  std::uint64_t invocations = 0;
  std::uint64_t last_invocation = 0;
  std::uint32_t count = 0;
  std::uint32_t instruction_pointer[9]{};
  std::uint32_t opcode[9]{};
  std::uint8_t operand_count[9]{};
  std::uint32_t sample_index[9]{};
};

void Begin(const std::uint64_t invocation_id, void* const context) noexcept {
  auto* capture = static_cast<Capture*>(context);
  ++capture->invocations;
  capture->last_invocation = invocation_id;
}

void Step(const std::uint32_t instruction_pointer,
          const std::uint32_t opcode,
          const std::uint8_t operand_count,
          const std::uint32_t sample_index,
          void* const context) noexcept {
  auto* capture = static_cast<Capture*>(context);
  if (capture->count >= 9) {
    ++capture->count;
    return;
  }
  capture->instruction_pointer[capture->count] = instruction_pointer;
  capture->opcode[capture->count] = opcode;
  capture->operand_count[capture->count] = operand_count;
  capture->sample_index[capture->count] = sample_index;
  ++capture->count;
}

}  // namespace

int main() {
  const auto disabled = reb::SampleOwnedRegisterInvocation(4, nullptr);
  if (!Check(disabled.halted && disabled.executed == 9 && disabled.submitted == 0,
             "disabled sampler still runs the register program")) {
    return 1;
  }
  reb::OwnedRegisterSamplerBinding inactive{};
  const auto unbound = reb::SampleOwnedRegisterInvocation(4, &inactive);
  if (!Check(unbound.submitted == 0 && unbound.executed == 9, "null callbacks submit nothing")) {
    return 1;
  }

  constexpr std::uint32_t kPcs[] = {0, 1, 2, 3, 4, 5, 6, 8, 10};
  constexpr std::uint32_t kOpcodes[] = {1, 1, 2, 3, 4, 5, 6, 7, 8};
  constexpr std::uint8_t kOperands[] = {1, 1, 2, 1, 1, 2, 1, 2, 0};
  Capture capture;
  const reb::OwnedRegisterSamplerBinding binding{&Begin, &Step, &capture};
  const auto sampled = reb::SampleOwnedRegisterInvocation(41, &binding);
  if (!Check(sampled.halted && sampled.executed == 9 && sampled.submitted == 9 &&
                 capture.invocations == 1 && capture.last_invocation == 41 && capture.count == 9,
             "one invocation submits nine committed steps")) {
    return 1;
  }
  for (std::uint32_t index = 0; index < 9; ++index) {
    if (!Check(capture.instruction_pointer[index] == kPcs[index] &&
                   capture.opcode[index] == kOpcodes[index] &&
                   capture.operand_count[index] == kOperands[index] &&
                   capture.sample_index[index] == index,
               "program counter, opcode, and sample index")) {
      return 1;
    }
  }
  Capture second;
  const reb::OwnedRegisterSamplerBinding again{&Begin, &Step, &second};
  const auto repeated = reb::SampleOwnedRegisterInvocation(42, &again);
  if (!Check(repeated.submitted == 9 && second.sample_index[0] == 0 && second.last_invocation == 42,
             "a later invocation restarts its sample index")) {
    return 1;
  }
  std::cout << "PASS owned register sampler observes instruction-index program counters\n";
  return 0;
}
