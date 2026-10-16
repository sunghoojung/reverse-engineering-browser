#ifndef REB_VM_DISPATCH_HPP_
#define REB_VM_DISPATCH_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "reb/event.hpp"

namespace reb {

inline constexpr std::uint16_t kVmDispatchSampleProtocolVersion = 1;
inline constexpr std::size_t kVmDispatchReservedSize = 40;
inline constexpr std::size_t kVmDispatchReservedTailSize = 16;

// Fixed little-endian payload for EventCategory::kVm and
// EventType::kVmDispatchSample. Reserved fields make every byte explicit so
// protocol validation is independent of compiler padding.
struct VmDispatchSamplePayload final {
  std::uint16_t protocol_version = kVmDispatchSampleProtocolVersion;
  std::uint16_t payload_size = sizeof(VmDispatchSamplePayload);
  std::uint32_t instruction_pointer = 0;
  std::uint32_t opcode = 0;
  std::uint32_t handler_index = 0;
  std::uint32_t sample_index = 0;
  std::uint32_t reserved_alignment = 0;
  std::uint64_t finding_id = 0;
  std::uint64_t investigation_id = 0;
  std::uint64_t interpreter_artifact_id = 0;
  std::uint64_t bytecode_artifact_id = 0;
  std::uint8_t flags = 0;
  std::uint8_t operand_count = 0;
  std::uint16_t reserved0 = 0;
  std::uint32_t reserved1 = 0;
  std::uint64_t reserved2 = 0;
  std::array<std::byte, kVmDispatchReservedSize> reserved{};
  std::array<std::byte, kVmDispatchReservedTailSize> reserved_tail{};
};

static_assert(std::is_standard_layout_v<VmDispatchSamplePayload>);
static_assert(std::is_trivially_copyable_v<VmDispatchSamplePayload>);
static_assert(std::has_unique_object_representations_v<VmDispatchSamplePayload>);
static_assert(sizeof(VmDispatchSamplePayload) == kInlinePayloadSize);
#define REB_ASSERT_VM_DISPATCH_OFFSET(member, expected) \
  static_assert(offsetof(VmDispatchSamplePayload, member) == expected)
REB_ASSERT_VM_DISPATCH_OFFSET(protocol_version, 0);
REB_ASSERT_VM_DISPATCH_OFFSET(payload_size, 2);
REB_ASSERT_VM_DISPATCH_OFFSET(instruction_pointer, 4);
REB_ASSERT_VM_DISPATCH_OFFSET(opcode, 8);
REB_ASSERT_VM_DISPATCH_OFFSET(handler_index, 12);
REB_ASSERT_VM_DISPATCH_OFFSET(sample_index, 16);
REB_ASSERT_VM_DISPATCH_OFFSET(reserved_alignment, 20);
REB_ASSERT_VM_DISPATCH_OFFSET(finding_id, 24);
REB_ASSERT_VM_DISPATCH_OFFSET(investigation_id, 32);
REB_ASSERT_VM_DISPATCH_OFFSET(interpreter_artifact_id, 40);
REB_ASSERT_VM_DISPATCH_OFFSET(bytecode_artifact_id, 48);
REB_ASSERT_VM_DISPATCH_OFFSET(flags, 56);
REB_ASSERT_VM_DISPATCH_OFFSET(operand_count, 57);
REB_ASSERT_VM_DISPATCH_OFFSET(reserved0, 58);
REB_ASSERT_VM_DISPATCH_OFFSET(reserved1, 60);
REB_ASSERT_VM_DISPATCH_OFFSET(reserved2, 64);
REB_ASSERT_VM_DISPATCH_OFFSET(reserved, 72);
REB_ASSERT_VM_DISPATCH_OFFSET(reserved_tail, 112);
#undef REB_ASSERT_VM_DISPATCH_OFFSET

[[nodiscard]] VmDispatchSamplePayload MakeVmDispatchSample(std::uint32_t instruction_pointer,
                                                           std::uint32_t opcode,
                                                           std::uint32_t handler_index,
                                                           std::uint32_t sample_index,
                                                           std::uint64_t finding_id,
                                                           std::uint64_t investigation_id,
                                                           std::uint64_t interpreter_artifact_id,
                                                           std::uint64_t bytecode_artifact_id,
                                                           std::uint8_t operand_count) noexcept;
[[nodiscard]] bool IsValidVmDispatchSample(const VmDispatchSamplePayload& sample) noexcept;
[[nodiscard]] bool SetVmDispatchSamplePayload(EventRecord& event,
                                              const VmDispatchSamplePayload& sample) noexcept;
[[nodiscard]] bool DecodeVmDispatchSample(const EventRecord& event,
                                          VmDispatchSamplePayload& sample) noexcept;

}  // namespace reb

#endif  // REB_VM_DISPATCH_HPP_
