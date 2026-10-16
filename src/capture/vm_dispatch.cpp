#include "reb/vm_dispatch.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <span>

namespace reb {

namespace {

static_assert(std::endian::native == std::endian::little);
inline constexpr std::uint8_t kKnownFlags = 0;

bool IsZero(const std::span<const std::byte> bytes) noexcept {
  return std::ranges::all_of(bytes, [](const std::byte value) { return value == std::byte{0}; });
}

}  // namespace

VmDispatchSamplePayload MakeVmDispatchSample(const std::uint32_t instruction_pointer,
                                             const std::uint32_t opcode,
                                             const std::uint32_t handler_index,
                                             const std::uint32_t sample_index,
                                             const std::uint64_t finding_id,
                                             const std::uint64_t investigation_id,
                                             const std::uint64_t interpreter_artifact_id,
                                             const std::uint64_t bytecode_artifact_id,
                                             const std::uint8_t operand_count) noexcept {
  VmDispatchSamplePayload sample{};
  sample.instruction_pointer = instruction_pointer;
  sample.opcode = opcode;
  sample.handler_index = handler_index;
  sample.sample_index = sample_index;
  sample.finding_id = finding_id;
  sample.investigation_id = investigation_id;
  sample.interpreter_artifact_id = interpreter_artifact_id;
  sample.bytecode_artifact_id = bytecode_artifact_id;
  sample.operand_count = operand_count;
  return sample;
}

bool IsValidVmDispatchSample(const VmDispatchSamplePayload& sample) noexcept {
  return sample.protocol_version == kVmDispatchSampleProtocolVersion &&
         sample.payload_size == sizeof(VmDispatchSamplePayload) &&
         (sample.flags & static_cast<std::uint8_t>(~kKnownFlags)) == 0 &&
         sample.reserved_alignment == 0 && sample.reserved0 == 0 && sample.reserved1 == 0 &&
         sample.reserved2 == 0 && sample.finding_id != 0 && sample.investigation_id != 0 &&
         IsZero(sample.reserved) && IsZero(sample.reserved_tail);
}

bool SetVmDispatchSamplePayload(EventRecord& event,
                                const VmDispatchSamplePayload& sample) noexcept {
  if (!IsValidVmDispatchSample(sample)) {
    return false;
  }
  event.header.category = EventCategory::kVm;
  event.header.type = EventType::kVmDispatchSample;
  const auto* bytes = reinterpret_cast<const std::byte*>(&sample);
  return SetInlinePayload(event, std::span<const std::byte>(bytes, sizeof(sample)));
}

bool DecodeVmDispatchSample(const EventRecord& event, VmDispatchSamplePayload& sample) noexcept {
  const bool payload_truncated =
      (event.header.flags & static_cast<std::uint16_t>(EventFlag::kPayloadTruncated)) != 0;
  if (!IsValidEvent(event) || payload_truncated || event.header.category != EventCategory::kVm ||
      event.header.type != EventType::kVmDispatchSample ||
      event.header.payload_size != sizeof(VmDispatchSamplePayload)) {
    return false;
  }
  VmDispatchSamplePayload decoded{};
  std::memcpy(&decoded, event.inline_payload.data(), sizeof(decoded));
  if (!IsValidVmDispatchSample(decoded)) {
    return false;
  }
  sample = decoded;
  return true;
}

}  // namespace reb
