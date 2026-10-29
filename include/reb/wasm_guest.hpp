#ifndef REB_WASM_GUEST_HPP_
#define REB_WASM_GUEST_HPP_
#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <type_traits>
#include "reb/event.hpp"
namespace reb {
// Adapter-interpreted values from an actual native execution. Semantics require
// a separately validated adapter and retained module/bytecode artifacts.
namespace wasm_guest_detail {
inline void Put(std::span<std::byte> out,
                std::size_t offset,
                std::uint64_t value,
                std::size_t width) noexcept {
  for (std::size_t i = 0; i < width; ++i)
    out[offset + i] = static_cast<std::byte>((value >> (8U * i)) & 255U);
}
inline std::uint64_t Get(std::span<const std::byte> bytes,
                         std::size_t offset,
                         std::size_t width) noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i)
    value |= std::to_integer<std::uint64_t>(bytes[offset + i]) << (8U * i);
  return value;
}
inline bool Envelope(const EventRecord& event) noexcept {
  return event.header.protocol_version == kEventProtocolVersion &&
         event.header.category == EventCategory::kVm && event.header.payload_size == 128 &&
         event.header.flags == 0 && event.header.session_id && event.header.sequence_number &&
         event.header.process_id && event.header.thread_id && event.header.monotonic_time_ns &&
         event.header.frame_id && event.header.artifact_id;
}
}  // namespace wasm_guest_detail
struct WasmGuestDispatchPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t selector = 0;
  std::uint32_t table_count = 0;
  std::uint32_t sample_index = 0;
  std::uint64_t instance_id = 0;
  std::uint64_t invocation_id = 0;
  std::uint64_t guest_pc = 0;
  std::uint64_t raw_pc_bits = 0;
  std::uint64_t bytecode_artifact_id = 0;
  std::uint64_t memory_base = 0;
  std::uint32_t memory_length = 0;
  std::uint32_t pc_local_index = 0;
  std::int64_t pc_adjustment = 0;
  std::uint32_t memory_index = 0;
  std::uint32_t opcode = 0;
  std::array<std::byte, 32> recipe_sha256{};
};
static_assert(sizeof(WasmGuestDispatchPayload) == 128);
static_assert(std::is_trivially_copyable_v<WasmGuestDispatchPayload>);
static_assert(std::is_standard_layout_v<WasmGuestDispatchPayload>);
static_assert(offsetof(WasmGuestDispatchPayload, protocol_version) == 0);
static_assert(offsetof(WasmGuestDispatchPayload, payload_size) == 2);
static_assert(offsetof(WasmGuestDispatchPayload, function_index) == 4);
static_assert(offsetof(WasmGuestDispatchPayload, module_byte_offset) == 8);
static_assert(offsetof(WasmGuestDispatchPayload, selector) == 12);
static_assert(offsetof(WasmGuestDispatchPayload, table_count) == 16);
static_assert(offsetof(WasmGuestDispatchPayload, sample_index) == 20);
static_assert(offsetof(WasmGuestDispatchPayload, instance_id) == 24);
static_assert(offsetof(WasmGuestDispatchPayload, invocation_id) == 32);
static_assert(offsetof(WasmGuestDispatchPayload, guest_pc) == 40);
static_assert(offsetof(WasmGuestDispatchPayload, raw_pc_bits) == 48);
static_assert(offsetof(WasmGuestDispatchPayload, bytecode_artifact_id) == 56);
static_assert(offsetof(WasmGuestDispatchPayload, memory_base) == 64);
static_assert(offsetof(WasmGuestDispatchPayload, memory_length) == 72);
static_assert(offsetof(WasmGuestDispatchPayload, pc_local_index) == 76);
static_assert(offsetof(WasmGuestDispatchPayload, pc_adjustment) == 80);
static_assert(offsetof(WasmGuestDispatchPayload, memory_index) == 88);
static_assert(offsetof(WasmGuestDispatchPayload, opcode) == 92);
static_assert(offsetof(WasmGuestDispatchPayload, recipe_sha256) == 96);
[[nodiscard]] inline std::array<std::byte, 128> EncodeWasmGuestDispatchPayload(
    const WasmGuestDispatchPayload& value) noexcept {
  std::array<std::byte, 128> out{};
  wasm_guest_detail::Put(out, 0, static_cast<std::uint64_t>(value.protocol_version),
                         sizeof(value.protocol_version));
  wasm_guest_detail::Put(out, 2, static_cast<std::uint64_t>(value.payload_size),
                         sizeof(value.payload_size));
  wasm_guest_detail::Put(out, 4, static_cast<std::uint64_t>(value.function_index),
                         sizeof(value.function_index));
  wasm_guest_detail::Put(out, 8, static_cast<std::uint64_t>(value.module_byte_offset),
                         sizeof(value.module_byte_offset));
  wasm_guest_detail::Put(out, 12, static_cast<std::uint64_t>(value.selector),
                         sizeof(value.selector));
  wasm_guest_detail::Put(out, 16, static_cast<std::uint64_t>(value.table_count),
                         sizeof(value.table_count));
  wasm_guest_detail::Put(out, 20, static_cast<std::uint64_t>(value.sample_index),
                         sizeof(value.sample_index));
  wasm_guest_detail::Put(out, 24, static_cast<std::uint64_t>(value.instance_id),
                         sizeof(value.instance_id));
  wasm_guest_detail::Put(out, 32, static_cast<std::uint64_t>(value.invocation_id),
                         sizeof(value.invocation_id));
  wasm_guest_detail::Put(out, 40, static_cast<std::uint64_t>(value.guest_pc),
                         sizeof(value.guest_pc));
  wasm_guest_detail::Put(out, 48, static_cast<std::uint64_t>(value.raw_pc_bits),
                         sizeof(value.raw_pc_bits));
  wasm_guest_detail::Put(out, 56, static_cast<std::uint64_t>(value.bytecode_artifact_id),
                         sizeof(value.bytecode_artifact_id));
  wasm_guest_detail::Put(out, 64, static_cast<std::uint64_t>(value.memory_base),
                         sizeof(value.memory_base));
  wasm_guest_detail::Put(out, 72, static_cast<std::uint64_t>(value.memory_length),
                         sizeof(value.memory_length));
  wasm_guest_detail::Put(out, 76, static_cast<std::uint64_t>(value.pc_local_index),
                         sizeof(value.pc_local_index));
  wasm_guest_detail::Put(out, 80, static_cast<std::uint64_t>(value.pc_adjustment),
                         sizeof(value.pc_adjustment));
  wasm_guest_detail::Put(out, 88, static_cast<std::uint64_t>(value.memory_index),
                         sizeof(value.memory_index));
  wasm_guest_detail::Put(out, 92, static_cast<std::uint64_t>(value.opcode), sizeof(value.opcode));
  std::copy(value.recipe_sha256.begin(), value.recipe_sha256.end(), out.begin() + 96);
  return out;
}
[[nodiscard]] inline bool DecodeWasmGuestDispatchPayload(std::span<const std::byte> bytes,
                                                         WasmGuestDispatchPayload& value) noexcept {
  if (bytes.size() != 128)
    return false;
  value.protocol_version =
      static_cast<std::uint16_t>(wasm_guest_detail::Get(bytes, 0, sizeof(value.protocol_version)));
  value.payload_size =
      static_cast<std::uint16_t>(wasm_guest_detail::Get(bytes, 2, sizeof(value.payload_size)));
  value.function_index =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 4, sizeof(value.function_index)));
  value.module_byte_offset = static_cast<std::uint32_t>(
      wasm_guest_detail::Get(bytes, 8, sizeof(value.module_byte_offset)));
  value.selector =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 12, sizeof(value.selector)));
  value.table_count =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 16, sizeof(value.table_count)));
  value.sample_index =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 20, sizeof(value.sample_index)));
  value.instance_id =
      static_cast<std::uint64_t>(wasm_guest_detail::Get(bytes, 24, sizeof(value.instance_id)));
  value.invocation_id =
      static_cast<std::uint64_t>(wasm_guest_detail::Get(bytes, 32, sizeof(value.invocation_id)));
  value.guest_pc =
      static_cast<std::uint64_t>(wasm_guest_detail::Get(bytes, 40, sizeof(value.guest_pc)));
  value.raw_pc_bits =
      static_cast<std::uint64_t>(wasm_guest_detail::Get(bytes, 48, sizeof(value.raw_pc_bits)));
  value.bytecode_artifact_id = static_cast<std::uint64_t>(
      wasm_guest_detail::Get(bytes, 56, sizeof(value.bytecode_artifact_id)));
  value.memory_base =
      static_cast<std::uint64_t>(wasm_guest_detail::Get(bytes, 64, sizeof(value.memory_base)));
  value.memory_length =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 72, sizeof(value.memory_length)));
  value.pc_local_index =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 76, sizeof(value.pc_local_index)));
  value.pc_adjustment =
      std::bit_cast<std::int64_t>(wasm_guest_detail::Get(bytes, 80, sizeof(value.pc_adjustment)));
  value.memory_index =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 88, sizeof(value.memory_index)));
  value.opcode =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 92, sizeof(value.opcode)));
  std::copy_n(bytes.begin() + 96, 32, value.recipe_sha256.begin());
  return true;
}
// Version 2 adds the exact outer dispatch at bytes 72..80. Version 1 reserved
// bytes 72..128 and still decodes, with a zero parent dispatch.
struct WasmGuestInvocationPayload final {
  std::uint16_t protocol_version = 2;
  std::uint16_t payload_size = 128;
  std::uint32_t function_index = 0;
  std::uint64_t instance_id = 0;
  std::uint64_t invocation_id = 0;
  std::uint64_t adapter_artifact_id = 0;
  std::array<std::byte, 32> recipe_sha256{};
  // The enclosing guest activation, and the renderer sequence number of its
  // retained dispatch that was current when this activation began. Zero is
  // not asserted; a parent without a dispatch names only the activation.
  std::uint64_t parent_invocation_id = 0;
  std::uint64_t parent_dispatch_sequence_number = 0;
  std::array<std::byte, 48> reserved{};
};
static_assert(sizeof(WasmGuestInvocationPayload) == 128);
static_assert(std::is_trivially_copyable_v<WasmGuestInvocationPayload>);
static_assert(std::is_standard_layout_v<WasmGuestInvocationPayload>);
static_assert(offsetof(WasmGuestInvocationPayload, protocol_version) == 0);
static_assert(offsetof(WasmGuestInvocationPayload, payload_size) == 2);
static_assert(offsetof(WasmGuestInvocationPayload, function_index) == 4);
static_assert(offsetof(WasmGuestInvocationPayload, instance_id) == 8);
static_assert(offsetof(WasmGuestInvocationPayload, invocation_id) == 16);
static_assert(offsetof(WasmGuestInvocationPayload, adapter_artifact_id) == 24);
static_assert(offsetof(WasmGuestInvocationPayload, parent_invocation_id) == 64);
static_assert(offsetof(WasmGuestInvocationPayload, parent_dispatch_sequence_number) == 72);
static_assert(offsetof(WasmGuestInvocationPayload, recipe_sha256) == 32);
[[nodiscard]] inline std::array<std::byte, 128> EncodeWasmGuestInvocationPayload(
    const WasmGuestInvocationPayload& value) noexcept {
  std::array<std::byte, 128> out{};
  wasm_guest_detail::Put(out, 0, static_cast<std::uint64_t>(value.protocol_version),
                         sizeof(value.protocol_version));
  wasm_guest_detail::Put(out, 2, static_cast<std::uint64_t>(value.payload_size),
                         sizeof(value.payload_size));
  wasm_guest_detail::Put(out, 4, static_cast<std::uint64_t>(value.function_index),
                         sizeof(value.function_index));
  wasm_guest_detail::Put(out, 8, static_cast<std::uint64_t>(value.instance_id),
                         sizeof(value.instance_id));
  wasm_guest_detail::Put(out, 16, static_cast<std::uint64_t>(value.invocation_id),
                         sizeof(value.invocation_id));
  wasm_guest_detail::Put(out, 24, static_cast<std::uint64_t>(value.adapter_artifact_id),
                         sizeof(value.adapter_artifact_id));
  wasm_guest_detail::Put(out, 64, static_cast<std::uint64_t>(value.parent_invocation_id),
                         sizeof(value.parent_invocation_id));
  wasm_guest_detail::Put(out, 72, value.parent_dispatch_sequence_number,
                         sizeof(value.parent_dispatch_sequence_number));
  std::copy(value.recipe_sha256.begin(), value.recipe_sha256.end(), out.begin() + 32);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 80);
  return out;
}
[[nodiscard]] inline bool DecodeWasmGuestInvocationPayload(
    std::span<const std::byte> bytes,
    WasmGuestInvocationPayload& value) noexcept {
  if (bytes.size() != 128)
    return false;
  value.protocol_version =
      static_cast<std::uint16_t>(wasm_guest_detail::Get(bytes, 0, sizeof(value.protocol_version)));
  value.payload_size =
      static_cast<std::uint16_t>(wasm_guest_detail::Get(bytes, 2, sizeof(value.payload_size)));
  value.function_index =
      static_cast<std::uint32_t>(wasm_guest_detail::Get(bytes, 4, sizeof(value.function_index)));
  value.instance_id =
      static_cast<std::uint64_t>(wasm_guest_detail::Get(bytes, 8, sizeof(value.instance_id)));
  value.invocation_id =
      static_cast<std::uint64_t>(wasm_guest_detail::Get(bytes, 16, sizeof(value.invocation_id)));
  value.adapter_artifact_id = static_cast<std::uint64_t>(
      wasm_guest_detail::Get(bytes, 24, sizeof(value.adapter_artifact_id)));
  value.parent_invocation_id = static_cast<std::uint64_t>(
      wasm_guest_detail::Get(bytes, 64, sizeof(value.parent_invocation_id)));
  value.parent_dispatch_sequence_number =
      wasm_guest_detail::Get(bytes, 72, sizeof(value.parent_dispatch_sequence_number));
  std::copy_n(bytes.begin() + 32, 32, value.recipe_sha256.begin());
  std::copy_n(bytes.begin() + 80, 48, value.reserved.begin());
  return true;
}
[[nodiscard]] inline bool IsValidWasmGuestDispatch(const EventRecord& event) noexcept {
  WasmGuestDispatchPayload value;
  return wasm_guest_detail::Envelope(event) && event.header.type == EventType::kWasmGuestDispatch &&
         event.header.parent_event_id &&
         event.header.parent_event_id < event.header.sequence_number &&
         DecodeWasmGuestDispatchPayload(event.inline_payload, value) &&
         value.protocol_version == 1 && value.payload_size == 128 &&
         value.function_index < 16U * 1024U * 1024U && value.module_byte_offset >= 8 &&
         value.module_byte_offset < 16U * 1024U * 1024U &&
         value.table_count < 16U * 1024U * 1024U && value.sample_index < 256 && value.instance_id &&
         value.invocation_id && value.bytecode_artifact_id &&
         value.bytecode_artifact_id != event.header.artifact_id && value.memory_length &&
         value.memory_length <= 65536 && value.guest_pc < value.memory_length &&
         value.memory_base <= std::numeric_limits<std::uint64_t>::max() - value.memory_length &&
         std::any_of(value.recipe_sha256.begin(), value.recipe_sha256.end(),
                     [](std::byte b) { return b != std::byte{0}; });
}
[[nodiscard]] inline bool IsValidWasmGuestInvocation(const EventRecord& event) noexcept {
  WasmGuestInvocationPayload value;
  return wasm_guest_detail::Envelope(event) &&
         event.header.type == EventType::kWasmGuestInvocation && !event.header.parent_event_id &&
         DecodeWasmGuestInvocationPayload(event.inline_payload, value) &&
         (value.protocol_version == 1 || value.protocol_version == 2) &&
         value.payload_size == 128 && value.function_index < 16U * 1024U * 1024U &&
         value.instance_id && value.invocation_id &&
         value.parent_invocation_id != value.invocation_id &&
         // Version 1 reserved the parent dispatch bytes. An exact parent
         // dispatch names its activation and precedes this marker.
         (value.protocol_version == 2 || !value.parent_dispatch_sequence_number) &&
         (!value.parent_dispatch_sequence_number ||
          (value.parent_invocation_id &&
           value.parent_dispatch_sequence_number < event.header.sequence_number)) &&
         value.adapter_artifact_id && value.adapter_artifact_id != event.header.artifact_id &&
         std::any_of(value.recipe_sha256.begin(), value.recipe_sha256.end(),
                     [](std::byte b) { return b != std::byte{0}; }) &&
         std::all_of(value.reserved.begin(), value.reserved.end(),
                     [](std::byte b) { return b == std::byte{0}; });
}
}  // namespace reb
#endif
