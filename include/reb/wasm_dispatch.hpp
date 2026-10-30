#ifndef REB_WASM_DISPATCH_HPP_
#define REB_WASM_DISPATCH_HPP_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include "reb/event.hpp"
namespace reb {
// Physical Wasm br_table execution, not an interpreter guest program counter.
struct WasmDispatchObservationPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t selector = 0;
  std::uint32_t table_count = 0;
  std::uint32_t sample_index = 0;
  std::array<std::byte, 104> reserved{};
};
static_assert(sizeof(WasmDispatchObservationPayload) == 128);
static_assert(std::is_standard_layout_v<WasmDispatchObservationPayload>);
static_assert(std::is_trivially_copyable_v<WasmDispatchObservationPayload>);
static_assert(offsetof(WasmDispatchObservationPayload, protocol_version) == 0);
static_assert(offsetof(WasmDispatchObservationPayload, payload_size) == 2);
static_assert(offsetof(WasmDispatchObservationPayload, function_index) == 4);
static_assert(offsetof(WasmDispatchObservationPayload, module_byte_offset) == 8);
static_assert(offsetof(WasmDispatchObservationPayload, selector) == 12);
static_assert(offsetof(WasmDispatchObservationPayload, table_count) == 16);
static_assert(offsetof(WasmDispatchObservationPayload, sample_index) == 20);
static_assert(offsetof(WasmDispatchObservationPayload, reserved) == 24);
[[nodiscard]] inline std::array<std::byte, 128> EncodeWasmDispatchObservationPayload(
    const WasmDispatchObservationPayload& value) noexcept {
  std::array<std::byte, 128> out{};
  const auto put = [&out](std::size_t offset, std::uint32_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
      out[offset + i] = static_cast<std::byte>((v >> (8U * i)) & 255U);
  };
  put(0, value.protocol_version, 2);
  put(2, value.payload_size, 2);
  put(4, value.function_index, 4);
  put(8, value.module_byte_offset, 4);
  put(12, value.selector, 4);
  put(16, value.table_count, 4);
  put(20, value.sample_index, 4);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 24);
  return out;
}
[[nodiscard]] inline bool DecodeWasmDispatchObservationPayload(
    std::span<const std::byte> bytes,
    WasmDispatchObservationPayload& value) noexcept {
  if (bytes.size() != 128)
    return false;
  const auto get = [bytes](std::size_t offset, std::size_t width) {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < width; ++i)
      v |= std::to_integer<std::uint32_t>(bytes[offset + i]) << (8U * i);
    return v;
  };
  value.protocol_version = static_cast<std::uint16_t>(get(0, 2));
  value.payload_size = static_cast<std::uint16_t>(get(2, 2));
  value.function_index = get(4, 4);
  value.module_byte_offset = get(8, 4);
  value.selector = get(12, 4);
  value.table_count = get(16, 4);
  value.sample_index = get(20, 4);
  std::copy(bytes.begin() + 24, bytes.end(), value.reserved.begin());
  return true;
}
[[nodiscard]] inline bool IsValidWasmDispatchObservation(const EventRecord& event) noexcept {
  WasmDispatchObservationPayload value;
  return event.header.protocol_version == kEventProtocolVersion &&
         event.header.category == EventCategory::kVm &&
         event.header.type == EventType::kWasmDispatchObservation &&
         event.header.payload_size == 128 && event.header.flags == 0 &&
         event.header.session_id != 0 && event.header.sequence_number != 0 &&
         event.header.process_id != 0 && event.header.thread_id != 0 &&
         event.header.monotonic_time_ns != 0 && event.header.frame_id != 0 &&
         event.header.artifact_id != 0 && event.header.parent_event_id == 0 &&
         DecodeWasmDispatchObservationPayload(event.inline_payload, value) &&
         value.protocol_version == 1 && value.payload_size == 128 &&
         value.function_index < 16U * 1024U * 1024U && value.table_count < 16U * 1024U * 1024U &&
         value.module_byte_offset >= 8 && value.module_byte_offset < 16U * 1024U * 1024U &&
         value.sample_index < 16 &&
         std::all_of(value.reserved.begin(), value.reserved.end(),
                     [](std::byte b) { return b == std::byte{0}; });
}
// Physical Wasm call_indirect or return_call_indirect execution. The slot is
// the dynamic table index, not a guest opcode or program counter.
enum class WasmIndirectResolution : std::uint32_t {
  kResolved = 0,
  kNull = 1,
  kOutOfBounds = 2,
  kForeign = 3,
  kUnresolved = 4,
};
inline constexpr std::uint32_t kWasmIndirectResolutionCount = 5;
struct WasmIndirectObservationPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t table_index = 0;
  std::uint32_t slot = 0;
  std::uint32_t callee_function_index = 0;
  std::uint32_t resolution = 0;
  std::uint32_t sample_index = 0;
  std::array<std::byte, 96> reserved{};
};
static_assert(sizeof(WasmIndirectObservationPayload) == 128);
static_assert(std::is_standard_layout_v<WasmIndirectObservationPayload>);
static_assert(std::is_trivially_copyable_v<WasmIndirectObservationPayload>);
static_assert(offsetof(WasmIndirectObservationPayload, protocol_version) == 0);
static_assert(offsetof(WasmIndirectObservationPayload, payload_size) == 2);
static_assert(offsetof(WasmIndirectObservationPayload, function_index) == 4);
static_assert(offsetof(WasmIndirectObservationPayload, module_byte_offset) == 8);
static_assert(offsetof(WasmIndirectObservationPayload, table_index) == 12);
static_assert(offsetof(WasmIndirectObservationPayload, slot) == 16);
static_assert(offsetof(WasmIndirectObservationPayload, callee_function_index) == 20);
static_assert(offsetof(WasmIndirectObservationPayload, resolution) == 24);
static_assert(offsetof(WasmIndirectObservationPayload, sample_index) == 28);
static_assert(offsetof(WasmIndirectObservationPayload, reserved) == 32);
[[nodiscard]] inline std::array<std::byte, 128> EncodeWasmIndirectObservationPayload(
    const WasmIndirectObservationPayload& value) noexcept {
  std::array<std::byte, 128> out{};
  const auto put = [&out](std::size_t offset, std::uint32_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
      out[offset + i] = static_cast<std::byte>((v >> (8U * i)) & 255U);
  };
  put(0, value.protocol_version, 2);
  put(2, value.payload_size, 2);
  put(4, value.function_index, 4);
  put(8, value.module_byte_offset, 4);
  put(12, value.table_index, 4);
  put(16, value.slot, 4);
  put(20, value.callee_function_index, 4);
  put(24, value.resolution, 4);
  put(28, value.sample_index, 4);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 32);
  return out;
}
[[nodiscard]] inline bool DecodeWasmIndirectObservationPayload(
    std::span<const std::byte> bytes,
    WasmIndirectObservationPayload& value) noexcept {
  if (bytes.size() != 128)
    return false;
  const auto get = [bytes](std::size_t offset, std::size_t width) {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < width; ++i)
      v |= std::to_integer<std::uint32_t>(bytes[offset + i]) << (8U * i);
    return v;
  };
  value.protocol_version = static_cast<std::uint16_t>(get(0, 2));
  value.payload_size = static_cast<std::uint16_t>(get(2, 2));
  value.function_index = get(4, 4);
  value.module_byte_offset = get(8, 4);
  value.table_index = get(12, 4);
  value.slot = get(16, 4);
  value.callee_function_index = get(20, 4);
  value.resolution = get(24, 4);
  value.sample_index = get(28, 4);
  std::copy(bytes.begin() + 32, bytes.end(), value.reserved.begin());
  return true;
}
[[nodiscard]] inline bool IsValidWasmIndirectObservation(const EventRecord& event) noexcept {
  constexpr std::uint32_t kLimit = 16U * 1024U * 1024U;
  WasmIndirectObservationPayload value;
  return event.header.protocol_version == kEventProtocolVersion &&
         event.header.category == EventCategory::kVm &&
         event.header.type == EventType::kWasmIndirectObservation &&
         event.header.payload_size == 128 && event.header.flags == 0 &&
         event.header.session_id != 0 && event.header.sequence_number != 0 &&
         event.header.process_id != 0 && event.header.thread_id != 0 &&
         event.header.monotonic_time_ns != 0 && event.header.frame_id != 0 &&
         event.header.artifact_id != 0 && event.header.parent_event_id == 0 &&
         DecodeWasmIndirectObservationPayload(event.inline_payload, value) &&
         value.protocol_version == 1 && value.payload_size == 128 &&
         value.function_index < kLimit && value.table_index < kLimit &&
         value.callee_function_index < kLimit && value.module_byte_offset >= 8 &&
         value.module_byte_offset < kLimit && value.resolution < kWasmIndirectResolutionCount &&
         (value.resolution == static_cast<std::uint32_t>(WasmIndirectResolution::kResolved) ||
          value.callee_function_index == 0) &&
         value.sample_index < 16 &&
         std::all_of(value.reserved.begin(), value.reserved.end(),
                     [](std::byte b) { return b == std::byte{0}; });
}
}  // namespace reb
#endif
