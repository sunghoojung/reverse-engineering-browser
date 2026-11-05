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
#include "reb/js_invocation.hpp"
namespace reb {
// Physical Wasm br_table execution, not an interpreter guest program counter.
// Version 2 records the JavaScript invocation context the instruction ran in
// (protocol/native-js-invocation-v1.md); version 1 reserved those bytes and
// still decodes, as state not_observed.
struct WasmDispatchObservationPayload final {
  std::uint16_t protocol_version = 2;
  std::uint16_t payload_size = 128;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t selector = 0;
  std::uint32_t table_count = 0;
  std::uint32_t sample_index = 0;
  std::uint8_t js_invocation_state = 0;
  std::array<std::byte, 3> js_invocation_reserved{};
  std::uint32_t js_invocation_id = 0;
  std::array<std::byte, 96> reserved{};
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
static_assert(offsetof(WasmDispatchObservationPayload, js_invocation_state) == 24);
static_assert(offsetof(WasmDispatchObservationPayload, js_invocation_id) == 28);
static_assert(offsetof(WasmDispatchObservationPayload, reserved) == 32);
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
  put(24, value.js_invocation_state, 1);
  std::copy(value.js_invocation_reserved.begin(), value.js_invocation_reserved.end(),
            out.begin() + 25);
  put(28, value.js_invocation_id, 4);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 32);
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
  value.js_invocation_state = static_cast<std::uint8_t>(get(24, 1));
  std::copy(bytes.begin() + 25, bytes.begin() + 28, value.js_invocation_reserved.begin());
  value.js_invocation_id = get(28, 4);
  std::copy(bytes.begin() + 32, bytes.end(), value.reserved.begin());
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
         (value.protocol_version == 1 || value.protocol_version == 2) &&
         value.payload_size == 128 && value.function_index < 16U * 1024U * 1024U &&
         value.table_count < 16U * 1024U * 1024U && value.module_byte_offset >= 8 &&
         value.module_byte_offset < 16U * 1024U * 1024U && value.sample_index < 16 &&
         // Version 1 reserved the context bytes, so it can only be not_observed.
         (value.protocol_version == 2 ||
          (value.js_invocation_state == 0 && value.js_invocation_id == 0)) &&
         IsValidJsInvocationContext(value.js_invocation_state, value.js_invocation_id) &&
         std::all_of(value.js_invocation_reserved.begin(), value.js_invocation_reserved.end(),
                     [](std::byte b) { return b == std::byte{0}; }) &&
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
// Version 2 adds the JavaScript invocation context, as for br_table.
struct WasmIndirectObservationPayload final {
  std::uint16_t protocol_version = 2;
  std::uint16_t payload_size = 128;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t table_index = 0;
  std::uint32_t slot = 0;
  std::uint32_t callee_function_index = 0;
  std::uint32_t resolution = 0;
  std::uint32_t sample_index = 0;
  std::uint8_t js_invocation_state = 0;
  std::array<std::byte, 3> js_invocation_reserved{};
  std::uint32_t js_invocation_id = 0;
  std::array<std::byte, 88> reserved{};
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
static_assert(offsetof(WasmIndirectObservationPayload, js_invocation_state) == 32);
static_assert(offsetof(WasmIndirectObservationPayload, js_invocation_id) == 36);
static_assert(offsetof(WasmIndirectObservationPayload, reserved) == 40);
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
  put(32, value.js_invocation_state, 1);
  std::copy(value.js_invocation_reserved.begin(), value.js_invocation_reserved.end(),
            out.begin() + 33);
  put(36, value.js_invocation_id, 4);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 40);
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
  value.js_invocation_state = static_cast<std::uint8_t>(get(32, 1));
  std::copy(bytes.begin() + 33, bytes.begin() + 36, value.js_invocation_reserved.begin());
  value.js_invocation_id = get(36, 4);
  std::copy(bytes.begin() + 40, bytes.end(), value.reserved.begin());
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
         (value.protocol_version == 1 || value.protocol_version == 2) &&
         value.payload_size == 128 &&
         (value.protocol_version == 2 ||
          (value.js_invocation_state == 0 && value.js_invocation_id == 0)) &&
         IsValidJsInvocationContext(value.js_invocation_state, value.js_invocation_id) &&
         std::all_of(value.js_invocation_reserved.begin(), value.js_invocation_reserved.end(),
                     [](std::byte b) { return b == std::byte{0}; }) &&
         value.function_index < kLimit && value.table_index < kLimit &&
         value.callee_function_index < kLimit && value.module_byte_offset >= 8 &&
         value.module_byte_offset < kLimit && value.resolution < kWasmIndirectResolutionCount &&
         (value.resolution == static_cast<std::uint32_t>(WasmIndirectResolution::kResolved) ||
          value.callee_function_index == 0) &&
         value.sample_index < 16 &&
         std::all_of(value.reserved.begin(), value.reserved.end(),
                     [](std::byte b) { return b == std::byte{0}; });
}
// Compact identity for a br_table execution that did not receive one of the 16
// full observations. Version 1. This is not an observation and has no parent.
inline constexpr std::uint8_t kWasmOverflowKindIdentity = 1;
inline constexpr std::uint8_t kWasmOverflowKindOmitted = 2;
inline constexpr std::size_t kWasmOverflowRingLimit = 32;
inline constexpr std::uint32_t kWasmOverflowFieldLimit = 16U * 1024U * 1024U;
struct WasmDispatchOverflowPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 32;
  std::uint8_t kind = kWasmOverflowKindIdentity;
  std::uint8_t reserved0 = 0;
  std::uint16_t ring_index = 0;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t selector = 0;
  std::uint32_t arm_count = 0;
  std::uint32_t omitted_count = 0;
  std::uint32_t reserved1 = 0;
};
static_assert(sizeof(WasmDispatchOverflowPayload) == 32);
static_assert(std::is_standard_layout_v<WasmDispatchOverflowPayload>);
static_assert(std::is_trivially_copyable_v<WasmDispatchOverflowPayload>);
static_assert(offsetof(WasmDispatchOverflowPayload, protocol_version) == 0);
static_assert(offsetof(WasmDispatchOverflowPayload, payload_size) == 2);
static_assert(offsetof(WasmDispatchOverflowPayload, kind) == 4);
static_assert(offsetof(WasmDispatchOverflowPayload, reserved0) == 5);
static_assert(offsetof(WasmDispatchOverflowPayload, ring_index) == 6);
static_assert(offsetof(WasmDispatchOverflowPayload, function_index) == 8);
static_assert(offsetof(WasmDispatchOverflowPayload, module_byte_offset) == 12);
static_assert(offsetof(WasmDispatchOverflowPayload, selector) == 16);
static_assert(offsetof(WasmDispatchOverflowPayload, arm_count) == 20);
static_assert(offsetof(WasmDispatchOverflowPayload, omitted_count) == 24);
static_assert(offsetof(WasmDispatchOverflowPayload, reserved1) == 28);
[[nodiscard]] inline std::array<std::byte, 32> EncodeWasmDispatchOverflowPayload(
    const WasmDispatchOverflowPayload& value) noexcept {
  std::array<std::byte, 32> out{};
  const auto put = [&out](std::size_t offset, std::uint64_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
      out[offset + i] = static_cast<std::byte>((v >> (8U * i)) & 255U);
  };
  put(0, value.protocol_version, 2);
  put(2, value.payload_size, 2);
  put(4, value.kind, 1);
  put(5, value.reserved0, 1);
  put(6, value.ring_index, 2);
  put(8, value.function_index, 4);
  put(12, value.module_byte_offset, 4);
  put(16, value.selector, 4);
  put(20, value.arm_count, 4);
  put(24, value.omitted_count, 4);
  put(28, value.reserved1, 4);
  return out;
}
[[nodiscard]] inline bool DecodeWasmDispatchOverflowPayload(
    std::span<const std::byte> bytes,
    WasmDispatchOverflowPayload& value) noexcept {
  if (bytes.size() != 32)
    return false;
  const auto get = [bytes](std::size_t offset, std::size_t width) {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < width; ++i)
      v |= std::to_integer<std::uint32_t>(bytes[offset + i]) << (8U * i);
    return v;
  };
  value.protocol_version = static_cast<std::uint16_t>(get(0, 2));
  value.payload_size = static_cast<std::uint16_t>(get(2, 2));
  value.kind = static_cast<std::uint8_t>(get(4, 1));
  value.reserved0 = static_cast<std::uint8_t>(get(5, 1));
  value.ring_index = static_cast<std::uint16_t>(get(6, 2));
  value.function_index = get(8, 4);
  value.module_byte_offset = get(12, 4);
  value.selector = get(16, 4);
  value.arm_count = get(20, 4);
  value.omitted_count = get(24, 4);
  value.reserved1 = get(28, 4);
  return true;
}
// Compact identity for a call_indirect execution past the 16-record cap.
// The callee index stays on the full observation only.
struct WasmIndirectOverflowPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 40;
  std::uint8_t kind = kWasmOverflowKindIdentity;
  std::uint8_t reserved0 = 0;
  std::uint16_t ring_index = 0;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t table_index = 0;
  std::uint32_t slot = 0;
  std::uint32_t resolution = 0;
  std::uint32_t omitted_count = 0;
  std::uint64_t reserved1 = 0;
};
static_assert(sizeof(WasmIndirectOverflowPayload) == 40);
static_assert(std::is_standard_layout_v<WasmIndirectOverflowPayload>);
static_assert(std::is_trivially_copyable_v<WasmIndirectOverflowPayload>);
static_assert(offsetof(WasmIndirectOverflowPayload, protocol_version) == 0);
static_assert(offsetof(WasmIndirectOverflowPayload, payload_size) == 2);
static_assert(offsetof(WasmIndirectOverflowPayload, kind) == 4);
static_assert(offsetof(WasmIndirectOverflowPayload, reserved0) == 5);
static_assert(offsetof(WasmIndirectOverflowPayload, ring_index) == 6);
static_assert(offsetof(WasmIndirectOverflowPayload, function_index) == 8);
static_assert(offsetof(WasmIndirectOverflowPayload, module_byte_offset) == 12);
static_assert(offsetof(WasmIndirectOverflowPayload, table_index) == 16);
static_assert(offsetof(WasmIndirectOverflowPayload, slot) == 20);
static_assert(offsetof(WasmIndirectOverflowPayload, resolution) == 24);
static_assert(offsetof(WasmIndirectOverflowPayload, omitted_count) == 28);
static_assert(offsetof(WasmIndirectOverflowPayload, reserved1) == 32);
[[nodiscard]] inline std::array<std::byte, 40> EncodeWasmIndirectOverflowPayload(
    const WasmIndirectOverflowPayload& value) noexcept {
  std::array<std::byte, 40> out{};
  const auto put = [&out](std::size_t offset, std::uint64_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
      out[offset + i] = static_cast<std::byte>((v >> (8U * i)) & 255U);
  };
  put(0, value.protocol_version, 2);
  put(2, value.payload_size, 2);
  put(4, value.kind, 1);
  put(5, value.reserved0, 1);
  put(6, value.ring_index, 2);
  put(8, value.function_index, 4);
  put(12, value.module_byte_offset, 4);
  put(16, value.table_index, 4);
  put(20, value.slot, 4);
  put(24, value.resolution, 4);
  put(28, value.omitted_count, 4);
  put(32, value.reserved1, 8);
  return out;
}
[[nodiscard]] inline bool DecodeWasmIndirectOverflowPayload(
    std::span<const std::byte> bytes,
    WasmIndirectOverflowPayload& value) noexcept {
  if (bytes.size() != 40)
    return false;
  const auto get = [bytes](std::size_t offset, std::size_t width) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < width; ++i)
      v |= static_cast<std::uint64_t>(std::to_integer<std::uint32_t>(bytes[offset + i]))
           << (8U * i);
    return v;
  };
  value.protocol_version = static_cast<std::uint16_t>(get(0, 2));
  value.payload_size = static_cast<std::uint16_t>(get(2, 2));
  value.kind = static_cast<std::uint8_t>(get(4, 1));
  value.reserved0 = static_cast<std::uint8_t>(get(5, 1));
  value.ring_index = static_cast<std::uint16_t>(get(6, 2));
  value.function_index = static_cast<std::uint32_t>(get(8, 4));
  value.module_byte_offset = static_cast<std::uint32_t>(get(12, 4));
  value.table_index = static_cast<std::uint32_t>(get(16, 4));
  value.slot = static_cast<std::uint32_t>(get(20, 4));
  value.resolution = static_cast<std::uint32_t>(get(24, 4));
  value.omitted_count = static_cast<std::uint32_t>(get(28, 4));
  value.reserved1 = get(32, 8);
  return true;
}
[[nodiscard]] inline bool OverflowTailIsZero(const EventRecord& event,
                                             const std::uint32_t payload_size) noexcept {
  if (payload_size > event.inline_payload.size())
    return false;
  return std::all_of(event.inline_payload.begin() + payload_size, event.inline_payload.end(),
                     [](std::byte b) { return b == std::byte{0}; });
}
[[nodiscard]] inline bool IsValidWasmDispatchOverflow(const EventRecord& event) noexcept {
  WasmDispatchOverflowPayload value;
  const bool envelope =
      event.header.protocol_version == kEventProtocolVersion &&
      event.header.category == EventCategory::kVm &&
      event.header.type == EventType::kWasmDispatchOverflow && event.header.payload_size == 32 &&
      event.header.flags == 0 && event.header.session_id != 0 &&
      event.header.sequence_number != 0 && event.header.process_id != 0 &&
      event.header.thread_id != 0 && event.header.monotonic_time_ns != 0 &&
      event.header.frame_id != 0 && event.header.parent_event_id == 0 &&
      DecodeWasmDispatchOverflowPayload(std::span(event.inline_payload).first(32), value) &&
      OverflowTailIsZero(event, 32) && value.protocol_version == 1 && value.payload_size == 32 &&
      value.reserved0 == 0 && value.reserved1 == 0;
  if (!envelope)
    return false;
  if (value.kind == kWasmOverflowKindIdentity) {
    return value.omitted_count == 0 && value.ring_index < kWasmOverflowRingLimit &&
           value.function_index < kWasmOverflowFieldLimit &&
           value.arm_count < kWasmOverflowFieldLimit && value.module_byte_offset >= 8 &&
           value.module_byte_offset < kWasmOverflowFieldLimit;
  }
  return value.kind == kWasmOverflowKindOmitted && value.ring_index == 0 &&
         value.function_index == 0 && value.module_byte_offset == 0 && value.selector == 0 &&
         value.arm_count == 0 && value.omitted_count >= 1;
}
[[nodiscard]] inline bool IsValidWasmIndirectOverflow(const EventRecord& event) noexcept {
  WasmIndirectOverflowPayload value;
  const bool envelope =
      event.header.protocol_version == kEventProtocolVersion &&
      event.header.category == EventCategory::kVm &&
      event.header.type == EventType::kWasmIndirectOverflow && event.header.payload_size == 40 &&
      event.header.flags == 0 && event.header.session_id != 0 &&
      event.header.sequence_number != 0 && event.header.process_id != 0 &&
      event.header.thread_id != 0 && event.header.monotonic_time_ns != 0 &&
      event.header.frame_id != 0 && event.header.parent_event_id == 0 &&
      DecodeWasmIndirectOverflowPayload(std::span(event.inline_payload).first(40), value) &&
      OverflowTailIsZero(event, 40) && value.protocol_version == 1 && value.payload_size == 40 &&
      value.reserved0 == 0 && value.reserved1 == 0;
  if (!envelope)
    return false;
  if (value.kind == kWasmOverflowKindIdentity) {
    return value.omitted_count == 0 && value.ring_index < kWasmOverflowRingLimit &&
           value.function_index < kWasmOverflowFieldLimit &&
           value.table_index < kWasmOverflowFieldLimit && value.module_byte_offset >= 8 &&
           value.module_byte_offset < kWasmOverflowFieldLimit &&
           value.resolution < kWasmIndirectResolutionCount;
  }
  return value.kind == kWasmOverflowKindOmitted && value.ring_index == 0 &&
         value.function_index == 0 && value.module_byte_offset == 0 && value.table_index == 0 &&
         value.slot == 0 && value.resolution == 0 && value.omitted_count >= 1;
}
}  // namespace reb
#endif
