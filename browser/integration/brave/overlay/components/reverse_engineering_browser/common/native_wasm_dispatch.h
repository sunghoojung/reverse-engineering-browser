// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_DISPATCH_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_DISPATCH_H_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include "native_artifact_header.h"
#include "native_probe_event.h"
namespace reb {
// Physical Wasm br_table execution, not an interpreter guest program counter.
struct NativeWasmDispatchObservationPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t selector = 0;
  std::uint32_t table_count = 0;
  std::uint32_t sample_index = 0;
  std::array<std::byte, 104> reserved{};
};
static_assert(sizeof(NativeWasmDispatchObservationPayload) == 128);
static_assert(std::is_standard_layout_v<NativeWasmDispatchObservationPayload>);
static_assert(std::is_trivially_copyable_v<NativeWasmDispatchObservationPayload>);
static_assert(offsetof(NativeWasmDispatchObservationPayload, protocol_version) == 0);
static_assert(offsetof(NativeWasmDispatchObservationPayload, payload_size) == 2);
static_assert(offsetof(NativeWasmDispatchObservationPayload, function_index) == 4);
static_assert(offsetof(NativeWasmDispatchObservationPayload, module_byte_offset) == 8);
static_assert(offsetof(NativeWasmDispatchObservationPayload, selector) == 12);
static_assert(offsetof(NativeWasmDispatchObservationPayload, table_count) == 16);
static_assert(offsetof(NativeWasmDispatchObservationPayload, sample_index) == 20);
static_assert(offsetof(NativeWasmDispatchObservationPayload, reserved) == 24);
[[nodiscard]] inline std::array<std::byte, 128> EncodeNativeWasmDispatchObservationPayload(
    const NativeWasmDispatchObservationPayload& value) noexcept {
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
inline constexpr std::size_t kNativeWasmDispatchSampleBudget = 16;
struct NativeWasmDispatchObservation final {
  NativeProbeHeader header{};
  std::uint64_t execution_context_id = 0;
  std::uint64_t document_token_high = 0;
  std::uint64_t document_token_low = 0;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t selector = 0;
  std::uint32_t table_count = 0;
  std::uint32_t sample_index = 0;
  std::string_view source_url;
  std::span<const std::uint8_t> module_bytes;
};
// Views are valid only during this call; transport must bound/copy before returning.
using NativeWasmDispatchEmitter = bool (*)(const NativeWasmDispatchObservation&,
                                           std::uint64_t) noexcept;
[[nodiscard]] inline bool IsValidNativeWasmDispatchInput(
    const NativeWasmDispatchObservation& value) noexcept {
  constexpr std::array<std::uint8_t, 8> magic{0, 97, 115, 109, 1, 0, 0, 0};
  const auto bytes = value.module_bytes;
  if (!value.execution_context_id || !value.header.frame_id ||
      !(value.document_token_high || value.document_token_low) || value.source_url.empty() ||
      value.source_url.size() > kNativeArtifactMaxUrlBytes || bytes.size() < magic.size() ||
      bytes.size() > kNativeArtifactMaxContentBytes ||
      !std::equal(magic.begin(), magic.end(), bytes.begin()) || value.module_byte_offset < 8 ||
      value.module_byte_offset >= bytes.size() || bytes[value.module_byte_offset] != 0x0e ||
      value.sample_index >= kNativeWasmDispatchSampleBudget)
    return false;
  // Match V8's immediate, including overflow rejection. This is not a Wasm interpreter.
  std::size_t offset = static_cast<std::size_t>(value.module_byte_offset) + 1;
  std::uint32_t count = 0;
  for (unsigned i = 0; i < 5; ++i) {
    if (offset >= bytes.size())
      return false;
    const auto byte = bytes[offset++];
    if (i == 4 && (byte & 0xf0U))
      return false;
    count |= static_cast<std::uint32_t>(byte & 0x7fU) << (7U * i);
    if (!(byte & 0x80U))
      return count == value.table_count;
  }
  return false;
}
// Physical Wasm call_indirect or return_call_indirect execution. The slot is
// the dynamic table index, not a guest opcode or program counter. Only
// kResolved names a callee in the calling module's function index space.
enum class NativeWasmIndirectResolution : std::uint32_t {
  kResolved = 0,
  kNull = 1,
  kOutOfBounds = 2,
  kForeign = 3,
  kUnresolved = 4,
};
inline constexpr std::uint32_t kNativeWasmIndirectResolutionCount = 5;
struct NativeWasmIndirectObservationPayload final {
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
static_assert(sizeof(NativeWasmIndirectObservationPayload) == 128);
static_assert(std::is_standard_layout_v<NativeWasmIndirectObservationPayload>);
static_assert(std::is_trivially_copyable_v<NativeWasmIndirectObservationPayload>);
static_assert(offsetof(NativeWasmIndirectObservationPayload, protocol_version) == 0);
static_assert(offsetof(NativeWasmIndirectObservationPayload, payload_size) == 2);
static_assert(offsetof(NativeWasmIndirectObservationPayload, function_index) == 4);
static_assert(offsetof(NativeWasmIndirectObservationPayload, module_byte_offset) == 8);
static_assert(offsetof(NativeWasmIndirectObservationPayload, table_index) == 12);
static_assert(offsetof(NativeWasmIndirectObservationPayload, slot) == 16);
static_assert(offsetof(NativeWasmIndirectObservationPayload, callee_function_index) == 20);
static_assert(offsetof(NativeWasmIndirectObservationPayload, resolution) == 24);
static_assert(offsetof(NativeWasmIndirectObservationPayload, sample_index) == 28);
static_assert(offsetof(NativeWasmIndirectObservationPayload, reserved) == 32);
[[nodiscard]] inline std::array<std::byte, 128> EncodeNativeWasmIndirectObservationPayload(
    const NativeWasmIndirectObservationPayload& value) noexcept {
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
// Separate from the br_table budget so neither stream can starve the other.
inline constexpr std::size_t kNativeWasmIndirectSampleBudget = 16;
struct NativeWasmIndirectObservation final {
  NativeProbeHeader header{};
  std::uint64_t execution_context_id = 0;
  std::uint64_t document_token_high = 0;
  std::uint64_t document_token_low = 0;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t table_index = 0;
  std::uint32_t slot = 0;
  std::uint32_t callee_function_index = 0;
  NativeWasmIndirectResolution resolution = NativeWasmIndirectResolution::kUnresolved;
  std::uint32_t sample_index = 0;
  std::string_view source_url;
  std::span<const std::uint8_t> module_bytes;
};
// Views are valid only during this call; transport must bound/copy before returning.
using NativeWasmIndirectEmitter = bool (*)(const NativeWasmIndirectObservation&,
                                           std::uint64_t) noexcept;
// One unsigned LEB128 u32 immediate as V8 decodes it, including overflow rejection.
[[nodiscard]] inline bool ReadNativeWasmU32(std::span<const std::uint8_t> bytes,
                                            std::size_t& offset,
                                            std::uint32_t& value) noexcept {
  value = 0;
  for (unsigned i = 0; i < 5; ++i) {
    if (offset >= bytes.size())
      return false;
    const auto byte = bytes[offset++];
    if (i == 4 && (byte & 0xf0U))
      return false;
    value |= static_cast<std::uint32_t>(byte & 0x7fU) << (7U * i);
    if (!(byte & 0x80U))
      return true;
  }
  return false;
}
[[nodiscard]] inline bool IsValidNativeWasmIndirectInput(
    const NativeWasmIndirectObservation& value) noexcept {
  constexpr std::array<std::uint8_t, 8> magic{0, 97, 115, 109, 1, 0, 0, 0};
  constexpr std::uint32_t kLimit = 16U * 1024U * 1024U;
  const auto bytes = value.module_bytes;
  const auto resolution = static_cast<std::uint32_t>(value.resolution);
  if (!value.execution_context_id || !value.header.frame_id ||
      !(value.document_token_high || value.document_token_low) || value.source_url.empty() ||
      value.source_url.size() > kNativeArtifactMaxUrlBytes || bytes.size() < magic.size() ||
      bytes.size() > kNativeArtifactMaxContentBytes ||
      !std::equal(magic.begin(), magic.end(), bytes.begin()) || value.module_byte_offset < 8 ||
      value.module_byte_offset >= bytes.size() ||
      (bytes[value.module_byte_offset] != 0x11 && bytes[value.module_byte_offset] != 0x13) ||
      value.function_index >= kLimit || value.table_index >= kLimit ||
      resolution >= kNativeWasmIndirectResolutionCount || value.callee_function_index >= kLimit ||
      (value.resolution != NativeWasmIndirectResolution::kResolved &&
       value.callee_function_index != 0) ||
      value.sample_index >= kNativeWasmIndirectSampleBudget)
    return false;
  // Type index, then table index; the observed table must be the immediate's.
  std::size_t offset = static_cast<std::size_t>(value.module_byte_offset) + 1;
  std::uint32_t type_index = 0, table_index = 0;
  return ReadNativeWasmU32(bytes, offset, type_index) &&
         ReadNativeWasmU32(bytes, offset, table_index) && table_index == value.table_index;
}
}  // namespace reb
#endif
