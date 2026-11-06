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
#include "native_js_invocation.h"
#include "native_probe_event.h"
namespace reb {
// Immediate live caller of a br_table. kUnknown is the host, another instance,
// a non-Liftoff frame, or a frame whose code could not be read; the index is
// then 0 and is not function 0. Versions 1 and 2 reserved these bytes (not
// observed).
// include/reb/wasm_dispatch.hpp defines the same values for the portable reader.
#ifndef REB_WASM_DIRECT_CALLER_KIND_DEFINED
#define REB_WASM_DIRECT_CALLER_KIND_DEFINED
inline constexpr std::uint8_t kWasmDirectCallerUnknown = 0;
inline constexpr std::uint8_t kWasmDirectCallerSameInstance = 1;
#endif
// Physical Wasm br_table execution, not an interpreter guest program counter.
// Version 2 adds the JavaScript invocation context the instruction ran in
// (protocol/native-js-invocation-v1.md); version 1 reserved those bytes.
// Version 3 records the direct caller walked from the live stack.
struct NativeWasmDispatchObservationPayload final {
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
  std::uint8_t caller_kind = kWasmDirectCallerUnknown;
  std::array<std::byte, 3> caller_reserved{};
  std::uint32_t caller_function_index = 0;
  std::array<std::byte, 88> reserved{};
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
static_assert(offsetof(NativeWasmDispatchObservationPayload, js_invocation_state) == 24);
static_assert(offsetof(NativeWasmDispatchObservationPayload, js_invocation_id) == 28);
static_assert(offsetof(NativeWasmDispatchObservationPayload, caller_kind) == 32);
static_assert(offsetof(NativeWasmDispatchObservationPayload, caller_function_index) == 36);
static_assert(offsetof(NativeWasmDispatchObservationPayload, reserved) == 40);
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
  put(24, value.js_invocation_state, 1);
  std::copy(value.js_invocation_reserved.begin(), value.js_invocation_reserved.end(),
            out.begin() + 25);
  put(28, value.js_invocation_id, 4);
  put(32, value.caller_kind, 1);
  std::copy(value.caller_reserved.begin(), value.caller_reserved.end(), out.begin() + 33);
  put(36, value.caller_function_index, 4);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 40);
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
  // The current JavaScript invocation, read by the renderer sink.
  std::uint8_t js_invocation_state = 0;
  std::uint32_t js_invocation_id = 0;
  // True only after the runtime walked this activation's stack. False keeps
  // payload version 2: the caller was not observed, which is not kUnknown.
  bool caller_observed = false;
  std::uint8_t caller_kind = kWasmDirectCallerUnknown;
  std::uint32_t caller_function_index = 0;
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
      value.sample_index >= kNativeWasmDispatchSampleBudget ||
      !IsValidNativeJsInvocationContext(value.js_invocation_state, value.js_invocation_id))
    return false;
  // A walked caller is either unknown (index 0, not a function index) or one
  // function of this module. An unwalked record cannot carry either.
  bool caller_ok =
      value.caller_kind == kWasmDirectCallerUnknown && value.caller_function_index == 0;
  if (value.caller_observed) {
    caller_ok = caller_ok || (value.caller_kind == kWasmDirectCallerSameInstance &&
                              value.caller_function_index < 16U * 1024U * 1024U);
  }
  if (!caller_ok)
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
// An execution the Liftoff document hooks did not cover. The gap names that
// scope only: it is not a dispatch observation and carries no function index,
// offset, selector, slot, or sample. Values match the sink's reason tables.
enum class NativeWasmScopeGap : std::uint8_t {
  kWorker = 0,
  kJitless = 1,
  kLeftLiftoff = 2,
  kWorklet = 3,
};
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
static_assert(offsetof(NativeWasmIndirectObservationPayload, js_invocation_state) == 32);
static_assert(offsetof(NativeWasmIndirectObservationPayload, js_invocation_id) == 36);
static_assert(offsetof(NativeWasmIndirectObservationPayload, reserved) == 40);
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
  put(32, value.js_invocation_state, 1);
  std::copy(value.js_invocation_reserved.begin(), value.js_invocation_reserved.end(),
            out.begin() + 33);
  put(36, value.js_invocation_id, 4);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 40);
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
  // The current JavaScript invocation, read by the renderer sink.
  std::uint8_t js_invocation_state = 0;
  std::uint32_t js_invocation_id = 0;
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
      value.sample_index >= kNativeWasmIndirectSampleBudget ||
      !IsValidNativeJsInvocationContext(value.js_invocation_state, value.js_invocation_id))
    return false;
  // Type index, then table index; the observed table must be the immediate's.
  std::size_t offset = static_cast<std::size_t>(value.module_byte_offset) + 1;
  std::uint32_t type_index = 0, table_index = 0;
  return ReadNativeWasmU32(bytes, offset, type_index) &&
         ReadNativeWasmU32(bytes, offset, table_index) && table_index == value.table_index;
}
// Compact identities for executions a function, module, call-site, or stream
// budget refused. Not observations.
inline constexpr std::uint8_t kNativeWasmOverflowKindIdentity = 1;
inline constexpr std::uint8_t kNativeWasmOverflowKindOmitted = 2;
inline constexpr std::size_t kNativeWasmOverflowRingLimit = 32;
struct NativeWasmDispatchOverflowPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 32;
  std::uint8_t kind = kNativeWasmOverflowKindIdentity;
  std::uint8_t reserved0 = 0;
  std::uint16_t ring_index = 0;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t selector = 0;
  std::uint32_t arm_count = 0;
  std::uint32_t omitted_count = 0;
  std::uint32_t reserved1 = 0;
};
static_assert(sizeof(NativeWasmDispatchOverflowPayload) == 32);
static_assert(std::is_standard_layout_v<NativeWasmDispatchOverflowPayload>);
static_assert(std::is_trivially_copyable_v<NativeWasmDispatchOverflowPayload>);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, protocol_version) == 0);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, payload_size) == 2);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, kind) == 4);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, ring_index) == 6);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, function_index) == 8);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, module_byte_offset) == 12);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, selector) == 16);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, arm_count) == 20);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, omitted_count) == 24);
static_assert(offsetof(NativeWasmDispatchOverflowPayload, reserved1) == 28);
[[nodiscard]] inline std::array<std::byte, 32> EncodeNativeWasmDispatchOverflowPayload(
    const NativeWasmDispatchOverflowPayload& value) noexcept {
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
[[nodiscard]] inline bool DecodeNativeWasmDispatchOverflowPayload(
    std::span<const std::byte> bytes,
    NativeWasmDispatchOverflowPayload& value) noexcept {
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
struct NativeWasmIndirectOverflowPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 40;
  std::uint8_t kind = kNativeWasmOverflowKindIdentity;
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
static_assert(sizeof(NativeWasmIndirectOverflowPayload) == 40);
static_assert(std::is_standard_layout_v<NativeWasmIndirectOverflowPayload>);
static_assert(std::is_trivially_copyable_v<NativeWasmIndirectOverflowPayload>);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, protocol_version) == 0);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, payload_size) == 2);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, kind) == 4);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, ring_index) == 6);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, function_index) == 8);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, module_byte_offset) == 12);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, table_index) == 16);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, slot) == 20);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, resolution) == 24);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, omitted_count) == 28);
static_assert(offsetof(NativeWasmIndirectOverflowPayload, reserved1) == 32);
[[nodiscard]] inline std::array<std::byte, 40> EncodeNativeWasmIndirectOverflowPayload(
    const NativeWasmIndirectOverflowPayload& value) noexcept {
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
[[nodiscard]] inline bool DecodeNativeWasmIndirectOverflowPayload(
    std::span<const std::byte> bytes,
    NativeWasmIndirectOverflowPayload& value) noexcept {
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

// Five seconds from host-call entry. A returning call finishes before it.
// Reaching it records that the call is still inside; it does not trap.
inline constexpr std::uint64_t kNativeWasmExecutionDeadlineNs = 5'000'000'000ULL;
// WasmExecutionNudgeDelayNs returns this when this thread has no open call
// waiting on the deadline. Otherwise it returns the remaining time, or 50ms
// when the deadline is already due and still-executing has not been emitted.
inline constexpr std::uint64_t kNativeWasmExecutionNoNudge = ~std::uint64_t{0};
inline constexpr std::size_t kNativeWasmExecutionBudget = 16;
enum class NativeWasmExecutionKind : std::uint8_t { kTrap = 0, kStillExecuting = 1 };
enum class NativeWasmExecutionReason : std::uint8_t {
  kUnknown = 0,
  kSignatureMismatch = 1,
  kUnreachable = 2,
  kOutOfBounds = 3,
  kNullEntry = 4,
  kInterrupt = 5,
};
inline constexpr std::uint8_t kNativeWasmExecutionReasonCount = 6;
enum class NativeWasmExecutionBounds : std::uint8_t {
  kNone = 0,
  kTable = 1,
  kMemory = 2,
  kDataSegment = 3,
  kElementSegment = 4,
  kArray = 5,
  kString = 6,
};
inline constexpr std::uint8_t kNativeWasmExecutionBoundsCount = 7;
inline constexpr std::uint8_t kNativeWasmExecutionFunctionKnown = 1U;
inline constexpr std::uint8_t kNativeWasmExecutionOffsetKnown = 2U;
enum class NativeWasmExecutionStream : std::uint8_t {
  kNone = 0,
  kBrTable = 1,
  kCallIndirect = 2,
};
inline constexpr std::uint32_t kNativeWasmExecutionNoSample = 0xffffffffu;
enum class NativeWasmExecutionHeartbeat : std::uint8_t { kContinue = 0, kInterrupt = 1 };
struct NativeWasmExecutionOutcomePayload final {
  std::uint8_t kind = 0;
  std::uint8_t reason = 0;
  std::uint8_t bounds = 0;
  std::uint8_t known = 0;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t invocation_id = 0;
  std::uint32_t related_sample_index = kNativeWasmExecutionNoSample;
  std::uint8_t related_stream = 0;
  std::uint8_t js_invocation_state = 0;
  std::uint32_t js_invocation_id = 0;
};
[[nodiscard]] inline std::array<std::byte, 128> EncodeNativeWasmExecutionOutcomePayload(
    const NativeWasmExecutionOutcomePayload& value) noexcept {
  std::array<std::byte, 128> out{};
  const auto put = [&out](std::size_t offset, std::uint32_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
      out[offset + i] = static_cast<std::byte>((v >> (8U * i)) & 255U);
  };
  put(0, 1, 2);
  put(2, 128, 2);
  put(4, value.kind, 1);
  put(5, value.reason, 1);
  put(6, value.bounds, 1);
  put(7, value.known, 1);
  put(8, value.function_index, 4);
  put(12, value.module_byte_offset, 4);
  put(16, value.invocation_id, 4);
  put(20, value.related_sample_index, 4);
  put(24, value.related_stream, 1);
  put(28, value.js_invocation_state, 1);
  put(32, value.js_invocation_id, 4);
  return out;
}
struct NativeWasmExecutionObservation final {
  NativeProbeHeader header{};
  std::uint64_t execution_context_id = 0;
  std::uint64_t document_token_high = 0;
  std::uint64_t document_token_low = 0;
  std::uint32_t invocation_id = 0;
  std::uint32_t function_index = 0;
  std::uint32_t module_byte_offset = 0;
  std::uint32_t related_sample_index = kNativeWasmExecutionNoSample;
  NativeWasmExecutionKind kind = NativeWasmExecutionKind::kTrap;
  NativeWasmExecutionReason reason = NativeWasmExecutionReason::kUnknown;
  NativeWasmExecutionBounds bounds = NativeWasmExecutionBounds::kNone;
  std::uint8_t known = 0;
  NativeWasmExecutionStream related_stream = NativeWasmExecutionStream::kNone;
  std::uint8_t js_invocation_state = 0;
  std::uint32_t js_invocation_id = 0;
  std::string_view source_url;
  // Empty when the record has no borrowed module bytes. The browser then
  // attaches the one module already captured for this document, or gaps.
  std::span<const std::uint8_t> module_bytes;
};
using NativeWasmExecutionEmitter = bool (*)(const NativeWasmExecutionObservation&,
                                            std::uint64_t) noexcept;
// Installed by the renderer. Forces the main isolate into its next Wasm
// stack check. It must not call TerminateExecution.
using NativeWasmExecutionNudge = void (*)() noexcept;
[[nodiscard]] inline bool IsValidNativeWasmExecutionInput(
    const NativeWasmExecutionObservation& value) noexcept {
  constexpr std::array<std::uint8_t, 8> magic{0, 97, 115, 109, 1, 0, 0, 0};
  constexpr std::uint32_t kLimit = 16U * 1024U * 1024U;
  const auto bytes = value.module_bytes;
  const auto reason = static_cast<std::uint8_t>(value.reason);
  const auto bounds = static_cast<std::uint8_t>(value.bounds);
  const bool function_known = (value.known & kNativeWasmExecutionFunctionKnown) != 0;
  const bool offset_known = (value.known & kNativeWasmExecutionOffsetKnown) != 0;
  if (!value.execution_context_id || !value.header.frame_id || !value.invocation_id ||
      !(value.document_token_high || value.document_token_low) || value.source_url.empty() ||
      value.source_url.size() > kNativeArtifactMaxUrlBytes || (value.known & ~3U) != 0 ||
      static_cast<std::uint8_t>(value.kind) > 1 ||
      static_cast<std::uint8_t>(value.related_stream) > 2 ||
      !IsValidNativeJsInvocationContext(value.js_invocation_state, value.js_invocation_id))
    return false;
  if (function_known) {
    if (value.function_index >= kLimit)
      return false;
  } else if (value.function_index != 0) {
    return false;
  }
  if (offset_known) {
    if (value.module_byte_offset < 8 || value.module_byte_offset >= kLimit)
      return false;
  } else if (value.module_byte_offset != 0) {
    return false;
  }
  if (!bytes.empty()) {
    if (bytes.size() < magic.size() || bytes.size() > kNativeArtifactMaxContentBytes ||
        !std::equal(magic.begin(), magic.end(), bytes.begin()) ||
        (offset_known && value.module_byte_offset >= bytes.size()))
      return false;
  }
  if (value.kind == NativeWasmExecutionKind::kStillExecuting) {
    if (reason != 0 || bounds != 0)
      return false;
  } else if (reason >= kNativeWasmExecutionReasonCount) {
    return false;
  }
  if (reason == static_cast<std::uint8_t>(NativeWasmExecutionReason::kOutOfBounds)) {
    if (bounds >= kNativeWasmExecutionBoundsCount)
      return false;
  } else if (bounds != 0) {
    return false;
  }
  if (value.related_stream == NativeWasmExecutionStream::kNone)
    return value.related_sample_index == kNativeWasmExecutionNoSample;
  return value.related_sample_index < kNativeWasmIndirectSampleBudget;
}
}  // namespace reb
#endif
