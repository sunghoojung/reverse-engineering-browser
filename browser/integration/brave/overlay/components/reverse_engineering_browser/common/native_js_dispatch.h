// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_DISPATCH_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_DISPATCH_H_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include "native_probe_event.h"
namespace reb {
// Live V8 dispatch at an armed static JavaScript site, see
// protocol/native-js-dispatch-v1.md. The renderer copies no argument,
// receiver or string contents; a selector keeps only its kind and low bits.
inline constexpr std::size_t kNativeJsDispatchSiteLimit = 8;
inline constexpr std::size_t kNativeJsDispatchSampleBudget = 256;
inline constexpr std::size_t kNativeJsDispatchSiteSampleBudget = 64;
inline constexpr std::size_t kNativeJsDispatchSiteRecordSize = 44;
inline constexpr std::size_t kNativeJsDispatchSitesFileLimit = 4096;
inline constexpr std::size_t kNativeJsDispatchPayloadSize = 128;

enum class NativeJsDispatchShape : std::uint8_t { kSwitch = 1, kIndexedCall = 2 };
enum class NativeJsDispatchSelectorKind : std::uint8_t {
  kInteger = 1,
  kNumber = 2,
  kString = 3,
  kSymbol = 4,
  kUndefined = 5,
  kNull = 6,
  kBoolean = 7,
  kBigInt = 8,
  kObject = 9,
};
enum class NativeJsDispatchSiteStatus : std::uint8_t { kCompiledBeforeArming = 1 };

inline constexpr std::uint8_t kNativeJsDispatchNewActivation = 1U << 0U;
inline constexpr std::uint8_t kNativeJsDispatchParentUnknown = 1U << 1U;
inline constexpr std::uint8_t kNativeJsDispatchParentSearchTruncated = 1U << 2U;
inline constexpr std::uint8_t kNativeJsDispatchHandlerSpan = 1U << 3U;
inline constexpr std::uint8_t kNativeJsDispatchFlagMask = 0x0FU;

// One armed site. The key is computed from the exact V8 script text:
// SHA-256 over UTF-16LE code units, the UTF-16 length, and the UTF-16 offset
// of the `switch` keyword or the callee's `[`.
struct NativeJsDispatchSite final {
  std::array<std::uint8_t, 32> source_sha256{};
  std::uint32_t source_length = 0;
  std::uint32_t anchor_offset = 0;
  NativeJsDispatchShape shape = NativeJsDispatchShape::kSwitch;
  friend bool operator==(const NativeJsDispatchSite&, const NativeJsDispatchSite&) = default;
};

[[nodiscard]] constexpr bool IsValidNativeJsDispatchSite(
    const NativeJsDispatchSite& site) noexcept {
  return (site.shape == NativeJsDispatchShape::kSwitch ||
          site.shape == NativeJsDispatchShape::kIndexedCall) &&
         site.source_length != 0 && site.anchor_offset < site.source_length;
}

struct NativeJsDispatchObservationPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint8_t shape = 0;
  std::uint8_t selector_kind = 0;
  std::uint8_t site_slot = 0;
  std::uint8_t flags = 0;
  std::uint32_t script_id = 0;
  std::uint32_t anchor_offset = 0;
  std::uint32_t source_length = 0;
  std::uint32_t selector_low32 = 0;
  std::uint32_t handler_script_id = 0;
  std::uint32_t handler_start = 0;
  std::uint32_t handler_end = 0;
  std::uint32_t activation_id = 0;
  std::uint32_t parent_activation_id = 0;
  std::uint16_t site_sample_index = 0;
  std::uint16_t sample_index = 0;
  std::array<std::uint8_t, 32> source_sha256{};
  std::array<std::byte, 48> reserved{};
};
static_assert(sizeof(NativeJsDispatchObservationPayload) == 128);
static_assert(std::is_standard_layout_v<NativeJsDispatchObservationPayload>);
static_assert(std::is_trivially_copyable_v<NativeJsDispatchObservationPayload>);
static_assert(std::has_unique_object_representations_v<NativeJsDispatchObservationPayload>);
static_assert(offsetof(NativeJsDispatchObservationPayload, protocol_version) == 0);
static_assert(offsetof(NativeJsDispatchObservationPayload, payload_size) == 2);
static_assert(offsetof(NativeJsDispatchObservationPayload, shape) == 4);
static_assert(offsetof(NativeJsDispatchObservationPayload, selector_kind) == 5);
static_assert(offsetof(NativeJsDispatchObservationPayload, site_slot) == 6);
static_assert(offsetof(NativeJsDispatchObservationPayload, flags) == 7);
static_assert(offsetof(NativeJsDispatchObservationPayload, script_id) == 8);
static_assert(offsetof(NativeJsDispatchObservationPayload, anchor_offset) == 12);
static_assert(offsetof(NativeJsDispatchObservationPayload, source_length) == 16);
static_assert(offsetof(NativeJsDispatchObservationPayload, selector_low32) == 20);
static_assert(offsetof(NativeJsDispatchObservationPayload, handler_script_id) == 24);
static_assert(offsetof(NativeJsDispatchObservationPayload, handler_start) == 28);
static_assert(offsetof(NativeJsDispatchObservationPayload, handler_end) == 32);
static_assert(offsetof(NativeJsDispatchObservationPayload, activation_id) == 36);
static_assert(offsetof(NativeJsDispatchObservationPayload, parent_activation_id) == 40);
static_assert(offsetof(NativeJsDispatchObservationPayload, site_sample_index) == 44);
static_assert(offsetof(NativeJsDispatchObservationPayload, sample_index) == 46);
static_assert(offsetof(NativeJsDispatchObservationPayload, source_sha256) == 48);
static_assert(offsetof(NativeJsDispatchObservationPayload, reserved) == 80);

// Every rule of the protocol table. Consistent with the C++ core, Rust and
// JavaScript readers, so a record the renderer emits is never refused later.
[[nodiscard]] constexpr bool IsValidNativeJsDispatchObservationPayload(
    const NativeJsDispatchObservationPayload& value) noexcept {
  if (value.protocol_version != 1 || value.payload_size != 128 ||
      (value.shape != 1 && value.shape != 2) || value.selector_kind < 1 ||
      value.selector_kind > 9 || value.site_slot >= kNativeJsDispatchSiteLimit ||
      (value.flags & ~kNativeJsDispatchFlagMask) != 0 || value.script_id == 0 ||
      value.source_length == 0 || value.anchor_offset >= value.source_length ||
      value.activation_id == 0 || value.site_sample_index >= kNativeJsDispatchSiteSampleBudget ||
      value.sample_index >= kNativeJsDispatchSampleBudget)
    return false;
  const auto kind = static_cast<NativeJsDispatchSelectorKind>(value.selector_kind);
  if (kind == NativeJsDispatchSelectorKind::kBoolean) {
    if (value.selector_low32 > 1)
      return false;
  } else if (kind != NativeJsDispatchSelectorKind::kInteger && value.selector_low32 != 0) {
    return false;
  }
  if ((value.flags & kNativeJsDispatchHandlerSpan) != 0) {
    if (value.shape != static_cast<std::uint8_t>(NativeJsDispatchShape::kIndexedCall) ||
        value.handler_script_id == 0 || value.handler_start >= value.handler_end)
      return false;
  } else if (value.handler_script_id != 0 || value.handler_start != 0 || value.handler_end != 0) {
    return false;
  }
  const bool unknown = (value.flags & kNativeJsDispatchParentUnknown) != 0;
  const bool truncated = (value.flags & kNativeJsDispatchParentSearchTruncated) != 0;
  if ((unknown && truncated) ||
      (value.parent_activation_id != 0 &&
       (unknown || truncated || value.parent_activation_id >= value.activation_id)))
    return false;
  return std::all_of(value.reserved.begin(), value.reserved.end(),
                     [](std::byte byte) { return byte == std::byte{0}; });
}

namespace native_js_dispatch_detail {
inline void Put(std::span<std::byte> out,
                std::size_t offset,
                std::uint32_t value,
                std::size_t width) noexcept {
  for (std::size_t i = 0; i < width; ++i)
    out[offset + i] = static_cast<std::byte>((value >> (8U * i)) & 255U);
}
[[nodiscard]] inline std::uint32_t Get(std::span<const std::byte> in,
                                       std::size_t offset,
                                       std::size_t width) noexcept {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < width; ++i)
    value |= std::to_integer<std::uint32_t>(in[offset + i]) << (8U * i);
  return value;
}
}  // namespace native_js_dispatch_detail

[[nodiscard]] inline std::array<std::byte, 128> EncodeNativeJsDispatchObservationPayload(
    const NativeJsDispatchObservationPayload& value) noexcept {
  using native_js_dispatch_detail::Put;
  std::array<std::byte, 128> out{};
  Put(out, 0, value.protocol_version, 2);
  Put(out, 2, value.payload_size, 2);
  Put(out, 4, value.shape, 1);
  Put(out, 5, value.selector_kind, 1);
  Put(out, 6, value.site_slot, 1);
  Put(out, 7, value.flags, 1);
  Put(out, 8, value.script_id, 4);
  Put(out, 12, value.anchor_offset, 4);
  Put(out, 16, value.source_length, 4);
  Put(out, 20, value.selector_low32, 4);
  Put(out, 24, value.handler_script_id, 4);
  Put(out, 28, value.handler_start, 4);
  Put(out, 32, value.handler_end, 4);
  Put(out, 36, value.activation_id, 4);
  Put(out, 40, value.parent_activation_id, 4);
  Put(out, 44, value.site_sample_index, 2);
  Put(out, 46, value.sample_index, 2);
  for (std::size_t i = 0; i < value.source_sha256.size(); ++i)
    out[48 + i] = static_cast<std::byte>(value.source_sha256[i]);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 80);
  return out;
}

[[nodiscard]] inline bool DecodeNativeJsDispatchObservationPayload(
    std::span<const std::byte> bytes,
    NativeJsDispatchObservationPayload& value) noexcept {
  using native_js_dispatch_detail::Get;
  if (bytes.size() != kNativeJsDispatchPayloadSize)
    return false;
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.shape = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  value.selector_kind = static_cast<std::uint8_t>(Get(bytes, 5, 1));
  value.site_slot = static_cast<std::uint8_t>(Get(bytes, 6, 1));
  value.flags = static_cast<std::uint8_t>(Get(bytes, 7, 1));
  value.script_id = Get(bytes, 8, 4);
  value.anchor_offset = Get(bytes, 12, 4);
  value.source_length = Get(bytes, 16, 4);
  value.selector_low32 = Get(bytes, 20, 4);
  value.handler_script_id = Get(bytes, 24, 4);
  value.handler_start = Get(bytes, 28, 4);
  value.handler_end = Get(bytes, 32, 4);
  value.activation_id = Get(bytes, 36, 4);
  value.parent_activation_id = Get(bytes, 40, 4);
  value.site_sample_index = static_cast<std::uint16_t>(Get(bytes, 44, 2));
  value.sample_index = static_cast<std::uint16_t>(Get(bytes, 46, 2));
  for (std::size_t i = 0; i < value.source_sha256.size(); ++i)
    value.source_sha256[i] = std::to_integer<std::uint8_t>(bytes[48 + i]);
  std::copy(bytes.begin() + 80, bytes.end(), value.reserved.begin());
  return true;
}

// The envelope the renderer writes; the browser bridge may add tab_id.
[[nodiscard]] constexpr bool IsValidNativeJsDispatchHeader(
    const NativeProbeHeader& header) noexcept {
  return header.protocol_version == kNativeProbeProtocolVersion &&
         header.header_size == sizeof(NativeProbeHeader) &&
         header.category == NativeProbeCategory::kVm &&
         header.type == NativeProbeType::kJsDispatchObservation &&
         header.payload_size == kNativeJsDispatchPayloadSize && header.flags == 0 &&
         header.session_id != 0 && header.sequence_number != 0 && header.monotonic_time_ns != 0 &&
         header.process_id != 0 && header.thread_id != 0 && header.frame_id != 0 &&
         header.artifact_id == 0 && header.parent_event_id == 0 && header.navigation_id == 0 &&
         header.request_id == 0;
}

// Fixed 44-byte renderer site records: sha256, length, anchor, shape, 3 zero.
[[nodiscard]] inline std::array<std::uint8_t, kNativeJsDispatchSiteRecordSize>
EncodeNativeJsDispatchSite(const NativeJsDispatchSite& site) noexcept {
  std::array<std::uint8_t, kNativeJsDispatchSiteRecordSize> out{};
  std::copy(site.source_sha256.begin(), site.source_sha256.end(), out.begin());
  for (std::size_t i = 0; i < 4; ++i) {
    out[32 + i] = static_cast<std::uint8_t>((site.source_length >> (8U * i)) & 255U);
    out[36 + i] = static_cast<std::uint8_t>((site.anchor_offset >> (8U * i)) & 255U);
  }
  out[40] = static_cast<std::uint8_t>(site.shape);
  return out;
}

// Decodes 1 to 8 records into out and returns the count, or 0 when any record
// is malformed or a (source_sha256, anchor_offset) key repeats.
[[nodiscard]] inline std::size_t DecodeNativeJsDispatchSites(
    std::span<const std::uint8_t> bytes,
    std::span<NativeJsDispatchSite, kNativeJsDispatchSiteLimit> out) noexcept {
  if (bytes.empty() || bytes.size() % kNativeJsDispatchSiteRecordSize != 0 ||
      bytes.size() / kNativeJsDispatchSiteRecordSize > kNativeJsDispatchSiteLimit)
    return 0;
  const std::size_t count = bytes.size() / kNativeJsDispatchSiteRecordSize;
  for (std::size_t n = 0; n < count; ++n) {
    const auto record =
        bytes.subspan(n * kNativeJsDispatchSiteRecordSize, kNativeJsDispatchSiteRecordSize);
    NativeJsDispatchSite site;
    std::copy(record.begin(), record.begin() + 32, site.source_sha256.begin());
    for (std::size_t i = 0; i < 4; ++i) {
      site.source_length |= static_cast<std::uint32_t>(record[32 + i]) << (8U * i);
      site.anchor_offset |= static_cast<std::uint32_t>(record[36 + i]) << (8U * i);
    }
    if ((record[40] != 1 && record[40] != 2) || record[41] || record[42] || record[43])
      return 0;
    site.shape = static_cast<NativeJsDispatchShape>(record[40]);
    if (!IsValidNativeJsDispatchSite(site))
      return 0;
    for (std::size_t previous = 0; previous < n; ++previous)
      if (out[previous].source_sha256 == site.source_sha256 &&
          out[previous].anchor_offset == site.anchor_offset)
        return 0;
    out[n] = site;
  }
  return count;
}
}  // namespace reb
#endif
