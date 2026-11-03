// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_INVOCATION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_JS_INVOCATION_H_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include "native_probe_event.h"
namespace reb {
// Native JavaScript invocation identity, see
// protocol/native-js-invocation-v1.md. The renderer copies no argument,
// receiver, return or exception content: values keep only a kind, integer and
// boolean low bits, a length and, under sensitive capture, a digest.
inline constexpr std::size_t kNativeJsInvocationSiteLimit = 8;
inline constexpr std::size_t kNativeJsInvocationSampleBudget = 256;
inline constexpr std::size_t kNativeJsInvocationSiteSampleBudget = 64;
inline constexpr std::size_t kNativeJsInvocationRequestBudget = 256;
inline constexpr std::size_t kNativeJsInvocationArgumentLimit = 8;
inline constexpr std::size_t kNativeJsInvocationSiteRecordSize = 44;
inline constexpr std::size_t kNativeJsInvocationSitesFileLimit = 4096;
inline constexpr std::size_t kNativeJsInvocationPayloadSize = 128;
inline constexpr std::uint32_t kNativeJsInvocationDigestByteLimit = 1U << 20U;
// The site record's shape byte. Dispatch sites use 1 and 2.
inline constexpr std::uint8_t kNativeJsInvocationFunctionEntryShape = 3;

enum class NativeJsInvocationValueKind : std::uint8_t {
  kInteger = 1,
  kNumber = 2,
  kString = 3,
  kSymbol = 4,
  kUndefined = 5,
  kNull = 6,
  kBoolean = 7,
  kBigInt = 8,
  kObject = 9,
  kFunction = 10,
  kArray = 11,
  kArrayBuffer = 12,
  kArrayBufferView = 13,
  kPromise = 14,
};
inline constexpr std::uint8_t kNativeJsInvocationValueKindLimit = 14;

enum class NativeJsInvocationContextState : std::uint8_t {
  kNotObserved = 0,
  kNone = 1,
  kInside = 2,
  kUnknown = 3,
};
enum class NativeJsInvocationOutcome : std::uint8_t { kFulfilled = 1, kRejected = 2 };
enum class NativeJsInvocationSettleVia : std::uint8_t {
  kSyncReturn = 1,
  kSyncThrow = 2,
  kPromise = 3,
};
enum class NativeJsInvocationDigestState : std::uint8_t {
  kNotRequested = 0,
  kPresent = 1,
  kNotDigestible = 2,
  kTooLarge = 3,
  kUnavailable = 4,
};
enum class NativeJsInvocationDigestEncoding : std::uint8_t { kNone = 0, kUtf8 = 1, kBytes = 2 };
enum class NativeJsInvocationSiteStatus : std::uint8_t {
  kCompiledBeforeArming = 1,
  kUnsupportedFunction = 2,
};

inline constexpr std::uint8_t kNativeJsInvocationParentUnknown = 1U << 0U;
inline constexpr std::uint8_t kNativeJsInvocationArgumentsTruncated = 1U << 1U;
inline constexpr std::uint8_t kNativeJsInvocationStartFlagMask = 0x03U;
inline constexpr std::uint8_t kNativeJsInvocationLossyUtf8 = 1U << 0U;

inline constexpr std::uint64_t kNativeJsInvocationRollingBase = 0x100000001b3ULL;
[[nodiscard]] constexpr std::uint64_t NativeJsInvocationRollingHash(
    std::span<const std::uint8_t> bytes) noexcept {
  std::uint64_t hash = 0;
  for (const std::uint8_t value : bytes)
    hash = hash * kNativeJsInvocationRollingBase + value;
  return hash;
}

[[nodiscard]] constexpr bool IsValidNativeJsInvocationContext(
    std::uint8_t state,
    std::uint32_t invocation_id) noexcept {
  return state <= static_cast<std::uint8_t>(NativeJsInvocationContextState::kUnknown) &&
         ((state == static_cast<std::uint8_t>(NativeJsInvocationContextState::kInside)) ==
          (invocation_id != 0));
}

// The invocation the running code belongs to, as Blink reads it from V8, and
// whether any script is on the stack (a loader start outside script cannot be
// attributed).
struct NativeJsInvocationContext final {
  std::uint8_t state = 0;
  std::uint32_t invocation_id = 0;
  bool script_on_stack = false;
};
using NativeJsInvocationContextProvider = NativeJsInvocationContext (*)() noexcept;

// One armed function-entry site, keyed exactly like a dispatch site: SHA-256
// over the script text as UTF-16LE code units, its UTF-16 length, and the
// UTF-16 offset of the function's V8 start position.
struct NativeJsInvocationSite final {
  std::array<std::uint8_t, 32> source_sha256{};
  std::uint32_t source_length = 0;
  std::uint32_t anchor_offset = 0;
  friend bool operator==(const NativeJsInvocationSite&, const NativeJsInvocationSite&) = default;
};

[[nodiscard]] constexpr bool IsValidNativeJsInvocationSite(
    const NativeJsInvocationSite& site) noexcept {
  return site.source_length != 0 && site.anchor_offset < site.source_length;
}

namespace native_js_invocation_detail {
inline void Put(std::span<std::byte> out,
                std::size_t offset,
                std::uint64_t value,
                std::size_t width) noexcept {
  for (std::size_t i = 0; i < width; ++i)
    out[offset + i] = static_cast<std::byte>((value >> (8U * i)) & 255U);
}
[[nodiscard]] inline std::uint64_t Get(std::span<const std::byte> in,
                                       std::size_t offset,
                                       std::size_t width) noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i)
    value |= std::to_integer<std::uint64_t>(in[offset + i]) << (8U * i);
  return value;
}
template <std::size_t N>
[[nodiscard]] constexpr bool AllZero(const std::array<std::byte, N>& bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::byte b) { return b == std::byte{0}; });
}
template <std::size_t N>
[[nodiscard]] constexpr bool AllZero(const std::array<std::uint8_t, N>& bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
}
[[nodiscard]] constexpr bool ValidKind(std::uint8_t kind) noexcept {
  return kind >= 1 && kind <= kNativeJsInvocationValueKindLimit;
}
[[nodiscard]] constexpr bool ValidLowBits(std::uint8_t kind, std::uint32_t low32) noexcept {
  return kind == static_cast<std::uint8_t>(NativeJsInvocationValueKind::kInteger) ||
         (kind == static_cast<std::uint8_t>(NativeJsInvocationValueKind::kBoolean) ? low32 <= 1
                                                                                     : low32 == 0);
}
[[nodiscard]] constexpr bool Envelope(const NativeProbeHeader& header,
                                      NativeProbeType type) noexcept {
  return header.protocol_version == kNativeProbeProtocolVersion &&
         header.header_size == sizeof(NativeProbeHeader) &&
         header.category == NativeProbeCategory::kVm && header.type == type &&
         header.payload_size == kNativeJsInvocationPayloadSize && header.flags == 0 &&
         header.session_id != 0 && header.sequence_number != 0 && header.monotonic_time_ns != 0 &&
         header.process_id != 0 && header.thread_id != 0 && header.artifact_id == 0 &&
         header.parent_event_id == 0 && header.navigation_id == 0;
}
}  // namespace native_js_invocation_detail

struct NativeJsInvocationStartPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint8_t site_slot = 0;
  std::uint8_t flags = 0;
  std::uint16_t argument_count = 0;
  std::uint32_t script_id = 0;
  std::uint32_t anchor_offset = 0;
  std::uint32_t source_length = 0;
  std::uint32_t invocation_id = 0;
  std::uint32_t parent_invocation_id = 0;
  std::uint16_t site_sample_index = 0;
  std::uint16_t sample_index = 0;
  std::array<std::uint8_t, kNativeJsInvocationArgumentLimit> argument_kinds{};
  std::array<std::uint32_t, kNativeJsInvocationArgumentLimit> argument_low32{};
  std::array<std::uint8_t, 32> source_sha256{};
  // Stable 64-bit digest of Blink's DocumentToken: the document (navigation)
  // the call ran in.
  std::uint64_t document_id = 0;
  std::array<std::byte, 16> reserved{};
};
static_assert(sizeof(NativeJsInvocationStartPayload) == 128);
static_assert(std::is_standard_layout_v<NativeJsInvocationStartPayload>);
static_assert(std::is_trivially_copyable_v<NativeJsInvocationStartPayload>);
static_assert(std::has_unique_object_representations_v<NativeJsInvocationStartPayload>);
static_assert(offsetof(NativeJsInvocationStartPayload, argument_count) == 6);
static_assert(offsetof(NativeJsInvocationStartPayload, invocation_id) == 20);
static_assert(offsetof(NativeJsInvocationStartPayload, argument_kinds) == 32);
static_assert(offsetof(NativeJsInvocationStartPayload, argument_low32) == 40);
static_assert(offsetof(NativeJsInvocationStartPayload, source_sha256) == 72);
static_assert(offsetof(NativeJsInvocationStartPayload, document_id) == 104);
static_assert(offsetof(NativeJsInvocationStartPayload, reserved) == 112);

[[nodiscard]] constexpr bool IsValidNativeJsInvocationStartPayload(
    const NativeJsInvocationStartPayload& value) noexcept {
  using native_js_invocation_detail::ValidKind;
  using native_js_invocation_detail::ValidLowBits;
  if (value.protocol_version != 1 || value.payload_size != 128 ||
      value.site_slot >= kNativeJsInvocationSiteLimit ||
      (value.flags & ~kNativeJsInvocationStartFlagMask) != 0 || value.script_id == 0 ||
      value.source_length == 0 || value.anchor_offset >= value.source_length ||
      value.invocation_id == 0 || value.site_sample_index >= kNativeJsInvocationSiteSampleBudget ||
      value.sample_index >= kNativeJsInvocationSampleBudget || value.document_id == 0)
    return false;
  if (value.parent_invocation_id != 0 &&
      (value.parent_invocation_id >= value.invocation_id ||
       (value.flags & kNativeJsInvocationParentUnknown) != 0))
    return false;
  if (((value.flags & kNativeJsInvocationArgumentsTruncated) != 0) !=
      (value.argument_count > kNativeJsInvocationArgumentLimit))
    return false;
  for (std::size_t i = 0; i < kNativeJsInvocationArgumentLimit; ++i) {
    const std::uint8_t kind = value.argument_kinds[i];
    if (i < value.argument_count) {
      if (!ValidKind(kind) || !ValidLowBits(kind, value.argument_low32[i]))
        return false;
    } else if (kind != 0 || value.argument_low32[i] != 0) {
      return false;
    }
  }
  return native_js_invocation_detail::AllZero(value.reserved);
}

[[nodiscard]] inline std::array<std::byte, 128> EncodeNativeJsInvocationStartPayload(
    const NativeJsInvocationStartPayload& value) noexcept {
  using native_js_invocation_detail::Put;
  std::array<std::byte, 128> out{};
  Put(out, 0, value.protocol_version, 2);
  Put(out, 2, value.payload_size, 2);
  Put(out, 4, value.site_slot, 1);
  Put(out, 5, value.flags, 1);
  Put(out, 6, value.argument_count, 2);
  Put(out, 8, value.script_id, 4);
  Put(out, 12, value.anchor_offset, 4);
  Put(out, 16, value.source_length, 4);
  Put(out, 20, value.invocation_id, 4);
  Put(out, 24, value.parent_invocation_id, 4);
  Put(out, 28, value.site_sample_index, 2);
  Put(out, 30, value.sample_index, 2);
  for (std::size_t i = 0; i < kNativeJsInvocationArgumentLimit; ++i) {
    Put(out, 32 + i, value.argument_kinds[i], 1);
    Put(out, 40 + 4 * i, value.argument_low32[i], 4);
  }
  for (std::size_t i = 0; i < value.source_sha256.size(); ++i)
    out[72 + i] = static_cast<std::byte>(value.source_sha256[i]);
  Put(out, 104, value.document_id, 8);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 112);
  return out;
}

struct NativeJsInvocationSettlePayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint8_t site_slot = 0;
  std::uint8_t outcome = 0;
  std::uint8_t via = 0;
  std::uint8_t value_kind = 0;
  std::uint32_t invocation_id = 0;
  std::uint32_t value_length = 0;
  std::uint8_t digest_state = 0;
  std::uint8_t digest_encoding = 0;
  std::uint8_t flags = 0;
  std::uint8_t reserved0 = 0;
  std::uint32_t digest_byte_length = 0;
  std::uint64_t rolling_hash = 0;
  std::array<std::uint8_t, 32> value_sha256{};
  std::uint64_t document_id = 0;
  std::array<std::byte, 56> reserved{};
};
static_assert(sizeof(NativeJsInvocationSettlePayload) == 128);
static_assert(std::is_standard_layout_v<NativeJsInvocationSettlePayload>);
static_assert(std::is_trivially_copyable_v<NativeJsInvocationSettlePayload>);
static_assert(std::has_unique_object_representations_v<NativeJsInvocationSettlePayload>);
static_assert(offsetof(NativeJsInvocationSettlePayload, invocation_id) == 8);
static_assert(offsetof(NativeJsInvocationSettlePayload, digest_state) == 16);
static_assert(offsetof(NativeJsInvocationSettlePayload, digest_byte_length) == 20);
static_assert(offsetof(NativeJsInvocationSettlePayload, rolling_hash) == 24);
static_assert(offsetof(NativeJsInvocationSettlePayload, value_sha256) == 32);
static_assert(offsetof(NativeJsInvocationSettlePayload, document_id) == 64);
static_assert(offsetof(NativeJsInvocationSettlePayload, reserved) == 72);

[[nodiscard]] constexpr bool IsValidNativeJsInvocationSettlePayload(
    const NativeJsInvocationSettlePayload& value) noexcept {
  using Kind = NativeJsInvocationValueKind;
  using State = NativeJsInvocationDigestState;
  using Encoding = NativeJsInvocationDigestEncoding;
  using Via = NativeJsInvocationSettleVia;
  const auto kind = static_cast<Kind>(value.value_kind);
  const bool fulfilled =
      value.outcome == static_cast<std::uint8_t>(NativeJsInvocationOutcome::kFulfilled);
  const bool rejected =
      value.outcome == static_cast<std::uint8_t>(NativeJsInvocationOutcome::kRejected);
  const auto via = static_cast<Via>(value.via);
  if (value.protocol_version != 1 || value.payload_size != 128 ||
      value.site_slot >= kNativeJsInvocationSiteLimit || (!fulfilled && !rejected) ||
      !native_js_invocation_detail::ValidKind(value.value_kind) || value.invocation_id == 0 ||
      value.document_id == 0 || value.reserved0 != 0 ||
      (value.flags & ~kNativeJsInvocationLossyUtf8) != 0)
    return false;
  if (via == Via::kSyncReturn ? !fulfilled
      : via == Via::kSyncThrow ? !rejected
                               : via != Via::kPromise)
    return false;
  const bool string = kind == Kind::kString;
  const bool bytes = kind == Kind::kArrayBuffer || kind == Kind::kArrayBufferView;
  if (value.value_length != 0 && !string && !bytes && kind != Kind::kArray)
    return false;
  const auto state = static_cast<State>(value.digest_state);
  if (state == State::kPresent) {
    const auto encoding = static_cast<Encoding>(value.digest_encoding);
    return fulfilled && value.digest_byte_length <= kNativeJsInvocationDigestByteLimit &&
           (string ? encoding == Encoding::kUtf8 : bytes && encoding == Encoding::kBytes) &&
           (string || (value.flags & kNativeJsInvocationLossyUtf8) == 0) &&
           (!string || value.digest_byte_length >= value.value_length) &&
           (!bytes || value.digest_byte_length == value.value_length) &&
           (value.digest_byte_length != 0 || value.rolling_hash == 0) &&
           native_js_invocation_detail::AllZero(value.reserved);
  }
  if (value.digest_encoding != 0 || value.digest_byte_length != 0 || value.rolling_hash != 0 ||
      value.flags != 0 || !native_js_invocation_detail::AllZero(value.value_sha256))
    return false;
  switch (state) {
    case State::kNotRequested:
      break;
    case State::kNotDigestible:
      if (fulfilled && (string || bytes))
        return false;
      break;
    case State::kTooLarge:
      if (!fulfilled || (!string && !bytes))
        return false;
      break;
    case State::kUnavailable:
      if (!fulfilled || !bytes)
        return false;
      break;
    default:
      return false;
  }
  return native_js_invocation_detail::AllZero(value.reserved);
}

[[nodiscard]] inline std::array<std::byte, 128> EncodeNativeJsInvocationSettlePayload(
    const NativeJsInvocationSettlePayload& value) noexcept {
  using native_js_invocation_detail::Put;
  std::array<std::byte, 128> out{};
  Put(out, 0, value.protocol_version, 2);
  Put(out, 2, value.payload_size, 2);
  Put(out, 4, value.site_slot, 1);
  Put(out, 5, value.outcome, 1);
  Put(out, 6, value.via, 1);
  Put(out, 7, value.value_kind, 1);
  Put(out, 8, value.invocation_id, 4);
  Put(out, 12, value.value_length, 4);
  Put(out, 16, value.digest_state, 1);
  Put(out, 17, value.digest_encoding, 1);
  Put(out, 18, value.flags, 1);
  Put(out, 19, value.reserved0, 1);
  Put(out, 20, value.digest_byte_length, 4);
  Put(out, 24, value.rolling_hash, 8);
  for (std::size_t i = 0; i < value.value_sha256.size(); ++i)
    out[32 + i] = static_cast<std::byte>(value.value_sha256[i]);
  Put(out, 64, value.document_id, 8);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 72);
  return out;
}

struct NativeJsInvocationRequestPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint8_t state = 0;
  std::array<std::byte, 3> reserved0{};
  std::uint32_t invocation_id = 0;
  std::uint16_t sample_index = 0;
  std::uint16_t reserved1 = 0;
  std::array<std::byte, 112> reserved{};
};
static_assert(sizeof(NativeJsInvocationRequestPayload) == 128);
static_assert(std::is_standard_layout_v<NativeJsInvocationRequestPayload>);
static_assert(std::is_trivially_copyable_v<NativeJsInvocationRequestPayload>);
static_assert(std::has_unique_object_representations_v<NativeJsInvocationRequestPayload>);
static_assert(offsetof(NativeJsInvocationRequestPayload, state) == 4);
static_assert(offsetof(NativeJsInvocationRequestPayload, invocation_id) == 8);
static_assert(offsetof(NativeJsInvocationRequestPayload, sample_index) == 12);
static_assert(offsetof(NativeJsInvocationRequestPayload, reserved) == 16);

[[nodiscard]] constexpr bool IsValidNativeJsInvocationRequestPayload(
    const NativeJsInvocationRequestPayload& value) noexcept {
  const bool inside =
      value.state == static_cast<std::uint8_t>(NativeJsInvocationContextState::kInside);
  const bool unknown =
      value.state == static_cast<std::uint8_t>(NativeJsInvocationContextState::kUnknown);
  return value.protocol_version == 1 && value.payload_size == 128 && (inside || unknown) &&
         IsValidNativeJsInvocationContext(value.state, value.invocation_id) &&
         value.sample_index < kNativeJsInvocationRequestBudget && value.reserved1 == 0 &&
         native_js_invocation_detail::AllZero(value.reserved0) &&
         native_js_invocation_detail::AllZero(value.reserved);
}

[[nodiscard]] inline std::array<std::byte, 128> EncodeNativeJsInvocationRequestPayload(
    const NativeJsInvocationRequestPayload& value) noexcept {
  using native_js_invocation_detail::Put;
  std::array<std::byte, 128> out{};
  Put(out, 0, value.protocol_version, 2);
  Put(out, 2, value.payload_size, 2);
  Put(out, 4, value.state, 1);
  std::copy(value.reserved0.begin(), value.reserved0.end(), out.begin() + 5);
  Put(out, 8, value.invocation_id, 4);
  Put(out, 12, value.sample_index, 2);
  Put(out, 14, value.reserved1, 2);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 16);
  return out;
}

// The envelopes the renderer writes; the browser bridge may add tab_id.
[[nodiscard]] constexpr bool IsValidNativeJsInvocationStartHeader(
    const NativeProbeHeader& header) noexcept {
  return native_js_invocation_detail::Envelope(header, NativeProbeType::kJsInvocationStart) &&
         header.frame_id != 0 && header.request_id == 0;
}
[[nodiscard]] constexpr bool IsValidNativeJsInvocationSettleHeader(
    const NativeProbeHeader& header) noexcept {
  return native_js_invocation_detail::Envelope(header, NativeProbeType::kJsInvocationSettle) &&
         header.frame_id != 0 && header.request_id == 0;
}
[[nodiscard]] constexpr bool IsValidNativeJsInvocationRequestHeader(
    const NativeProbeHeader& header) noexcept {
  return native_js_invocation_detail::Envelope(header, NativeProbeType::kJsInvocationRequest) &&
         header.request_id != 0 && header.request_id <= 0xffffffffULL;
}

// Fixed 44-byte renderer site records, the dispatch site layout with shape 3:
// sha256, length, anchor, shape, 3 zero bytes.
[[nodiscard]] inline std::array<std::uint8_t, kNativeJsInvocationSiteRecordSize>
EncodeNativeJsInvocationSite(const NativeJsInvocationSite& site) noexcept {
  std::array<std::uint8_t, kNativeJsInvocationSiteRecordSize> out{};
  std::copy(site.source_sha256.begin(), site.source_sha256.end(), out.begin());
  for (std::size_t i = 0; i < 4; ++i) {
    out[32 + i] = static_cast<std::uint8_t>((site.source_length >> (8U * i)) & 255U);
    out[36 + i] = static_cast<std::uint8_t>((site.anchor_offset >> (8U * i)) & 255U);
  }
  out[40] = kNativeJsInvocationFunctionEntryShape;
  return out;
}

// Decodes 1 to 8 records into out and returns the count, or 0 when any record
// is malformed or a (source_sha256, anchor_offset) key repeats.
[[nodiscard]] inline std::size_t DecodeNativeJsInvocationSites(
    std::span<const std::uint8_t> bytes,
    std::span<NativeJsInvocationSite, kNativeJsInvocationSiteLimit> out) noexcept {
  if (bytes.empty() || bytes.size() % kNativeJsInvocationSiteRecordSize != 0 ||
      bytes.size() / kNativeJsInvocationSiteRecordSize > kNativeJsInvocationSiteLimit)
    return 0;
  const std::size_t count = bytes.size() / kNativeJsInvocationSiteRecordSize;
  for (std::size_t n = 0; n < count; ++n) {
    const auto record =
        bytes.subspan(n * kNativeJsInvocationSiteRecordSize, kNativeJsInvocationSiteRecordSize);
    NativeJsInvocationSite site;
    std::copy(record.begin(), record.begin() + 32, site.source_sha256.begin());
    for (std::size_t i = 0; i < 4; ++i) {
      site.source_length |= static_cast<std::uint32_t>(record[32 + i]) << (8U * i);
      site.anchor_offset |= static_cast<std::uint32_t>(record[36 + i]) << (8U * i);
    }
    if (record[40] != kNativeJsInvocationFunctionEntryShape || record[41] || record[42] ||
        record[43] || !IsValidNativeJsInvocationSite(site))
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
