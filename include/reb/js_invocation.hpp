#ifndef REB_JS_INVOCATION_HPP_
#define REB_JS_INVOCATION_HPP_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include "reb/event.hpp"
namespace reb {
// One admitted call of an armed JavaScript function, observed by V8. The site
// is named exactly like a JavaScript dispatch site: source_sha256 over the
// script text as UTF-16LE, source_length and the UTF-16 anchor_offset of the
// function's V8 start position. See protocol/native-js-invocation-v1.md. No
// argument, receiver, return or exception content is part of any record here.
inline constexpr std::size_t kJsInvocationSiteLimit = 8;
inline constexpr std::size_t kJsInvocationSampleBudget = 256;
inline constexpr std::size_t kJsInvocationSiteSampleBudget = 64;
inline constexpr std::size_t kJsInvocationRequestBudget = 256;
inline constexpr std::size_t kJsInvocationArgumentLimit = 8;
// Encoded bytes a settle digest may cover.
inline constexpr std::uint32_t kJsInvocationDigestByteLimit = 1U << 20U;

// Value kinds for arguments and settled values. Only an integer records its
// low 32 bits and only a boolean its 0 or 1; nothing else records content.
enum class JsInvocationValueKind : std::uint8_t {
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
inline constexpr std::uint8_t kJsInvocationValueKindLimit = 14;

// Which invocation context a consumer record was produced in. kNotObserved is
// also what every older payload version means.
enum class JsInvocationContextState : std::uint8_t {
  kNotObserved = 0,
  kNone = 1,
  kInside = 2,
  kUnknown = 3,
};

enum class JsInvocationOutcome : std::uint8_t {
  kFulfilled = 1,
  kRejected = 2,
};

enum class JsInvocationSettleVia : std::uint8_t {
  kSyncReturn = 1,
  kSyncThrow = 2,
  kPromise = 3,
};

enum class JsInvocationDigestState : std::uint8_t {
  kNotRequested = 0,
  kPresent = 1,
  kNotDigestible = 2,
  kTooLarge = 3,
  kUnavailable = 4,
};

enum class JsInvocationDigestEncoding : std::uint8_t {
  kNone = 0,
  kUtf8 = 1,
  kBytes = 2,
};

// Start flag bits. Every other bit must be zero.
inline constexpr std::uint8_t kJsInvocationParentUnknown = 1U << 0U;
inline constexpr std::uint8_t kJsInvocationArgumentsTruncated = 1U << 1U;
inline constexpr std::uint8_t kJsInvocationStartKnownFlags =
    kJsInvocationParentUnknown | kJsInvocationArgumentsTruncated;
// Settle flag bits.
inline constexpr std::uint8_t kJsInvocationLossyUtf8 = 1U << 0U;

// 64-bit polynomial rolling hash over the digested bytes, base 0x100000001b3,
// evaluated as h = h * base + byte modulo 2^64. It only selects candidate
// windows; SHA-256 alone confirms a match.
inline constexpr std::uint64_t kJsInvocationRollingBase = 0x100000001b3ULL;
[[nodiscard]] constexpr std::uint64_t JsInvocationRollingHash(
    std::span<const std::byte> bytes) noexcept {
  std::uint64_t hash = 0;
  for (const std::byte value : bytes)
    hash = hash * kJsInvocationRollingBase + std::to_integer<std::uint64_t>(value);
  return hash;
}

namespace js_invocation_detail {
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
template <std::size_t N>
inline bool AllZero(const std::array<std::byte, N>& bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::byte b) { return b == std::byte{0}; });
}
inline bool Envelope(const EventRecord& event, EventType type) noexcept {
  return event.header.protocol_version == kEventProtocolVersion &&
         event.header.category == EventCategory::kVm && event.header.type == type &&
         event.header.payload_size == 128 && event.header.flags == 0 &&
         event.header.session_id != 0 && event.header.sequence_number != 0 &&
         event.header.process_id != 0 && event.header.thread_id != 0 &&
         event.header.monotonic_time_ns != 0 && event.header.artifact_id == 0 &&
         event.header.parent_event_id == 0 && event.header.navigation_id == 0;
}
inline bool ValidKind(std::uint8_t kind) noexcept {
  return kind >= 1 && kind <= kJsInvocationValueKindLimit;
}
// Integer and boolean values record low bits; every other kind records zero.
inline bool ValidLowBits(std::uint8_t kind, std::uint32_t low32) noexcept {
  if (kind == static_cast<std::uint8_t>(JsInvocationValueKind::kInteger))
    return true;
  if (kind == static_cast<std::uint8_t>(JsInvocationValueKind::kBoolean))
    return low32 <= 1;
  return low32 == 0;
}
}  // namespace js_invocation_detail

[[nodiscard]] constexpr bool IsValidJsInvocationContext(std::uint8_t state,
                                                        std::uint32_t invocation_id) noexcept {
  return state <= static_cast<std::uint8_t>(JsInvocationContextState::kUnknown) &&
         ((state == static_cast<std::uint8_t>(JsInvocationContextState::kInside)) ==
          (invocation_id != 0));
}

struct JsInvocationStartPayload final {
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
  std::array<std::uint8_t, kJsInvocationArgumentLimit> argument_kinds{};
  std::array<std::uint32_t, kJsInvocationArgumentLimit> argument_low32{};
  std::array<std::byte, 32> source_sha256{};
  std::uint64_t document_id = 0;
  std::array<std::byte, 16> reserved{};
};
static_assert(sizeof(JsInvocationStartPayload) == 128);
static_assert(std::is_standard_layout_v<JsInvocationStartPayload>);
static_assert(std::is_trivially_copyable_v<JsInvocationStartPayload>);
static_assert(offsetof(JsInvocationStartPayload, site_slot) == 4);
static_assert(offsetof(JsInvocationStartPayload, flags) == 5);
static_assert(offsetof(JsInvocationStartPayload, argument_count) == 6);
static_assert(offsetof(JsInvocationStartPayload, script_id) == 8);
static_assert(offsetof(JsInvocationStartPayload, anchor_offset) == 12);
static_assert(offsetof(JsInvocationStartPayload, source_length) == 16);
static_assert(offsetof(JsInvocationStartPayload, invocation_id) == 20);
static_assert(offsetof(JsInvocationStartPayload, parent_invocation_id) == 24);
static_assert(offsetof(JsInvocationStartPayload, site_sample_index) == 28);
static_assert(offsetof(JsInvocationStartPayload, sample_index) == 30);
static_assert(offsetof(JsInvocationStartPayload, argument_kinds) == 32);
static_assert(offsetof(JsInvocationStartPayload, argument_low32) == 40);
static_assert(offsetof(JsInvocationStartPayload, source_sha256) == 72);
static_assert(offsetof(JsInvocationStartPayload, document_id) == 104);
static_assert(offsetof(JsInvocationStartPayload, reserved) == 112);

// Explicit little-endian encoding; no native structure padding is serialized.
[[nodiscard]] inline std::array<std::byte, 128> EncodeJsInvocationStartPayload(
    const JsInvocationStartPayload& value) noexcept {
  using js_invocation_detail::Put;
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
  for (std::size_t i = 0; i < kJsInvocationArgumentLimit; ++i) {
    Put(out, 32 + i, value.argument_kinds[i], 1);
    Put(out, 40 + 4 * i, value.argument_low32[i], 4);
  }
  std::copy(value.source_sha256.begin(), value.source_sha256.end(), out.begin() + 72);
  Put(out, 104, value.document_id, 8);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 112);
  return out;
}

[[nodiscard]] inline bool DecodeJsInvocationStartPayload(std::span<const std::byte> bytes,
                                                         JsInvocationStartPayload& value) noexcept {
  using js_invocation_detail::Get;
  if (bytes.size() != 128)
    return false;
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.site_slot = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  value.flags = static_cast<std::uint8_t>(Get(bytes, 5, 1));
  value.argument_count = static_cast<std::uint16_t>(Get(bytes, 6, 2));
  value.script_id = static_cast<std::uint32_t>(Get(bytes, 8, 4));
  value.anchor_offset = static_cast<std::uint32_t>(Get(bytes, 12, 4));
  value.source_length = static_cast<std::uint32_t>(Get(bytes, 16, 4));
  value.invocation_id = static_cast<std::uint32_t>(Get(bytes, 20, 4));
  value.parent_invocation_id = static_cast<std::uint32_t>(Get(bytes, 24, 4));
  value.site_sample_index = static_cast<std::uint16_t>(Get(bytes, 28, 2));
  value.sample_index = static_cast<std::uint16_t>(Get(bytes, 30, 2));
  for (std::size_t i = 0; i < kJsInvocationArgumentLimit; ++i) {
    value.argument_kinds[i] = static_cast<std::uint8_t>(Get(bytes, 32 + i, 1));
    value.argument_low32[i] = static_cast<std::uint32_t>(Get(bytes, 40 + 4 * i, 4));
  }
  std::copy(bytes.begin() + 72, bytes.begin() + 104, value.source_sha256.begin());
  value.document_id = Get(bytes, 104, 8);
  std::copy(bytes.begin() + 112, bytes.end(), value.reserved.begin());
  return true;
}

[[nodiscard]] inline bool IsValidJsInvocationStartPayload(
    const JsInvocationStartPayload& value) noexcept {
  if (value.protocol_version != 1 || value.payload_size != 128 ||
      value.site_slot >= kJsInvocationSiteLimit ||
      (value.flags & ~kJsInvocationStartKnownFlags) != 0 || value.script_id == 0 ||
      value.source_length == 0 || value.anchor_offset >= value.source_length ||
      value.invocation_id == 0 || value.site_sample_index >= kJsInvocationSiteSampleBudget ||
      value.sample_index >= kJsInvocationSampleBudget || value.document_id == 0)
    return false;
  // A parent is an earlier allocation; an unknown parent records none.
  if (value.parent_invocation_id != 0 &&
      (value.parent_invocation_id >= value.invocation_id ||
       (value.flags & kJsInvocationParentUnknown) != 0))
    return false;
  if (((value.flags & kJsInvocationArgumentsTruncated) != 0) !=
      (value.argument_count > kJsInvocationArgumentLimit))
    return false;
  for (std::size_t i = 0; i < kJsInvocationArgumentLimit; ++i) {
    const std::uint8_t kind = value.argument_kinds[i];
    if (i < value.argument_count) {
      if (!js_invocation_detail::ValidKind(kind) ||
          !js_invocation_detail::ValidLowBits(kind, value.argument_low32[i]))
        return false;
    } else if (kind != 0 || value.argument_low32[i] != 0) {
      return false;
    }
  }
  return js_invocation_detail::AllZero(value.reserved);
}

[[nodiscard]] inline bool IsValidJsInvocationStart(const EventRecord& event) noexcept {
  JsInvocationStartPayload value;
  return js_invocation_detail::Envelope(event, EventType::kJsInvocationStart) &&
         event.header.frame_id != 0 && event.header.request_id == 0 &&
         DecodeJsInvocationStartPayload(event.inline_payload, value) &&
         IsValidJsInvocationStartPayload(value);
}

struct JsInvocationSettlePayload final {
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
  std::array<std::byte, 32> value_sha256{};
  std::uint64_t document_id = 0;
  std::array<std::byte, 56> reserved{};
};
static_assert(sizeof(JsInvocationSettlePayload) == 128);
static_assert(std::is_standard_layout_v<JsInvocationSettlePayload>);
static_assert(std::is_trivially_copyable_v<JsInvocationSettlePayload>);
static_assert(offsetof(JsInvocationSettlePayload, site_slot) == 4);
static_assert(offsetof(JsInvocationSettlePayload, outcome) == 5);
static_assert(offsetof(JsInvocationSettlePayload, via) == 6);
static_assert(offsetof(JsInvocationSettlePayload, value_kind) == 7);
static_assert(offsetof(JsInvocationSettlePayload, invocation_id) == 8);
static_assert(offsetof(JsInvocationSettlePayload, value_length) == 12);
static_assert(offsetof(JsInvocationSettlePayload, digest_state) == 16);
static_assert(offsetof(JsInvocationSettlePayload, digest_encoding) == 17);
static_assert(offsetof(JsInvocationSettlePayload, flags) == 18);
static_assert(offsetof(JsInvocationSettlePayload, reserved0) == 19);
static_assert(offsetof(JsInvocationSettlePayload, digest_byte_length) == 20);
static_assert(offsetof(JsInvocationSettlePayload, rolling_hash) == 24);
static_assert(offsetof(JsInvocationSettlePayload, value_sha256) == 32);
static_assert(offsetof(JsInvocationSettlePayload, document_id) == 64);
static_assert(offsetof(JsInvocationSettlePayload, reserved) == 72);

[[nodiscard]] inline std::array<std::byte, 128> EncodeJsInvocationSettlePayload(
    const JsInvocationSettlePayload& value) noexcept {
  using js_invocation_detail::Put;
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
  std::copy(value.value_sha256.begin(), value.value_sha256.end(), out.begin() + 32);
  Put(out, 64, value.document_id, 8);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 72);
  return out;
}

[[nodiscard]] inline bool DecodeJsInvocationSettlePayload(
    std::span<const std::byte> bytes,
    JsInvocationSettlePayload& value) noexcept {
  using js_invocation_detail::Get;
  if (bytes.size() != 128)
    return false;
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.site_slot = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  value.outcome = static_cast<std::uint8_t>(Get(bytes, 5, 1));
  value.via = static_cast<std::uint8_t>(Get(bytes, 6, 1));
  value.value_kind = static_cast<std::uint8_t>(Get(bytes, 7, 1));
  value.invocation_id = static_cast<std::uint32_t>(Get(bytes, 8, 4));
  value.value_length = static_cast<std::uint32_t>(Get(bytes, 12, 4));
  value.digest_state = static_cast<std::uint8_t>(Get(bytes, 16, 1));
  value.digest_encoding = static_cast<std::uint8_t>(Get(bytes, 17, 1));
  value.flags = static_cast<std::uint8_t>(Get(bytes, 18, 1));
  value.reserved0 = static_cast<std::uint8_t>(Get(bytes, 19, 1));
  value.digest_byte_length = static_cast<std::uint32_t>(Get(bytes, 20, 4));
  value.rolling_hash = Get(bytes, 24, 8);
  std::copy(bytes.begin() + 32, bytes.begin() + 64, value.value_sha256.begin());
  value.document_id = Get(bytes, 64, 8);
  std::copy(bytes.begin() + 72, bytes.end(), value.reserved.begin());
  return true;
}

[[nodiscard]] inline bool IsValidJsInvocationSettlePayload(
    const JsInvocationSettlePayload& value) noexcept {
  using Kind = JsInvocationValueKind;
  using State = JsInvocationDigestState;
  using Encoding = JsInvocationDigestEncoding;
  const auto kind = static_cast<Kind>(value.value_kind);
  const bool fulfilled = value.outcome == static_cast<std::uint8_t>(JsInvocationOutcome::kFulfilled);
  const bool rejected = value.outcome == static_cast<std::uint8_t>(JsInvocationOutcome::kRejected);
  const auto via = static_cast<JsInvocationSettleVia>(value.via);
  if (value.protocol_version != 1 || value.payload_size != 128 ||
      value.site_slot >= kJsInvocationSiteLimit || (!fulfilled && !rejected) ||
      !js_invocation_detail::ValidKind(value.value_kind) || value.invocation_id == 0 ||
      value.document_id == 0 || value.reserved0 != 0 ||
      (value.flags & ~kJsInvocationLossyUtf8) != 0)
    return false;
  if (via == JsInvocationSettleVia::kSyncReturn ? !fulfilled
      : via == JsInvocationSettleVia::kSyncThrow ? !rejected
                                                 : via != JsInvocationSettleVia::kPromise)
    return false;
  const bool string = kind == Kind::kString;
  const bool bytes = kind == Kind::kArrayBuffer || kind == Kind::kArrayBufferView;
  if (value.value_length != 0 && !string && !bytes && kind != Kind::kArray)
    return false;
  const auto state = static_cast<State>(value.digest_state);
  if (state == State::kPresent) {
    const auto encoding = static_cast<Encoding>(value.digest_encoding);
    if (!fulfilled || value.digest_byte_length > kJsInvocationDigestByteLimit ||
        !(string ? encoding == Encoding::kUtf8 : bytes && encoding == Encoding::kBytes) ||
        (!string && (value.flags & kJsInvocationLossyUtf8) != 0) ||
        (string && value.digest_byte_length < value.value_length) ||
        (bytes && value.digest_byte_length != value.value_length) ||
        (value.digest_byte_length == 0 && value.rolling_hash != 0))
      return false;
  } else {
    if (value.digest_encoding != 0 || value.digest_byte_length != 0 || value.rolling_hash != 0 ||
        value.flags != 0 || !js_invocation_detail::AllZero(value.value_sha256))
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
  }
  return js_invocation_detail::AllZero(value.reserved);
}

[[nodiscard]] inline bool IsValidJsInvocationSettle(const EventRecord& event) noexcept {
  JsInvocationSettlePayload value;
  return js_invocation_detail::Envelope(event, EventType::kJsInvocationSettle) &&
         event.header.frame_id != 0 && event.header.request_id == 0 &&
         DecodeJsInvocationSettlePayload(event.inline_payload, value) &&
         IsValidJsInvocationSettlePayload(value);
}

struct JsInvocationRequestPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint8_t state = 0;
  std::array<std::byte, 3> reserved0{};
  std::uint32_t invocation_id = 0;
  std::uint16_t sample_index = 0;
  std::uint16_t reserved1 = 0;
  std::array<std::byte, 112> reserved{};
};
static_assert(sizeof(JsInvocationRequestPayload) == 128);
static_assert(std::is_standard_layout_v<JsInvocationRequestPayload>);
static_assert(std::is_trivially_copyable_v<JsInvocationRequestPayload>);
static_assert(offsetof(JsInvocationRequestPayload, state) == 4);
static_assert(offsetof(JsInvocationRequestPayload, invocation_id) == 8);
static_assert(offsetof(JsInvocationRequestPayload, sample_index) == 12);
static_assert(offsetof(JsInvocationRequestPayload, reserved) == 16);

[[nodiscard]] inline std::array<std::byte, 128> EncodeJsInvocationRequestPayload(
    const JsInvocationRequestPayload& value) noexcept {
  using js_invocation_detail::Put;
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

[[nodiscard]] inline bool DecodeJsInvocationRequestPayload(
    std::span<const std::byte> bytes,
    JsInvocationRequestPayload& value) noexcept {
  using js_invocation_detail::Get;
  if (bytes.size() != 128)
    return false;
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.state = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  std::copy(bytes.begin() + 5, bytes.begin() + 8, value.reserved0.begin());
  value.invocation_id = static_cast<std::uint32_t>(Get(bytes, 8, 4));
  value.sample_index = static_cast<std::uint16_t>(Get(bytes, 12, 2));
  value.reserved1 = static_cast<std::uint16_t>(Get(bytes, 14, 2));
  std::copy(bytes.begin() + 16, bytes.end(), value.reserved.begin());
  return true;
}

// Only an attributed request (inside) or an unattributable one while an
// invocation was open (unknown) is ever recorded.
[[nodiscard]] inline bool IsValidJsInvocationRequestPayload(
    const JsInvocationRequestPayload& value) noexcept {
  const bool inside = value.state == static_cast<std::uint8_t>(JsInvocationContextState::kInside);
  const bool unknown =
      value.state == static_cast<std::uint8_t>(JsInvocationContextState::kUnknown);
  return value.protocol_version == 1 && value.payload_size == 128 && (inside || unknown) &&
         IsValidJsInvocationContext(value.state, value.invocation_id) &&
         value.sample_index < kJsInvocationRequestBudget && value.reserved1 == 0 &&
         js_invocation_detail::AllZero(value.reserved0) &&
         js_invocation_detail::AllZero(value.reserved);
}

[[nodiscard]] inline bool IsValidJsInvocationRequest(const EventRecord& event) noexcept {
  JsInvocationRequestPayload value;
  return js_invocation_detail::Envelope(event, EventType::kJsInvocationRequest) &&
         event.header.request_id != 0 && event.header.request_id <= 0xffffffffULL &&
         DecodeJsInvocationRequestPayload(event.inline_payload, value) &&
         IsValidJsInvocationRequestPayload(value);
}
}  // namespace reb
#endif
