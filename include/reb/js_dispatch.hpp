#ifndef REB_JS_DISPATCH_HPP_
#define REB_JS_DISPATCH_HPP_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include "reb/event.hpp"
namespace reb {
// One live JavaScript dispatch at an armed static site, observed by the V8
// bytecode generator's runtime call. Positions are UTF-16 code-unit offsets
// into the script source V8 compiled; the site is named by source_sha256 (over
// that text as UTF-16LE), source_length and anchor_offset. No argument,
// receiver or string content is part of this record.
inline constexpr std::size_t kJsDispatchSiteLimit = 8;
inline constexpr std::size_t kJsDispatchSampleBudget = 256;
inline constexpr std::size_t kJsDispatchSiteSampleBudget = 64;

enum class JsDispatchShape : std::uint8_t {
  kSwitch = 1,
  kIndexedCall = 2,
};

enum class JsDispatchSelectorKind : std::uint8_t {
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

// Payload flag bits. Every other bit must be zero.
inline constexpr std::uint8_t kJsDispatchNewActivation = 1U << 0U;
inline constexpr std::uint8_t kJsDispatchParentUnknown = 1U << 1U;
inline constexpr std::uint8_t kJsDispatchParentSearchTruncated = 1U << 2U;
inline constexpr std::uint8_t kJsDispatchHandlerSpan = 1U << 3U;
inline constexpr std::uint8_t kJsDispatchKnownFlags =
    kJsDispatchNewActivation | kJsDispatchParentUnknown | kJsDispatchParentSearchTruncated |
    kJsDispatchHandlerSpan;

struct JsDispatchObservationPayload final {
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
  std::array<std::byte, 32> source_sha256{};
  std::array<std::byte, 48> reserved{};
};
static_assert(sizeof(JsDispatchObservationPayload) == 128);
static_assert(std::is_standard_layout_v<JsDispatchObservationPayload>);
static_assert(std::is_trivially_copyable_v<JsDispatchObservationPayload>);
static_assert(offsetof(JsDispatchObservationPayload, protocol_version) == 0);
static_assert(offsetof(JsDispatchObservationPayload, payload_size) == 2);
static_assert(offsetof(JsDispatchObservationPayload, shape) == 4);
static_assert(offsetof(JsDispatchObservationPayload, selector_kind) == 5);
static_assert(offsetof(JsDispatchObservationPayload, site_slot) == 6);
static_assert(offsetof(JsDispatchObservationPayload, flags) == 7);
static_assert(offsetof(JsDispatchObservationPayload, script_id) == 8);
static_assert(offsetof(JsDispatchObservationPayload, anchor_offset) == 12);
static_assert(offsetof(JsDispatchObservationPayload, source_length) == 16);
static_assert(offsetof(JsDispatchObservationPayload, selector_low32) == 20);
static_assert(offsetof(JsDispatchObservationPayload, handler_script_id) == 24);
static_assert(offsetof(JsDispatchObservationPayload, handler_start) == 28);
static_assert(offsetof(JsDispatchObservationPayload, handler_end) == 32);
static_assert(offsetof(JsDispatchObservationPayload, activation_id) == 36);
static_assert(offsetof(JsDispatchObservationPayload, parent_activation_id) == 40);
static_assert(offsetof(JsDispatchObservationPayload, site_sample_index) == 44);
static_assert(offsetof(JsDispatchObservationPayload, sample_index) == 46);
static_assert(offsetof(JsDispatchObservationPayload, source_sha256) == 48);
static_assert(offsetof(JsDispatchObservationPayload, reserved) == 80);

// Explicit little-endian encoding; no native structure padding is serialized.
[[nodiscard]] inline std::array<std::byte, 128> EncodeJsDispatchObservationPayload(
    const JsDispatchObservationPayload& value) noexcept {
  std::array<std::byte, 128> out{};
  const auto put = [&out](std::size_t offset, std::uint32_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
      out[offset + i] = static_cast<std::byte>((v >> (8U * i)) & 255U);
  };
  put(0, value.protocol_version, 2);
  put(2, value.payload_size, 2);
  put(4, value.shape, 1);
  put(5, value.selector_kind, 1);
  put(6, value.site_slot, 1);
  put(7, value.flags, 1);
  put(8, value.script_id, 4);
  put(12, value.anchor_offset, 4);
  put(16, value.source_length, 4);
  put(20, value.selector_low32, 4);
  put(24, value.handler_script_id, 4);
  put(28, value.handler_start, 4);
  put(32, value.handler_end, 4);
  put(36, value.activation_id, 4);
  put(40, value.parent_activation_id, 4);
  put(44, value.site_sample_index, 2);
  put(46, value.sample_index, 2);
  std::copy(value.source_sha256.begin(), value.source_sha256.end(), out.begin() + 48);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 80);
  return out;
}

[[nodiscard]] inline bool DecodeJsDispatchObservationPayload(
    std::span<const std::byte> bytes,
    JsDispatchObservationPayload& value) noexcept {
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
  value.shape = static_cast<std::uint8_t>(get(4, 1));
  value.selector_kind = static_cast<std::uint8_t>(get(5, 1));
  value.site_slot = static_cast<std::uint8_t>(get(6, 1));
  value.flags = static_cast<std::uint8_t>(get(7, 1));
  value.script_id = get(8, 4);
  value.anchor_offset = get(12, 4);
  value.source_length = get(16, 4);
  value.selector_low32 = get(20, 4);
  value.handler_script_id = get(24, 4);
  value.handler_start = get(28, 4);
  value.handler_end = get(32, 4);
  value.activation_id = get(36, 4);
  value.parent_activation_id = get(40, 4);
  value.site_sample_index = static_cast<std::uint16_t>(get(44, 2));
  value.sample_index = static_cast<std::uint16_t>(get(46, 2));
  std::copy(bytes.begin() + 48, bytes.begin() + 80, value.source_sha256.begin());
  std::copy(bytes.begin() + 80, bytes.end(), value.reserved.begin());
  return true;
}

// Payload rules from protocol/native-js-dispatch-v1.md, independent of the
// envelope so other boundaries can reuse them.
[[nodiscard]] inline bool IsValidJsDispatchObservationPayload(
    const JsDispatchObservationPayload& value) noexcept {
  const bool switch_shape = value.shape == static_cast<std::uint8_t>(JsDispatchShape::kSwitch);
  const bool indexed_shape =
      value.shape == static_cast<std::uint8_t>(JsDispatchShape::kIndexedCall);
  if (value.protocol_version != 1 || value.payload_size != 128 ||
      (!switch_shape && !indexed_shape) || value.selector_kind < 1 || value.selector_kind > 9 ||
      value.site_slot >= kJsDispatchSiteLimit || (value.flags & ~kJsDispatchKnownFlags) != 0 ||
      value.script_id == 0 || value.source_length == 0 ||
      value.anchor_offset >= value.source_length || value.activation_id == 0 ||
      value.site_sample_index >= kJsDispatchSiteSampleBudget ||
      value.sample_index >= kJsDispatchSampleBudget)
    return false;
  const auto kind = static_cast<JsDispatchSelectorKind>(value.selector_kind);
  if ((kind == JsDispatchSelectorKind::kBoolean && value.selector_low32 > 1) ||
      (kind != JsDispatchSelectorKind::kInteger && kind != JsDispatchSelectorKind::kBoolean &&
       value.selector_low32 != 0))
    return false;
  if ((value.flags & kJsDispatchHandlerSpan) != 0) {
    if (!indexed_shape || value.handler_script_id == 0 || value.handler_start >= value.handler_end)
      return false;
  } else if (value.handler_script_id != 0 || value.handler_start != 0 || value.handler_end != 0) {
    return false;
  }
  if (value.parent_activation_id != 0 &&
      (value.parent_activation_id >= value.activation_id ||
       (value.flags & (kJsDispatchParentUnknown | kJsDispatchParentSearchTruncated)) != 0))
    return false;
  return std::all_of(value.reserved.begin(), value.reserved.end(),
                     [](std::byte b) { return b == std::byte{0}; });
}

[[nodiscard]] inline bool IsValidJsDispatchObservation(const EventRecord& event) noexcept {
  JsDispatchObservationPayload value;
  return event.header.protocol_version == kEventProtocolVersion &&
         event.header.category == EventCategory::kVm &&
         event.header.type == EventType::kJsDispatchObservation &&
         event.header.payload_size == 128 && event.header.flags == 0 &&
         event.header.session_id != 0 && event.header.sequence_number != 0 &&
         event.header.process_id != 0 && event.header.thread_id != 0 &&
         event.header.monotonic_time_ns != 0 && event.header.frame_id != 0 &&
         event.header.artifact_id == 0 && event.header.parent_event_id == 0 &&
         event.header.navigation_id == 0 && event.header.request_id == 0 &&
         DecodeJsDispatchObservationPayload(event.inline_payload, value) &&
         IsValidJsDispatchObservationPayload(value);
}
}  // namespace reb
#endif
