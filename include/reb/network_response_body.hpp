#ifndef REB_NETWORK_RESPONSE_BODY_HPP_
#define REB_NETWORK_RESPONSE_BODY_HPP_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include "reb/event.hpp"
#include "reb/network_request.hpp"
namespace reb {
// The response_body record, see protocol/native-network-v3.md. The Brave
// overlay's common/native_network_response_body.h is the producer half.
// Version 2 adds flag bit 7; version 1 records stay valid without it.
inline constexpr std::uint16_t kResponseBodyPayloadVersion = 2;
inline constexpr std::uint64_t kResponseBodyCaptureBytes = 16ULL * 1024ULL * 1024ULL;

enum class ResponseBodyState : std::uint8_t {
  kCaptured = 1,
  kCapturedTruncated = 2,
  kPartial = 3,
  kAborted = 4,
  kCancelled = 5,
  kEmpty = 6,
  kNotModified = 7,
  kRedirected = 8,
  kNotCapturedType = 9,
  kNotCapturedArtifactUnavailable = 10,
  kNotCapturedTransferRefused = 11,
  kNotCapturedSessionBudget = 12,
};

inline constexpr std::uint8_t kResponseBodyShared = 1U << 0U;
inline constexpr std::uint8_t kResponseBodyFromCache = 1U << 1U;
inline constexpr std::uint8_t kResponseBodyServiceWorker = 1U << 2U;
inline constexpr std::uint8_t kResponseBodyStillEncoded = 1U << 3U;
inline constexpr std::uint8_t kResponseBodyCodingsOmitted = 1U << 4U;
inline constexpr std::uint8_t kResponseBodyCompletionUnobserved = 1U << 5U;
inline constexpr std::uint8_t kResponseBodyContentTypePresent = 1U << 6U;
// Version 2: a snapshot the schedule's spacing allowed was withheld by a byte
// bound (the body's allowance, the session's snapshot share or the budget).
inline constexpr std::uint8_t kResponseBodySnapshotsWithheld = 1U << 7U;
inline constexpr std::uint8_t kResponseBodyKnownFlags = 0x7FU;

struct ResponseBodyPayload final {
  std::uint16_t protocol_version = kResponseBodyPayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint8_t state = 0;
  std::uint8_t flags = 0;
  std::uint8_t content_type_length = 0;
  std::uint8_t coding_count = 0;
  std::uint64_t body_length = 0;
  std::uint64_t captured_length = 0;
  std::array<std::uint8_t, 4> codings{};
  std::uint16_t partial_index = 0;
  std::uint16_t reserved0 = 0;
  std::array<std::uint8_t, 32> sha256{};
  std::array<char, kRequestContentTypeBytes> content_type{};
};
static_assert(sizeof(ResponseBodyPayload) == 128);
static_assert(std::is_standard_layout_v<ResponseBodyPayload>);
static_assert(std::is_trivially_copyable_v<ResponseBodyPayload>);
static_assert(offsetof(ResponseBodyPayload, state) == 4);
static_assert(offsetof(ResponseBodyPayload, flags) == 5);
static_assert(offsetof(ResponseBodyPayload, content_type_length) == 6);
static_assert(offsetof(ResponseBodyPayload, coding_count) == 7);
static_assert(offsetof(ResponseBodyPayload, body_length) == 8);
static_assert(offsetof(ResponseBodyPayload, captured_length) == 16);
static_assert(offsetof(ResponseBodyPayload, codings) == 24);
static_assert(offsetof(ResponseBodyPayload, partial_index) == 28);
static_assert(offsetof(ResponseBodyPayload, reserved0) == 30);
static_assert(offsetof(ResponseBodyPayload, sha256) == 32);
static_assert(offsetof(ResponseBodyPayload, content_type) == 64);

[[nodiscard]] inline bool DecodeResponseBodyPayload(std::span<const std::byte> bytes,
                                                    ResponseBodyPayload& value) noexcept {
  using request_detail::Get;
  if (bytes.size() != 128) {
    return false;
  }
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.state = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  value.flags = static_cast<std::uint8_t>(Get(bytes, 5, 1));
  value.content_type_length = static_cast<std::uint8_t>(Get(bytes, 6, 1));
  value.coding_count = static_cast<std::uint8_t>(Get(bytes, 7, 1));
  value.body_length = Get(bytes, 8, 8);
  value.captured_length = Get(bytes, 16, 8);
  for (std::size_t i = 0; i < value.codings.size(); ++i) {
    value.codings[i] = static_cast<std::uint8_t>(Get(bytes, 24 + i, 1));
  }
  value.partial_index = static_cast<std::uint16_t>(Get(bytes, 28, 2));
  value.reserved0 = static_cast<std::uint16_t>(Get(bytes, 30, 2));
  std::transform(bytes.begin() + 32, bytes.begin() + 64, value.sha256.begin(),
                 [](std::byte b) { return std::to_integer<std::uint8_t>(b); });
  std::transform(bytes.begin() + 64, bytes.end(), value.content_type.begin(),
                 [](std::byte b) { return static_cast<char>(std::to_integer<unsigned char>(b)); });
  return true;
}

// Payload rules from protocol/native-network-v3.md. has_artifact is whether the
// envelope names the artifact holding the retained bytes.
[[nodiscard]] inline bool IsValidResponseBodyPayload(const ResponseBodyPayload& value,
                                                     const bool has_artifact) noexcept {
  using enum ResponseBodyState;
  const auto state = static_cast<ResponseBodyState>(value.state);
  const std::span<const char> type(value.content_type);
  const bool type_present = (value.flags & kResponseBodyContentTypePresent) != 0;
  const std::uint8_t known_flags =
      kResponseBodyKnownFlags |
      (value.protocol_version >= 2 ? kResponseBodySnapshotsWithheld : std::uint8_t{0});
  if (value.protocol_version == 0 || value.protocol_version > kResponseBodyPayloadVersion ||
      value.payload_size != 128 || value.reserved0 != 0 ||
      value.state < static_cast<std::uint8_t>(kCaptured) ||
      value.state > static_cast<std::uint8_t>(kNotCapturedSessionBudget) ||
      (value.flags & static_cast<std::uint8_t>(~known_flags)) != 0 ||
      value.content_type_length > kRequestContentTypeBytes ||
      type_present != (value.content_type_length != 0) ||
      !request_detail::AllZero(type.subspan(value.content_type_length)) ||
      (type_present && !IsNormalizedContentType(std::string_view(value.content_type.data(),
                                                                 value.content_type_length))) ||
      value.coding_count > value.codings.size() ||
      ((value.flags & kResponseBodyCodingsOmitted) != 0 &&
       value.coding_count != value.codings.size())) {
    return false;
  }
  for (std::size_t i = 0; i < value.codings.size(); ++i) {
    const std::uint8_t coding = value.codings[i];
    if (i < value.coding_count ? coding == 0 || (coding > 7 && coding != 15) : coding != 0) {
      return false;
    }
  }
  const bool digest =
      std::any_of(value.sha256.begin(), value.sha256.end(), [](std::uint8_t b) { return b != 0; });
  const bool retained = value.captured_length != 0;
  const std::uint64_t whole = std::min(value.body_length, kResponseBodyCaptureBytes);
  if (value.captured_length > value.body_length || has_artifact != retained || digest != retained ||
      ((value.flags & kResponseBodyShared) != 0 && !retained) ||
      (value.partial_index != 0) != (state == kPartial) ||
      ((value.flags & kResponseBodyCompletionUnobserved) != 0 && state != kCaptured &&
       state != kCapturedTruncated && state != kEmpty)) {
    return false;
  }
  switch (state) {
    case kCaptured:
      return value.body_length != 0 && value.captured_length == value.body_length;
    case kCapturedTruncated:
      return value.body_length > kResponseBodyCaptureBytes &&
             value.captured_length == kResponseBodyCaptureBytes;
    case kPartial:
      return value.body_length != 0 && value.captured_length == whole;
    case kAborted:
    case kCancelled:
      return !retained || value.captured_length == whole;
    case kEmpty:
    case kNotModified:
    case kRedirected:
    case kNotCapturedType:
      return value.body_length == 0;
    case kNotCapturedArtifactUnavailable:
    case kNotCapturedTransferRefused:
    case kNotCapturedSessionBudget:
      return !retained;
  }
  return false;
}

[[nodiscard]] inline bool IsValidResponseBodyEvent(const EventRecord& event) noexcept {
  ResponseBodyPayload value;
  return request_detail::IsRequestChildEnvelope(event, EventType::kResponseBody) &&
         DecodeResponseBodyPayload(event.inline_payload, value) &&
         IsValidResponseBodyPayload(value, event.header.artifact_id != 0);
}
}  // namespace reb
#endif
