#ifndef REB_NETWORK_REQUEST_HPP_
#define REB_NETWORK_REQUEST_HPP_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include "reb/event.hpp"
namespace reb {
// Network request target and body records, see protocol/native-network-v2.md.
// The Brave overlay's common/native_network_request.h is the producer half of
// this ABI; tests/network_request_test.cpp keeps the two in step.
inline constexpr std::uint16_t kRequestPayloadVersion = 1;
// Version 1 targets predate full-target retention and keep byte 9 zero.
inline constexpr std::uint16_t kRequestTargetPayloadVersion = 2;
inline constexpr std::size_t kRequestTargetPrefixBytes = 116;
inline constexpr std::size_t kRequestContentTypeBytes = 64;
inline constexpr std::uint64_t kRequestBodyDigestBytes = 4ULL * 1024ULL * 1024ULL;

enum class RequestBodyKind : std::uint8_t {
  kNone = 0,
  kBytes = 1,
  kFile = 2,
  kDataPipe = 3,
  kChunkedDataPipe = 4,
  kMixed = 5,
  kUnknown = 6,
};

enum class RequestBodyState : std::uint8_t {
  kNoBody = 1,
  kEmpty = 2,
  kMetadataOnly = 3,
  kCaptured = 4,
  kCapturedTruncated = 5,
  kNotCapturedBodyKind = 6,
  kNotCapturedArtifactUnavailable = 7,
  kNotCapturedTransferRefused = 8,
  kNotCapturedUrl = 9,
  kNotCapturedSessionBudget = 10,
  kNotCapturedCredentialForm = 11,
};

inline constexpr std::uint8_t kRequestBodyContentCapture = 1U << 0U;
inline constexpr std::uint8_t kRequestBodyDigestPresent = 1U << 1U;
inline constexpr std::uint8_t kRequestBodyDigestSizeLimit = 1U << 2U;
inline constexpr std::uint8_t kRequestBodyLengthPartial = 1U << 3U;
inline constexpr std::uint8_t kRequestBodyContentTypePresent = 1U << 4U;
inline constexpr std::uint8_t kRequestBodyContentTypeOmitted = 1U << 5U;
inline constexpr std::uint8_t kRequestBodyKnownFlags = 0x3FU;

enum class RequestTargetRetention : std::uint8_t {
  kComplete = 0,
  kRetained = 1,
  kNotRetainedArtifactUnavailable = 2,
  kNotRetainedTransferRefused = 3,
  kNotRetainedSessionBudget = 4,
  kNotRetainedUrl = 5,
};

enum class RequestScheme : std::uint8_t {
  kOther = 0,
  kHttp = 1,
  kHttps = 2,
  kWs = 3,
  kWss = 4,
};

struct RequestBodyPayload final {
  std::uint16_t protocol_version = kRequestPayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint8_t kind = 0;
  std::uint8_t state = 0;
  std::uint8_t flags = 0;
  std::uint8_t content_type_length = 0;
  std::uint64_t body_length = 0;
  std::uint64_t captured_length = 0;
  std::uint32_t element_count = 0;
  std::uint32_t reserved0 = 0;
  std::array<std::uint8_t, 32> sha256{};
  std::array<char, kRequestContentTypeBytes> content_type{};
};
static_assert(sizeof(RequestBodyPayload) == 128);
static_assert(std::is_standard_layout_v<RequestBodyPayload>);
static_assert(std::is_trivially_copyable_v<RequestBodyPayload>);
static_assert(offsetof(RequestBodyPayload, kind) == 4);
static_assert(offsetof(RequestBodyPayload, state) == 5);
static_assert(offsetof(RequestBodyPayload, flags) == 6);
static_assert(offsetof(RequestBodyPayload, content_type_length) == 7);
static_assert(offsetof(RequestBodyPayload, body_length) == 8);
static_assert(offsetof(RequestBodyPayload, captured_length) == 16);
static_assert(offsetof(RequestBodyPayload, element_count) == 24);
static_assert(offsetof(RequestBodyPayload, reserved0) == 28);
static_assert(offsetof(RequestBodyPayload, sha256) == 32);
static_assert(offsetof(RequestBodyPayload, content_type) == 64);

struct RequestTargetPayload final {
  std::uint16_t protocol_version = kRequestTargetPayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint32_t target_length = 0;
  std::uint8_t scheme = 0;
  // Version 2: RequestTargetRetention. Version 1: zero.
  std::uint8_t reserved0 = 0;
  std::uint16_t port = 0;
  std::array<char, kRequestTargetPrefixBytes> target_prefix{};
};
static_assert(sizeof(RequestTargetPayload) == 128);
static_assert(std::is_standard_layout_v<RequestTargetPayload>);
static_assert(std::is_trivially_copyable_v<RequestTargetPayload>);
static_assert(offsetof(RequestTargetPayload, target_length) == 4);
static_assert(offsetof(RequestTargetPayload, scheme) == 8);
static_assert(offsetof(RequestTargetPayload, reserved0) == 9);
static_assert(offsetof(RequestTargetPayload, port) == 10);
static_assert(offsetof(RequestTargetPayload, target_prefix) == 12);

namespace request_detail {
[[nodiscard]] inline std::uint64_t Get(std::span<const std::byte> bytes,
                                       const std::size_t offset,
                                       const std::size_t width) noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i) {
    value |= std::to_integer<std::uint64_t>(bytes[offset + i]) << (8U * i);
  }
  return value;
}
[[nodiscard]] constexpr bool IsTokenCharacter(const char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
         std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
}
[[nodiscard]] inline bool AllZero(std::span<const char> bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](char c) { return c == '\0'; });
}
}  // namespace request_detail

// A normalized media type: lower-case token, one slash, lower-case token.
[[nodiscard]] constexpr bool IsNormalizedContentType(const std::string_view value) noexcept {
  const auto slash = value.find('/');
  if (value.empty() || value.size() > kRequestContentTypeBytes || slash == 0 ||
      slash == std::string_view::npos || slash + 1 == value.size() ||
      value.find('/', slash + 1) != std::string_view::npos) {
    return false;
  }
  return std::all_of(value.begin(), value.end(),
                     [](char c) { return c == '/' || request_detail::IsTokenCharacter(c); });
}

[[nodiscard]] inline bool DecodeRequestBodyPayload(std::span<const std::byte> bytes,
                                                   RequestBodyPayload& value) noexcept {
  using request_detail::Get;
  if (bytes.size() != 128) {
    return false;
  }
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.kind = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  value.state = static_cast<std::uint8_t>(Get(bytes, 5, 1));
  value.flags = static_cast<std::uint8_t>(Get(bytes, 6, 1));
  value.content_type_length = static_cast<std::uint8_t>(Get(bytes, 7, 1));
  value.body_length = Get(bytes, 8, 8);
  value.captured_length = Get(bytes, 16, 8);
  value.element_count = static_cast<std::uint32_t>(Get(bytes, 24, 4));
  value.reserved0 = static_cast<std::uint32_t>(Get(bytes, 28, 4));
  std::transform(bytes.begin() + 32, bytes.begin() + 64, value.sha256.begin(),
                 [](std::byte b) { return std::to_integer<std::uint8_t>(b); });
  std::transform(bytes.begin() + 64, bytes.end(), value.content_type.begin(),
                 [](std::byte b) { return static_cast<char>(std::to_integer<unsigned char>(b)); });
  return true;
}

[[nodiscard]] inline bool DecodeRequestTargetPayload(std::span<const std::byte> bytes,
                                                     RequestTargetPayload& value) noexcept {
  using request_detail::Get;
  if (bytes.size() != 128) {
    return false;
  }
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.target_length = static_cast<std::uint32_t>(Get(bytes, 4, 4));
  value.scheme = static_cast<std::uint8_t>(Get(bytes, 8, 1));
  value.reserved0 = static_cast<std::uint8_t>(Get(bytes, 9, 1));
  value.port = static_cast<std::uint16_t>(Get(bytes, 10, 2));
  std::transform(bytes.begin() + 12, bytes.end(), value.target_prefix.begin(),
                 [](std::byte b) { return static_cast<char>(std::to_integer<unsigned char>(b)); });
  return true;
}

// Payload rules from protocol/native-network-v2.md. has_artifact is whether the
// envelope names a request-body artifact.
[[nodiscard]] inline bool IsValidRequestBodyPayload(const RequestBodyPayload& value,
                                                    const bool has_artifact) noexcept {
  using enum RequestBodyState;
  const auto kind = static_cast<RequestBodyKind>(value.kind);
  const auto state = static_cast<RequestBodyState>(value.state);
  const bool content = (value.flags & kRequestBodyContentCapture) != 0;
  const bool digest = (value.flags & kRequestBodyDigestPresent) != 0;
  const bool size_limit = (value.flags & kRequestBodyDigestSizeLimit) != 0;
  const bool partial = (value.flags & kRequestBodyLengthPartial) != 0;
  const bool type_present = (value.flags & kRequestBodyContentTypePresent) != 0;
  const bool type_omitted = (value.flags & kRequestBodyContentTypeOmitted) != 0;
  const std::span<const char> type(value.content_type);
  if (value.protocol_version != kRequestPayloadVersion || value.payload_size != 128 ||
      value.reserved0 != 0 || value.kind > static_cast<std::uint8_t>(RequestBodyKind::kUnknown) ||
      value.state < static_cast<std::uint8_t>(kNoBody) ||
      value.state > static_cast<std::uint8_t>(kNotCapturedCredentialForm) ||
      (value.flags & ~kRequestBodyKnownFlags) != 0 ||
      value.content_type_length > kRequestContentTypeBytes || (type_present && type_omitted) ||
      type_present != (value.content_type_length != 0) ||
      !request_detail::AllZero(type.subspan(value.content_type_length)) ||
      (type_present && !IsNormalizedContentType(std::string_view(value.content_type.data(),
                                                                 value.content_type_length))) ||
      value.captured_length > value.body_length) {
    return false;
  }
  const bool bytes = kind == RequestBodyKind::kBytes;
  const bool none = kind == RequestBodyKind::kNone;
  if ((digest && (!bytes || size_limit || value.body_length > kRequestBodyDigestBytes)) ||
      (!digest && !std::all_of(value.sha256.begin(), value.sha256.end(),
                               [](std::uint8_t b) { return b == 0; })) ||
      (size_limit && (!bytes || value.body_length <= kRequestBodyDigestBytes)) ||
      (bytes && state != kNotCapturedCredentialForm && digest == size_limit) ||
      (state == kNotCapturedCredentialForm && (digest || size_limit)) ||
      partial != (!none && !bytes) || none != (state == kNoBody) ||
      (none && (value.element_count != 0 || value.body_length != 0)) ||
      (!none && value.element_count == 0) ||
      (kind == RequestBodyKind::kMixed && value.element_count < 2)) {
    return false;
  }
  const bool retained = state == kCaptured || state == kCapturedTruncated;
  if (has_artifact != retained || (!retained && value.captured_length != 0)) {
    return false;
  }
  switch (state) {
    case kNoBody:
    case kNotCapturedCredentialForm:
      return true;
    case kEmpty:
      return bytes && value.body_length == 0;
    case kMetadataOnly:
      return !content && (!bytes || value.body_length != 0);
    case kCaptured:
      return content && bytes && value.body_length != 0 &&
             value.captured_length == value.body_length;
    case kCapturedTruncated:
      return content && bytes && value.captured_length != 0 &&
             value.captured_length < value.body_length;
    case kNotCapturedBodyKind:
      return content && !none && !bytes;
    case kNotCapturedArtifactUnavailable:
    case kNotCapturedTransferRefused:
    case kNotCapturedUrl:
    case kNotCapturedSessionBudget:
      return content && bytes && value.body_length != 0;
  }
  return false;
}

// has_artifact is whether the envelope names a full-target artifact.
[[nodiscard]] inline bool IsValidRequestTargetPayload(const RequestTargetPayload& value,
                                                      const bool has_artifact) noexcept {
  const std::size_t prefix = std::min<std::size_t>(value.target_length, value.target_prefix.size());
  const std::span<const char> bytes(value.target_prefix);
  const bool past_prefix = value.target_length > kRequestTargetPrefixBytes;
  const auto retention = static_cast<RequestTargetRetention>(value.reserved0);
  const bool retention_valid =
      value.protocol_version == kRequestPayloadVersion
          ? value.reserved0 == 0 && !has_artifact
          : value.protocol_version == kRequestTargetPayloadVersion &&
                value.reserved0 <=
                    static_cast<std::uint8_t>(RequestTargetRetention::kNotRetainedUrl) &&
                (retention == RequestTargetRetention::kComplete) != past_prefix &&
                (retention == RequestTargetRetention::kRetained) == has_artifact;
  return retention_valid && value.payload_size == 128 &&
         value.scheme <= static_cast<std::uint8_t>(RequestScheme::kWss) &&
         std::all_of(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(prefix),
                     [](char c) { return c != '\0'; }) &&
         request_detail::AllZero(bytes.subspan(prefix));
}

namespace request_detail {
// Both records are children of a browser lifecycle record of the same request.
[[nodiscard]] inline bool IsRequestChildEnvelope(const EventRecord& event,
                                                 const EventType type) noexcept {
  const auto& h = event.header;
  return h.protocol_version == kEventProtocolVersion && h.category == EventCategory::kNetwork &&
         h.type == type && h.payload_size == 128 && h.flags == 0 && h.session_id != 0 &&
         h.sequence_number != 0 && h.process_id != 0 && h.parent_event_id != 0 &&
         h.parent_event_id < h.sequence_number && h.navigation_id == 0 && h.status_code == 0 &&
         h.error_code == 0 && h.encoded_data_length == 0 && h.decoded_body_length == 0 &&
         h.resource_type == 0;
}
}  // namespace request_detail

[[nodiscard]] inline bool IsValidRequestBodyEvent(const EventRecord& event) noexcept {
  RequestBodyPayload value;
  return request_detail::IsRequestChildEnvelope(event, EventType::kRequestBody) &&
         DecodeRequestBodyPayload(event.inline_payload, value) &&
         IsValidRequestBodyPayload(value, event.header.artifact_id != 0);
}

[[nodiscard]] inline bool IsValidRequestTargetEvent(const EventRecord& event) noexcept {
  RequestTargetPayload value;
  return request_detail::IsRequestChildEnvelope(event, EventType::kRequestTarget) &&
         DecodeRequestTargetPayload(event.inline_payload, value) &&
         IsValidRequestTargetPayload(value, event.header.artifact_id != 0);
}
}  // namespace reb
#endif
