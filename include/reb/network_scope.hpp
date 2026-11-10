#ifndef REB_NETWORK_SCOPE_HPP_
#define REB_NETWORK_SCOPE_HPP_
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include "reb/event.hpp"
namespace reb {
// Scheme classes and capture exclusions, see protocol/native-network-v3.md.
// The overlay's common/native_network_scope.h is the producer half;
// tests/network_scope_test.cpp keeps the two in step.
enum class SchemeClass : std::uint8_t {
  kNotRecorded = 0,
  kHttp = 1,
  kHttps = 2,
  kWs = 3,
  kWss = 4,
  kData = 5,
  kBlob = 6,
  kFile = 7,
  kExtension = 8,
  kOther = 15,
  kChrome = 16,
  kChromeUntrusted = 17,
  kBrave = 18,
  kDevTools = 19,
  kChromeSearch = 20,
};

enum class ExclusionClass : std::uint8_t {
  kChrome = 16,
  kChromeUntrusted = 17,
  kBrave = 18,
  kDevTools = 19,
  kChromeSearch = 20,
  kWebUiRenderer = 64,
  kExtensionWorker = 65,
  kDevToolsLoad = 66,
  kWebUiRequest = 67,
};

inline constexpr std::uint16_t kCaptureExclusionPayloadVersion = 1;
inline constexpr std::size_t kCaptureExclusionPayloadSize = 16;

[[nodiscard]] constexpr bool IsKnownSchemeClass(const std::uint8_t value) noexcept {
  return value <= 8 || value == 15 || (value >= 16 && value <= 20);
}

[[nodiscard]] constexpr bool IsBrowserInternalSchemeClass(const std::uint8_t value) noexcept {
  return value >= 16 && value <= 20;
}

[[nodiscard]] constexpr bool IsKnownExclusionClass(const std::uint8_t value) noexcept {
  return IsBrowserInternalSchemeClass(value) || (value >= 64 && value <= 67);
}

// The record types that may name the scheme of their request.
[[nodiscard]] constexpr bool CarriesSchemeClass(const EventHeader& header) noexcept {
  return header.category == EventCategory::kNetwork &&
         (header.type == EventType::kRequestInitiated ||
          header.type == EventType::kRequestStarted ||
          header.type == EventType::kRequestCompleted || header.type == EventType::kRequestFailed);
}

struct CaptureExclusionPayload final {
  std::uint16_t version = kCaptureExclusionPayloadVersion;
  std::uint16_t size = kCaptureExclusionPayloadSize;
  std::uint8_t exclusion_class = 0;
  std::array<std::uint8_t, 3> reserved{};
  std::uint64_t count = 0;
};

[[nodiscard]] inline bool DecodeCaptureExclusionPayload(std::span<const std::byte> bytes,
                                                        CaptureExclusionPayload& value) noexcept {
  if (bytes.size() < kCaptureExclusionPayloadSize)
    return false;
  const auto at = [bytes](const std::size_t offset, const std::size_t size) {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < size; ++index)
      result |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[offset + index]))
                << (8U * index);
    return result;
  };
  value.version = static_cast<std::uint16_t>(at(0, 2));
  value.size = static_cast<std::uint16_t>(at(2, 2));
  value.exclusion_class = static_cast<std::uint8_t>(at(4, 1));
  for (std::size_t index = 0; index < value.reserved.size(); ++index)
    value.reserved[index] = static_cast<std::uint8_t>(at(5 + index, 1));
  value.count = at(8, 8);
  return true;
}

[[nodiscard]] inline bool IsValidCaptureExclusionEvent(const EventRecord& event) noexcept {
  const auto& h = event.header;
  CaptureExclusionPayload value;
  return h.category == EventCategory::kNetwork && h.type == EventType::kCaptureExclusion &&
         h.payload_size == kCaptureExclusionPayloadSize && h.flags == 0 && h.session_id != 0 &&
         h.sequence_number != 0 && h.process_id != 0 && h.tab_id == 0 && h.navigation_id == 0 &&
         h.frame_id == 0 && h.artifact_id == 0 && h.parent_event_id == 0 && h.request_id == 0 &&
         h.browser_context_id_high == 0 && h.browser_context_id_low == 0 &&
         h.encoded_data_length == 0 && h.decoded_body_length == 0 && h.status_code == 0 &&
         h.error_code == 0 && h.resource_type == 0 && h.initiator_request_id == 0 &&
         DecodeCaptureExclusionPayload(event.inline_payload, value) &&
         value.version == kCaptureExclusionPayloadVersion &&
         value.size == kCaptureExclusionPayloadSize &&
         IsKnownExclusionClass(value.exclusion_class) &&
         value.reserved == std::array<std::uint8_t, 3>{} && value.count != 0 &&
         ((value.exclusion_class != static_cast<std::uint8_t>(ExclusionClass::kWebUiRenderer) &&
           value.exclusion_class != static_cast<std::uint8_t>(ExclusionClass::kDevToolsLoad) &&
           value.exclusion_class != static_cast<std::uint8_t>(ExclusionClass::kWebUiRequest)) ||
          h.initiator_process_id == 0);
}
}  // namespace reb
#endif
