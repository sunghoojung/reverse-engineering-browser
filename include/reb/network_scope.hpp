#ifndef REB_NETWORK_SCOPE_HPP_
#define REB_NETWORK_SCOPE_HPP_
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include "reb/event.hpp"
#include "reb/tab_link.hpp"
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
  kServiceWorkerNoPage = 68,
  kBrowserPrefetch = 69,
  kMemoryCacheReuse = 70,
  kNonOrdinaryPageReuse = 71,
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
  return IsBrowserInternalSchemeClass(value) || (value >= 64 && value <= 71);
}

// The record types that may name the scheme of their request.
[[nodiscard]] constexpr bool CarriesSchemeClass(const EventHeader& header) noexcept {
  return header.category == EventCategory::kNetwork &&
         (header.type == EventType::kRequestInitiated ||
          header.type == EventType::kRequestStarted ||
          header.type == EventType::kRequestCompleted || header.type == EventType::kRequestFailed ||
          header.type == EventType::kMemoryCacheReuse);
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
           value.exclusion_class != static_cast<std::uint8_t>(ExclusionClass::kWebUiRequest) &&
           value.exclusion_class != static_cast<std::uint8_t>(ExclusionClass::kBrowserPrefetch)) ||
          h.initiator_process_id == 0) &&
         // Only a renderer counts the reuses it did not record.
         ((value.exclusion_class != static_cast<std::uint8_t>(ExclusionClass::kMemoryCacheReuse) &&
           value.exclusion_class !=
               static_cast<std::uint8_t>(ExclusionClass::kNonOrdinaryPageReuse)) ||
          h.initiator_process_id != 0);
}

// memory_cache_reuse (type 52), see "Memory-cache reuse" in
// protocol/native-network-v3.md.
inline constexpr std::uint16_t kMemoryCacheReusePayloadVersion = 2;
inline constexpr std::size_t kMemoryCacheReusePayloadSize = 128;
inline constexpr std::size_t kMemoryCacheReuseHostSize = 120;
inline constexpr std::uint8_t kMemoryCacheReuseStaticData = 1U << 0U;
inline constexpr std::uint8_t kMemoryCacheReuseHostTruncated = 1U << 1U;
// Version 2: the envelope's initiator fields name the renderer request whose
// response was reused (its own process and that request's ID).
inline constexpr std::uint8_t kMemoryCacheReuseSourceNamed = 1U << 2U;
// Blink ResourceType at the pin, kImage to kDictionary.
inline constexpr std::uint8_t kMemoryCacheReuseResourceTypeLimit = 15;

struct MemoryCacheReusePayload final {
  std::uint16_t version = kMemoryCacheReusePayloadVersion;
  std::uint16_t size = kMemoryCacheReusePayloadSize;
  std::uint8_t resource_type = 0;
  std::uint8_t flags = 0;
  std::uint8_t host_length = 0;
  std::uint8_t reserved = 0;
  std::array<std::uint8_t, kMemoryCacheReuseHostSize> host{};
};

[[nodiscard]] inline bool DecodeMemoryCacheReusePayload(std::span<const std::byte> bytes,
                                                        MemoryCacheReusePayload& value) noexcept {
  if (bytes.size() < kMemoryCacheReusePayloadSize)
    return false;
  const auto at = [bytes](const std::size_t offset) {
    return std::to_integer<std::uint8_t>(bytes[offset]);
  };
  value.version = static_cast<std::uint16_t>(at(0) | (at(1) << 8U));
  value.size = static_cast<std::uint16_t>(at(2) | (at(3) << 8U));
  value.resource_type = at(4);
  value.flags = at(5);
  value.host_length = at(6);
  value.reserved = at(7);
  for (std::size_t index = 0; index < value.host.size(); ++index)
    value.host[index] = at(8 + index);
  return true;
}

[[nodiscard]] constexpr bool IsValidMemoryCacheReusePayload(
    const MemoryCacheReusePayload& value) noexcept {
  // Version 1 records, from before the source was named, stay valid.
  const std::uint8_t known_flags =
      kMemoryCacheReuseStaticData | kMemoryCacheReuseHostTruncated |
      (value.version >= 2 ? kMemoryCacheReuseSourceNamed : std::uint8_t{0});
  if (value.version == 0 || value.version > kMemoryCacheReusePayloadVersion ||
      value.size != kMemoryCacheReusePayloadSize || value.resource_type == 0 ||
      value.resource_type > kMemoryCacheReuseResourceTypeLimit ||
      (value.flags & static_cast<std::uint8_t>(~known_flags)) != 0 ||
      ((value.flags & kMemoryCacheReuseSourceNamed) != 0 &&
       (value.flags & kMemoryCacheReuseStaticData) != 0) ||
      value.host_length > kMemoryCacheReuseHostSize || value.reserved != 0 ||
      ((value.flags & kMemoryCacheReuseHostTruncated) != 0 &&
       value.host_length != kMemoryCacheReuseHostSize)) {
    return false;
  }
  for (std::size_t index = 0; index < value.host.size(); ++index) {
    const std::uint8_t byte = value.host[index];
    if (index < value.host_length ? byte < 0x21 || byte > 0x7e : byte != 0)
      return false;
  }
  return true;
}

[[nodiscard]] inline bool IsValidMemoryCacheReuseEvent(const EventRecord& event) noexcept {
  const auto& h = event.header;
  MemoryCacheReusePayload value;
  return h.category == EventCategory::kNetwork && h.type == EventType::kMemoryCacheReuse &&
         h.payload_size == kMemoryCacheReusePayloadSize && h.flags == 0 && h.session_id != 0 &&
         h.sequence_number != 0 && h.process_id != 0 && h.navigation_id == 0 &&
         h.artifact_id == 0 && h.parent_event_id == 0 && h.browser_context_id_high == 0 &&
         h.browser_context_id_low == 0 && h.encoded_data_length == 0 &&
         h.decoded_body_length >= 0 && h.status_code >= 0 && h.error_code == 0 &&
         h.resource_type == 0 && h.scheme_class != 0 && IsRendererLoaderKind(h.loader_kind) &&
         DecodeMemoryCacheReusePayload(event.inline_payload, value) &&
         IsValidMemoryCacheReusePayload(value) &&
         ((value.flags & kMemoryCacheReuseSourceNamed) != 0
              ? h.initiator_process_id == h.process_id && h.initiator_request_id != 0
              : h.initiator_request_id == 0 && h.initiator_process_id == 0);
}
}  // namespace reb
#endif
