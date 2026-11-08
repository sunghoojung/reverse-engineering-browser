#ifndef REB_TAB_LINK_HPP_
#define REB_TAB_LINK_HPP_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include "reb/event.hpp"
namespace reb {
// Loader kinds, tab sets and request tab links, see protocol/native-network-v3.md.
// The overlay's common/native_tab_link.h is the producer half;
// tests/tab_link_test.cpp keeps the two in step.
enum class LoaderKind : std::uint8_t {
  kNotRecorded = 0,
  kNavigation = 1,
  kDownload = 2,
  kDocumentSubresource = 3,
  kWorkerMainResource = 4,
  kWorkerSubresource = 5,
  kServiceWorkerScript = 6,
  kServiceWorkerSubresource = 7,
  kPrefetch = 8,
  kDevTools = 9,
  kEarlyHints = 10,
  kDocument = 16,
  kDedicatedWorker = 17,
  kSharedWorker = 18,
  kServiceWorker = 19,
  kOtherContext = 20,
  kScriptContext = 21,
};

enum class TabLinkKind : std::uint8_t {
  kDedicatedWorker = 1,
  kSharedWorkerClients = 2,
  kServiceWorkerClients = 3,
  kServiceWorkerLastClients = 4,
};

inline constexpr std::uint16_t kTabSetPayloadVersion = 1;
inline constexpr std::size_t kTabSetPayloadSize = 128;
inline constexpr std::size_t kTabSetPartTabs = 26;
inline constexpr std::uint8_t kTabSetLastClients = 1;
inline constexpr std::uint16_t kRequestTabLinkPayloadVersion = 1;
inline constexpr std::size_t kRequestTabLinkPayloadSize = 24;
inline constexpr std::uint16_t kRequestExtensionLinkPayloadVersion = 1;
inline constexpr std::size_t kRequestExtensionLinkPayloadSize = 40;
inline constexpr std::size_t kExtensionIdSize = 32;

[[nodiscard]] constexpr bool IsBrowserLoaderKind(const std::uint8_t value) noexcept {
  return value >= 1 && value <= 10;
}

[[nodiscard]] constexpr bool IsRendererLoaderKind(const std::uint8_t value) noexcept {
  return value >= 16 && value <= 21;
}

[[nodiscard]] constexpr bool IsWorkerOwnerKind(const std::uint8_t value) noexcept {
  return value >= 17 && value <= 19;
}

// Browser kinds only on request_started, renderer kinds only on request_initiated.
[[nodiscard]] constexpr bool IsValidLoaderKind(const EventHeader& header) noexcept {
  if (header.loader_kind == 0)
    return true;
  if (header.category != EventCategory::kNetwork)
    return false;
  return header.type == EventType::kRequestStarted     ? IsBrowserLoaderKind(header.loader_kind)
         : header.type == EventType::kRequestInitiated ? IsRendererLoaderKind(header.loader_kind)
                                                       : false;
}

namespace tab_link_detail {
inline std::uint64_t At(const std::span<const std::byte> bytes,
                        const std::size_t offset,
                        const std::size_t size) noexcept {
  std::uint64_t result = 0;
  for (std::size_t index = 0; index < size; ++index)
    result |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[offset + index]))
              << (8U * index);
  return result;
}

inline bool QuietLinkFields(const EventHeader& h) noexcept {
  return h.navigation_id == 0 && h.artifact_id == 0 && h.encoded_data_length == 0 &&
         h.decoded_body_length == 0 && h.status_code == 0 && h.error_code == 0 &&
         h.resource_type == 0 && h.flags == 0 && h.scheme_class == 0 && h.loader_kind == 0;
}

inline bool ZeroRequestFields(const EventHeader& h) noexcept {
  return QuietLinkFields(h) && h.request_id == 0 && h.browser_context_id_high == 0 &&
         h.browser_context_id_low == 0;
}

// A browser record without a renderer request is named by its request id and context.
inline bool NamesBrowserRecord(const EventHeader& h) noexcept {
  return h.initiator_process_id == 0 && h.initiator_request_id == 0 && h.request_id != 0 &&
         (h.browser_context_id_high != 0 || h.browser_context_id_low != 0);
}

inline bool NamesLinkedRecord(const EventHeader& h) noexcept {
  const bool renderer = h.initiator_process_id != 0 && h.request_id == 0 &&
                        h.browser_context_id_high == 0 && h.browser_context_id_low == 0;
  return QuietLinkFields(h) && h.parent_event_id != 0 && (renderer || NamesBrowserRecord(h));
}
}  // namespace tab_link_detail

struct TabSetPayload final {
  std::uint8_t owner_kind = 0;
  std::uint8_t flags = 0;
  std::uint16_t part_index = 0;
  std::uint64_t set_id = 0;
  std::uint32_t total_tabs = 0;
  std::uint16_t part_tabs = 0;
  std::array<std::uint32_t, kTabSetPartTabs> tabs{};
};

// Decodes a structurally valid payload; false for any malformed byte.
[[nodiscard]] inline bool DecodeTabSetPayload(const std::span<const std::byte> bytes,
                                              TabSetPayload& value) noexcept {
  using tab_link_detail::At;
  if (bytes.size() < kTabSetPayloadSize || At(bytes, 0, 2) != kTabSetPayloadVersion ||
      At(bytes, 2, 2) != kTabSetPayloadSize || At(bytes, 22, 2) != 0)
    return false;
  value.owner_kind = static_cast<std::uint8_t>(At(bytes, 4, 1));
  value.flags = static_cast<std::uint8_t>(At(bytes, 5, 1));
  value.part_index = static_cast<std::uint16_t>(At(bytes, 6, 2));
  value.set_id = At(bytes, 8, 8);
  value.total_tabs = static_cast<std::uint32_t>(At(bytes, 16, 4));
  value.part_tabs = static_cast<std::uint16_t>(At(bytes, 20, 2));
  for (std::size_t index = 0; index < kTabSetPartTabs; ++index)
    value.tabs[index] = static_cast<std::uint32_t>(At(bytes, 24 + 4 * index, 4));
  const std::uint64_t parts =
      (std::uint64_t{value.total_tabs} + kTabSetPartTabs - 1) / kTabSetPartTabs;
  const std::uint64_t before = std::uint64_t{value.part_index} * kTabSetPartTabs;
  if (!IsWorkerOwnerKind(value.owner_kind) || (value.flags & ~kTabSetLastClients) != 0 ||
      value.set_id == 0 || value.total_tabs == 0 || value.part_index >= parts ||
      value.part_tabs == 0 || value.part_tabs > kTabSetPartTabs ||
      value.part_tabs != std::min<std::uint64_t>(kTabSetPartTabs, value.total_tabs - before))
    return false;
  for (std::size_t index = 0; index < kTabSetPartTabs; ++index) {
    const bool used = index < value.part_tabs;
    if (used ? value.tabs[index] == 0 || (index > 0 && value.tabs[index] <= value.tabs[index - 1])
             : value.tabs[index] != 0)
      return false;
  }
  return true;
}

[[nodiscard]] inline bool IsValidTabSetEvent(const EventRecord& event) noexcept {
  const auto& h = event.header;
  TabSetPayload value;
  return h.category == EventCategory::kNetwork && h.type == EventType::kTabSet &&
         h.payload_size == kTabSetPayloadSize && h.session_id != 0 && h.sequence_number != 0 &&
         h.process_id != 0 && h.initiator_request_id == 0 && h.initiator_process_id == 0 &&
         tab_link_detail::ZeroRequestFields(h) &&
         DecodeTabSetPayload(event.inline_payload, value) && h.tab_id == value.tabs[0] &&
         (value.part_index == 0) == (h.parent_event_id == 0);
}

struct RequestTabLinkPayload final {
  std::uint8_t link_kind = 0;
  std::uint64_t set_id = 0;
  std::uint32_t tab_count = 0;
};

[[nodiscard]] inline bool DecodeRequestTabLinkPayload(const std::span<const std::byte> bytes,
                                                      RequestTabLinkPayload& value) noexcept {
  using tab_link_detail::At;
  if (bytes.size() < kRequestTabLinkPayloadSize ||
      At(bytes, 0, 2) != kRequestTabLinkPayloadVersion ||
      At(bytes, 2, 2) != kRequestTabLinkPayloadSize || At(bytes, 5, 3) != 0 ||
      At(bytes, 20, 4) != 0)
    return false;
  value.link_kind = static_cast<std::uint8_t>(At(bytes, 4, 1));
  value.set_id = At(bytes, 8, 8);
  value.tab_count = static_cast<std::uint32_t>(At(bytes, 16, 4));
  return value.link_kind >= 1 && value.link_kind <= 4 && value.set_id != 0 && value.tab_count != 0;
}

// tab_id is the set's only tab, else 0.
[[nodiscard]] inline bool IsValidRequestTabLinkEvent(const EventRecord& event) noexcept {
  const auto& h = event.header;
  RequestTabLinkPayload value;
  return h.category == EventCategory::kNetwork && h.type == EventType::kRequestTabLink &&
         h.payload_size == kRequestTabLinkPayloadSize && h.session_id != 0 &&
         h.sequence_number != 0 && h.process_id != 0 && tab_link_detail::NamesLinkedRecord(h) &&
         DecodeRequestTabLinkPayload(event.inline_payload, value) &&
         (value.tab_count == 1) == (h.tab_id != 0);
}

struct RequestExtensionLinkPayload final {
  std::uint8_t loader_kind = 0;
  std::array<char, kExtensionIdSize> extension_id{};
};

// Chromium extension ids are 32 letters a to p.
[[nodiscard]] inline bool DecodeRequestExtensionLinkPayload(
    const std::span<const std::byte> bytes,
    RequestExtensionLinkPayload& value) noexcept {
  using tab_link_detail::At;
  if (bytes.size() < kRequestExtensionLinkPayloadSize ||
      At(bytes, 0, 2) != kRequestExtensionLinkPayloadVersion ||
      At(bytes, 2, 2) != kRequestExtensionLinkPayloadSize || At(bytes, 5, 3) != 0)
    return false;
  value.loader_kind = static_cast<std::uint8_t>(At(bytes, 4, 1));
  for (std::size_t index = 0; index < kExtensionIdSize; ++index) {
    value.extension_id[index] = static_cast<char>(At(bytes, 8 + index, 1));
    if (value.extension_id[index] < 'a' || value.extension_id[index] > 'p')
      return false;
  }
  return value.loader_kind == static_cast<std::uint8_t>(LoaderKind::kWorkerMainResource) ||
         value.loader_kind == static_cast<std::uint8_t>(LoaderKind::kServiceWorkerScript) ||
         IsWorkerOwnerKind(value.loader_kind);
}

// A browser record is a worker script the browser fetched (loader kind 4 or 6).
[[nodiscard]] inline bool IsValidRequestExtensionLinkEvent(const EventRecord& event) noexcept {
  const auto& h = event.header;
  RequestExtensionLinkPayload value;
  return h.category == EventCategory::kNetwork && h.type == EventType::kRequestExtensionLink &&
         h.payload_size == kRequestExtensionLinkPayloadSize && h.session_id != 0 &&
         h.sequence_number != 0 && h.process_id != 0 && h.tab_id == 0 &&
         tab_link_detail::NamesLinkedRecord(h) &&
         DecodeRequestExtensionLinkPayload(event.inline_payload, value) &&
         tab_link_detail::NamesBrowserRecord(h) == !IsWorkerOwnerKind(value.loader_kind);
}
}  // namespace reb
#endif
