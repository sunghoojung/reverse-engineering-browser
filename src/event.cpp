#include "reb/event.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <locale>
#include <sstream>

namespace reb {

namespace {

constexpr std::uint16_t kKnownEventFlags =
    static_cast<std::uint16_t>(EventFlag::kPayloadTruncated) |
    static_cast<std::uint16_t>(EventFlag::kFromCache) |
    static_cast<std::uint16_t>(EventFlag::kFromServiceWorker);

constexpr std::uint16_t ClearEventFlag(const std::uint16_t flags, const EventFlag flag) noexcept {
  const auto flag_mask = static_cast<std::uint16_t>(flag);
  return static_cast<std::uint16_t>(flags & static_cast<std::uint16_t>(~flag_mask));
}

bool IsKnownCategory(const EventCategory category) noexcept {
  switch (category) {
    case EventCategory::kCanvas:
    case EventCategory::kWebGl:
    case EventCategory::kWebAudio:
    case EventCategory::kNavigator:
    case EventCategory::kPermissions:
    case EventCategory::kStorage:
    case EventCategory::kWebRtc:
    case EventCategory::kWasm:
    case EventCategory::kNetwork:
    case EventCategory::kVm:
      return true;
    case EventCategory::kUnknown:
      return false;
  }
  return false;
}

bool IsKnownType(const EventType type) noexcept {
  switch (type) {
    case EventType::kApiCall:
    case EventType::kPropertyRead:
    case EventType::kModuleCompiled:
    case EventType::kModuleInstantiated:
    case EventType::kRequestStarted:
    case EventType::kResponseCompleted:
    case EventType::kGap:
    case EventType::kRequestInitiated:
    case EventType::kRequestRedirected:
    case EventType::kResponseStarted:
    case EventType::kRequestCompleted:
    case EventType::kRequestFailed:
    case EventType::kVmFinding:
      return true;
    case EventType::kUnknown:
      return false;
  }
  return false;
}

}  // namespace

EventRecord MakeEvent(const EventCategory category,
                      const EventType type,
                      const std::uint64_t sequence_number,
                      const std::uint64_t monotonic_time_ns,
                      const std::uint64_t session_id) noexcept {
  EventRecord event{};
  event.header.category = category;
  event.header.type = type;
  event.header.sequence_number = sequence_number;
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.session_id = session_id;
  return event;
}

bool SetInlinePayload(EventRecord& event, const std::span<const std::byte> payload) noexcept {
  if (payload.size() > event.inline_payload.size()) {
    return false;
  }

  std::fill(event.inline_payload.begin(), event.inline_payload.end(), std::byte{0});
  std::copy(payload.begin(), payload.end(), event.inline_payload.begin());
  event.header.payload_size = static_cast<std::uint32_t>(payload.size());
  event.header.flags = ClearEventFlag(event.header.flags, EventFlag::kPayloadTruncated);
  return true;
}

bool SetInlinePayload(EventRecord& event, const std::string_view payload) noexcept {
  const auto* data = reinterpret_cast<const std::byte*>(payload.data());
  return SetInlinePayload(event, std::span<const std::byte>(data, payload.size()));
}

void SetInlinePayloadPrefix(EventRecord& event, const std::string_view payload) noexcept {
  event.header.flags = ClearEventFlag(event.header.flags, EventFlag::kPayloadTruncated);
  const std::size_t size = std::min(payload.size(), event.inline_payload.size());
  const auto* data = reinterpret_cast<const std::byte*>(payload.data());
  static_cast<void>(SetInlinePayload(event, std::span<const std::byte>(data, size)));
  if (size != payload.size()) {
    event.header.flags |= static_cast<std::uint16_t>(EventFlag::kPayloadTruncated);
  }
}

std::span<const std::byte> InlinePayload(const EventRecord& event) noexcept {
  const std::size_t size =
      std::min<std::size_t>(event.header.payload_size, event.inline_payload.size());
  return std::span<const std::byte>(event.inline_payload.data(), size);
}

bool IsValidEvent(const EventRecord& event) noexcept {
  return event.header.protocol_version == kEventProtocolVersion &&
         event.header.header_size == sizeof(EventHeader) &&
         event.header.payload_size <= event.inline_payload.size() && event.header.reserved0 == 0 &&
         event.header.reserved1 == 0 && IsKnownCategory(event.header.category) &&
         IsKnownType(event.header.type) &&
         (event.header.flags & static_cast<std::uint16_t>(~kKnownEventFlags)) == 0 &&
         std::ranges::all_of(event.reserved,
                             [](const std::byte value) { return value == std::byte{0}; });
}

std::string EventToJson(const EventRecord& event) {
  constexpr std::array<char, 16> kHex = {'0', '1', '2', '3', '4', '5', '6', '7',
                                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string payload_hex;
  payload_hex.reserve(InlinePayload(event).size() * 2);
  for (const std::byte value : InlinePayload(event)) {
    const auto byte_value = static_cast<unsigned int>(std::to_integer<unsigned char>(value));
    payload_hex.push_back(kHex[(byte_value >> 4U) & 0x0fU]);
    payload_hex.push_back(kHex[byte_value & 0x0fU]);
  }

  std::ostringstream output;
  output.imbue(std::locale::classic());
  output << '{' << "\"protocol_version\":" << event.header.protocol_version << ','
         << "\"session_id\":\"" << event.header.session_id << "\","
         << "\"sequence_number\":\"" << event.header.sequence_number << "\","
         << "\"monotonic_time_ns\":\"" << event.header.monotonic_time_ns << "\","
         << "\"process_id\":" << event.header.process_id << ','
         << "\"thread_id\":" << event.header.thread_id << ',' << "\"navigation_id\":\""
         << event.header.navigation_id << "\","
         << "\"frame_id\":\"" << event.header.frame_id << "\","
         << "\"artifact_id\":\"" << event.header.artifact_id << "\","
         << "\"parent_event_id\":\"" << event.header.parent_event_id << "\","
         << "\"request_id\":\"" << event.header.request_id << "\","
         << "\"browser_context_id_high\":\"" << event.header.browser_context_id_high << "\","
         << "\"browser_context_id_low\":\"" << event.header.browser_context_id_low << "\","
         << "\"encoded_data_length\":\"" << event.header.encoded_data_length << "\","
         << "\"decoded_body_length\":\"" << event.header.decoded_body_length << "\","
         << "\"status_code\":" << event.header.status_code << ','
         << "\"error_code\":" << event.header.error_code << ','
         << "\"resource_type\":" << event.header.resource_type << ','
         << "\"flags\":" << event.header.flags << ','
         << "\"initiator_request_id\":" << event.header.initiator_request_id << ','
         << "\"initiator_process_id\":" << event.header.initiator_process_id << ','
         << "\"payload_truncated\":"
         << ((event.header.flags & static_cast<std::uint16_t>(EventFlag::kPayloadTruncated)) != 0
                 ? "true"
                 : "false")
         << ',' << "\"category\":\"" << EventCategoryName(event.header.category) << "\","
         << "\"type\":\"" << EventTypeName(event.header.type) << "\","
         << "\"payload_size\":" << event.header.payload_size << ','
         << "\"payload_encoding\":\"hex\","
         << "\"payload\":\"" << payload_hex << "\"}";
  return output.str();
}

std::string_view EventCategoryName(const EventCategory category) noexcept {
  switch (category) {
    case EventCategory::kCanvas:
      return "canvas";
    case EventCategory::kWebGl:
      return "webgl";
    case EventCategory::kWebAudio:
      return "web_audio";
    case EventCategory::kNavigator:
      return "navigator";
    case EventCategory::kPermissions:
      return "permissions";
    case EventCategory::kStorage:
      return "storage";
    case EventCategory::kWebRtc:
      return "webrtc";
    case EventCategory::kWasm:
      return "wasm";
    case EventCategory::kNetwork:
      return "network";
    case EventCategory::kVm:
      return "vm";
    case EventCategory::kUnknown:
      return "unknown";
  }
  return "unknown";
}

std::string_view EventTypeName(const EventType type) noexcept {
  switch (type) {
    case EventType::kApiCall:
      return "api_call";
    case EventType::kPropertyRead:
      return "property_read";
    case EventType::kModuleCompiled:
      return "module_compiled";
    case EventType::kModuleInstantiated:
      return "module_instantiated";
    case EventType::kRequestStarted:
      return "request_started";
    case EventType::kResponseCompleted:
      return "response_completed";
    case EventType::kGap:
      return "gap";
    case EventType::kRequestInitiated:
      return "request_initiated";
    case EventType::kRequestRedirected:
      return "request_redirected";
    case EventType::kResponseStarted:
      return "response_started";
    case EventType::kRequestCompleted:
      return "request_completed";
    case EventType::kRequestFailed:
      return "request_failed";
    case EventType::kVmFinding:
      return "vm_finding";
    case EventType::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace reb
