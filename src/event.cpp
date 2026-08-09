#include "reb/event.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>

namespace reb {

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

bool SetInlinePayload(EventRecord& event,
                      const std::span<const std::byte> payload) noexcept {
  if (payload.size() > event.inline_payload.size()) {
    return false;
  }

  std::fill(event.inline_payload.begin(), event.inline_payload.end(), std::byte{0});
  std::copy(payload.begin(), payload.end(), event.inline_payload.begin());
  event.header.payload_size = static_cast<std::uint32_t>(payload.size());
  return true;
}

bool SetInlinePayload(EventRecord& event, const std::string_view payload) noexcept {
  const auto* data = reinterpret_cast<const std::byte*>(payload.data());
  return SetInlinePayload(event, std::span<const std::byte>(data, payload.size()));
}

std::span<const std::byte> InlinePayload(const EventRecord& event) noexcept {
  const std::size_t size = std::min<std::size_t>(event.header.payload_size,
                                                 event.inline_payload.size());
  return std::span<const std::byte>(event.inline_payload.data(), size);
}

bool IsValidEvent(const EventRecord& event) noexcept {
  return event.header.protocol_version == kEventProtocolVersion &&
         event.header.header_size == sizeof(EventHeader) &&
         event.header.payload_size <= event.inline_payload.size();
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
  output << '{'
         << "\"protocol_version\":" << event.header.protocol_version << ','
         << "\"session_id\":" << event.header.session_id << ','
         << "\"sequence_number\":" << event.header.sequence_number << ','
         << "\"monotonic_time_ns\":" << event.header.monotonic_time_ns << ','
         << "\"process_id\":" << event.header.process_id << ','
         << "\"thread_id\":" << event.header.thread_id << ','
         << "\"navigation_id\":" << event.header.navigation_id << ','
         << "\"frame_id\":" << event.header.frame_id << ','
         << "\"artifact_id\":" << event.header.artifact_id << ','
         << "\"parent_event_id\":" << event.header.parent_event_id << ','
         << "\"category\":\"" << EventCategoryName(event.header.category) << "\","
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
    case EventType::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace reb
