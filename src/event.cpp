#include "reb/event.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>

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
    case EventCategory::kArtifact:
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
    case EventType::kArtifactCaptured:
    case EventType::kArtifactCaptureFailed:
      return true;
    case EventType::kUnknown:
      return false;
  }
  return false;
}

template <typename Integer>
void AppendInteger(std::string& output, const Integer value) {
  std::array<char, std::numeric_limits<Integer>::digits10 + 3> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  output.append(buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data()));
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
  const std::span<const std::byte> payload = InlinePayload(event);
  std::string output;
  output.reserve(768 + payload.size() * 2);
  output.append("{\"protocol_version\":");
  AppendInteger(output, event.header.protocol_version);
  output.append(",\"session_id\":\"");
  AppendInteger(output, event.header.session_id);
  output.append("\",\"sequence_number\":\"");
  AppendInteger(output, event.header.sequence_number);
  output.append("\",\"monotonic_time_ns\":\"");
  AppendInteger(output, event.header.monotonic_time_ns);
  output.append("\",\"process_id\":");
  AppendInteger(output, event.header.process_id);
  output.append(",\"thread_id\":");
  AppendInteger(output, event.header.thread_id);
  output.append(",\"navigation_id\":\"");
  AppendInteger(output, event.header.navigation_id);
  output.append("\",\"frame_id\":\"");
  AppendInteger(output, event.header.frame_id);
  output.append("\",\"artifact_id\":\"");
  AppendInteger(output, event.header.artifact_id);
  output.append("\",\"parent_event_id\":\"");
  AppendInteger(output, event.header.parent_event_id);
  output.append("\",\"request_id\":\"");
  AppendInteger(output, event.header.request_id);
  output.append("\",\"browser_context_id_high\":\"");
  AppendInteger(output, event.header.browser_context_id_high);
  output.append("\",\"browser_context_id_low\":\"");
  AppendInteger(output, event.header.browser_context_id_low);
  output.append("\",\"encoded_data_length\":\"");
  AppendInteger(output, event.header.encoded_data_length);
  output.append("\",\"decoded_body_length\":\"");
  AppendInteger(output, event.header.decoded_body_length);
  output.append("\",\"status_code\":");
  AppendInteger(output, event.header.status_code);
  output.append(",\"error_code\":");
  AppendInteger(output, event.header.error_code);
  output.append(",\"resource_type\":");
  AppendInteger(output, event.header.resource_type);
  output.append(",\"flags\":");
  AppendInteger(output, event.header.flags);
  output.append(",\"initiator_request_id\":");
  AppendInteger(output, event.header.initiator_request_id);
  output.append(",\"initiator_process_id\":");
  AppendInteger(output, event.header.initiator_process_id);
  output.append(",\"payload_truncated\":");
  output.append((event.header.flags & static_cast<std::uint16_t>(EventFlag::kPayloadTruncated)) != 0
                    ? "true"
                    : "false");
  output.append(",\"category\":\"");
  output.append(EventCategoryName(event.header.category));
  output.append("\",\"type\":\"");
  output.append(EventTypeName(event.header.type));
  output.append("\",\"payload_size\":");
  AppendInteger(output, event.header.payload_size);
  output.append(",\"payload_encoding\":\"hex\",\"payload\":\"");
  for (const std::byte value : payload) {
    const auto byte_value = static_cast<unsigned int>(std::to_integer<unsigned char>(value));
    output.push_back(kHex[(byte_value >> 4U) & 0x0fU]);
    output.push_back(kHex[byte_value & 0x0fU]);
  }
  output.append("\"}");
  return output;
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
    case EventCategory::kArtifact:
      return "artifact";
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
    case EventType::kArtifactCaptured:
      return "artifact_captured";
    case EventType::kArtifactCaptureFailed:
      return "artifact_capture_failed";
    case EventType::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace reb
