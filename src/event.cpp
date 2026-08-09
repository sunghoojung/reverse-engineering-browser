#include "reb/event.hpp"

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
