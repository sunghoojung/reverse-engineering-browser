#ifndef REB_DEBUGGER_OBSERVATION_HPP_
#define REB_DEBUGGER_OBSERVATION_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "reb/event.hpp"
#include "reb/request_stack.hpp"

// Non-pausing debugger observations, protocol/native-debugger-observation-v1.md.
namespace reb {

inline constexpr std::size_t kObservationStackSummaryBytes = 80;
inline constexpr std::size_t kObservationTailBytes = 48;
inline constexpr std::size_t kObservationEventTypeBytes = 27;
inline constexpr std::size_t kObservationHostBytes = 45;
inline constexpr std::size_t kObservationAttributeBytes = 32;
inline constexpr std::uint32_t kObservationRequestRules = 8;
inline constexpr std::uint32_t kObservationEventRules = 16;
inline constexpr std::uint32_t kObservationDomNodes = 4;
inline constexpr std::uint32_t kObservationBudget = 1024;

struct ObservationPayload final {
  RequestStackPayload stack{};
};
static_assert(sizeof(ObservationPayload) == kInlinePayloadSize);
static_assert(offsetof(RequestStackPayload, reserved1) == kObservationStackSummaryBytes);

[[nodiscard]] inline std::span<const std::uint8_t> ObservationTail(
    const ObservationPayload& value) noexcept {
  return value.stack.reserved1;
}

namespace observation_detail {
[[nodiscard]] inline bool Envelope(const EventRecord& event,
                                   const EventCategory category,
                                   const EventType type,
                                   const bool parent_required) noexcept {
  const auto& h = event.header;
  return h.protocol_version == kEventProtocolVersion && h.category == category && h.type == type &&
         h.payload_size == kInlinePayloadSize && h.flags == 0 && h.session_id != 0 &&
         h.sequence_number != 0 && h.process_id != 0 &&
         (parent_required ? h.parent_event_id != 0 : true) &&
         (h.parent_event_id == 0 || h.parent_event_id < h.sequence_number) && h.artifact_id == 0 &&
         h.navigation_id == 0 && h.status_code == 0 && h.error_code == 0 &&
         h.encoded_data_length == 0 && h.decoded_body_length == 0 && h.resource_type == 0 &&
         h.initiator_request_id == 0 && h.initiator_process_id == 0;
}

[[nodiscard]] inline bool StackSummary(const ObservationPayload& value) noexcept {
  RequestStackPayload prefix = value.stack;
  prefix.reserved1 = {};
  return prefix.protocol_version == kRequestStackPayloadVersion &&
         IsValidRequestStackPayload(prefix);
}

[[nodiscard]] inline bool AsciiName(std::span<const std::uint8_t> bytes,
                                    const std::uint8_t length,
                                    const bool require) noexcept {
  if (length > bytes.size() || (require && length == 0)) {
    return false;
  }
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const std::uint8_t c = bytes[i];
    if (i >= length ? c != 0 : (c <= 0x20 || c >= 0x7f)) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] inline bool OptionalFrame(std::span<const std::uint8_t> bytes) noexcept {
  const auto frame = request_stack_detail::Decode<StackFrame>(std::as_bytes(bytes));
  return frame == StackFrame{} ||
         (frame.kind == static_cast<std::uint8_t>(StackFrameKind::kJavaScript) &&
          IsValidStackFrame(frame, false));
}
}  // namespace observation_detail

[[nodiscard]] inline bool IsValidObservationTail(const EventType type,
                                                 std::span<const std::uint8_t> t) noexcept {
  using observation_detail::AsciiName;
  using observation_detail::OptionalFrame;
  using request_stack_detail::AllZero;
  switch (type) {
    case EventType::kRequestWatchMatch:
      return t[0] < kObservationRequestRules && (t[1] & ~1U) == 0 && AllZero(t.subspan(2));
    case EventType::kListenerDispatch:
      return t[0] < kObservationEventRules && t[1] >= 1 && t[1] <= 5 &&
             OptionalFrame(t.subspan(4, 16)) &&
             AsciiName(t.subspan(21, kObservationEventTypeBytes), t[20], true);
    case EventType::kTimerObservation:
      return t[0] >= 1 && t[0] <= 2 && t[1] >= 1 && t[1] <= 2 && t[3] == 0 && (t[2] & ~1U) == 0 &&
             OptionalFrame(t.subspan(12, 16)) && AllZero(t.subspan(28));
    case EventType::kCspViolation:
      return t[1] >= 1 && t[1] <= 2 && AsciiName(t.subspan(3, kObservationHostBytes), t[2], false);
    case EventType::kExceptionObservation:
      return t[0] >= 1 && t[0] <= 3 && AllZero(t.subspan(1, 3)) &&
             OptionalFrame(t.subspan(4, 16)) && AllZero(t.subspan(20));
    case EventType::kDomMutation:
      return t[0] >= 1 && t[0] <= 3 && t[1] < kObservationDomNodes &&
             AsciiName(t.subspan(5, kObservationAttributeBytes), t[4], t[0] == 1) &&
             (t[0] == 1 || t[4] == 0) && AllZero(t.subspan(37));
    default:
      return false;
  }
}

[[nodiscard]] inline bool IsValidObservationEvent(const EventRecord& event) noexcept {
  const EventType type = event.header.type;
  const bool request = type == EventType::kRequestWatchMatch;
  if (!observation_detail::Envelope(
          event, request ? EventCategory::kNetwork : EventCategory::kRuntime, type, request) ||
      (request ? event.header.request_id == 0 : event.header.request_id != 0)) {
    return false;
  }
  const auto value = request_stack_detail::Decode<ObservationPayload>(event.inline_payload);
  return observation_detail::StackSummary(value) &&
         IsValidObservationTail(type, ObservationTail(value));
}

}  // namespace reb

#endif  // REB_DEBUGGER_OBSERVATION_HPP_
