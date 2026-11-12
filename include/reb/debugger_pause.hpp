#ifndef REB_DEBUGGER_PAUSE_HPP_
#define REB_DEBUGGER_PAUSE_HPP_

#include <cstddef>
#include <cstdint>
#include <span>

#include "reb/debugger_observation.hpp"
#include "reb/event.hpp"
#include "reb/request_stack.hpp"

// What the pausing debugger did, protocol/native-debugger-pause-v1.md. These
// records say that a page was stopped, stepped or resumed and why. They never
// carry a function name, expression, value, property name, URL or condition:
// everything the debugger reads while paused stays in the renderer.
namespace reb {

inline constexpr std::uint8_t kDebuggerAttachPhaseAttach = 1;
inline constexpr std::uint8_t kDebuggerAttachPhaseDetach = 2;
// Why an authorization ended. Attach always carries kDebuggerClearNone.
inline constexpr std::uint8_t kDebuggerClearNone = 0;
inline constexpr std::uint8_t kDebuggerClearNavigated = 1;
inline constexpr std::uint8_t kDebuggerClearReleased = 2;
inline constexpr std::uint8_t kDebuggerClearReplaced = 3;
inline constexpr std::uint8_t kDebuggerClearPeerLost = 4;
inline constexpr std::uint8_t kDebuggerClearIdle = 5;
// 1 breakpoint, 2 exception, 3 step, 4 pause, 5 the page's own `debugger;`.
// Numbers 6 to 9 are reserved for a later phase; version 1 cannot produce
// them, so this core refuses them.
inline constexpr std::uint8_t kDebuggerPauseReasonMax = 5;
// Only a breakpoint pause names a breakpoint.
inline constexpr std::uint8_t kDebuggerPauseReasonBreakpoint = 1;
inline constexpr std::uint8_t kDebuggerPauseFramesTruncated = 1U << 0U;
// 1 resume, 2 step, 3 release, 4 expired, 5 cleared, 6 a stop in another
// document of the same context group that was ended at once, 7 a pause
// something else continued.
inline constexpr std::uint8_t kDebuggerResumeEndMax = 7;
inline constexpr std::uint8_t kDebuggerBreakpointPhaseRefused = 3;
// 1 line, 2 conditional, 3 logpoint: every kind an inspector session can
// serve, and every one of them positioned in a script. The DevTools XHR,
// event listener, DOM and CSP breakpoints are Blink's DOMDebugger domain,
// which a session does not dispatch, so this contract has no number for
// them; native debugger observation v1 records all four without pausing.
inline constexpr std::uint8_t kDebuggerBreakpointKindMax = 3;
inline constexpr std::uint32_t kDebuggerBreakpointLimit = 64;
// The pause stack uses the request-stack bounds, so one reader fits both.
inline constexpr std::uint32_t kDebuggerFrameLimit = kRequestStackSyncLimit;
inline constexpr std::uint32_t kDebuggerAsyncFrameLimit = kRequestStackAsyncLimit;

namespace debugger_pause_detail {
[[nodiscard]] inline std::uint16_t Read16(std::span<const std::uint8_t> tail,
                                          const std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(tail[offset] |
                                    static_cast<std::uint16_t>(tail[offset + 1] << 8U));
}
[[nodiscard]] inline std::uint32_t Read32(std::span<const std::uint8_t> tail,
                                          const std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(Read16(tail, offset)) |
         (static_cast<std::uint32_t>(Read16(tail, offset + 2)) << 16U);
}
[[nodiscard]] inline std::uint64_t Read64(std::span<const std::uint8_t> tail,
                                          const std::size_t offset) noexcept {
  return static_cast<std::uint64_t>(Read32(tail, offset)) |
         (static_cast<std::uint64_t>(Read32(tail, offset + 4)) << 32U);
}
}  // namespace debugger_pause_detail

[[nodiscard]] inline bool IsValidDebuggerPauseTail(const EventType type,
                                                   std::span<const std::uint8_t> t) noexcept {
  using debugger_pause_detail::Read16;
  using debugger_pause_detail::Read32;
  using debugger_pause_detail::Read64;
  using request_stack_detail::AllZero;
  switch (type) {
    case EventType::kDebuggerAttached: {
      const bool attach = t[0] == kDebuggerAttachPhaseAttach;
      return (attach || t[0] == kDebuggerAttachPhaseDetach) &&
             (attach ? t[1] == kDebuggerClearNone && Read32(t, 4) == 0
                     : t[1] >= kDebuggerClearNavigated && t[1] <= kDebuggerClearIdle) &&
             AllZero(t.subspan(2, 2)) && AllZero(t.subspan(8));
    }
    case EventType::kDebuggerPaused:
      return t[0] >= 1 && t[0] <= kDebuggerPauseReasonMax &&
             (t[1] & ~kDebuggerPauseFramesTruncated) == 0 && Read16(t, 2) <= kDebuggerFrameLimit &&
             Read16(t, 4) <= kDebuggerAsyncFrameLimit && AllZero(t.subspan(6, 2)) &&
             Read64(t, 8) != 0 && (t[0] == kDebuggerPauseReasonBreakpoint || Read32(t, 16) == 0) &&
             AllZero(t.subspan(20));
    case EventType::kDebuggerResumed:
      return t[0] >= 1 && t[0] <= kDebuggerResumeEndMax && AllZero(t.subspan(1, 3)) &&
             Read64(t, 8) != 0 && AllZero(t.subspan(16));
    case EventType::kDebuggerBreakpoint: {
      const bool refused = t[0] == kDebuggerBreakpointPhaseRefused;
      return t[0] >= 1 && t[0] <= kDebuggerBreakpointPhaseRefused && t[1] >= 1 &&
             t[1] <= kDebuggerBreakpointKindMax && AllZero(t.subspan(2, 2)) &&
             (refused ? Read32(t, 12) == 0 : Read32(t, 12) != 0) && AllZero(t.subspan(16));
    }
    default:
      return false;
  }
}

// Each record stands alone: a resumed record carries the lease id of the
// pause it ends, which is a stronger join than a parent pointer because both
// records already hold it and neither needs the other's sequence number.
[[nodiscard]] inline bool IsValidDebuggerPauseEvent(const EventRecord& event) noexcept {
  const EventType type = event.header.type;
  if (!observation_detail::Envelope(event, EventCategory::kRuntime, type, false) ||
      event.header.request_id != 0 || event.header.frame_id == 0 ||
      event.header.parent_event_id != 0) {
    return false;
  }
  const auto value = request_stack_detail::Decode<ObservationPayload>(event.inline_payload);
  return observation_detail::StackSummary(value) &&
         IsValidDebuggerPauseTail(type, ObservationTail(value));
}

}  // namespace reb

#endif  // REB_DEBUGGER_PAUSE_HPP_
