// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_DEBUGGER_PAUSE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_DEBUGGER_PAUSE_H_

#include <cstddef>
#include <cstdint>
#include <type_traits>

// Wire records of the pausing debugger, protocol/native-debugger-pause-v1.md.
// Same-machine, little-endian, no pointers and no allocation from an
// unchecked peer length. tests/debugger_pause_wire_test.cpp compiles this
// header on the host and checks every rule below.
namespace reb {

// The experiment. Its value is the command socket path the browser creates.
// Without it no agent, inspector session, channel, breakpoint table or
// socket exists; the renderer pays one command-line check per frame.
inline constexpr char kNativeDebuggerPauseSwitch[] = "reb-native-debugger";

inline constexpr std::uint32_t kNativeDebuggerPauseMagic = 0x44424552;
inline constexpr std::uint16_t kNativeDebuggerPauseVersion = 1;
inline constexpr std::uint32_t kNativeDebuggerPauseRequestLimit = 16384;
inline constexpr std::uint32_t kNativeDebuggerPauseReplyLimit = 1048576;
// The deadline the browser holds over every pause. It starts when the page
// stops, not when a client first asks, and the browser resumes the page when
// it runs out whether or not anything is still connected.
inline constexpr std::uint32_t kNativeDebuggerPauseLeaseMs = 60000;
// How long an authorization survives with no command at all. A client that
// goes away cannot leave breakpoints armed on a page for the rest of the
// session.
inline constexpr std::uint32_t kNativeDebuggerPauseIdleMs = 300000;
inline constexpr int kNativeDebuggerPauseReplyMs = 2000;
// Taken off the reply deadline when the browser stamps a command's
// execute-before, so the margin is left for writing the reply rather than
// spent running a command the client has already given up on.
inline constexpr int kNativeDebuggerPauseReplyMarginMs = 250;
// One pause's bounds. Frames match the request-stack walker so one reader
// fits both; see protocol/native-network-v3.md.
inline constexpr std::uint32_t kNativeDebuggerPauseFrameLimit = 1024;
inline constexpr std::uint32_t kNativeDebuggerPauseAsyncFrameLimit = 32;
inline constexpr std::uint32_t kNativeDebuggerPauseScopeLimit = 8;
inline constexpr std::uint32_t kNativeDebuggerPauseBreakpointLimit = 64;
inline constexpr std::uint32_t kNativeDebuggerPauseValueBytes = 2048;
inline constexpr std::uint32_t kNativeDebuggerPauseNameBytes = 128;
inline constexpr std::uint32_t kNativeDebuggerPausePropertyPage = 64;
inline constexpr std::uint32_t kNativeDebuggerPausePropertyLimit = 4096;
inline constexpr std::uint32_t kNativeDebuggerPauseObjectLimit = 1024;
inline constexpr std::uint32_t kNativeDebuggerPauseExpressionBytes = 8192;
// An evaluation on a paused frame that has not returned by then is refused
// with no result, so a watch cannot hold the nested loop open.
inline constexpr int kNativeDebuggerPauseEvaluationMs = 200;
// The object group every value this contract hands out belongs to, released
// as a group the moment the page resumes.
inline constexpr char kNativeDebuggerPauseObjectGroup[] = "reb-native-debugger-pause";

// The notice every state read and every action result carries while a
// document is selected. Pausing is detectable, so the interface and the tool
// results say so in the same words.
inline constexpr char kNativeDebuggerPauseActiveIndication[] = "Debugger active (detectable)";

enum class NativeDebuggerPauseOperation : std::uint16_t {
  kState = 1,
  kSelectDocument = 2,
  kReleaseDocument = 3,
  kSetBreakpoint = 4,
  kRemoveBreakpoint = 5,
  kPauseOnExceptions = 6,
  kPause = 7,
  kResume = 8,
  kStepOver = 9,
  kStepInto = 10,
  kStepOut = 11,
  kReleaseLease = 12,
  kEvaluateOnFrame = 13,
  kGetProperties = 14,
  // The last code the socket accepts. The backend never sends anything past
  // it, and the browser refuses a frame that does.
  kMaximum = kGetProperties,
  // Browser to renderer only: the deadline the browser holds has run out, or
  // the authorization went idle. Neither ever crosses the socket, so a client
  // can neither claim a lease expired nor keep one from expiring.
  kExpireLease = 15,
  kReleaseIdle = 16,
  kMaximumInternal = kReleaseIdle,
};

enum class NativeDebuggerPauseStatus : std::uint16_t {
  kOk = 0,
  kMalformed = 1,
  kStaleDocument = 2,
  kNotAuthorized = 3,
  kNotPaused = 4,
  kStaleLease = 5,
  kUnknownBreakpoint = 6,
  kUnknownObject = 7,
  kLimit = 8,
  kInvalidInput = 9,
  kEvaluationError = 10,
  kUnsupported = 11,
  // A command arrived while this session was already dispatching one.
  // Nothing ran. The pinned V8 postpones interrupts inside a DebugScope, so
  // this cannot happen during a paused evaluation; the guard stays because
  // failing closed is cheaper than reasoning about every future caller.
  kBusy = 12,
  // The deadline the browser carried into the renderer had already passed, so
  // the command did not run. No client reads this: the socket thread stopped
  // waiting first and reported the outcome unknown.
  kExpired = 13,
};

// Why an authorization ended, why a page stopped and how a pause ended, as
// the state reports them and as include/reb/debugger_pause.hpp records them.
// This header keeps its own copy of the numbers because a Chromium build has
// no include/reb; tests/debugger_pause_wire_test.cpp asserts the two agree,
// the way the probe event types already do.
inline constexpr std::uint8_t kNativeDebuggerPauseClearNone = 0;
inline constexpr std::uint8_t kNativeDebuggerPauseClearNavigated = 1;
inline constexpr std::uint8_t kNativeDebuggerPauseClearReleased = 2;
inline constexpr std::uint8_t kNativeDebuggerPauseClearReplaced = 3;
inline constexpr std::uint8_t kNativeDebuggerPauseClearPeerLost = 4;
// No command touched the authorization for the idle bound above, so it ended
// on its own. Told apart from a lost connection, which is a different event.
inline constexpr std::uint8_t kNativeDebuggerPauseClearIdle = 5;

// Why a page stopped, as event type 67 records it.
inline constexpr std::uint8_t kNativeDebuggerPauseReasonBreakpoint = 1;
inline constexpr std::uint8_t kNativeDebuggerPauseReasonException = 2;
inline constexpr std::uint8_t kNativeDebuggerPauseReasonStep = 3;
inline constexpr std::uint8_t kNativeDebuggerPauseReasonPause = 4;
inline constexpr std::uint8_t kNativeDebuggerPauseReasonDebuggerStatement = 5;

// Set in a pause record when the stack was longer than the frame bound. The
// core's copy is `kDebuggerPauseFramesTruncated`; a Chromium build does not
// see `include/reb`, so the number lives here too and the wire harness checks
// the two agree.
inline constexpr std::uint8_t kNativeDebuggerPauseFramesTruncated = 1U << 0U;

// How a pause ended, as event type 68 records it.
inline constexpr std::uint8_t kNativeDebuggerPauseEndResume = 1;
inline constexpr std::uint8_t kNativeDebuggerPauseEndStep = 2;
inline constexpr std::uint8_t kNativeDebuggerPauseEndRelease = 3;
inline constexpr std::uint8_t kNativeDebuggerPauseEndExpired = 4;
inline constexpr std::uint8_t kNativeDebuggerPauseEndCleared = 5;
// A stop in another document of the same context group, ended at once and
// never read, and a pause something else continued, a DevTools window on the
// same isolate for instance.
inline constexpr std::uint8_t kNativeDebuggerPauseEndForeign = 6;
inline constexpr std::uint8_t kNativeDebuggerPauseEndElsewhere = 7;

[[nodiscard]] constexpr const char* NativeDebuggerPauseStatusName(
    const NativeDebuggerPauseStatus status) noexcept {
  switch (status) {
    case NativeDebuggerPauseStatus::kOk:
      return "ok";
    case NativeDebuggerPauseStatus::kMalformed:
      return "malformed";
    case NativeDebuggerPauseStatus::kStaleDocument:
      return "stale_document";
    case NativeDebuggerPauseStatus::kNotAuthorized:
      return "not_authorized";
    case NativeDebuggerPauseStatus::kNotPaused:
      return "not_paused";
    case NativeDebuggerPauseStatus::kStaleLease:
      return "stale_lease";
    case NativeDebuggerPauseStatus::kUnknownBreakpoint:
      return "unknown_breakpoint";
    case NativeDebuggerPauseStatus::kUnknownObject:
      return "unknown_object";
    case NativeDebuggerPauseStatus::kLimit:
      return "limit";
    case NativeDebuggerPauseStatus::kInvalidInput:
      return "invalid_input";
    case NativeDebuggerPauseStatus::kEvaluationError:
      return "evaluation_error";
    case NativeDebuggerPauseStatus::kUnsupported:
      return "unsupported";
    case NativeDebuggerPauseStatus::kBusy:
      return "busy";
    case NativeDebuggerPauseStatus::kExpired:
      return "expired";
  }
  return "malformed";
}

// The action name this contract gives an operation code. Every reply names
// its action, including one refused before its body could be parsed, so the
// backend never has to report an outcome it was told.
[[nodiscard]] constexpr const char* NativeDebuggerPauseOperationName(
    const NativeDebuggerPauseOperation operation) noexcept {
  switch (operation) {
    case NativeDebuggerPauseOperation::kState:
      return "state";
    case NativeDebuggerPauseOperation::kSelectDocument:
      return "select_document";
    case NativeDebuggerPauseOperation::kReleaseDocument:
      return "release_document";
    case NativeDebuggerPauseOperation::kSetBreakpoint:
      return "set_breakpoint";
    case NativeDebuggerPauseOperation::kRemoveBreakpoint:
      return "remove_breakpoint";
    case NativeDebuggerPauseOperation::kPauseOnExceptions:
      return "pause_on_exceptions";
    case NativeDebuggerPauseOperation::kPause:
      return "pause";
    case NativeDebuggerPauseOperation::kResume:
      return "resume";
    case NativeDebuggerPauseOperation::kStepOver:
      return "step_over";
    case NativeDebuggerPauseOperation::kStepInto:
      return "step_into";
    case NativeDebuggerPauseOperation::kStepOut:
      return "step_out";
    case NativeDebuggerPauseOperation::kReleaseLease:
      return "release_lease";
    case NativeDebuggerPauseOperation::kEvaluateOnFrame:
      return "evaluate_on_frame";
    case NativeDebuggerPauseOperation::kGetProperties:
      return "get_properties";
    case NativeDebuggerPauseOperation::kExpireLease:
      return "expire_lease";
    case NativeDebuggerPauseOperation::kReleaseIdle:
      return "release_idle";
    default:
      return "";
  }
}

[[nodiscard]] constexpr const char* NativeDebuggerPauseClearName(
    const std::uint8_t reason) noexcept {
  switch (reason) {
    case kNativeDebuggerPauseClearNavigated:
      return "navigated";
    case kNativeDebuggerPauseClearReplaced:
      return "replaced";
    case kNativeDebuggerPauseClearIdle:
      return "idle";
    case kNativeDebuggerPauseClearPeerLost:
      return "peer_lost";
    default:
      return "released";
  }
}

struct NativeDebuggerPauseRequest final {
  std::uint32_t magic = kNativeDebuggerPauseMagic;
  std::uint16_t version = kNativeDebuggerPauseVersion;
  NativeDebuggerPauseOperation operation = NativeDebuggerPauseOperation::kState;
  std::uint64_t request_id = 0;
  // The Console document id, which is itself one document generation: a
  // navigation retires it and hands out a new one, so there is no second
  // identity for the two sides to disagree about.
  std::uint64_t target_id = 0;
  std::uint64_t reserved0 = 0;
  std::uint64_t lease_id = 0;
  std::uint32_t payload_size = 0;
  std::uint32_t reserved1 = 0;
};
static_assert(sizeof(NativeDebuggerPauseRequest) == 48);
static_assert(std::is_trivially_copyable_v<NativeDebuggerPauseRequest>);
static_assert(std::has_unique_object_representations_v<NativeDebuggerPauseRequest>);
static_assert(offsetof(NativeDebuggerPauseRequest, request_id) == 8);
static_assert(offsetof(NativeDebuggerPauseRequest, target_id) == 16);
static_assert(offsetof(NativeDebuggerPauseRequest, reserved0) == 24);
static_assert(offsetof(NativeDebuggerPauseRequest, lease_id) == 32);
static_assert(offsetof(NativeDebuggerPauseRequest, payload_size) == 40);

// Bit 0 of the reply flags: this command let the page run again.
inline constexpr std::uint16_t kNativeDebuggerPauseResumed = 1;

struct NativeDebuggerPauseReply final {
  std::uint32_t magic = kNativeDebuggerPauseMagic;
  std::uint16_t version = kNativeDebuggerPauseVersion;
  NativeDebuggerPauseStatus status = NativeDebuggerPauseStatus::kOk;
  std::uint64_t request_id = 0;
  std::uint8_t paused = 0;
  std::uint8_t reserved0 = 0;
  std::uint16_t flags = 0;
  std::uint32_t payload_size = 0;
  std::uint64_t reserved1 = 0;
};
static_assert(sizeof(NativeDebuggerPauseReply) == 32);
static_assert(std::is_trivially_copyable_v<NativeDebuggerPauseReply>);
static_assert(std::has_unique_object_representations_v<NativeDebuggerPauseReply>);
static_assert(offsetof(NativeDebuggerPauseReply, request_id) == 8);
static_assert(offsetof(NativeDebuggerPauseReply, paused) == 16);
static_assert(offsetof(NativeDebuggerPauseReply, payload_size) == 20);

[[nodiscard]] constexpr bool IsValidNativeDebuggerPauseRequest(
    const NativeDebuggerPauseRequest& request) noexcept {
  return request.magic == kNativeDebuggerPauseMagic &&
         request.version == kNativeDebuggerPauseVersion && request.request_id != 0 &&
         request.reserved0 == 0 && request.reserved1 == 0 &&
         static_cast<std::uint16_t>(request.operation) >= 1 &&
         request.operation <= NativeDebuggerPauseOperation::kMaximum &&
         request.payload_size <= kNativeDebuggerPauseRequestLimit;
}

// A command that runs page JavaScript. V8 is not prepared to run script at an
// interrupt, so these two are posted to the paused main thread without one,
// exactly as DevTools does for the same inspector methods.
[[nodiscard]] constexpr bool NativeDebuggerPauseRunsScript(
    const NativeDebuggerPauseOperation operation) noexcept {
  return operation == NativeDebuggerPauseOperation::kEvaluateOnFrame ||
         operation == NativeDebuggerPauseOperation::kGetProperties;
}

// A command that needs the current pause and the lease the caller named.
[[nodiscard]] constexpr bool NativeDebuggerPauseNeedsLease(
    const NativeDebuggerPauseOperation operation) noexcept {
  switch (operation) {
    case NativeDebuggerPauseOperation::kResume:
    case NativeDebuggerPauseOperation::kStepOver:
    case NativeDebuggerPauseOperation::kStepInto:
    case NativeDebuggerPauseOperation::kStepOut:
    case NativeDebuggerPauseOperation::kReleaseLease:
    case NativeDebuggerPauseOperation::kEvaluateOnFrame:
    case NativeDebuggerPauseOperation::kGetProperties:
    case NativeDebuggerPauseOperation::kExpireLease:
      return true;
    default:
      return false;
  }
}

// A command that can make the page stop, and so carries confirm_pause. One
// confirmation covers arming the debugger on that document.
[[nodiscard]] constexpr bool NativeDebuggerPauseNeedsConfirmation(
    const NativeDebuggerPauseOperation operation) noexcept {
  switch (operation) {
    case NativeDebuggerPauseOperation::kSelectDocument:
    case NativeDebuggerPauseOperation::kSetBreakpoint:
    case NativeDebuggerPauseOperation::kPauseOnExceptions:
    case NativeDebuggerPauseOperation::kPause:
      return true;
    default:
      return false;
  }
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_DEBUGGER_PAUSE_H_
