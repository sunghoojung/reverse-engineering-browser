// The overlay's wire header compiled on the host, so the one part of the
// browser side that needs nothing from Chromium is checked rather than read.
// It holds the framing the backend writes, the status and clear names both
// sides print, and the rules that decide how a command reaches a paused main
// thread. See protocol/native-debugger-pause-v1.md.
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>
#include <utility>

#include "components/reverse_engineering_browser/common/native_debugger_pause.h"
#include "reb/debugger_pause.hpp"

namespace {

int failures = 0;

void Expect(const bool condition, const std::string_view name) {
  if (!condition) {
    std::cerr << "FAIL " << name << '\n';
    ++failures;
  }
}

reb::NativeDebuggerPauseRequest Request(const reb::NativeDebuggerPauseOperation operation) {
  reb::NativeDebuggerPauseRequest request;
  request.operation = operation;
  request.request_id = 7;
  request.target_id = 22;
  return request;
}

// The backend writes these 48 bytes by hand; this is the layout it writes.
void Framing() {
  const auto good = Request(reb::NativeDebuggerPauseOperation::kSelectDocument);
  Expect(reb::IsValidNativeDebuggerPauseRequest(good), "a well formed request");

  auto magic = good;
  magic.magic = 0x41424344;
  Expect(!reb::IsValidNativeDebuggerPauseRequest(magic), "another protocol's magic");

  auto version = good;
  version.version = 2;
  Expect(!reb::IsValidNativeDebuggerPauseRequest(version), "a version this peer cannot speak");

  auto unnumbered = good;
  unnumbered.request_id = 0;
  Expect(!reb::IsValidNativeDebuggerPauseRequest(unnumbered), "a zero request id");

  // The document generation is the target id; the slot that used to hold a
  // second identity must stay zero so neither side can start using it.
  auto second_identity = good;
  second_identity.reserved0 = 3;
  Expect(!reb::IsValidNativeDebuggerPauseRequest(second_identity),
         "a second identity in the reserved slot");

  auto tail = good;
  tail.reserved1 = 1;
  Expect(!reb::IsValidNativeDebuggerPauseRequest(tail), "a nonzero reserved tail");

  auto zero_operation = good;
  zero_operation.operation = static_cast<reb::NativeDebuggerPauseOperation>(0);
  Expect(!reb::IsValidNativeDebuggerPauseRequest(zero_operation), "operation zero");

  // The browser's own deadline operations never cross the socket.
  for (const auto internal : {reb::NativeDebuggerPauseOperation::kExpireLease,
                              reb::NativeDebuggerPauseOperation::kReleaseIdle}) {
    auto request = good;
    request.operation = internal;
    Expect(!reb::IsValidNativeDebuggerPauseRequest(request),
           "a browser-only operation from the socket");
  }

  auto oversized = good;
  oversized.payload_size = reb::kNativeDebuggerPauseRequestLimit + 1;
  Expect(!reb::IsValidNativeDebuggerPauseRequest(oversized), "a payload past the request limit");
  auto exact = good;
  exact.payload_size = reb::kNativeDebuggerPauseRequestLimit;
  Expect(reb::IsValidNativeDebuggerPauseRequest(exact), "a payload at the request limit");
}

// Every status and clear reason this contract names, with no gaps: a number
// the two sides spell differently is a reply a reader would misbelieve.
void Names() {
  const char* const statuses[] = {
      "ok",         "malformed",     "stale_document",     "not_authorized",
      "not_paused", "stale_lease",   "unknown_breakpoint", "unknown_object",
      "limit",      "invalid_input", "evaluation_error",   "unsupported",
      "busy"};
  for (std::uint16_t code = 0; code <= 12; ++code) {
    const auto status = static_cast<reb::NativeDebuggerPauseStatus>(code);
    Expect(std::strcmp(reb::NativeDebuggerPauseStatusName(status), statuses[code]) == 0,
           statuses[code]);
  }
  for (const auto& [reason, name] :
       {std::pair<std::uint8_t, const char*>{reb::kNativeDebuggerPauseClearNavigated, "navigated"},
        {reb::kNativeDebuggerPauseClearReleased, "released"},
        {reb::kNativeDebuggerPauseClearReplaced, "replaced"},
        {reb::kNativeDebuggerPauseClearPeerLost, "peer_lost"}}) {
    Expect(std::strcmp(reb::NativeDebuggerPauseClearName(reason), name) == 0, name);
  }
  // The overlay keeps its own copy of these numbers; they are the record
  // core's numbers or a record the renderer writes is one the store refuses.
  Expect(reb::kNativeDebuggerPauseClearNone == reb::kDebuggerClearNone &&
             reb::kNativeDebuggerPauseClearNavigated == reb::kDebuggerClearNavigated &&
             reb::kNativeDebuggerPauseClearReleased == reb::kDebuggerClearReleased &&
             reb::kNativeDebuggerPauseClearReplaced == reb::kDebuggerClearReplaced &&
             reb::kNativeDebuggerPauseClearPeerLost == reb::kDebuggerClearPeerLost &&
             reb::kNativeDebuggerPauseClearIdle == reb::kDebuggerClearIdle,
         "clear reasons agree with the record core");
}

// How a command reaches a main thread that is already stopped.
void Routing() {
  using Operation = reb::NativeDebuggerPauseOperation;
  Expect(reb::NativeDebuggerPauseRunsScript(Operation::kEvaluateOnFrame) &&
             reb::NativeDebuggerPauseRunsScript(Operation::kGetProperties),
         "the two commands that run page script");
  for (const auto operation :
       {Operation::kState, Operation::kSelectDocument, Operation::kResume, Operation::kStepOver,
        Operation::kSetBreakpoint, Operation::kReleaseLease, Operation::kExpireLease}) {
    Expect(!reb::NativeDebuggerPauseRunsScript(operation), "a command that runs no script");
  }

  for (const auto operation :
       {Operation::kResume, Operation::kStepOver, Operation::kStepInto, Operation::kStepOut,
        Operation::kReleaseLease, Operation::kEvaluateOnFrame, Operation::kGetProperties,
        Operation::kExpireLease}) {
    Expect(reb::NativeDebuggerPauseNeedsLease(operation), "a command that needs the pause");
  }
  for (const auto operation :
       {Operation::kState, Operation::kSelectDocument, Operation::kReleaseDocument,
        Operation::kSetBreakpoint, Operation::kRemoveBreakpoint, Operation::kPauseOnExceptions,
        Operation::kPause, Operation::kReleaseIdle}) {
    Expect(!reb::NativeDebuggerPauseNeedsLease(operation), "a command that needs no pause");
  }

  for (const auto operation : {Operation::kSelectDocument, Operation::kSetBreakpoint,
                               Operation::kPauseOnExceptions, Operation::kPause}) {
    Expect(reb::NativeDebuggerPauseNeedsConfirmation(operation), "a command that can stop a page");
  }
  for (const auto operation :
       {Operation::kState, Operation::kReleaseDocument, Operation::kRemoveBreakpoint,
        Operation::kResume, Operation::kStepOver, Operation::kGetProperties}) {
    Expect(!reb::NativeDebuggerPauseNeedsConfirmation(operation), "a command that stops nothing");
  }
}

// The numbers the overlay uses and the ones the record core validates are the
// same numbers, so a record the renderer writes is one the store accepts.
void RecordNumbers() {
  Expect(reb::kNativeDebuggerPauseReasonBreakpoint == reb::kDebuggerPauseReasonBreakpoint &&
             reb::kNativeDebuggerPauseReasonException == 2 &&
             reb::kNativeDebuggerPauseReasonStep == 3 &&
             reb::kNativeDebuggerPauseReasonPause == 4 &&
             reb::kNativeDebuggerPauseReasonDebuggerStatement == 5,
         "pause reasons");
  Expect(reb::kNativeDebuggerPauseReasonDebuggerStatement == reb::kDebuggerPauseReasonMax,
         "the record core validates exactly these reasons");
  Expect(reb::kNativeDebuggerPauseEndResume == 1 && reb::kNativeDebuggerPauseEndExpired == 4 &&
             reb::kNativeDebuggerPauseEndElsewhere == reb::kDebuggerResumeEndMax,
         "resume ends");
  Expect(reb::kNativeDebuggerPauseFramesTruncated == reb::kDebuggerPauseFramesTruncated,
         "the truncation flag the overlay sets is the one the core reads");
  Expect(reb::kNativeDebuggerPauseFrameLimit == reb::kDebuggerFrameLimit &&
             reb::kNativeDebuggerPauseAsyncFrameLimit == reb::kDebuggerAsyncFrameLimit,
         "the pause stack uses the request-stack bounds");
  Expect(reb::kNativeDebuggerPauseBreakpointLimit == reb::kDebuggerBreakpointLimit,
         "one breakpoint bound");
  Expect(reb::kNativeDebuggerPauseLeaseMs == 60000, "the contract's deadline");
  Expect(reb::kNativeDebuggerPauseIdleMs > reb::kNativeDebuggerPauseLeaseMs,
         "an authorization outlives one pause");
}

}  // namespace

int main() {
  Framing();
  Names();
  Routing();
  RecordNumbers();
  if (failures != 0) {
    return 1;
  }
  std::cout << "debugger pause wire ok\n";
  return 0;
}
