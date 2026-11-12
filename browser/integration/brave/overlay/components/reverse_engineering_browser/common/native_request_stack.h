// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_REQUEST_STACK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_REQUEST_STACK_H_

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "native_probe_event.h"

namespace reb {
// Renderer producer half of the request stack records in
// protocol/native-network-v3.md. include/reb/request_stack.hpp decodes the same
// bytes; tests/request_stack_test.cpp keeps the two in step.
inline constexpr std::uint16_t kNativeRequestStackPayloadVersion = 1;
// Version 2 adds the task chain; navigation stacks use it.
inline constexpr std::uint16_t kNativeRequestStackTaskPayloadVersion = 2;
// Version 3 adds the stack scope; request stacks use it.
inline constexpr std::uint16_t kNativeRequestStackScopePayloadVersion = 3;
// script_identity and async_task_stack version 2 add the stack scope.
inline constexpr std::uint16_t kNativeScriptIdentityScopeVersion = 2;
inline constexpr std::uint16_t kNativeAsyncTaskStackScopeVersion = 2;
inline constexpr std::uint32_t kNativeRequestStackSyncLimit = 1024;
inline constexpr std::uint32_t kNativeRequestStackAsyncLimit = 32;
inline constexpr std::uint32_t kNativeTaskSegmentLimit = 32;
// Innermost frames kept per task segment: above DevTools' 200, so a framework's
// wrapper frames do not hide the frames that scheduled the task.
inline constexpr std::uint32_t kNativeAsyncTaskFrameLimit = 256;
// Innermost frames kept per promise registration. Registrations are far more
// frequent than task schedules, so their walk is bounded tighter.
inline constexpr std::uint32_t kNativePromiseRegistrationFrameLimit = 32;
inline constexpr std::uint32_t kNativeStackArtifactMagic = 0x4b534252U;
inline constexpr std::uint16_t kNativeStackArtifactVersion = 1;
inline constexpr std::uint16_t kNativeStackArtifactTaskVersion = 2;
// Version 3 appends the stack scope to the header; types 34, 46 and 48 use it.
inline constexpr std::uint16_t kNativeStackArtifactScopeVersion = 3;
inline constexpr std::size_t kNativeStackArtifactHeaderSize = 32;
inline constexpr std::size_t kNativeStackArtifactScopeHeaderSize = 48;
inline constexpr std::size_t kNativeStackFrameSize = 16;
inline constexpr std::size_t kNativeTaskSegmentSize = 48;
inline constexpr std::size_t kNativeStackArtifactMaxBytes =
    kNativeStackArtifactScopeHeaderSize +
    kNativeStackFrameSize * (kNativeRequestStackSyncLimit + kNativeRequestStackAsyncLimit) +
    kNativeTaskSegmentSize * kNativeTaskSegmentLimit;
inline constexpr std::uint64_t kNativeScriptIdentityMaxSourceBytes = 16ULL * 1024ULL * 1024ULL;

enum class NativeStackFrameKind : std::uint8_t {
  kJavaScript = 1,
  kWasm = 2,
  kAwait = 3,
  kPromiseCombinator = 4,
};
inline constexpr std::uint8_t kNativeStackFrameConstructor = 1U << 0U;
inline constexpr std::uint8_t kNativeStackFrameTopLevel = 1U << 1U;

enum class NativeRequestStackState : std::uint8_t {
  kCaptured = 1,
  kNoScript = 2,
  kUnsupportedThread = 3,
  kNotRetainedArtifactUnavailable = 4,
  kNotRetainedBudget = 5,
  // Version 3: a worker thread found the renderer's stack tables all in use
  // (kNativeStackThreadLimit), so nothing was walked. The scope is carried.
  kNotWalkedThreadLimit = 6,
};
inline constexpr std::uint8_t kNativeRequestStackArtifactQueued = 1U << 0U;
inline constexpr std::uint8_t kNativeRequestStackFramesOmitted = 1U << 1U;
inline constexpr std::uint8_t kNativeRequestStackAsyncTruncated = 1U << 2U;
// Bit 3: version 1 task callers not captured; version 2 task chain cut.
inline constexpr std::uint8_t kNativeRequestStackTaskCallersNotCaptured = 1U << 3U;
inline constexpr std::uint8_t kNativeRequestStackTaskChainCut = 1U << 3U;
inline constexpr std::uint8_t kNativeRequestStackTaskChainTruncated = 1U << 4U;

enum class NativeAsyncTaskKind : std::uint8_t {
  kSetTimeout = 1,
  kSetInterval = 2,
  kRequestAnimationFrame = 3,
  kRequestIdleCallback = 4,
  kPostMessage = 5,
  kXmlHttpRequest = 6,
  kPostTask = 7,
  kEvent = 8,
  kMicrotask = 9,
  // Version 3 task segments and version 2 async_task_stack records only.
  kMessagePort = 10,
  kBroadcastChannel = 11,
  kWorkerMessage = 12,
};
inline constexpr std::uint8_t kNativeAsyncTaskKindLimit = 12;
enum class NativeTaskSegmentState : std::uint8_t {
  kCaptured = 1,
  kNotRetainedArtifactUnavailable = 4,
  kNotRetainedBudget = 5,
  kNotRecorded = 6,
  // Version 3: scheduled while no script ran; the chain ends here.
  kNoScript = 7,
};
inline constexpr std::uint8_t kNativeTaskSegmentBounded = 1U << 0U;
// The call that registered a microtask's promise reaction, version 3.
enum class NativePromiseRegistration : std::uint8_t {
  kThen = 1,
  kCatch = 2,
  kFinally = 3,
  kAwait = 4,
};

// The isolate a stack's script IDs belong to. V8 script IDs are unique only
// within one isolate, so every frame is read with the scope of its record.
enum class NativeStackThread : std::uint8_t {
  kDocument = 1,
  kDedicatedWorker = 2,
  kSharedWorker = 3,
  kServiceWorker = 4,
};
struct NativeStackScope final {
  std::uint8_t thread = 0;
  std::array<std::uint8_t, 7> reserved{};
  // Zero on the document main thread; else the worker's context ID, the
  // frame_id its own requests carry.
  std::uint64_t isolate_key = 0;
  friend bool operator==(const NativeStackScope&, const NativeStackScope&) = default;
};
static_assert(sizeof(NativeStackScope) == 16);
static_assert(std::has_unique_object_representations_v<NativeStackScope>);
static_assert(offsetof(NativeStackScope, isolate_key) == 8);

enum class NativeNavigationKind : std::uint8_t {
  kLocation = 1,
  kFormSubmission = 2,
  kWindowOpen = 3,
  kOtherScript = 4,
};

enum class NativeScriptIdentityKind : std::uint8_t { kJavaScript = 1, kWasm = 2 };
inline constexpr std::uint8_t kNativeScriptIdentityEval = 1U << 0U;
inline constexpr std::uint8_t kNativeScriptIdentitySourceQueued = 1U << 1U;
inline constexpr std::uint8_t kNativeScriptIdentitySourceTooLarge = 1U << 2U;
inline constexpr std::uint8_t kNativeScriptIdentitySourceUnavailable = 1U << 3U;
inline constexpr std::uint8_t kNativeScriptIdentityNotRetained = 1U << 4U;

struct NativeStackFrame final {
  std::uint8_t kind = 0;
  std::uint8_t flags = 0;
  std::uint16_t combinator = 0;
  std::uint32_t script_id = 0;
  // Source position, module byte offset, or promise index.
  std::uint32_t position = 0;
  // Function start position, Wasm function index, or zero.
  std::uint32_t detail = 0;
  friend bool operator==(const NativeStackFrame&, const NativeStackFrame&) = default;
};
static_assert(sizeof(NativeStackFrame) == kNativeStackFrameSize);
static_assert(std::has_unique_object_representations_v<NativeStackFrame>);
static_assert(offsetof(NativeStackFrame, script_id) == 4);
static_assert(offsetof(NativeStackFrame, position) == 8);
static_assert(offsetof(NativeStackFrame, detail) == 12);

struct NativeRequestStackPayload final {
  std::uint16_t protocol_version = kNativeRequestStackPayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint8_t state = 0;
  std::uint8_t flags = 0;
  // Version 2 only; zero in version 1.
  std::uint16_t task_segments = 0;
  std::uint32_t total_depth = 0;
  std::uint32_t recorded = 0;
  std::uint32_t omitted = 0;
  std::uint16_t async_frames = 0;
  std::uint16_t async_segments = 0;
  std::uint32_t wasm_frames = 0;
  std::uint32_t scripts = 0;
  std::array<std::uint8_t, 32> digest{};
  NativeStackFrame innermost{};
  // Version 3: NativeStackScope, then zero. Navigation stacks (version 2):
  // NativeNavigationStackTail. Debugger observations: their tail. Else zero.
  std::array<std::uint8_t, 48> reserved1{};
};
static_assert(sizeof(NativeRequestStackPayload) == kNativeProbeInlinePayloadSize);
static_assert(std::has_unique_object_representations_v<NativeRequestStackPayload>);
static_assert(offsetof(NativeRequestStackPayload, state) == 4);
static_assert(offsetof(NativeRequestStackPayload, total_depth) == 8);
static_assert(offsetof(NativeRequestStackPayload, async_frames) == 20);
static_assert(offsetof(NativeRequestStackPayload, wasm_frames) == 24);
static_assert(offsetof(NativeRequestStackPayload, digest) == 32);
static_assert(offsetof(NativeRequestStackPayload, innermost) == 64);
static_assert(offsetof(NativeRequestStackPayload, reserved1) == 80);

struct NativeScriptIdentityPayload final {
  std::uint16_t protocol_version = kNativeRequestStackPayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint8_t kind = 0;
  std::uint8_t flags = 0;
  std::uint16_t reserved0 = 0;
  std::uint32_t script_id = 0;
  std::uint32_t start_line = 0;
  std::uint32_t start_column = 0;
  std::uint32_t reserved1 = 0;
  std::uint64_t execution_context_id = 0;
  std::uint64_t source_length = 0;
  std::array<std::uint8_t, 32> sha256{};
  // Version 2: NativeStackScope, then zero.
  std::array<std::uint8_t, 56> reserved2{};
};
static_assert(sizeof(NativeScriptIdentityPayload) == kNativeProbeInlinePayloadSize);
static_assert(std::has_unique_object_representations_v<NativeScriptIdentityPayload>);
static_assert(offsetof(NativeScriptIdentityPayload, script_id) == 8);
static_assert(offsetof(NativeScriptIdentityPayload, execution_context_id) == 24);
static_assert(offsetof(NativeScriptIdentityPayload, sha256) == 40);
static_assert(offsetof(NativeScriptIdentityPayload, reserved2) == 72);

struct NativeStackArtifactHeader final {
  std::uint32_t magic = kNativeStackArtifactMagic;
  std::uint16_t version = kNativeStackArtifactVersion;
  std::uint16_t header_size = kNativeStackArtifactHeaderSize;
  std::uint16_t frame_size = kNativeStackFrameSize;
  std::uint16_t flags = 0;
  std::uint32_t total_depth = 0;
  std::uint32_t recorded = 0;
  std::uint32_t omitted = 0;
  std::uint16_t async_frames = 0;
  std::uint16_t async_segments = 0;
  std::uint16_t task_segments = 0;
  std::uint16_t reserved = 0;
};
static_assert(sizeof(NativeStackArtifactHeader) == kNativeStackArtifactHeaderSize);
static_assert(std::has_unique_object_representations_v<NativeStackArtifactHeader>);
static_assert(offsetof(NativeStackArtifactHeader, total_depth) == 12);
static_assert(offsetof(NativeStackArtifactHeader, async_frames) == 24);
static_assert(offsetof(NativeStackArtifactHeader, task_segments) == 28);

// Bytes 32-47 of a version 3 stack artifact header. The renderer process
// makes a digest name one scope, so a task segment carried to another
// process still resolves its own frames.
struct NativeStackArtifactScope final {
  std::uint32_t process_id = 0;
  std::uint8_t thread = 0;
  std::array<std::uint8_t, 3> reserved{};
  std::uint64_t isolate_key = 0;
};
static_assert(sizeof(NativeStackArtifactScope) ==
              kNativeStackArtifactScopeHeaderSize - kNativeStackArtifactHeaderSize);
static_assert(std::has_unique_object_representations_v<NativeStackArtifactScope>);
static_assert(offsetof(NativeStackArtifactScope, isolate_key) == 8);

// One caller of the task chain in a version 2 stack artifact, nearest first.
struct NativeTaskSegment final {
  std::uint8_t kind = 0;
  std::uint8_t state = 0;
  std::uint8_t flags = 0;
  // Version 3, kind 9 with a recorded stack: NativePromiseRegistration. Else zero.
  std::uint8_t registration = 0;
  std::uint32_t recorded = 0;
  std::array<std::uint8_t, 8> reserved1{};
  std::array<std::uint8_t, 32> digest{};
  friend bool operator==(const NativeTaskSegment&, const NativeTaskSegment&) = default;
};
static_assert(sizeof(NativeTaskSegment) == kNativeTaskSegmentSize);
static_assert(std::has_unique_object_representations_v<NativeTaskSegment>);
static_assert(offsetof(NativeTaskSegment, recorded) == 4);
static_assert(offsetof(NativeTaskSegment, digest) == 16);

// async_task_stack (type 48): a scheduling-time stack first sent.
struct NativeAsyncTaskStackPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint8_t kind = 0;
  std::uint8_t flags = 0;
  // Version 2, kind 9: NativePromiseRegistration. Else zero.
  std::uint8_t registration = 0;
  std::uint8_t reserved0 = 0;
  std::uint32_t recorded = 0;
  std::uint32_t wasm_frames = 0;
  std::uint32_t scripts = 0;
  std::array<std::uint8_t, 12> reserved1{};
  std::array<std::uint8_t, 32> digest{};
  NativeStackFrame innermost{};
  // Version 2: NativeStackScope, then zero.
  std::array<std::uint8_t, 48> reserved2{};
};
static_assert(sizeof(NativeAsyncTaskStackPayload) == kNativeProbeInlinePayloadSize);
static_assert(std::has_unique_object_representations_v<NativeAsyncTaskStackPayload>);
static_assert(offsetof(NativeAsyncTaskStackPayload, recorded) == 8);
static_assert(offsetof(NativeAsyncTaskStackPayload, digest) == 32);
static_assert(offsetof(NativeAsyncTaskStackPayload, innermost) == 64);

// Bytes 80-127 of navigation_initiator_stack (type 46).
struct NativeNavigationStackTail final {
  std::uint8_t kind = 0;
  std::array<std::uint8_t, 7> reserved0{};
  std::uint64_t target_frame_id = 0;
  std::array<std::uint8_t, 32> reserved1{};
};
static_assert(sizeof(NativeNavigationStackTail) == 48);
static_assert(std::has_unique_object_representations_v<NativeNavigationStackTail>);
static_assert(offsetof(NativeNavigationStackTail, target_frame_id) == 8);

// navigation_initiator_link (type 47), a browser child of request_started.
struct NativeNavigationLinkPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint32_t renderer_process_id = 0;
  std::uint64_t renderer_sequence = 0;
  std::array<std::uint8_t, 112> reserved{};
};
static_assert(sizeof(NativeNavigationLinkPayload) == kNativeProbeInlinePayloadSize);
static_assert(std::has_unique_object_representations_v<NativeNavigationLinkPayload>);
static_assert(offsetof(NativeNavigationLinkPayload, renderer_sequence) == 8);

namespace native_request_stack_detail {
[[nodiscard]] inline bool AllZero(std::span<const std::uint8_t> bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
}
}  // namespace native_request_stack_detail

[[nodiscard]] inline bool IsValidNativeStackFrame(const NativeStackFrame& frame,
                                                  const bool async) noexcept {
  const auto kind = static_cast<NativeStackFrameKind>(frame.kind);
  switch (kind) {
    case NativeStackFrameKind::kJavaScript:
      return !async && frame.script_id != 0 && frame.combinator == 0 &&
             (frame.flags & ~(kNativeStackFrameConstructor | kNativeStackFrameTopLevel)) == 0;
    case NativeStackFrameKind::kWasm:
      return !async && frame.script_id != 0 && frame.combinator == 0 && frame.flags == 0;
    case NativeStackFrameKind::kAwait:
      return async && frame.script_id != 0 && frame.combinator == 0 &&
             (frame.flags & ~kNativeStackFrameTopLevel) == 0;
    case NativeStackFrameKind::kPromiseCombinator:
      return async && frame.script_id == 0 && frame.combinator >= 1 && frame.combinator <= 3 &&
             frame.flags == 0 && frame.detail == 0;
  }
  return false;
}

[[nodiscard]] inline bool IsValidNativeStackScope(const NativeStackScope& scope) noexcept {
  if (!native_request_stack_detail::AllZero(scope.reserved)) {
    return false;
  }
  if (scope.thread == static_cast<std::uint8_t>(NativeStackThread::kDocument)) {
    return scope.isolate_key == 0;
  }
  return scope.thread >= static_cast<std::uint8_t>(NativeStackThread::kDedicatedWorker) &&
         scope.thread <= static_cast<std::uint8_t>(NativeStackThread::kServiceWorker) &&
         scope.isolate_key != 0;
}

// The scope at the head of a record tail; the rest of the tail is zero.
template <std::size_t N>
[[nodiscard]] inline NativeStackScope NativeStackScopeOf(
    const std::array<std::uint8_t, N>& tail) noexcept {
  static_assert(N >= sizeof(NativeStackScope));
  std::array<std::uint8_t, sizeof(NativeStackScope)> head{};
  std::copy_n(tail.begin(), head.size(), head.begin());
  return std::bit_cast<NativeStackScope>(head);
}
template <std::size_t N>
[[nodiscard]] inline bool IsZeroAfterNativeStackScope(
    const std::array<std::uint8_t, N>& tail) noexcept {
  return native_request_stack_detail::AllZero(
      std::span<const std::uint8_t>(tail).subspan(sizeof(NativeStackScope)));
}
template <std::size_t N>
inline void SetNativeStackScope(std::array<std::uint8_t, N>& tail,
                                const NativeStackScope& scope) noexcept {
  const auto bytes = std::bit_cast<std::array<std::uint8_t, sizeof(NativeStackScope)>>(scope);
  std::copy(bytes.begin(), bytes.end(), tail.begin());
}

[[nodiscard]] inline bool IsValidNativeRequestStackPayload(
    const NativeRequestStackPayload& v) noexcept {
  using native_request_stack_detail::AllZero;
  const bool scoped = v.protocol_version == kNativeRequestStackScopePayloadVersion;
  const bool tasks = scoped || v.protocol_version == kNativeRequestStackTaskPayloadVersion;
  const std::uint8_t known_flags = tasks ? 0x1FU : 0x0FU;
  if ((v.protocol_version != kNativeRequestStackPayloadVersion && !tasks) ||
      v.payload_size != 128 || (!tasks && v.task_segments != 0) ||
      (!scoped && !AllZero(v.reserved1)) || (v.flags & ~known_flags) != 0) {
    return false;
  }
  const auto state = static_cast<NativeRequestStackState>(v.state);
  // Version 3: a thread with no worker or document isolate has no scope.
  if (state == NativeRequestStackState::kNotWalkedThreadLimit && !scoped) {
    return false;
  }
  if (scoped && (!IsZeroAfterNativeStackScope(v.reserved1) ||
                 (state == NativeRequestStackState::kUnsupportedThread
                      ? NativeStackScopeOf(v.reserved1) != NativeStackScope{}
                      : !IsValidNativeStackScope(NativeStackScopeOf(v.reserved1))))) {
    return false;
  }
  if (state == NativeRequestStackState::kNoScript ||
      state == NativeRequestStackState::kUnsupportedThread ||
      state == NativeRequestStackState::kNotWalkedThreadLimit) {
    const std::uint8_t allowed = tasks ? 0 : kNativeRequestStackTaskCallersNotCaptured;
    return (v.flags & ~allowed) == 0 && v.task_segments == 0 && v.total_depth == 0 &&
           v.recorded == 0 && v.omitted == 0 && v.async_frames == 0 && v.async_segments == 0 &&
           v.wasm_frames == 0 && v.scripts == 0 && AllZero(v.digest) &&
           v.innermost == NativeStackFrame{};
  }
  if (state != NativeRequestStackState::kCaptured &&
      state != NativeRequestStackState::kNotRetainedArtifactUnavailable &&
      state != NativeRequestStackState::kNotRetainedBudget) {
    return false;
  }
  const bool omitted = v.omitted != 0;
  const std::uint64_t frames = std::uint64_t{v.recorded} + v.async_frames;
  return v.recorded >= 1 && v.recorded <= kNativeRequestStackSyncLimit &&
         std::uint64_t{v.recorded} + v.omitted == v.total_depth &&
         omitted == ((v.flags & kNativeRequestStackFramesOmitted) != 0) &&
         (!omitted || v.recorded == kNativeRequestStackSyncLimit) &&
         v.async_frames <= kNativeRequestStackAsyncLimit &&
         (tasks ? v.task_segments <= kNativeTaskSegmentLimit &&
                      v.async_segments == v.async_frames + v.task_segments &&
                      ((v.flags & kNativeRequestStackTaskChainTruncated) == 0 ||
                       v.task_segments == kNativeTaskSegmentLimit)
                : v.async_segments <= v.async_frames) &&
         ((v.flags & kNativeRequestStackAsyncTruncated) == 0 ||
          v.async_frames == kNativeRequestStackAsyncLimit) &&
         ((v.flags & kNativeRequestStackArtifactQueued) == 0 ||
          state == NativeRequestStackState::kCaptured) &&
         v.wasm_frames <= frames && v.scripts <= frames && !AllZero(v.digest) &&
         IsValidNativeStackFrame(v.innermost, false);
}

// artifact_version: the stack artifact's version, 2 or 3.
[[nodiscard]] inline bool IsValidNativeTaskSegment(
    const NativeTaskSegment& s,
    const std::uint16_t artifact_version = kNativeStackArtifactTaskVersion) noexcept {
  using native_request_stack_detail::AllZero;
  const bool scoped = artifact_version == kNativeStackArtifactScopeVersion;
  if (!AllZero(s.reserved1) || (s.flags & ~kNativeTaskSegmentBounded) != 0) {
    return false;
  }
  const auto state = static_cast<NativeTaskSegmentState>(s.state);
  const bool walked = state == NativeTaskSegmentState::kCaptured ||
                      state == NativeTaskSegmentState::kNotRetainedArtifactUnavailable ||
                      state == NativeTaskSegmentState::kNotRetainedBudget;
  const auto frames = [&](const std::uint32_t limit) {
    return walked && s.recorded >= 1 && s.recorded <= limit &&
           ((s.flags & kNativeTaskSegmentBounded) == 0 || s.recorded == limit) &&
           !AllZero(s.digest);
  };
  const bool empty = s.flags == 0 && s.recorded == 0 && AllZero(s.digest);
  if (s.kind == static_cast<std::uint8_t>(NativeAsyncTaskKind::kMicrotask)) {
    if (state == NativeTaskSegmentState::kNotRecorded) {
      return s.registration == 0 && empty;
    }
    return scoped && s.registration >= 1 && s.registration <= 4 &&
           frames(kNativePromiseRegistrationFrameLimit);
  }
  if (s.registration != 0 || s.kind < 1 || s.kind > (scoped ? kNativeAsyncTaskKindLimit : 8)) {
    return false;
  }
  if (state == NativeTaskSegmentState::kNoScript) {
    return scoped && empty;
  }
  return frames(kNativeAsyncTaskFrameLimit);
}

[[nodiscard]] inline bool IsValidNativeAsyncTaskStackPayload(
    const NativeAsyncTaskStackPayload& v) noexcept {
  using native_request_stack_detail::AllZero;
  const bool scoped = v.protocol_version == kNativeAsyncTaskStackScopeVersion;
  if ((v.protocol_version != 1 && !scoped) || v.payload_size != 128 ||
      (v.flags & ~kNativeTaskSegmentBounded) != 0 || v.reserved0 != 0 || !AllZero(v.reserved1) ||
      (scoped ? !IsValidNativeStackScope(NativeStackScopeOf(v.reserved2)) ||
                    !IsZeroAfterNativeStackScope(v.reserved2)
              : !AllZero(v.reserved2))) {
    return false;
  }
  const bool microtask = v.kind == static_cast<std::uint8_t>(NativeAsyncTaskKind::kMicrotask);
  if (microtask ? !scoped || v.registration < 1 || v.registration > 4
                : v.registration != 0 || v.kind < 1 ||
                      v.kind > (scoped ? kNativeAsyncTaskKindLimit : 8)) {
    return false;
  }
  const std::uint32_t limit =
      microtask ? kNativePromiseRegistrationFrameLimit : kNativeAsyncTaskFrameLimit;
  return v.recorded >= 1 && v.recorded <= limit &&
         ((v.flags & kNativeTaskSegmentBounded) == 0 || v.recorded == limit) &&
         v.wasm_frames <= v.recorded && v.scripts <= v.recorded && !AllZero(v.digest) &&
         IsValidNativeStackFrame(v.innermost, false);
}

[[nodiscard]] inline bool IsValidNativeNavigationStackPayload(
    const NativeRequestStackPayload& v) noexcept {
  using native_request_stack_detail::AllZero;
  const auto tail = std::bit_cast<NativeNavigationStackTail>(v.reserved1);
  NativeRequestStackPayload stack = v;
  stack.reserved1 = {};
  const auto state = static_cast<NativeRequestStackState>(v.state);
  return v.protocol_version == kNativeRequestStackTaskPayloadVersion && tail.kind >= 1 &&
         tail.kind <= 4 && AllZero(tail.reserved0) && AllZero(tail.reserved1) &&
         tail.target_frame_id != 0 &&
         (state == NativeRequestStackState::kCaptured ||
          state == NativeRequestStackState::kNotRetainedArtifactUnavailable ||
          state == NativeRequestStackState::kNotRetainedBudget) &&
         IsValidNativeRequestStackPayload(stack);
}

[[nodiscard]] inline bool IsValidNativeNavigationLinkPayload(
    const NativeNavigationLinkPayload& v) noexcept {
  return v.protocol_version == 1 && v.payload_size == 128 && v.renderer_process_id != 0 &&
         v.renderer_sequence != 0 && native_request_stack_detail::AllZero(v.reserved);
}

[[nodiscard]] inline bool IsValidNativeScriptIdentityPayload(
    const NativeScriptIdentityPayload& v) noexcept {
  using native_request_stack_detail::AllZero;
  constexpr std::uint8_t kRetention =
      kNativeScriptIdentitySourceQueued | kNativeScriptIdentitySourceTooLarge |
      kNativeScriptIdentitySourceUnavailable | kNativeScriptIdentityNotRetained;
  const std::uint8_t retention = v.flags & kRetention;
  const bool scoped = v.protocol_version == kNativeScriptIdentityScopeVersion;
  if ((v.protocol_version != kNativeRequestStackPayloadVersion && !scoped) ||
      v.payload_size != 128 || v.reserved0 != 0 || v.reserved1 != 0 ||
      (scoped ? !IsValidNativeStackScope(NativeStackScopeOf(v.reserved2)) ||
                    !IsZeroAfterNativeStackScope(v.reserved2)
              : !AllZero(v.reserved2)) ||
      v.script_id == 0 || v.execution_context_id == 0 ||
      (v.flags & ~(kRetention | kNativeScriptIdentityEval)) != 0 || std::popcount(retention) > 1) {
    return false;
  }
  if (v.kind == static_cast<std::uint8_t>(NativeScriptIdentityKind::kWasm) &&
      (v.flags & ~(kNativeScriptIdentitySourceTooLarge | kNativeScriptIdentitySourceUnavailable)) !=
          0) {
    return false;
  }
  if (v.kind == static_cast<std::uint8_t>(NativeScriptIdentityKind::kJavaScript) &&
      retention == 0) {
    return false;
  }
  if (v.kind != static_cast<std::uint8_t>(NativeScriptIdentityKind::kJavaScript) &&
      v.kind != static_cast<std::uint8_t>(NativeScriptIdentityKind::kWasm)) {
    return false;
  }
  if (retention == kNativeScriptIdentitySourceUnavailable) {
    return v.source_length == 0 && AllZero(v.sha256);
  }
  if (retention == kNativeScriptIdentitySourceTooLarge) {
    return v.source_length > kNativeScriptIdentityMaxSourceBytes && AllZero(v.sha256);
  }
  return v.source_length != 0 && v.source_length <= kNativeScriptIdentityMaxSourceBytes &&
         !AllZero(v.sha256);
}

// A message's task origin, carried beside Chromium's sender_stack_trace_id
// from the posting renderer to the one that runs its handler: the posting
// segment, then at most 31 earlier segments of the sender's chain, nearest
// first. Never stored. The receiver treats it as untrusted input and drops an
// origin that does not validate; the message itself is unaffected.
inline constexpr std::uint16_t kNativeTaskOriginVersion = 1;
inline constexpr std::size_t kNativeTaskOriginHeaderSize = 24;
inline constexpr std::size_t kNativeTaskOriginMaxBytes =
    kNativeTaskOriginHeaderSize + kNativeTaskSegmentSize * kNativeTaskSegmentLimit;
// The sender's chain continued past the carried segments, or was cut there.
inline constexpr std::uint8_t kNativeTaskOriginCut = 1U << 0U;

struct NativeTaskOriginHeader final {
  std::uint16_t version = kNativeTaskOriginVersion;
  std::uint8_t count = 0;
  std::uint8_t flags = 0;
  // The sender's OS process and segment table; with the serial they let a
  // receiver on the same thread link the posting segment directly.
  std::uint32_t process_id = 0;
  std::uint64_t table = 0;
  // The posting segment's serial in that table; 0 when it was scheduled with
  // no script running and so has no table entry.
  std::uint64_t serial = 0;
};
static_assert(sizeof(NativeTaskOriginHeader) == kNativeTaskOriginHeaderSize);
static_assert(std::has_unique_object_representations_v<NativeTaskOriginHeader>);

// Validates an origin and copies its segments into `out`; false keeps nothing.
[[nodiscard]] inline bool DecodeNativeTaskOrigin(
    std::span<const std::uint8_t> bytes,
    NativeTaskOriginHeader& header,
    std::span<NativeTaskSegment, kNativeTaskSegmentLimit> out) noexcept {
  if (bytes.size() < kNativeTaskOriginHeaderSize || bytes.size() > kNativeTaskOriginMaxBytes) {
    return false;
  }
  std::array<std::uint8_t, kNativeTaskOriginHeaderSize> head{};
  std::copy_n(bytes.begin(), head.size(), head.begin());
  header = std::bit_cast<NativeTaskOriginHeader>(head);
  if (header.version != kNativeTaskOriginVersion || header.count == 0 ||
      header.count > kNativeTaskSegmentLimit || (header.flags & ~kNativeTaskOriginCut) != 0 ||
      header.process_id == 0 || header.table == 0 ||
      bytes.size() != kNativeTaskOriginHeaderSize + kNativeTaskSegmentSize * header.count) {
    return false;
  }
  for (std::size_t i = 0; i < header.count; ++i) {
    std::array<std::uint8_t, kNativeTaskSegmentSize> raw{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(kNativeTaskOriginHeaderSize +
                                                            i * kNativeTaskSegmentSize),
                raw.size(), raw.begin());
    out[i] = std::bit_cast<NativeTaskSegment>(raw);
    const bool no_script =
        out[i].state == static_cast<std::uint8_t>(NativeTaskSegmentState::kNoScript);
    if (!IsValidNativeTaskSegment(out[i], kNativeStackArtifactScopeVersion) ||
        (no_script && (i + 1 != header.count || header.flags != 0))) {
      return false;
    }
  }
  const std::uint8_t posting = out[0].kind;
  return posting >= static_cast<std::uint8_t>(NativeAsyncTaskKind::kMessagePort) &&
         posting <= static_cast<std::uint8_t>(NativeAsyncTaskKind::kWorkerMessage) &&
         (header.serial == 0) ==
             (out[0].state == static_cast<std::uint8_t>(NativeTaskSegmentState::kNoScript));
}

template <typename T>
[[nodiscard]] inline std::array<std::byte, sizeof(T)> EncodeNativeRequestStackRecord(
    const T& value) noexcept {
  return std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
}
}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_REQUEST_STACK_H_
