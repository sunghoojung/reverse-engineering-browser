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
// Version 2 adds the task chain; request and navigation stacks use it.
inline constexpr std::uint16_t kNativeRequestStackTaskPayloadVersion = 2;
inline constexpr std::uint32_t kNativeRequestStackSyncLimit = 1024;
inline constexpr std::uint32_t kNativeRequestStackAsyncLimit = 32;
inline constexpr std::uint32_t kNativeTaskSegmentLimit = 32;
// Innermost frames kept per task segment: above DevTools' 200, so a framework's
// wrapper frames do not hide the frames that scheduled the task.
inline constexpr std::uint32_t kNativeAsyncTaskFrameLimit = 256;
inline constexpr std::uint32_t kNativeStackArtifactMagic = 0x4b534252U;
inline constexpr std::uint16_t kNativeStackArtifactVersion = 1;
inline constexpr std::uint16_t kNativeStackArtifactTaskVersion = 2;
inline constexpr std::size_t kNativeStackArtifactHeaderSize = 32;
inline constexpr std::size_t kNativeStackFrameSize = 16;
inline constexpr std::size_t kNativeTaskSegmentSize = 48;
inline constexpr std::size_t kNativeStackArtifactMaxBytes =
    kNativeStackArtifactHeaderSize +
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
};
enum class NativeTaskSegmentState : std::uint8_t {
  kCaptured = 1,
  kNotRetainedArtifactUnavailable = 4,
  kNotRetainedBudget = 5,
  kNotRecorded = 6,
};
inline constexpr std::uint8_t kNativeTaskSegmentBounded = 1U << 0U;

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

// One caller of the task chain in a version 2 stack artifact, nearest first.
struct NativeTaskSegment final {
  std::uint8_t kind = 0;
  std::uint8_t state = 0;
  std::uint8_t flags = 0;
  std::uint8_t reserved0 = 0;
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
  std::uint16_t reserved0 = 0;
  std::uint32_t recorded = 0;
  std::uint32_t wasm_frames = 0;
  std::uint32_t scripts = 0;
  std::array<std::uint8_t, 12> reserved1{};
  std::array<std::uint8_t, 32> digest{};
  NativeStackFrame innermost{};
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

[[nodiscard]] inline bool IsValidNativeRequestStackPayload(
    const NativeRequestStackPayload& v) noexcept {
  using native_request_stack_detail::AllZero;
  const bool tasks = v.protocol_version == kNativeRequestStackTaskPayloadVersion;
  const std::uint8_t known_flags = tasks ? 0x1FU : 0x0FU;
  if ((v.protocol_version != kNativeRequestStackPayloadVersion && !tasks) ||
      v.payload_size != 128 || (!tasks && v.task_segments != 0) || !AllZero(v.reserved1) ||
      (v.flags & ~known_flags) != 0) {
    return false;
  }
  const auto state = static_cast<NativeRequestStackState>(v.state);
  if (state == NativeRequestStackState::kNoScript ||
      state == NativeRequestStackState::kUnsupportedThread) {
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

[[nodiscard]] inline bool IsValidNativeTaskSegment(const NativeTaskSegment& s) noexcept {
  using native_request_stack_detail::AllZero;
  if (s.reserved0 != 0 || !AllZero(s.reserved1) || (s.flags & ~kNativeTaskSegmentBounded) != 0) {
    return false;
  }
  if (s.kind == static_cast<std::uint8_t>(NativeAsyncTaskKind::kMicrotask)) {
    return s.state == static_cast<std::uint8_t>(NativeTaskSegmentState::kNotRecorded) &&
           s.flags == 0 && s.recorded == 0 && AllZero(s.digest);
  }
  const auto state = static_cast<NativeTaskSegmentState>(s.state);
  return s.kind >= 1 && s.kind <= 8 &&
         (state == NativeTaskSegmentState::kCaptured ||
          state == NativeTaskSegmentState::kNotRetainedArtifactUnavailable ||
          state == NativeTaskSegmentState::kNotRetainedBudget) &&
         s.recorded >= 1 && s.recorded <= kNativeAsyncTaskFrameLimit &&
         ((s.flags & kNativeTaskSegmentBounded) == 0 || s.recorded == kNativeAsyncTaskFrameLimit) &&
         !AllZero(s.digest);
}

[[nodiscard]] inline bool IsValidNativeAsyncTaskStackPayload(
    const NativeAsyncTaskStackPayload& v) noexcept {
  using native_request_stack_detail::AllZero;
  return v.protocol_version == 1 && v.payload_size == 128 && v.kind >= 1 && v.kind <= 8 &&
         (v.flags & ~kNativeTaskSegmentBounded) == 0 && v.reserved0 == 0 && AllZero(v.reserved1) &&
         AllZero(v.reserved2) && v.recorded >= 1 && v.recorded <= kNativeAsyncTaskFrameLimit &&
         ((v.flags & kNativeTaskSegmentBounded) == 0 || v.recorded == kNativeAsyncTaskFrameLimit) &&
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
  if (v.protocol_version != kNativeRequestStackPayloadVersion || v.payload_size != 128 ||
      v.reserved0 != 0 || v.reserved1 != 0 || !AllZero(v.reserved2) || v.script_id == 0 ||
      v.execution_context_id == 0 || (v.flags & ~(kRetention | kNativeScriptIdentityEval)) != 0 ||
      std::popcount(retention) > 1) {
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

template <typename T>
[[nodiscard]] inline std::array<std::byte, sizeof(T)> EncodeNativeRequestStackRecord(
    const T& value) noexcept {
  return std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
}
}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_REQUEST_STACK_H_
