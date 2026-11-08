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
inline constexpr std::uint32_t kNativeRequestStackSyncLimit = 1024;
inline constexpr std::uint32_t kNativeRequestStackAsyncLimit = 32;
inline constexpr std::uint32_t kNativeStackArtifactMagic = 0x4b534252U;
inline constexpr std::uint16_t kNativeStackArtifactVersion = 1;
inline constexpr std::size_t kNativeStackArtifactHeaderSize = 32;
inline constexpr std::size_t kNativeStackFrameSize = 16;
inline constexpr std::size_t kNativeStackArtifactMaxBytes =
    kNativeStackArtifactHeaderSize +
    kNativeStackFrameSize * (kNativeRequestStackSyncLimit + kNativeRequestStackAsyncLimit);
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
inline constexpr std::uint8_t kNativeRequestStackTaskCallersNotCaptured = 1U << 3U;

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
  std::uint16_t reserved0 = 0;
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
  std::uint32_t reserved = 0;
};
static_assert(sizeof(NativeStackArtifactHeader) == kNativeStackArtifactHeaderSize);
static_assert(std::has_unique_object_representations_v<NativeStackArtifactHeader>);
static_assert(offsetof(NativeStackArtifactHeader, total_depth) == 12);
static_assert(offsetof(NativeStackArtifactHeader, async_frames) == 24);

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
  constexpr std::uint8_t kKnownFlags = 0x0FU;
  if (v.protocol_version != kNativeRequestStackPayloadVersion || v.payload_size != 128 ||
      v.reserved0 != 0 || !AllZero(v.reserved1) || (v.flags & ~kKnownFlags) != 0) {
    return false;
  }
  const auto state = static_cast<NativeRequestStackState>(v.state);
  if (state == NativeRequestStackState::kNoScript ||
      state == NativeRequestStackState::kUnsupportedThread) {
    return (v.flags & ~kNativeRequestStackTaskCallersNotCaptured) == 0 && v.total_depth == 0 &&
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
         v.async_frames <= kNativeRequestStackAsyncLimit && v.async_segments <= v.async_frames &&
         ((v.flags & kNativeRequestStackAsyncTruncated) == 0 ||
          v.async_frames == kNativeRequestStackAsyncLimit) &&
         ((v.flags & kNativeRequestStackArtifactQueued) == 0 ||
          state == NativeRequestStackState::kCaptured) &&
         v.wasm_frames <= frames && v.scripts <= frames && !AllZero(v.digest) &&
         IsValidNativeStackFrame(v.innermost, false);
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
