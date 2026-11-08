#ifndef REB_REQUEST_STACK_HPP_
#define REB_REQUEST_STACK_HPP_

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "reb/event.hpp"

namespace reb {
// Request initiator stacks and script identities, protocol/native-network-v3.md.
// The overlay's common/native_request_stack.h is the producer half of this ABI;
// tests/request_stack_test.cpp keeps the two in step.
inline constexpr std::uint16_t kRequestStackPayloadVersion = 1;
inline constexpr std::uint32_t kRequestStackSyncLimit = 1024;
inline constexpr std::uint32_t kRequestStackAsyncLimit = 32;
inline constexpr std::uint32_t kStackArtifactMagic = 0x4b534252U;
inline constexpr std::uint16_t kStackArtifactVersion = 1;
inline constexpr std::size_t kStackArtifactHeaderSize = 32;
inline constexpr std::size_t kStackFrameSize = 16;
inline constexpr std::size_t kStackArtifactMaxBytes =
    kStackArtifactHeaderSize + kStackFrameSize * (kRequestStackSyncLimit + kRequestStackAsyncLimit);
inline constexpr std::uint64_t kScriptIdentityMaxSourceBytes = 16ULL * 1024ULL * 1024ULL;

enum class StackFrameKind : std::uint8_t {
  kJavaScript = 1,
  kWasm = 2,
  kAwait = 3,
  kPromiseCombinator = 4,
};
inline constexpr std::uint8_t kStackFrameConstructor = 1U << 0U;
inline constexpr std::uint8_t kStackFrameTopLevel = 1U << 1U;

enum class RequestStackState : std::uint8_t {
  kCaptured = 1,
  kNoScript = 2,
  kUnsupportedThread = 3,
  kNotRetainedArtifactUnavailable = 4,
  kNotRetainedBudget = 5,
};
inline constexpr std::uint8_t kRequestStackArtifactQueued = 1U << 0U;
inline constexpr std::uint8_t kRequestStackFramesOmitted = 1U << 1U;
inline constexpr std::uint8_t kRequestStackAsyncTruncated = 1U << 2U;
inline constexpr std::uint8_t kRequestStackTaskCallersNotCaptured = 1U << 3U;

enum class ScriptIdentityKind : std::uint8_t { kJavaScript = 1, kWasm = 2 };
inline constexpr std::uint8_t kScriptIdentityEval = 1U << 0U;
inline constexpr std::uint8_t kScriptIdentitySourceQueued = 1U << 1U;
inline constexpr std::uint8_t kScriptIdentitySourceTooLarge = 1U << 2U;
inline constexpr std::uint8_t kScriptIdentitySourceUnavailable = 1U << 3U;
inline constexpr std::uint8_t kScriptIdentityNotRetained = 1U << 4U;

struct StackFrame final {
  std::uint8_t kind = 0;
  std::uint8_t flags = 0;
  std::uint16_t combinator = 0;
  std::uint32_t script_id = 0;
  // Source position, module byte offset, or promise index.
  std::uint32_t position = 0;
  // Function start position, Wasm function index, or zero.
  std::uint32_t detail = 0;
  friend bool operator==(const StackFrame&, const StackFrame&) = default;
};
static_assert(sizeof(StackFrame) == kStackFrameSize);
static_assert(std::has_unique_object_representations_v<StackFrame>);
static_assert(offsetof(StackFrame, script_id) == 4);
static_assert(offsetof(StackFrame, position) == 8);
static_assert(offsetof(StackFrame, detail) == 12);

struct RequestStackPayload final {
  std::uint16_t protocol_version = kRequestStackPayloadVersion;
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
  StackFrame innermost{};
  std::array<std::uint8_t, 48> reserved1{};
};
static_assert(sizeof(RequestStackPayload) == kInlinePayloadSize);
static_assert(std::has_unique_object_representations_v<RequestStackPayload>);
static_assert(offsetof(RequestStackPayload, state) == 4);
static_assert(offsetof(RequestStackPayload, total_depth) == 8);
static_assert(offsetof(RequestStackPayload, async_frames) == 20);
static_assert(offsetof(RequestStackPayload, wasm_frames) == 24);
static_assert(offsetof(RequestStackPayload, digest) == 32);
static_assert(offsetof(RequestStackPayload, innermost) == 64);
static_assert(offsetof(RequestStackPayload, reserved1) == 80);

struct ScriptIdentityPayload final {
  std::uint16_t protocol_version = kRequestStackPayloadVersion;
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
static_assert(sizeof(ScriptIdentityPayload) == kInlinePayloadSize);
static_assert(std::has_unique_object_representations_v<ScriptIdentityPayload>);
static_assert(offsetof(ScriptIdentityPayload, script_id) == 8);
static_assert(offsetof(ScriptIdentityPayload, execution_context_id) == 24);
static_assert(offsetof(ScriptIdentityPayload, sha256) == 40);
static_assert(offsetof(ScriptIdentityPayload, reserved2) == 72);

struct StackArtifactHeader final {
  std::uint32_t magic = kStackArtifactMagic;
  std::uint16_t version = kStackArtifactVersion;
  std::uint16_t header_size = kStackArtifactHeaderSize;
  std::uint16_t frame_size = kStackFrameSize;
  std::uint16_t flags = 0;
  std::uint32_t total_depth = 0;
  std::uint32_t recorded = 0;
  std::uint32_t omitted = 0;
  std::uint16_t async_frames = 0;
  std::uint16_t async_segments = 0;
  std::uint32_t reserved = 0;
};
static_assert(sizeof(StackArtifactHeader) == kStackArtifactHeaderSize);
static_assert(std::has_unique_object_representations_v<StackArtifactHeader>);
static_assert(offsetof(StackArtifactHeader, total_depth) == 12);
static_assert(offsetof(StackArtifactHeader, async_frames) == 24);

namespace request_stack_detail {
template <typename T>
[[nodiscard]] inline T Decode(std::span<const std::byte> bytes) noexcept {
  std::array<std::byte, sizeof(T)> copy{};
  std::copy_n(bytes.begin(), sizeof(T), copy.begin());
  return std::bit_cast<T>(copy);
}
[[nodiscard]] inline bool AllZero(std::span<const std::uint8_t> bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
}
[[nodiscard]] inline bool ChildEnvelope(const EventRecord& event,
                                        const EventCategory category,
                                        const EventType type) noexcept {
  const auto& h = event.header;
  return h.protocol_version == kEventProtocolVersion && h.category == category && h.type == type &&
         h.payload_size == kInlinePayloadSize && h.flags == 0 && h.session_id != 0 &&
         h.sequence_number != 0 && h.process_id != 0 && h.parent_event_id != 0 &&
         h.parent_event_id < h.sequence_number && h.artifact_id == 0 && h.navigation_id == 0 &&
         h.status_code == 0 && h.error_code == 0 && h.encoded_data_length == 0 &&
         h.decoded_body_length == 0 && h.resource_type == 0 && h.initiator_request_id == 0 &&
         h.initiator_process_id == 0;
}
}  // namespace request_stack_detail

[[nodiscard]] inline bool IsValidStackFrame(const StackFrame& frame, const bool async) noexcept {
  const auto kind = static_cast<StackFrameKind>(frame.kind);
  switch (kind) {
    case StackFrameKind::kJavaScript:
      return !async && frame.script_id != 0 && frame.combinator == 0 &&
             (frame.flags & ~(kStackFrameConstructor | kStackFrameTopLevel)) == 0;
    case StackFrameKind::kWasm:
      return !async && frame.script_id != 0 && frame.combinator == 0 && frame.flags == 0;
    case StackFrameKind::kAwait:
      return async && frame.script_id != 0 && frame.combinator == 0 &&
             (frame.flags & ~kStackFrameTopLevel) == 0;
    case StackFrameKind::kPromiseCombinator:
      return async && frame.script_id == 0 && frame.combinator >= 1 && frame.combinator <= 3 &&
             frame.flags == 0 && frame.detail == 0;
  }
  return false;
}

[[nodiscard]] inline bool IsValidRequestStackPayload(const RequestStackPayload& v) noexcept {
  using request_stack_detail::AllZero;
  constexpr std::uint8_t kKnownFlags = 0x0FU;
  if (v.protocol_version != kRequestStackPayloadVersion || v.payload_size != 128 ||
      v.reserved0 != 0 || !AllZero(v.reserved1) || (v.flags & ~kKnownFlags) != 0) {
    return false;
  }
  const auto state = static_cast<RequestStackState>(v.state);
  if (state == RequestStackState::kNoScript || state == RequestStackState::kUnsupportedThread) {
    return (v.flags & ~kRequestStackTaskCallersNotCaptured) == 0 && v.total_depth == 0 &&
           v.recorded == 0 && v.omitted == 0 && v.async_frames == 0 && v.async_segments == 0 &&
           v.wasm_frames == 0 && v.scripts == 0 && AllZero(v.digest) && v.innermost == StackFrame{};
  }
  if (state != RequestStackState::kCaptured &&
      state != RequestStackState::kNotRetainedArtifactUnavailable &&
      state != RequestStackState::kNotRetainedBudget) {
    return false;
  }
  const bool omitted = v.omitted != 0;
  const std::uint64_t frames = std::uint64_t{v.recorded} + v.async_frames;
  return v.recorded >= 1 && v.recorded <= kRequestStackSyncLimit &&
         std::uint64_t{v.recorded} + v.omitted == v.total_depth &&
         omitted == ((v.flags & kRequestStackFramesOmitted) != 0) &&
         (!omitted || v.recorded == kRequestStackSyncLimit) &&
         v.async_frames <= kRequestStackAsyncLimit && v.async_segments <= v.async_frames &&
         ((v.flags & kRequestStackAsyncTruncated) == 0 ||
          v.async_frames == kRequestStackAsyncLimit) &&
         ((v.flags & kRequestStackArtifactQueued) == 0 || state == RequestStackState::kCaptured) &&
         v.wasm_frames <= frames && v.scripts <= frames && !AllZero(v.digest) &&
         IsValidStackFrame(v.innermost, false);
}

[[nodiscard]] inline bool IsValidScriptIdentityPayload(const ScriptIdentityPayload& v) noexcept {
  using request_stack_detail::AllZero;
  constexpr std::uint8_t kRetention = kScriptIdentitySourceQueued | kScriptIdentitySourceTooLarge |
                                      kScriptIdentitySourceUnavailable | kScriptIdentityNotRetained;
  const std::uint8_t retention = v.flags & kRetention;
  if (v.protocol_version != kRequestStackPayloadVersion || v.payload_size != 128 ||
      v.reserved0 != 0 || v.reserved1 != 0 || !AllZero(v.reserved2) || v.script_id == 0 ||
      v.execution_context_id == 0 || (v.flags & ~(kRetention | kScriptIdentityEval)) != 0 ||
      std::popcount(retention) > 1) {
    return false;
  }
  if (v.kind == static_cast<std::uint8_t>(ScriptIdentityKind::kWasm) &&
      (v.flags & ~(kScriptIdentitySourceTooLarge | kScriptIdentitySourceUnavailable)) != 0) {
    return false;
  }
  if (v.kind == static_cast<std::uint8_t>(ScriptIdentityKind::kJavaScript) && retention == 0) {
    return false;
  }
  if (v.kind != static_cast<std::uint8_t>(ScriptIdentityKind::kJavaScript) &&
      v.kind != static_cast<std::uint8_t>(ScriptIdentityKind::kWasm)) {
    return false;
  }
  if (retention == kScriptIdentitySourceUnavailable) {
    return v.source_length == 0 && AllZero(v.sha256);
  }
  if (retention == kScriptIdentitySourceTooLarge) {
    return v.source_length > kScriptIdentityMaxSourceBytes && AllZero(v.sha256);
  }
  return v.source_length != 0 && v.source_length <= kScriptIdentityMaxSourceBytes &&
         !AllZero(v.sha256);
}

[[nodiscard]] inline bool DecodeRequestStackPayload(std::span<const std::byte> bytes,
                                                    RequestStackPayload& value) noexcept {
  if (bytes.size() != sizeof(RequestStackPayload)) {
    return false;
  }
  value = request_stack_detail::Decode<RequestStackPayload>(bytes);
  return true;
}

[[nodiscard]] inline bool DecodeScriptIdentityPayload(std::span<const std::byte> bytes,
                                                      ScriptIdentityPayload& value) noexcept {
  if (bytes.size() != sizeof(ScriptIdentityPayload)) {
    return false;
  }
  value = request_stack_detail::Decode<ScriptIdentityPayload>(bytes);
  return true;
}

[[nodiscard]] inline bool IsValidRequestStackEvent(const EventRecord& event) noexcept {
  RequestStackPayload value;
  return request_stack_detail::ChildEnvelope(event, EventCategory::kNetwork,
                                             EventType::kRequestInitiatorStack) &&
         event.header.request_id != 0 && DecodeRequestStackPayload(event.inline_payload, value) &&
         IsValidRequestStackPayload(value);
}

[[nodiscard]] inline bool IsValidScriptIdentityEvent(const EventRecord& event) noexcept {
  ScriptIdentityPayload value;
  return request_stack_detail::ChildEnvelope(event, EventCategory::kNetwork,
                                             EventType::kScriptIdentity) &&
         event.header.request_id == 0 && DecodeScriptIdentityPayload(event.inline_payload, value) &&
         IsValidScriptIdentityPayload(value);
}

// Validates one stack artifact's content and returns its frames through out.
[[nodiscard]] inline bool DecodeStackArtifact(std::span<const std::byte> content,
                                              StackArtifactHeader& header,
                                              std::span<StackFrame> out,
                                              std::size_t& frame_count) noexcept {
  frame_count = 0;
  if (content.size() < kStackArtifactHeaderSize || content.size() > kStackArtifactMaxBytes) {
    return false;
  }
  header = request_stack_detail::Decode<StackArtifactHeader>(content);
  const std::size_t frames = std::size_t{header.recorded} + header.async_frames;
  if (header.magic != kStackArtifactMagic || header.version != kStackArtifactVersion ||
      header.header_size != kStackArtifactHeaderSize || header.frame_size != kStackFrameSize ||
      header.reserved != 0 ||
      (header.flags & ~(kRequestStackFramesOmitted | kRequestStackAsyncTruncated)) != 0 ||
      header.recorded == 0 || header.recorded > kRequestStackSyncLimit ||
      std::uint64_t{header.recorded} + header.omitted != header.total_depth ||
      (header.omitted != 0) != ((header.flags & kRequestStackFramesOmitted) != 0) ||
      (header.omitted != 0 && header.recorded != kRequestStackSyncLimit) ||
      header.async_frames > kRequestStackAsyncLimit ||
      header.async_segments > header.async_frames ||
      ((header.flags & kRequestStackAsyncTruncated) != 0 &&
       header.async_frames != kRequestStackAsyncLimit) ||
      content.size() != kStackArtifactHeaderSize + kStackFrameSize * frames ||
      out.size() < frames) {
    return false;
  }
  for (std::size_t i = 0; i < frames; ++i) {
    out[i] = request_stack_detail::Decode<StackFrame>(
        content.subspan(kStackArtifactHeaderSize + i * kStackFrameSize, kStackFrameSize));
    if (!IsValidStackFrame(out[i], i >= header.recorded)) {
      return false;
    }
  }
  frame_count = frames;
  return true;
}
}  // namespace reb

#endif  // REB_REQUEST_STACK_HPP_
