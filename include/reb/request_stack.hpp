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
inline constexpr std::uint16_t kRequestStackTaskPayloadVersion = 2;
inline constexpr std::uint32_t kRequestStackSyncLimit = 1024;
inline constexpr std::uint32_t kRequestStackAsyncLimit = 32;
inline constexpr std::uint32_t kTaskSegmentLimit = 32;
inline constexpr std::uint32_t kAsyncTaskFrameLimit = 256;
inline constexpr std::uint32_t kStackArtifactMagic = 0x4b534252U;
inline constexpr std::uint16_t kStackArtifactVersion = 1;
inline constexpr std::uint16_t kStackArtifactTaskVersion = 2;
inline constexpr std::size_t kStackArtifactHeaderSize = 32;
inline constexpr std::size_t kStackFrameSize = 16;
inline constexpr std::size_t kTaskSegmentSize = 48;
inline constexpr std::size_t kStackArtifactMaxBytes =
    kStackArtifactHeaderSize +
    kStackFrameSize * (kRequestStackSyncLimit + kRequestStackAsyncLimit) +
    kTaskSegmentSize * kTaskSegmentLimit;
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
// Version 1: task-attributed callers not captured. Version 2: chain cut.
inline constexpr std::uint8_t kRequestStackTaskCallersNotCaptured = 1U << 3U;
inline constexpr std::uint8_t kRequestStackTaskChainCut = 1U << 3U;
inline constexpr std::uint8_t kRequestStackTaskChainTruncated = 1U << 4U;
inline constexpr std::uint8_t kTaskKindMicrotask = 9;
inline constexpr std::uint8_t kTaskSegmentNotRecorded = 6;
inline constexpr std::uint8_t kTaskSegmentBounded = 1U << 0U;

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
  std::uint16_t task_segments = 0;
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
  std::uint16_t task_segments = 0;
  std::uint16_t reserved = 0;
};
static_assert(sizeof(StackArtifactHeader) == kStackArtifactHeaderSize);
static_assert(std::has_unique_object_representations_v<StackArtifactHeader>);
static_assert(offsetof(StackArtifactHeader, total_depth) == 12);
static_assert(offsetof(StackArtifactHeader, async_frames) == 24);
static_assert(offsetof(StackArtifactHeader, task_segments) == 28);

struct TaskSegment final {
  std::uint8_t kind = 0;
  std::uint8_t state = 0;
  std::uint8_t flags = 0;
  std::uint8_t reserved0 = 0;
  std::uint32_t recorded = 0;
  std::array<std::uint8_t, 8> reserved1{};
  std::array<std::uint8_t, 32> digest{};
};
static_assert(sizeof(TaskSegment) == kTaskSegmentSize);
static_assert(std::has_unique_object_representations_v<TaskSegment>);
static_assert(offsetof(TaskSegment, digest) == 16);

struct AsyncTaskStackPayload final {
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
  StackFrame innermost{};
  std::array<std::uint8_t, 48> reserved2{};
};
static_assert(sizeof(AsyncTaskStackPayload) == kInlinePayloadSize);
static_assert(std::has_unique_object_representations_v<AsyncTaskStackPayload>);
static_assert(offsetof(AsyncTaskStackPayload, digest) == 32);
static_assert(offsetof(AsyncTaskStackPayload, innermost) == 64);

struct NavigationStackTail final {
  std::uint8_t kind = 0;
  std::array<std::uint8_t, 7> reserved0{};
  std::uint64_t target_frame_id = 0;
  std::array<std::uint8_t, 32> reserved1{};
};
static_assert(sizeof(NavigationStackTail) == 48);
static_assert(std::has_unique_object_representations_v<NavigationStackTail>);

struct NavigationLinkPayload final {
  std::uint16_t protocol_version = 1;
  std::uint16_t payload_size = 128;
  std::uint32_t renderer_process_id = 0;
  std::uint64_t renderer_sequence = 0;
  std::array<std::uint8_t, 112> reserved{};
};
static_assert(sizeof(NavigationLinkPayload) == kInlinePayloadSize);
static_assert(std::has_unique_object_representations_v<NavigationLinkPayload>);

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
  const bool tasks = v.protocol_version == kRequestStackTaskPayloadVersion;
  const std::uint8_t known_flags = tasks ? 0x1FU : 0x0FU;
  if ((v.protocol_version != kRequestStackPayloadVersion && !tasks) || v.payload_size != 128 ||
      (!tasks && v.task_segments != 0) || !AllZero(v.reserved1) || (v.flags & ~known_flags) != 0) {
    return false;
  }
  const auto state = static_cast<RequestStackState>(v.state);
  if (state == RequestStackState::kNoScript || state == RequestStackState::kUnsupportedThread) {
    const std::uint8_t allowed = tasks ? 0 : kRequestStackTaskCallersNotCaptured;
    return (v.flags & ~allowed) == 0 && v.task_segments == 0 && v.total_depth == 0 &&
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
         v.async_frames <= kRequestStackAsyncLimit &&
         (tasks ? v.task_segments <= kTaskSegmentLimit &&
                      v.async_segments == v.async_frames + v.task_segments &&
                      ((v.flags & kRequestStackTaskChainTruncated) == 0 ||
                       v.task_segments == kTaskSegmentLimit)
                : v.async_segments <= v.async_frames) &&
         ((v.flags & kRequestStackAsyncTruncated) == 0 ||
          v.async_frames == kRequestStackAsyncLimit) &&
         ((v.flags & kRequestStackArtifactQueued) == 0 || state == RequestStackState::kCaptured) &&
         v.wasm_frames <= frames && v.scripts <= frames && !AllZero(v.digest) &&
         IsValidStackFrame(v.innermost, false);
}

[[nodiscard]] inline bool IsValidTaskSegment(const TaskSegment& s) noexcept {
  using request_stack_detail::AllZero;
  if (s.reserved0 != 0 || !AllZero(s.reserved1) || (s.flags & ~kTaskSegmentBounded) != 0) {
    return false;
  }
  if (s.kind == kTaskKindMicrotask) {
    return s.state == kTaskSegmentNotRecorded && s.flags == 0 && s.recorded == 0 &&
           AllZero(s.digest);
  }
  return s.kind >= 1 && s.kind <= 8 && (s.state == 1 || s.state == 4 || s.state == 5) &&
         s.recorded >= 1 && s.recorded <= kAsyncTaskFrameLimit &&
         ((s.flags & kTaskSegmentBounded) == 0 || s.recorded == kAsyncTaskFrameLimit) &&
         !AllZero(s.digest);
}

[[nodiscard]] inline bool IsValidAsyncTaskStackPayload(const AsyncTaskStackPayload& v) noexcept {
  using request_stack_detail::AllZero;
  return v.protocol_version == 1 && v.payload_size == 128 && v.kind >= 1 && v.kind <= 8 &&
         (v.flags & ~kTaskSegmentBounded) == 0 && v.reserved0 == 0 && AllZero(v.reserved1) &&
         AllZero(v.reserved2) && v.recorded >= 1 && v.recorded <= kAsyncTaskFrameLimit &&
         ((v.flags & kTaskSegmentBounded) == 0 || v.recorded == kAsyncTaskFrameLimit) &&
         v.wasm_frames <= v.recorded && v.scripts <= v.recorded && !AllZero(v.digest) &&
         IsValidStackFrame(v.innermost, false);
}

[[nodiscard]] inline bool IsValidNavigationStackPayload(const RequestStackPayload& v) noexcept {
  using request_stack_detail::AllZero;
  const auto tail = std::bit_cast<NavigationStackTail>(v.reserved1);
  RequestStackPayload stack = v;
  stack.reserved1 = {};
  return v.protocol_version == kRequestStackTaskPayloadVersion && tail.kind >= 1 &&
         tail.kind <= 4 && AllZero(tail.reserved0) && AllZero(tail.reserved1) &&
         tail.target_frame_id != 0 &&
         (v.state == static_cast<std::uint8_t>(RequestStackState::kCaptured) ||
          v.state ==
              static_cast<std::uint8_t>(RequestStackState::kNotRetainedArtifactUnavailable) ||
          v.state == static_cast<std::uint8_t>(RequestStackState::kNotRetainedBudget)) &&
         IsValidRequestStackPayload(stack);
}

[[nodiscard]] inline bool IsValidNavigationLinkPayload(const NavigationLinkPayload& v) noexcept {
  return v.protocol_version == 1 && v.payload_size == 128 && v.renderer_process_id != 0 &&
         v.renderer_sequence != 0 && request_stack_detail::AllZero(v.reserved);
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

// Parentless renderer records: navigation and scheduling-time stacks.
[[nodiscard]] inline bool IsValidRendererStackEnvelope(const EventRecord& event,
                                                       const EventType type) noexcept {
  const auto& h = event.header;
  return h.protocol_version == kEventProtocolVersion && h.category == EventCategory::kNetwork &&
         h.type == type && h.payload_size == kInlinePayloadSize && h.flags == 0 &&
         h.session_id != 0 && h.sequence_number != 0 && h.process_id != 0 &&
         h.parent_event_id == 0 && h.request_id == 0 && h.artifact_id == 0 &&
         h.navigation_id == 0 && h.status_code == 0 && h.error_code == 0 &&
         h.encoded_data_length == 0 && h.decoded_body_length == 0 && h.resource_type == 0 &&
         h.initiator_request_id == 0 && h.initiator_process_id == 0;
}

[[nodiscard]] inline bool IsValidNavigationStackEvent(const EventRecord& event) noexcept {
  RequestStackPayload value;
  return IsValidRendererStackEnvelope(event, EventType::kNavigationInitiatorStack) &&
         DecodeRequestStackPayload(event.inline_payload, value) &&
         IsValidNavigationStackPayload(value);
}

[[nodiscard]] inline bool IsValidAsyncTaskStackEvent(const EventRecord& event) noexcept {
  return IsValidRendererStackEnvelope(event, EventType::kAsyncTaskStack) &&
         IsValidAsyncTaskStackPayload(
             request_stack_detail::Decode<AsyncTaskStackPayload>(event.inline_payload));
}

// A browser child of the navigation's request_started, like request_target.
[[nodiscard]] inline bool IsValidNavigationLinkEvent(const EventRecord& event) noexcept {
  const auto& h = event.header;
  return h.protocol_version == kEventProtocolVersion && h.category == EventCategory::kNetwork &&
         h.type == EventType::kNavigationInitiatorLink && h.payload_size == kInlinePayloadSize &&
         h.flags == 0 && h.session_id != 0 && h.sequence_number != 0 && h.process_id != 0 &&
         h.parent_event_id != 0 && h.parent_event_id < h.sequence_number && h.request_id != 0 &&
         h.artifact_id == 0 && h.navigation_id == 0 && h.status_code == 0 && h.error_code == 0 &&
         h.encoded_data_length == 0 && h.decoded_body_length == 0 && h.resource_type == 0 &&
         IsValidNavigationLinkPayload(
             request_stack_detail::Decode<NavigationLinkPayload>(event.inline_payload));
}

// Validates one stack artifact; returns its frames and version 2 task chain.
[[nodiscard]] inline bool DecodeStackArtifact(std::span<const std::byte> content,
                                              StackArtifactHeader& header,
                                              std::span<StackFrame> out,
                                              std::size_t& frame_count,
                                              std::span<TaskSegment> segments = {},
                                              std::size_t* segment_count = nullptr) noexcept {
  frame_count = 0;
  if (segment_count) {
    *segment_count = 0;
  }
  if (content.size() < kStackArtifactHeaderSize || content.size() > kStackArtifactMaxBytes) {
    return false;
  }
  header = request_stack_detail::Decode<StackArtifactHeader>(content);
  const bool tasks = header.version == kStackArtifactTaskVersion;
  const std::size_t frames = std::size_t{header.recorded} + header.async_frames;
  const std::uint16_t known =
      kRequestStackFramesOmitted | kRequestStackAsyncTruncated |
      (tasks ? kRequestStackTaskChainCut | kRequestStackTaskChainTruncated : 0);
  if (header.magic != kStackArtifactMagic || (header.version != kStackArtifactVersion && !tasks) ||
      header.header_size != kStackArtifactHeaderSize || header.frame_size != kStackFrameSize ||
      header.reserved != 0 || (!tasks && header.task_segments != 0) ||
      (header.flags & ~known) != 0 || header.recorded == 0 ||
      header.recorded > kRequestStackSyncLimit ||
      std::uint64_t{header.recorded} + header.omitted != header.total_depth ||
      (header.omitted != 0) != ((header.flags & kRequestStackFramesOmitted) != 0) ||
      (header.omitted != 0 && header.recorded != kRequestStackSyncLimit) ||
      header.async_frames > kRequestStackAsyncLimit ||
      (tasks ? header.task_segments > kTaskSegmentLimit ||
                   header.async_segments != header.async_frames + header.task_segments ||
                   ((header.flags & kRequestStackTaskChainTruncated) != 0 &&
                    header.task_segments != kTaskSegmentLimit)
             : header.async_segments > header.async_frames) ||
      ((header.flags & kRequestStackAsyncTruncated) != 0 &&
       header.async_frames != kRequestStackAsyncLimit) ||
      content.size() != kStackArtifactHeaderSize + kStackFrameSize * frames +
                            kTaskSegmentSize * header.task_segments ||
      out.size() < frames ||
      (header.task_segments != 0 && segments.size() < header.task_segments)) {
    return false;
  }
  for (std::size_t i = 0; i < frames; ++i) {
    out[i] = request_stack_detail::Decode<StackFrame>(
        content.subspan(kStackArtifactHeaderSize + i * kStackFrameSize, kStackFrameSize));
    if (!IsValidStackFrame(out[i], i >= header.recorded)) {
      return false;
    }
  }
  const std::size_t chain = kStackArtifactHeaderSize + kStackFrameSize * frames;
  for (std::size_t i = 0; i < header.task_segments; ++i) {
    segments[i] = request_stack_detail::Decode<TaskSegment>(
        content.subspan(chain + i * kTaskSegmentSize, kTaskSegmentSize));
    if (!IsValidTaskSegment(segments[i])) {
      return false;
    }
  }
  frame_count = frames;
  if (segment_count) {
    *segment_count = header.task_segments;
  }
  return true;
}
}  // namespace reb

#endif  // REB_REQUEST_STACK_HPP_
