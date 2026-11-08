// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <span>
#include <string_view>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "crypto/hash.h"

namespace reb {

// Touched only by main-thread walks; keyed by configuration generation so a new
// session never sees an old session's digests, scripts or budgets.
struct NativeRequestStackTables final {
  struct Digest final {
    std::uint64_t generation = 0;
    std::array<std::uint8_t, 32> value{};
  };
  struct Script final {
    std::uint64_t generation = 0;
    std::uint32_t id = 0;
  };
  std::array<NativeStackFrame, kNativeRequestStackFrameCapacity> frames{};
  std::array<std::uint8_t, kNativeStackArtifactMaxBytes> artifact{};
  std::array<Digest, kNativeRequestStackDigestTable> digests{};
  std::array<Script, kNativeRequestStackScriptTable> scripts{};
  std::array<std::uint64_t, 2 * kNativeRequestStackFrameCapacity> distinct{};
  std::uint32_t distinct_stamp = 0;
  std::size_t evict = 0;
  std::uint64_t budget_generation = 0;
  std::uint32_t stacks_sent = 0;
  std::uint32_t sources_sent = 0;
  std::uint64_t source_bytes = 0;
};

namespace {

constexpr std::size_t kProbe = 8;
static_assert((kNativeRequestStackDigestTable & (kNativeRequestStackDigestTable - 1)) == 0);
static_assert((kNativeRequestStackScriptTable & (kNativeRequestStackScriptTable - 1)) == 0);

// The state is published before the provider; a loaded provider implies it.
std::atomic<NativeRequestStackProvider> g_provider{nullptr};
NativeRequestStackTables* g_state = nullptr;
thread_local bool g_walking = false;

std::uint64_t MonotonicNs() noexcept {
  return static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
}

std::size_t Mix(std::uint64_t value) noexcept {
  value ^= value >> 33U;
  value *= 0xff51afd7ed558ccdULL;
  value ^= value >> 33U;
  return static_cast<std::size_t>(value);
}

std::uint64_t DigestKey(const std::array<std::uint8_t, 32>& digest) noexcept {
  std::uint64_t key = 0;
  std::memcpy(&key, digest.data(), sizeof(key));
  return key;
}

template <typename Entry, std::size_t N, typename Match>
Entry* Find(std::array<Entry, N>& table, const std::size_t hash, const Match& match) noexcept {
  for (std::size_t i = 0; i < kProbe; ++i) {
    Entry& entry = table[(hash + i) & (N - 1)];
    if (match(entry)) {
      return &entry;
    }
  }
  return nullptr;
}

// A stale slot in the probe window, or the next one round robin.
template <typename Entry, std::size_t N>
Entry& Slot(std::array<Entry, N>& table,
            const std::size_t hash,
            const std::uint64_t generation,
            std::size_t& evict) noexcept {
  for (std::size_t i = 0; i < kProbe; ++i) {
    Entry& entry = table[(hash + i) & (N - 1)];
    if (entry.generation != generation) {
      return entry;
    }
  }
  return table[(hash + (evict++ % kProbe)) & (N - 1)];
}

std::uint32_t CountDistinctScripts(NativeRequestStackTables& state,
                                   std::span<const NativeStackFrame> sync,
                                   std::span<const NativeStackFrame> async) noexcept {
  if (++state.distinct_stamp == 0) {
    state.distinct.fill(0);
    state.distinct_stamp = 1;
  }
  const std::uint64_t stamp = std::uint64_t{state.distinct_stamp} << 32U;
  const std::size_t mask = state.distinct.size() - 1;
  std::uint32_t count = 0;
  for (const auto part : {sync, async}) {
    for (const NativeStackFrame& frame : part) {
      if (frame.script_id == 0) {
        continue;
      }
      const std::uint64_t key = stamp | frame.script_id;
      for (std::size_t slot = Mix(frame.script_id) & mask;; slot = (slot + 1) & mask) {
        std::uint64_t& entry = state.distinct[slot];
        if (entry == key) {
          break;
        }
        if ((entry >> 32U) != state.distinct_stamp) {
          entry = key;
          ++count;
          break;
        }
      }
    }
  }
  return count;
}

NativeProbeEvent ChildEvent(const NativeProbeType type,
                            const std::uint64_t session_id,
                            const std::uint64_t frame_id,
                            const std::uint64_t parent) noexcept {
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = type;
  event.header.payload_size = static_cast<std::uint32_t>(kNativeProbeInlinePayloadSize);
  event.header.session_id = session_id;
  event.header.monotonic_time_ns = MonotonicNs();
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.frame_id = frame_id;
  event.header.parent_event_id = parent;
  return event;
}

}  // namespace

void NativeRequestStackWalk::SetProvider(const NativeRequestStackProvider provider) noexcept {
  if (!provider || g_provider.load(std::memory_order_acquire)) {
    return;
  }
  // Process lifetime: the frame buffer and tables are allocated once, here.
  g_state = new NativeRequestStackTables();
  g_provider.store(provider, std::memory_order_release);
}

void NativeRequestStackWalk::Record(const std::int32_t request_id,
                                    const std::uint64_t initiated_sequence) noexcept {
  if (initiated_sequence == 0) {
    return;
  }
  const NativeRequestStackProvider provider = g_provider.load(std::memory_order_acquire);
  if (!provider || request_id == 0 || g_walking) {
    return;
  }
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return;
  }
  const NativeProbeFrameIdProvider frame_ids =
      sink.frame_id_provider_.load(std::memory_order_relaxed);
  g_walking = true;
  NativeRequestStackWalk walk(g_state, generation, request_id, initiated_sequence,
                              frame_ids ? frame_ids() : 0);
  const NativeRequestStackWalkResult result = provider(walk);
  g_walking = false;
  if (result == NativeRequestStackWalkResult::kWalked) {
    if (!walk.frames_ready_) {
      walk.FramesReady(0, 0, 0, 0, false);
    }
    return;
  }
  NativeRequestStackPayload payload;
  payload.state = static_cast<std::uint8_t>(result == NativeRequestStackWalkResult::kNoScript
                                                ? NativeRequestStackState::kNoScript
                                                : NativeRequestStackState::kUnsupportedThread);
  payload.flags = kNativeRequestStackTaskCallersNotCaptured;
  walk.Emit(payload);
}

NativeRequestStackWalk::NativeRequestStackWalk(NativeRequestStackTables* const state,
                                               const std::uint64_t generation,
                                               const std::int32_t request_id,
                                               const std::uint64_t parent_sequence,
                                               const std::uint64_t frame_id) noexcept
    : state_(state),
      generation_(generation),
      request_id_(request_id),
      parent_sequence_(parent_sequence),
      frame_id_(frame_id) {}

std::span<NativeStackFrame> NativeRequestStackWalk::frames() noexcept {
  return state_ ? std::span<NativeStackFrame>(state_->frames) : std::span<NativeStackFrame>();
}

void NativeRequestStackWalk::SetExecutionContext(
    const std::uint64_t execution_context_id) noexcept {
  execution_context_id_ = execution_context_id;
}

bool NativeRequestStackWalk::ScriptNeeded(const std::uint32_t script_id) const noexcept {
  if (!state_ || script_id == 0) {
    return false;
  }
  return !Find(state_->scripts, Mix(script_id), [&](const NativeRequestStackTables::Script& entry) {
    return entry.generation == generation_ && entry.id == script_id;
  });
}

void NativeRequestStackWalk::Emit(const NativeRequestStackPayload& payload) noexcept {
  NativeProbeSink& sink = NativeProbeSink::Get();
  if (!IsValidNativeRequestStackPayload(payload)) {
    // A walk that produced no valid record still leaves a visible omission.
    NativeProbeEvent gap = ChildEvent(
        NativeProbeType::kGap, sink.session_id_.load(std::memory_order_relaxed), frame_id_, 0);
    constexpr std::string_view kReason = "request_stack_malformed";
    gap.header.payload_size = static_cast<std::uint32_t>(kReason.size());
    std::transform(kReason.begin(), kReason.end(), gap.inline_payload.begin(),
                   [](const char c) { return static_cast<std::byte>(c); });
    gap.header.sequence_number = sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
    static_cast<void>(sink.EmitStatus(gap, generation_));
    return;
  }
  NativeProbeEvent event =
      ChildEvent(NativeProbeType::kRequestInitiatorStack,
                 sink.session_id_.load(std::memory_order_relaxed), frame_id_, parent_sequence_);
  event.header.request_id = static_cast<std::uint64_t>(static_cast<std::uint32_t>(request_id_));
  event.header.sequence_number = sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.inline_payload = EncodeNativeRequestStackRecord(payload);
  if (sink.EmitStatus(event, generation_) == NativeProbeEmitStatus::kAdmitted) {
    stack_sequence_ = event.header.sequence_number;
  }
}

void NativeRequestStackWalk::FramesReady(const std::uint32_t total_depth,
                                         std::uint32_t recorded,
                                         const std::uint32_t omitted,
                                         std::uint32_t async_frames,
                                         const bool async_truncated) noexcept {
  if (frames_ready_) {
    return;
  }
  frames_ready_ = true;
  NativeRequestStackPayload payload;
  payload.flags = kNativeRequestStackTaskCallersNotCaptured;
  if (recorded == 0 || !state_) {
    payload.state = static_cast<std::uint8_t>(NativeRequestStackState::kNoScript);
    Emit(payload);
    return;
  }
  NativeRequestStackTables& state = *state_;
  if (state.budget_generation != generation_) {
    state.budget_generation = generation_;
    state.stacks_sent = 0;
    state.sources_sent = 0;
    state.source_bytes = 0;
  }
  recorded = std::min(recorded, kNativeRequestStackSyncLimit);
  async_frames = std::min(async_frames, kNativeRequestStackAsyncLimit);
  payload.total_depth = total_depth;
  payload.recorded = recorded;
  payload.omitted = omitted;
  payload.async_frames = static_cast<std::uint16_t>(async_frames);
  payload.async_segments = static_cast<std::uint16_t>(async_frames);
  if (omitted != 0) {
    payload.flags |= kNativeRequestStackFramesOmitted;
  }
  if (async_truncated && async_frames == kNativeRequestStackAsyncLimit) {
    payload.flags |= kNativeRequestStackAsyncTruncated;
  }

  NativeStackArtifactHeader header;
  header.flags =
      payload.flags & (kNativeRequestStackFramesOmitted | kNativeRequestStackAsyncTruncated);
  header.total_depth = total_depth;
  header.recorded = recorded;
  header.omitted = omitted;
  header.async_frames = payload.async_frames;
  header.async_segments = payload.async_segments;
  const std::span<const NativeStackFrame> sync(state.frames.data(), recorded);
  const std::span<const NativeStackFrame> async(state.frames.data() + kNativeRequestStackSyncLimit,
                                                async_frames);
  std::size_t size = kNativeStackArtifactHeaderSize;
  std::memcpy(state.artifact.data(), &header, sizeof(header));
  for (std::size_t i = 0; i < std::size_t{recorded} + async_frames; ++i) {
    const bool is_async = i >= recorded;
    const NativeStackFrame& frame = is_async ? async[i - recorded] : sync[i];
    if (!IsValidNativeStackFrame(frame, is_async)) {
      // payload.state stays 0, so Emit reports the walk as a gap.
      Emit(payload);
      return;
    }
    payload.wasm_frames += frame.kind == static_cast<std::uint8_t>(NativeStackFrameKind::kWasm);
    std::memcpy(state.artifact.data() + size, &frame, sizeof(frame));
    size += sizeof(frame);
  }
  payload.scripts = CountDistinctScripts(state, sync, async);
  payload.innermost = state.frames[0];
  const std::span<const std::uint8_t> content(state.artifact.data(), size);
  payload.digest = crypto::hash::Sha256(content);

  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::size_t hash = Mix(DigestKey(payload.digest));
  const bool known = Find(state.digests, hash, [&](const NativeRequestStackTables::Digest& entry) {
                       return entry.generation == generation_ && entry.value == payload.digest;
                     }) != nullptr;
  bool queue = false;
  if (execution_context_id_ == 0 || !sink.IsArtifactCaptureEnabled()) {
    payload.state =
        static_cast<std::uint8_t>(NativeRequestStackState::kNotRetainedArtifactUnavailable);
  } else if (known) {
    payload.state = static_cast<std::uint8_t>(NativeRequestStackState::kCaptured);
  } else if (state.stacks_sent >= kNativeRequestStackArtifactBudget) {
    payload.state = static_cast<std::uint8_t>(NativeRequestStackState::kNotRetainedBudget);
  } else {
    payload.state = static_cast<std::uint8_t>(NativeRequestStackState::kCaptured);
    payload.flags |= kNativeRequestStackArtifactQueued;
    queue = true;
  }
  Emit(payload);
  if (stack_sequence_ == 0 || !queue) {
    return;
  }
  constexpr std::string_view kPrefix = "reb-stack:sha256-";
  constexpr std::string_view kHex = "0123456789abcdef";
  std::array<char, kPrefix.size() + 64> url{};
  std::copy(kPrefix.begin(), kPrefix.end(), url.begin());
  for (std::size_t i = 0; i < payload.digest.size(); ++i) {
    url[kPrefix.size() + 2 * i] = kHex[payload.digest[i] >> 4U];
    url[kPrefix.size() + 2 * i + 1] = kHex[payload.digest[i] & 0x0fU];
  }
  sink.CaptureGeneratedArtifact(
      NativeArtifactKind::kStack, NativeArtifactCaptureOrigin::kRequestStack, stack_sequence_,
      execution_context_id_, frame_id_, std::string_view(url.data(), url.size()), content);
  NativeRequestStackTables::Digest& slot = Slot(state.digests, hash, generation_, state.evict);
  slot.generation = generation_;
  slot.value = payload.digest;
  ++state.stacks_sent;
}

void NativeRequestStackWalk::DescribeScript(const NativeStackScriptSource& script) noexcept {
  if (!state_ || stack_sequence_ == 0 || script.execution_context_id == 0 ||
      !ScriptNeeded(script.script_id)) {
    return;
  }
  NativeRequestStackTables& state = *state_;
  const bool javascript = script.kind == NativeScriptIdentityKind::kJavaScript;
  NativeScriptIdentityPayload payload;
  payload.kind = static_cast<std::uint8_t>(script.kind);
  payload.flags = javascript && script.is_eval ? kNativeScriptIdentityEval : 0;
  payload.script_id = script.script_id;
  payload.start_line = script.start_line;
  payload.start_column = script.start_column;
  payload.execution_context_id = script.execution_context_id;
  NativeProbeSink& sink = NativeProbeSink::Get();
  bool queue = false;
  if (script.too_large) {
    payload.flags |= kNativeScriptIdentitySourceTooLarge;
    payload.source_length = script.too_large_length;
  } else if (script.bytes.empty() || script.bytes.size() > kNativeScriptIdentityMaxSourceBytes) {
    payload.flags |= kNativeScriptIdentitySourceUnavailable;
  } else {
    payload.source_length = script.bytes.size();
    payload.sha256 = crypto::hash::Sha256(script.bytes);
    if (javascript) {
      queue = sink.IsArtifactCaptureEnabled() && !script.url.empty() &&
              script.url.size() <= kNativeArtifactMaxUrlBytes &&
              state.sources_sent < kNativeRequestStackSourceBudget &&
              state.source_bytes + script.bytes.size() <= kNativeRequestStackSourceBytes;
      payload.flags |= queue ? kNativeScriptIdentitySourceQueued : kNativeScriptIdentityNotRetained;
    }
  }
  if (!IsValidNativeScriptIdentityPayload(payload)) {
    return;
  }
  NativeProbeEvent event =
      ChildEvent(NativeProbeType::kScriptIdentity, sink.session_id_.load(std::memory_order_relaxed),
                 frame_id_, stack_sequence_);
  event.header.sequence_number = sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.inline_payload = EncodeNativeRequestStackRecord(payload);
  if (sink.EmitStatus(event, generation_) != NativeProbeEmitStatus::kAdmitted) {
    return;
  }
  const std::size_t hash = Mix(script.script_id);
  NativeRequestStackTables::Script& slot = Slot(state.scripts, hash, generation_, state.evict);
  slot.generation = generation_;
  slot.id = script.script_id;
  if (!queue) {
    return;
  }
  sink.CaptureGeneratedArtifact(NativeArtifactKind::kJavaScript,
                                NativeArtifactCaptureOrigin::kStackScript,
                                event.header.sequence_number, script.execution_context_id,
                                frame_id_, script.url, script.bytes);
  ++state.sources_sent;
  state.source_bytes += script.bytes.size();
}

}  // namespace reb
