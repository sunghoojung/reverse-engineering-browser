// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/renderer/native_fetch_owner.h"
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
  struct Segment final {
    std::uint64_t serial = 0;
    std::uint64_t generation = 0;
    std::uint64_t parent = 0;
    std::array<std::uint8_t, 32> digest{};
    std::uint32_t recorded = 0;
    std::uint8_t kind = 0;
    std::uint8_t state = 0;
    std::uint8_t flags = 0;
    // Scheduled in a microtask: a microtask hop precedes the parent.
    bool parent_via_microtask = false;
    // That microtask's task attribution named no remembered segment.
    bool parent_unknown = false;
  };
  struct Attribution final {
    std::uint64_t generation = 0;
    std::uint32_t id = 0;
    std::uint64_t segment = 0;
  };
  struct FormNavigation final {
    std::uint64_t generation = 0;
    std::uint64_t target = 0;
    std::uint64_t sequence = 0;
  };
  std::array<NativeStackFrame, kNativeRequestStackFrameCapacity> frames{};
  std::array<std::uint8_t, kNativeStackArtifactMaxBytes> artifact{};
  std::array<Digest, kNativeRequestStackDigestTable> digests{};
  std::array<Script, kNativeRequestStackScriptTable> scripts{};
  std::array<std::uint64_t, std::bit_ceil(2 * kNativeRequestStackFrameCapacity)> distinct{};
  std::uint32_t distinct_stamp = 0;
  std::size_t evict = 0;
  std::uint64_t budget_generation = 0;
  std::uint32_t stacks_sent = 0;
  std::uint32_t sources_sent = 0;
  std::uint64_t source_bytes = 0;
  std::uint32_t async_sent = 0;
  std::array<Segment, kNativeAsyncTaskRing> segments{};
  std::uint64_t next_segment = 0;
  std::array<Attribution, kNativeTaskAttributionTable> attributions{};
  std::size_t attribution_evict = 0;
  std::array<FormNavigation, kNativeFormNavigationTable> forms{};
  std::size_t form_evict = 0;
};

namespace {

constexpr std::size_t kProbe = 8;
static_assert((kNativeRequestStackDigestTable & (kNativeRequestStackDigestTable - 1)) == 0);
static_assert((kNativeRequestStackScriptTable & (kNativeRequestStackScriptTable - 1)) == 0);
static_assert((kNativeAsyncTaskRing & (kNativeAsyncTaskRing - 1)) == 0);
static_assert((kNativeTaskAttributionTable & (kNativeTaskAttributionTable - 1)) == 0);

// The state is published before the provider; a loaded provider implies it.
std::atomic<NativeRequestStackProvider> g_provider{nullptr};
NativeRequestStackTables* g_state = nullptr;
thread_local bool g_walking = false;
thread_local std::uint64_t g_current_segment = 0;
thread_local NativeNavigationKind g_navigation_kind = NativeNavigationKind::kOtherScript;

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

// The checks RecordRequestInitiated makes before admitting a network record.
bool NetworkActive(const std::uint64_t category_mask,
                   const std::uint64_t expires_at,
                   const bool emitter) noexcept {
  return emitter && (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) != 0 &&
         MonotonicNs() < expires_at;
}

void ResetBudgets(NativeRequestStackTables& state, const std::uint64_t generation) noexcept {
  if (state.budget_generation != generation) {
    state.budget_generation = generation;
    state.stacks_sent = 0;
    state.sources_sent = 0;
    state.source_bytes = 0;
    state.async_sent = 0;
  }
}

const NativeRequestStackTables::Segment* FindSegment(const NativeRequestStackTables& state,
                                                     const std::uint64_t serial,
                                                     const std::uint64_t generation) noexcept {
  const auto& entry = state.segments[serial & (kNativeAsyncTaskRing - 1)];
  return serial != 0 && entry.serial == serial && entry.generation == generation ? &entry : nullptr;
}

std::uint64_t AttributedSegment(NativeRequestStackTables& state,
                                const std::uint32_t id,
                                const std::uint64_t generation) noexcept {
  if (id == 0) {
    return 0;
  }
  const auto* entry = Find(state.attributions, Mix(id), [&](const auto& item) {
    return item.generation == generation && item.id == id;
  });
  return entry ? entry->segment : 0;
}

bool IsObservation(const NativeProbeType type) noexcept {
  return type >= NativeProbeType::kRequestWatchMatch && type <= NativeProbeType::kDomMutation;
}

NativeProbeEvent ChildEvent(const NativeProbeType type,
                            const std::uint64_t session_id,
                            const std::uint64_t frame_id,
                            const std::uint64_t parent) noexcept {
  NativeProbeEvent event;
  event.header.category = IsObservation(type) && type != NativeProbeType::kRequestWatchMatch
                              ? NativeProbeCategory::kRuntime
                              : NativeProbeCategory::kNetwork;
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
  g_walking = true;
  NativeRequestStackWalk walk(g_state, generation, request_id, initiated_sequence,
                              RequestFrameId());
  const NativeRequestStackWalkResult result = provider(walk);
  g_walking = false;
  if (result == NativeRequestStackWalkResult::kWalked) {
    if (!walk.frames_ready_) {
      walk.FramesReady(0, 0, 0, 0, false);
    }
    return;
  }
  NativeRequestStackPayload payload;
  payload.protocol_version = kNativeRequestStackTaskPayloadVersion;
  payload.state = static_cast<std::uint8_t>(result == NativeRequestStackWalkResult::kNoScript
                                                ? NativeRequestStackState::kNoScript
                                                : NativeRequestStackState::kUnsupportedThread);
  walk.Emit(payload);
}

std::uint64_t NativeRequestStackWalk::RequestFrameId() noexcept {
  if (const NativeFetchOwner owner = NativeFetchOwnerScope::Current();
      owner.kind != NativeLoaderKind::kNotRecorded) {
    return owner.context_id;
  }
  const NativeProbeFrameIdProvider frame_ids =
      NativeProbeSink::Get().frame_id_provider_.load(std::memory_order_relaxed);
  return frame_ids ? frame_ids() : 0;
}

void NativeRequestStackWalk::RecordObservation(const NativeProbeType type,
                                               const std::int32_t request_id,
                                               const std::uint64_t parent_sequence,
                                               const std::uint64_t frame_id,
                                               const std::array<std::uint8_t, 48>& tail) noexcept {
  if (!IsObservation(type) || g_walking) {
    return;
  }
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return;
  }
  // Zero means the current document's frame, as the request stack walk resolves.
  std::uint64_t resolved_frame = frame_id;
  if (resolved_frame == 0) {
    const NativeProbeFrameIdProvider frame_ids =
        sink.frame_id_provider_.load(std::memory_order_relaxed);
    resolved_frame = frame_ids ? frame_ids() : 0;
  }
  const NativeRequestStackProvider provider = g_provider.load(std::memory_order_acquire);
  NativeRequestStackWalk walk(provider ? g_state : nullptr, generation, request_id, parent_sequence,
                              resolved_frame, type, tail);
  NativeRequestStackWalkResult result = NativeRequestStackWalkResult::kNoScript;
  if (provider) {
    g_walking = true;
    result = provider(walk);
    g_walking = false;
  }
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

bool NativeRequestStackWalk::RecordCookieStack(const std::uint64_t cookie_sequence,
                                               const std::uint64_t frame_id,
                                               std::array<std::uint8_t, 32>& digest,
                                               NativeStackFrame& innermost) noexcept {
  const NativeRequestStackProvider provider = g_provider.load(std::memory_order_acquire);
  if (!provider || cookie_sequence == 0 || g_walking) {
    return false;
  }
  const std::uint64_t generation =
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return false;
  }
  g_walking = true;
  NativeRequestStackWalk walk(g_state, generation, 0, cookie_sequence, frame_id,
                              NativeProbeType::kScriptCookie);
  const NativeRequestStackWalkResult result = provider(walk);
  g_walking = false;
  if (result != NativeRequestStackWalkResult::kWalked || walk.stack_sequence_ == 0) {
    return false;
  }
  digest = walk.digest_;
  innermost = walk.innermost_;
  return true;
}

NativeNavigationKindScope::NativeNavigationKindScope(const NativeNavigationKind kind) noexcept
    : previous_(g_navigation_kind) {
  g_navigation_kind = kind;
}

NativeNavigationKindScope::~NativeNavigationKindScope() {
  g_navigation_kind = previous_;
}

NativeNavigationKind NativeNavigationKindScope::Current() noexcept {
  return g_navigation_kind;
}

bool NativeRequestStackWalk::Enabled() noexcept {
  return g_provider.load(std::memory_order_acquire) != nullptr;
}

std::uint64_t NativeRequestStackWalk::RecordNavigation(
    const NativeNavigationKind kind,
    const std::uint64_t target_frame_id) noexcept {
  const NativeRequestStackProvider provider = g_provider.load(std::memory_order_acquire);
  if (!provider || target_frame_id == 0 || g_walking) {
    return 0;
  }
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0 ||
      !NetworkActive(sink.category_mask_.load(std::memory_order_relaxed),
                     sink.expires_at_monotonic_ns_.load(std::memory_order_relaxed),
                     sink.emitter_.load(std::memory_order_relaxed) != nullptr)) {
    return 0;
  }
  NativeNavigationStackTail tail;
  tail.kind = static_cast<std::uint8_t>(kind);
  tail.target_frame_id = target_frame_id;
  g_walking = true;
  NativeRequestStackWalk walk(g_state, generation, 0, 0, RequestFrameId(),
                              NativeProbeType::kNavigationInitiatorStack,
                              std::bit_cast<std::array<std::uint8_t, 48>>(tail));
  const NativeRequestStackWalkResult result = provider(walk);
  g_walking = false;
  return result == NativeRequestStackWalkResult::kWalked ? walk.stack_sequence_ : 0;
}

void NativeRequestStackWalk::ScheduleFormNavigation(const std::uint64_t target_frame_id) noexcept {
  if (!g_provider.load(std::memory_order_acquire) || target_frame_id == 0) {
    return;
  }
  const std::uint64_t sequence =
      RecordNavigation(NativeNavigationKind::kFormSubmission, target_frame_id);
  const std::uint64_t generation =
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire);
  NativeRequestStackTables& state = *g_state;
  // A later submission replaces the pending one, even with no script.
  auto* slot = Find(state.forms, 0, [&](const auto& entry) {
    return entry.generation == generation && entry.target == target_frame_id;
  });
  if (!slot) {
    slot = &Slot(state.forms, 0, generation, state.form_evict);
  }
  *slot = {generation, target_frame_id, sequence};
}

std::uint64_t NativeRequestStackWalk::TakeFormNavigation(
    const std::uint64_t target_frame_id) noexcept {
  if (!g_provider.load(std::memory_order_acquire) || target_frame_id == 0) {
    return 0;
  }
  const std::uint64_t generation =
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire);
  auto* slot = Find(g_state->forms, 0, [&](const auto& entry) {
    return entry.generation == generation && entry.target == target_frame_id;
  });
  if (!slot) {
    return 0;
  }
  const std::uint64_t sequence = slot->sequence;
  *slot = {};
  return sequence;
}

std::uint64_t NativeRequestStackWalk::RecordAsyncTask(const NativeAsyncTaskKind kind) noexcept {
  const NativeRequestStackProvider provider = g_provider.load(std::memory_order_acquire);
  if (!provider || g_walking) {
    return 0;
  }
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0 ||
      !NetworkActive(sink.category_mask_.load(std::memory_order_relaxed),
                     sink.expires_at_monotonic_ns_.load(std::memory_order_relaxed),
                     sink.emitter_.load(std::memory_order_relaxed) != nullptr)) {
    return 0;
  }
  g_walking = true;
  NativeRequestStackWalk walk(g_state, generation, 0, 0, RequestFrameId(),
                              NativeProbeType::kAsyncTaskStack);
  walk.task_kind_ = kind;
  const NativeRequestStackWalkResult result = provider(walk);
  g_walking = false;
  return result == NativeRequestStackWalkResult::kWalked ? walk.segment_ : 0;
}

std::uint64_t NativeRequestStackWalk::EnterAsyncTask(const std::uint64_t segment) noexcept {
  if (!g_provider.load(std::memory_order_acquire)) {
    return 0;
  }
  return std::exchange(g_current_segment, segment);
}

void NativeRequestStackWalk::ExitAsyncTask(const std::uint64_t previous) noexcept {
  if (g_provider.load(std::memory_order_acquire)) {
    g_current_segment = previous;
  }
}

std::uint64_t NativeRequestStackWalk::CurrentAsyncTask() noexcept {
  return g_provider.load(std::memory_order_acquire) ? g_current_segment : 0;
}

void NativeRequestStackWalk::AttributeAsyncTask(const std::uint32_t task_attribution,
                                                const std::uint64_t segment) noexcept {
  if (!g_provider.load(std::memory_order_acquire) || task_attribution == 0 || segment == 0) {
    return;
  }
  const std::uint64_t generation =
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return;
  }
  NativeRequestStackTables& state = *g_state;
  auto& slot = Slot(state.attributions, Mix(task_attribution), generation, state.attribution_evict);
  slot = {generation, task_attribution, segment};
}

NativeRequestStackWalk::NativeRequestStackWalk(NativeRequestStackTables* const state,
                                               const std::uint64_t generation,
                                               const std::int32_t request_id,
                                               const std::uint64_t parent_sequence,
                                               const std::uint64_t frame_id,
                                               const NativeProbeType type,
                                               const std::array<std::uint8_t, 48>& tail) noexcept
    : state_(state),
      generation_(generation),
      type_(type),
      tail_(tail),
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

void NativeRequestStackWalk::SetAsyncContext(const bool in_microtask,
                                             const std::uint32_t task_attribution) noexcept {
  in_microtask_ = in_microtask;
  task_attribution_ = task_attribution;
}

bool NativeRequestStackWalk::async_task_walk() const noexcept {
  return type_ == NativeProbeType::kAsyncTaskStack;
}

bool NativeRequestStackWalk::ScriptNeeded(const std::uint32_t script_id) const noexcept {
  if (!state_ || script_id == 0) {
    return false;
  }
  return !Find(state_->scripts, Mix(script_id), [&](const NativeRequestStackTables::Script& entry) {
    return entry.generation == generation_ && entry.id == script_id;
  });
}

void NativeRequestStackWalk::EmitMalformed() noexcept {
  // A walk that produced no valid record still leaves a visible omission.
  NativeProbeSink& sink = NativeProbeSink::Get();
  NativeProbeEvent gap = ChildEvent(NativeProbeType::kGap,
                                    sink.session_id_.load(std::memory_order_relaxed), frame_id_, 0);
  constexpr std::string_view kReason = "request_stack_malformed";
  gap.header.payload_size = static_cast<std::uint32_t>(kReason.size());
  std::transform(kReason.begin(), kReason.end(), gap.inline_payload.begin(),
                 [](const char c) { return static_cast<std::byte>(c); });
  gap.header.sequence_number = sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
  static_cast<void>(sink.EmitStatus(gap, generation_));
}

void NativeRequestStackWalk::Emit(const NativeRequestStackPayload& payload) noexcept {
  NativeProbeSink& sink = NativeProbeSink::Get();
  if (!IsValidNativeRequestStackPayload(payload)) {
    EmitMalformed();
    return;
  }
  const bool walked =
      payload.state != static_cast<std::uint8_t>(NativeRequestStackState::kNoScript) &&
      payload.state != static_cast<std::uint8_t>(NativeRequestStackState::kUnsupportedThread);
  if (type_ == NativeProbeType::kScriptCookie) {
    if (walked) {
      digest_ = payload.digest;
      innermost_ = payload.innermost;
      stack_sequence_ = parent_sequence_;
    }
    return;
  }
  // Only a navigation script started is recorded.
  if (type_ == NativeProbeType::kNavigationInitiatorStack && !walked) {
    return;
  }
  NativeProbeEvent event = ChildEvent(type_, sink.session_id_.load(std::memory_order_relaxed),
                                      frame_id_, parent_sequence_);
  if (type_ == NativeProbeType::kRequestInitiatorStack ||
      type_ == NativeProbeType::kRequestWatchMatch) {
    event.header.request_id = static_cast<std::uint64_t>(static_cast<std::uint32_t>(request_id_));
  }
  event.header.sequence_number = sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
  NativeRequestStackPayload record = payload;
  record.reserved1 = tail_;
  event.inline_payload = EncodeNativeRequestStackRecord(record);
  if (sink.EmitStatus(event, generation_) == NativeProbeEmitStatus::kAdmitted) {
    stack_sequence_ = event.header.sequence_number;
  }
}

// Nearest first: the running task, or the one a microtask's attribution names.
std::size_t NativeRequestStackWalk::AppendTaskChain(std::uint8_t* const out,
                                                    std::uint16_t& count,
                                                    std::uint8_t& flags) const noexcept {
  NativeRequestStackTables& state = *state_;
  NativeTaskSegment microtask;
  microtask.kind = static_cast<std::uint8_t>(NativeAsyncTaskKind::kMicrotask);
  microtask.state = static_cast<std::uint8_t>(NativeTaskSegmentState::kNotRecorded);
  count = 0;
  const auto push = [&](const NativeTaskSegment& segment) {
    if (count == kNativeTaskSegmentLimit) {
      flags |= kNativeRequestStackTaskChainTruncated;
      return false;
    }
    std::memcpy(out + kNativeTaskSegmentSize * count++, &segment, sizeof(segment));
    return true;
  };
  std::uint64_t next = g_current_segment;
  if (in_microtask_) {
    if (!push(microtask)) {
      return 0;
    }
    next = AttributedSegment(state, task_attribution_, generation_);
    if (next == 0) {
      flags |= kNativeRequestStackTaskChainCut;
    }
  }
  while (next != 0) {
    const NativeRequestStackTables::Segment* entry = FindSegment(state, next, generation_);
    if (!entry) {
      flags |= kNativeRequestStackTaskChainCut;
      break;
    }
    NativeTaskSegment segment;
    segment.kind = entry->kind;
    segment.state = entry->state;
    segment.flags = entry->flags;
    segment.recorded = entry->recorded;
    segment.digest = entry->digest;
    if (!push(segment) || (entry->parent_via_microtask && !push(microtask))) {
      break;
    }
    if (entry->parent_unknown) {
      flags |= kNativeRequestStackTaskChainCut;
      break;
    }
    next = entry->parent;
  }
  return kNativeTaskSegmentSize * count;
}

void NativeRequestStackWalk::FramesReady(const std::uint32_t total_depth,
                                         std::uint32_t recorded,
                                         const std::uint32_t omitted,
                                         std::uint32_t async_frames,
                                         const bool async_truncated,
                                         const bool bounded) noexcept {
  if (frames_ready_) {
    return;
  }
  frames_ready_ = true;
  if (type_ == NativeProbeType::kAsyncTaskStack) {
    AsyncTaskFramesReady(recorded, bounded);
    return;
  }
  const bool tasks = type_ == NativeProbeType::kRequestInitiatorStack ||
                     type_ == NativeProbeType::kNavigationInitiatorStack;
  NativeRequestStackPayload payload;
  if (tasks) {
    payload.protocol_version = kNativeRequestStackTaskPayloadVersion;
  } else {
    payload.flags = kNativeRequestStackTaskCallersNotCaptured;
  }
  if (recorded == 0 || !state_) {
    payload.state = static_cast<std::uint8_t>(NativeRequestStackState::kNoScript);
    Emit(payload);
    return;
  }
  NativeRequestStackTables& state = *state_;
  ResetBudgets(state, generation_);
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

  const std::span<const NativeStackFrame> sync(state.frames.data(), recorded);
  const std::span<const NativeStackFrame> async(state.frames.data() + kNativeRequestStackSyncLimit,
                                                async_frames);
  std::size_t size = kNativeStackArtifactHeaderSize;
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
  if (tasks) {
    size += AppendTaskChain(state.artifact.data() + size, payload.task_segments, payload.flags);
    payload.async_segments =
        static_cast<std::uint16_t>(payload.async_segments + payload.task_segments);
  }
  NativeStackArtifactHeader header;
  header.version = tasks ? kNativeStackArtifactTaskVersion : kNativeStackArtifactVersion;
  header.flags =
      payload.flags &
      (kNativeRequestStackFramesOmitted | kNativeRequestStackAsyncTruncated |
       (tasks ? kNativeRequestStackTaskChainCut | kNativeRequestStackTaskChainTruncated : 0));
  header.total_depth = total_depth;
  header.recorded = recorded;
  header.omitted = omitted;
  header.async_frames = payload.async_frames;
  header.async_segments = payload.async_segments;
  header.task_segments = payload.task_segments;
  std::memcpy(state.artifact.data(), &header, sizeof(header));
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
  QueueStackArtifact(sink, state, hash, payload.digest, content);
  ++state.stacks_sent;
}

void NativeRequestStackWalk::AsyncTaskFramesReady(std::uint32_t recorded,
                                                  const bool bounded) noexcept {
  if (recorded == 0 || !state_) {
    return;
  }
  NativeRequestStackTables& state = *state_;
  ResetBudgets(state, generation_);
  recorded = std::min(recorded, kNativeAsyncTaskFrameLimit);
  NativeAsyncTaskStackPayload payload;
  payload.kind = static_cast<std::uint8_t>(task_kind_);
  payload.flags = bounded && recorded == kNativeAsyncTaskFrameLimit ? kNativeTaskSegmentBounded : 0;
  payload.recorded = recorded;
  const std::span<const NativeStackFrame> frames(state.frames.data(), recorded);
  std::size_t size = kNativeStackArtifactHeaderSize;
  for (const NativeStackFrame& frame : frames) {
    if (!IsValidNativeStackFrame(frame, false)) {
      EmitMalformed();
      return;
    }
    payload.wasm_frames += frame.kind == static_cast<std::uint8_t>(NativeStackFrameKind::kWasm);
    std::memcpy(state.artifact.data() + size, &frame, sizeof(frame));
    size += sizeof(frame);
  }
  NativeStackArtifactHeader header;
  header.total_depth = recorded;
  header.recorded = recorded;
  std::memcpy(state.artifact.data(), &header, sizeof(header));
  payload.scripts = CountDistinctScripts(state, frames, {});
  payload.innermost = frames[0];
  const std::span<const std::uint8_t> content(state.artifact.data(), size);
  payload.digest = crypto::hash::Sha256(content);
  if (!IsValidNativeAsyncTaskStackPayload(payload)) {
    EmitMalformed();
    return;
  }

  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::size_t hash = Mix(DigestKey(payload.digest));
  const bool known = Find(state.digests, hash, [&](const NativeRequestStackTables::Digest& entry) {
                       return entry.generation == generation_ && entry.value == payload.digest;
                     }) != nullptr;
  auto segment_state = NativeTaskSegmentState::kCaptured;
  if (execution_context_id_ == 0 || !sink.IsArtifactCaptureEnabled()) {
    segment_state = NativeTaskSegmentState::kNotRetainedArtifactUnavailable;
  } else if (!known && state.async_sent >= kNativeAsyncTaskArtifactBudget) {
    segment_state = NativeTaskSegmentState::kNotRetainedBudget;
  } else if (!known) {
    NativeProbeEvent event =
        ChildEvent(NativeProbeType::kAsyncTaskStack,
                   sink.session_id_.load(std::memory_order_relaxed), frame_id_, 0);
    event.header.sequence_number = sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
    event.inline_payload = EncodeNativeRequestStackRecord(payload);
    if (sink.EmitStatus(event, generation_) == NativeProbeEmitStatus::kAdmitted) {
      stack_sequence_ = event.header.sequence_number;
      QueueStackArtifact(sink, state, hash, payload.digest, content);
      ++state.async_sent;
    } else {
      // No record and no artifact left this renderer for this segment.
      segment_state = NativeTaskSegmentState::kNotRetainedArtifactUnavailable;
    }
  }
  NativeRequestStackTables::Segment segment;
  segment.serial = ++state.next_segment;
  segment.generation = generation_;
  segment.digest = payload.digest;
  segment.recorded = recorded;
  segment.kind = payload.kind;
  segment.state = static_cast<std::uint8_t>(segment_state);
  segment.flags = payload.flags;
  if (in_microtask_) {
    segment.parent_via_microtask = true;
    segment.parent = AttributedSegment(state, task_attribution_, generation_);
    segment.parent_unknown = segment.parent == 0;
  } else {
    segment.parent = g_current_segment;
  }
  state.segments[segment.serial & (kNativeAsyncTaskRing - 1)] = segment;
  segment_ = segment.serial;
}

void NativeRequestStackWalk::QueueStackArtifact(
    NativeProbeSink& sink,
    NativeRequestStackTables& state,
    const std::size_t hash,
    const std::array<std::uint8_t, 32>& digest,
    const std::span<const std::uint8_t> content) noexcept {
  constexpr std::string_view kPrefix = "reb-stack:sha256-";
  constexpr std::string_view kHex = "0123456789abcdef";
  std::array<char, kPrefix.size() + 64> url{};
  std::copy(kPrefix.begin(), kPrefix.end(), url.begin());
  for (std::size_t i = 0; i < digest.size(); ++i) {
    url[kPrefix.size() + 2 * i] = kHex[digest[i] >> 4U];
    url[kPrefix.size() + 2 * i + 1] = kHex[digest[i] & 0x0fU];
  }
  sink.CaptureGeneratedArtifact(
      NativeArtifactKind::kStack, NativeArtifactCaptureOrigin::kRequestStack, stack_sequence_,
      execution_context_id_, frame_id_, std::string_view(url.data(), url.size()), content);
  NativeRequestStackTables::Digest& slot = Slot(state.digests, hash, generation_, state.evict);
  slot.generation = generation_;
  slot.value = digest;
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
