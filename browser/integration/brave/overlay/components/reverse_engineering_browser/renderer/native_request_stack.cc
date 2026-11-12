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
#include <memory>
#include <span>
#include <string_view>
#include <utility>

#include "base/no_destructor.h"
#include "base/process/process_handle.h"
#include "base/synchronization/lock.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/renderer/native_fetch_owner.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "crypto/hash.h"

namespace reb {

// One thread's tables: written only by that thread's walks, except the
// refusal mailbox (see below). Keyed by configuration generation so a new
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
  // A task segment, or a kind 9 microtask hop in front of its parent.
  struct Segment final {
    std::uint64_t serial = 0;
    std::uint64_t generation = 0;
    // A segment handle: a serial in this ring, a synthetic handle, or 0.
    std::uint64_t parent = 0;
    std::array<std::uint8_t, 32> digest{};
    std::uint32_t recorded = 0;
    std::uint8_t kind = 0;
    std::uint8_t state = 0;
    std::uint8_t flags = 0;
    std::uint8_t registration = 0;
    // Earlier callers were not recorded: the chain is cut after this one.
    bool cut_after = false;
  };
  struct Attribution final {
    std::uint64_t generation = 0;
    std::uint32_t id = 0;
    std::uint64_t segment = 0;
  };
  // A promise registration, until its reaction runs (--reb-promise-stacks).
  struct Registration final {
    std::uint64_t generation = 0;
    std::uint32_t task_id = 0;
    std::uint32_t recorded = 0;
    std::array<std::uint8_t, 32> digest{};
    std::uint8_t state = 0;
    std::uint8_t registration = 0;
    std::uint8_t flags = 0;
  };
  struct FormNavigation final {
    std::uint64_t generation = 0;
    std::uint64_t target = 0;
    std::uint64_t sequence = 0;
  };
  // A stack artifact this thread queued, until a browser refusal needs it.
  struct QueuedStack final {
    std::uint64_t generation = 0;
    std::uint64_t sequence = 0;
    std::array<std::uint8_t, 32> digest{};
    // Which budget admitted it.
    enum class Budget : std::uint8_t { kRequest, kTask, kPromise } budget = Budget::kRequest;
  };
  NativeStackScope scope;
  std::uint32_t process_id = 0;
  // Process-unique; a message origin names it so a receiver on this thread
  // links the posting segment directly.
  std::uint64_t ordinal = 0;
  void* embedder_frames = nullptr;
  void (*release)(void*) = nullptr;
  // Registry list, guarded by the registry lock.
  NativeRequestStackTables* next = nullptr;
  // Refusal mailbox, one producer (the transport's sequence) and one consumer
  // (this thread). The producer stores an entry relaxed, then publishes
  // refused_head with release; the consumer reads refused_head with acquire,
  // so every entry below it is visible. A producer more than the mailbox ahead
  // overwrites unread entries, which the consumer detects and treats as lost.
  std::array<std::atomic<std::uint64_t>, kNativeStackRefusalMailbox> refused{};
  std::atomic<std::uint64_t> refused_head{0};
  std::uint64_t refused_tail = 0;
  std::array<NativeStackFrame, kNativeRequestStackFrameCapacity> frames{};
  std::array<std::uint8_t, kNativeStackArtifactMaxBytes> artifact{};
  std::array<Digest, kNativeRequestStackDigestTable> digests{};
  // As long as all three artifact budgets: a task that blocks this thread can
  // queue that many before the first refusal is delivered, and a forgotten
  // entry would leave its segments claiming a captured artifact.
  std::array<QueuedStack,
             kNativeRequestStackArtifactBudget + kNativeAsyncTaskArtifactBudget +
                 kNativePromiseStackArtifactBudget>
      queued_stacks{};
  std::size_t queued_stack_next = 0;
  std::array<Script, kNativeRequestStackScriptTable> scripts{};
  std::array<std::uint64_t, std::bit_ceil(2 * kNativeRequestStackFrameCapacity)> distinct{};
  std::uint32_t distinct_stamp = 0;
  std::size_t evict = 0;
  std::uint64_t budget_generation = 0;
  std::uint32_t stacks_sent = 0;
  std::uint64_t source_bytes = 0;
  std::uint32_t async_sent = 0;
  std::uint32_t promise_sent = 0;
  std::array<Segment, kNativeAsyncTaskRing> segments{};
  std::uint64_t next_segment = 0;
  std::array<Attribution, kNativeTaskAttributionTable> attributions{};
  std::size_t attribution_evict = 0;
  // Allocated with the tables only under --reb-promise-stacks.
  std::unique_ptr<std::array<Registration, kNativePromiseRegistrationRing>> registrations;
  std::array<FormNavigation, kNativeFormNavigationTable> forms{};
  std::size_t form_evict = 0;
};

namespace {

constexpr std::size_t kProbe = 8;
static_assert((kNativeRequestStackDigestTable & (kNativeRequestStackDigestTable - 1)) == 0);
static_assert((kNativeRequestStackScriptTable & (kNativeRequestStackScriptTable - 1)) == 0);
static_assert((kNativeAsyncTaskRing & (kNativeAsyncTaskRing - 1)) == 0);
static_assert((kNativeTaskAttributionTable & (kNativeTaskAttributionTable - 1)) == 0);
static_assert((kNativePromiseRegistrationRing & (kNativePromiseRegistrationRing - 1)) == 0);
static_assert((kNativeStackRefusalMailbox & (kNativeStackRefusalMailbox - 1)) == 0);
static_assert((kNativeStackOwnerRing & (kNativeStackOwnerRing - 1)) == 0);

// A segment handle with the top bit set names no ring entry. Bits 0-7 hold
// the task kind; bit 62 set means the caller is unknown (the chain is cut),
// clear means the task was scheduled with no script running.
constexpr std::uint64_t kSyntheticSegment = 1ULL << 63U;
constexpr std::uint64_t kUnknownCaller = 1ULL << 62U;

std::uint64_t NoScriptHandle(const NativeAsyncTaskKind kind) noexcept {
  return kSyntheticSegment | static_cast<std::uint8_t>(kind);
}

std::atomic<NativeRequestStackProvider> g_provider{nullptr};
std::atomic<bool> g_promise_stacks{false};
std::atomic<std::uint64_t> g_next_table{0};
// This thread's tables, set by AttachThread and cleared by DetachThread.
thread_local NativeRequestStackTables* t_tables = nullptr;
thread_local bool g_walking = false;
thread_local std::uint64_t g_current_segment = 0;
// The V8 async task ID of the promise reaction running on this thread, or 0.
thread_local std::uint32_t t_reaction = 0;
thread_local NativeNavigationKind g_navigation_kind = NativeNavigationKind::kOtherScript;

// Attached tables, for routing refusals. The lock is taken by AttachThread,
// DetachThread and StackArtifactRefused, never by a walk.
base::Lock& RegistryLock() {
  static base::NoDestructor<base::Lock> lock;
  return *lock;
}
NativeRequestStackTables* g_registry = nullptr;

// Which table queued the stack artifact a creator sequence names. Any walking
// thread writes a slot it claimed from g_owner_next; the transport's sequence
// reads. Each slot is a seqlock: the writer clears creator, stores table, then
// publishes creator with release; the reader loads creator with acquire,
// reads table, and accepts it only if creator is unchanged after an acquire
// fence. A slot reused 8,192 artifacts later fails that check.
struct QueuedOwner final {
  std::atomic<std::uint64_t> creator{0};
  std::atomic<std::uint64_t> table{0};
};
std::array<QueuedOwner, kNativeStackOwnerRing> g_owners{};
std::atomic<std::uint64_t> g_owner_next{0};

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

void ResetBudgets(NativeRequestStackTables& state, const std::uint64_t generation) noexcept {
  if (state.budget_generation != generation) {
    state.budget_generation = generation;
    state.stacks_sent = 0;
    state.source_bytes = 0;
    state.async_sent = 0;
    state.promise_sent = 0;
  }
}

const NativeRequestStackTables::Segment* FindSegment(const NativeRequestStackTables& state,
                                                     const std::uint64_t serial,
                                                     const std::uint64_t generation) noexcept {
  const auto& entry = state.segments[serial & (kNativeAsyncTaskRing - 1)];
  return serial != 0 && (serial & kSyntheticSegment) == 0 && entry.serial == serial &&
                 entry.generation == generation
             ? &entry
             : nullptr;
}

std::uint64_t StoreSegment(NativeRequestStackTables& state,
                           NativeRequestStackTables::Segment segment,
                           const std::uint64_t generation) noexcept {
  segment.serial = ++state.next_segment;
  segment.generation = generation;
  state.segments[segment.serial & (kNativeAsyncTaskRing - 1)] = segment;
  return segment.serial;
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

// Nothing a refusal names can be trusted any more: forget every digest so
// each stack is sent again, and stop calling any remembered segment captured.
void ForgetCapturedStacks(NativeRequestStackTables& state) noexcept {
  state.digests.fill({});
  const auto unretained =
      static_cast<std::uint8_t>(NativeTaskSegmentState::kNotRetainedArtifactUnavailable);
  for (auto& segment : state.segments) {
    if (segment.state == static_cast<std::uint8_t>(NativeTaskSegmentState::kCaptured)) {
      segment.state = unretained;
    }
  }
  if (state.registrations) {
    for (auto& registration : *state.registrations) {
      if (registration.state == static_cast<std::uint8_t>(NativeTaskSegmentState::kCaptured)) {
        registration.state = unretained;
      }
    }
  }
}

void ApplyRefusal(NativeRequestStackTables& state,
                  const std::uint64_t creator,
                  const std::uint64_t generation) noexcept {
  const auto queued =
      std::find_if(state.queued_stacks.begin(), state.queued_stacks.end(), [&](const auto& entry) {
        return creator != 0 && entry.generation == generation && entry.sequence == creator;
      });
  if (queued == state.queued_stacks.end()) {
    return;
  }
  if (auto* digest = Find(state.digests, Mix(DigestKey(queued->digest)), [&](const auto& entry) {
        return entry.generation == generation && entry.value == queued->digest;
      })) {
    *digest = {};
  }
  // A segment names its artifact by digest, whether it queued that artifact or
  // found the digest already remembered, so every one on this digest lost it.
  const auto captured = static_cast<std::uint8_t>(NativeTaskSegmentState::kCaptured);
  const auto unretained =
      static_cast<std::uint8_t>(NativeTaskSegmentState::kNotRetainedArtifactUnavailable);
  for (NativeRequestStackTables::Segment& segment : state.segments) {
    if (segment.generation == generation && segment.digest == queued->digest &&
        segment.state == captured) {
      segment.state = unretained;
    }
  }
  if (state.registrations) {
    for (auto& registration : *state.registrations) {
      if (registration.generation == generation && registration.digest == queued->digest &&
          registration.state == captured) {
        registration.state = unretained;
      }
    }
  }
  // The refused attempt stored nothing, so its retry must not be charged again.
  using Budget = NativeRequestStackTables::QueuedStack::Budget;
  std::uint32_t& sent = queued->budget == Budget::kTask      ? state.async_sent
                        : queued->budget == Budget::kPromise ? state.promise_sent
                                                             : state.stacks_sent;
  if (sent != 0) {
    --sent;
  }
  *queued = {};
}

// Applies the refusals routed to this thread since its last walk.
void DrainRefusals(NativeRequestStackTables& state, const std::uint64_t generation) noexcept {
  const std::uint64_t head = state.refused_head.load(std::memory_order_acquire);
  const std::uint64_t tail = state.refused_tail;
  if (head == tail) {
    return;
  }
  bool lost = head - tail > kNativeStackRefusalMailbox;
  for (std::uint64_t at = lost ? head : tail; at < head; ++at) {
    ApplyRefusal(
        state, state.refused[at & (kNativeStackRefusalMailbox - 1)].load(std::memory_order_relaxed),
        generation);
  }
  // The producer may have lapped the entries just read.
  lost |= state.refused_head.load(std::memory_order_acquire) - tail > kNativeStackRefusalMailbox;
  if (lost) {
    ForgetCapturedStacks(state);
  }
  state.refused_tail = head;
}

// This thread's tables with every routed refusal applied, or null.
NativeRequestStackTables* ThreadTables(const std::uint64_t generation) noexcept {
  NativeRequestStackTables* const state = t_tables;
  if (state) {
    DrainRefusals(*state, generation);
  }
  return state;
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

// The stack scope a version 3 record or version 2 record tail carries.
std::array<std::uint8_t, 48> ScopeTail(const NativeRequestStackTables* state) noexcept {
  std::array<std::uint8_t, 48> tail{};
  if (state) {
    SetNativeStackScope(tail, state->scope);
  }
  return tail;
}

// Writes the chain from `next`, nearest first, after `count` segments already
// in `out`. Stops at 32 (bit 4), a forgotten or unknown caller (bit 3), or a
// segment scheduled with no script running, which ends the chain.
void AppendChainFrom(const NativeRequestStackTables& state,
                     std::uint64_t next,
                     const std::uint64_t generation,
                     std::uint8_t* const out,
                     std::uint16_t& count,
                     std::uint8_t& flags) noexcept {
  const auto push = [&](const NativeTaskSegment& segment) {
    if (count == kNativeTaskSegmentLimit) {
      flags |= kNativeRequestStackTaskChainTruncated;
      return false;
    }
    std::memcpy(out + kNativeTaskSegmentSize * count++, &segment, sizeof(segment));
    return true;
  };
  while (next != 0) {
    if ((next & kSyntheticSegment) != 0) {
      if ((next & kUnknownCaller) != 0) {
        flags |= kNativeRequestStackTaskChainCut;
        return;
      }
      NativeTaskSegment no_script;
      no_script.kind = static_cast<std::uint8_t>(next & 0xffU);
      no_script.state = static_cast<std::uint8_t>(NativeTaskSegmentState::kNoScript);
      static_cast<void>(push(no_script));
      return;
    }
    const NativeRequestStackTables::Segment* entry = FindSegment(state, next, generation);
    if (!entry) {
      flags |= kNativeRequestStackTaskChainCut;
      return;
    }
    NativeTaskSegment segment;
    segment.kind = entry->kind;
    segment.state = entry->state;
    segment.flags = entry->flags;
    segment.registration = entry->registration;
    segment.recorded = entry->recorded;
    segment.digest = entry->digest;
    if (!push(segment)) {
      return;
    }
    if (entry->cut_after) {
      flags |= kNativeRequestStackTaskChainCut;
      return;
    }
    next = entry->parent;
  }
}

}  // namespace

bool NativeRequestStackWalk::NetworkActive(const NativeProbeSink& sink) noexcept {
  return sink.emitter_.load(std::memory_order_relaxed) != nullptr &&
         (sink.category_mask_.load(std::memory_order_relaxed) &
          NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) != 0 &&
         MonotonicNs() < sink.expires_at_monotonic_ns_.load(std::memory_order_relaxed);
}

void NativeRequestStackWalk::SetProvider(const NativeRequestStackProvider provider) noexcept {
  if (!provider || g_provider.load(std::memory_order_acquire)) {
    return;
  }
  // Tables are thread-local, so nothing is published through the provider;
  // release/acquire only orders EnablePromiseRegistrations before it.
  g_provider.store(provider, std::memory_order_release);
}

void NativeRequestStackWalk::EnablePromiseRegistrations() noexcept {
  g_promise_stacks.store(true, std::memory_order_release);
}

void NativeRequestStackWalk::AttachThread(const NativeStackScope& scope,
                                          void* const embedder_frames,
                                          void (*const release)(void*)) noexcept {
  if (t_tables || !IsValidNativeStackScope(scope)) {
    if (release) {
      release(embedder_frames);
    }
    return;
  }
  // Thread lifetime: allocated once here, never in a walk.
  auto* state = new NativeRequestStackTables();
  state->scope = scope;
  state->process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  state->ordinal = g_next_table.fetch_add(1, std::memory_order_relaxed) + 1;
  state->embedder_frames = embedder_frames;
  state->release = release;
  if (g_promise_stacks.load(std::memory_order_acquire)) {
    state->registrations = std::make_unique<
        std::array<NativeRequestStackTables::Registration, kNativePromiseRegistrationRing>>();
  }
  {
    base::AutoLock lock(RegistryLock());
    state->next = g_registry;
    g_registry = state;
  }
  t_tables = state;
}

void NativeRequestStackWalk::DetachThread() noexcept {
  NativeRequestStackTables* const state = t_tables;
  if (!state) {
    return;
  }
  {
    // After this no refusal can reach the tables.
    base::AutoLock lock(RegistryLock());
    for (NativeRequestStackTables** link = &g_registry; *link; link = &(*link)->next) {
      if (*link == state) {
        *link = state->next;
        break;
      }
    }
  }
  t_tables = nullptr;
  g_current_segment = 0;
  t_reaction = 0;
  if (state->release) {
    state->release(state->embedder_frames);
  }
  delete state;
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
  NativeRequestStackTables* const state = ThreadTables(generation);
  g_walking = true;
  NativeRequestStackWalk walk(state, generation, request_id, initiated_sequence, RequestFrameId(),
                              NativeProbeType::kRequestInitiatorStack, ScopeTail(state));
  NativeRequestStackWalkResult result = provider(walk);
  g_walking = false;
  if (result == NativeRequestStackWalkResult::kWalked) {
    if (!walk.frames_ready_) {
      walk.FramesReady(0, 0, 0, 0, false);
    }
    return;
  }
  // A thread without tables has no scope, so it can only be unsupported.
  if (!state) {
    result = NativeRequestStackWalkResult::kUnsupportedThread;
  }
  NativeRequestStackPayload payload;
  payload.protocol_version = kNativeRequestStackScopePayloadVersion;
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
  // A worker's records name the worker, as its own requests do.
  if (const NativeRequestStackTables* state = t_tables;
      state && state->scope.thread != static_cast<std::uint8_t>(NativeStackThread::kDocument)) {
    return state->scope.isolate_key;
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
  NativeRequestStackWalk walk(provider ? ThreadTables(generation) : nullptr, generation, request_id,
                              parent_sequence, resolved_frame, type, tail);
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
  NativeRequestStackWalk walk(ThreadTables(generation), generation, 0, cookie_sequence, frame_id,
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
  if ((generation & 1U) != 0 || !NetworkActive(sink)) {
    return 0;
  }
  NativeNavigationStackTail tail;
  tail.kind = static_cast<std::uint8_t>(kind);
  tail.target_frame_id = target_frame_id;
  g_walking = true;
  NativeRequestStackWalk walk(ThreadTables(generation), generation, 0, 0, RequestFrameId(),
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
  NativeRequestStackTables* const tables = ThreadTables(generation);
  if (!tables) {
    return;
  }
  NativeRequestStackTables& state = *tables;
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
  NativeRequestStackTables* const tables = ThreadTables(generation);
  if (!tables) {
    return 0;
  }
  auto* slot = Find(tables->forms, 0, [&](const auto& entry) {
    return entry.generation == generation && entry.target == target_frame_id;
  });
  if (!slot) {
    return 0;
  }
  const std::uint64_t sequence = slot->sequence;
  *slot = {};
  return sequence;
}

std::uint64_t NativeRequestStackWalk::RecordAsyncTask(const NativeAsyncTaskKind kind,
                                                      const bool script_running) noexcept {
  const NativeRequestStackProvider provider = g_provider.load(std::memory_order_acquire);
  if (!provider || g_walking) {
    return 0;
  }
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0 || !NetworkActive(sink)) {
    return 0;
  }
  NativeRequestStackTables* const state = ThreadTables(generation);
  if (!state) {
    return 0;
  }
  // Nothing to walk or store: the handle itself says why the chain ends.
  if (!script_running) {
    return NoScriptHandle(kind);
  }
  g_walking = true;
  NativeRequestStackWalk walk(state, generation, 0, 0, RequestFrameId(),
                              NativeProbeType::kAsyncTaskStack, ScopeTail(state));
  walk.task_kind_ = kind;
  const NativeRequestStackWalkResult result = provider(walk);
  g_walking = false;
  if (result == NativeRequestStackWalkResult::kNoScript) {
    return NoScriptHandle(kind);
  }
  return result == NativeRequestStackWalkResult::kWalked ? walk.segment_ : 0;
}

std::size_t NativeRequestStackWalk::PostMessageOrigin(
    const NativeAsyncTaskKind kind,
    const bool script_running,
    const std::span<std::uint8_t, kNativeTaskOriginMaxBytes> out) noexcept {
  const std::uint64_t segment = RecordAsyncTask(kind, script_running);
  NativeRequestStackTables* const state = t_tables;
  if (segment == 0 || !state) {
    return 0;
  }
  const std::uint64_t generation =
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire);
  NativeTaskOriginHeader header;
  header.process_id = state->process_id;
  header.table = state->ordinal;
  header.serial = (segment & kSyntheticSegment) != 0 ? 0 : segment;
  std::uint16_t count = 0;
  std::uint8_t flags = 0;
  AppendChainFrom(*state, segment, generation, out.data() + kNativeTaskOriginHeaderSize, count,
                  flags);
  if (count == 0) {
    return 0;
  }
  header.count = static_cast<std::uint8_t>(count);
  header.flags = flags != 0 ? kNativeTaskOriginCut : 0;
  std::memcpy(out.data(), &header, sizeof(header));
  return kNativeTaskOriginHeaderSize + kNativeTaskSegmentSize * count;
}

std::uint64_t NativeRequestStackWalk::ReceiveMessageOrigin(
    const NativeAsyncTaskKind kind,
    const std::span<const std::uint8_t> origin) noexcept {
  if (!g_provider.load(std::memory_order_acquire)) {
    return 0;
  }
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0 || !NetworkActive(sink)) {
    return 0;
  }
  NativeRequestStackTables* const state = ThreadTables(generation);
  if (!state) {
    return 0;
  }
  NativeTaskOriginHeader header;
  std::array<NativeTaskSegment, kNativeTaskSegmentLimit> carried{};
  // No origin, or one that does not validate: the poster is unknown.
  if (!DecodeNativeTaskOrigin(origin, header, carried) ||
      carried[0].kind != static_cast<std::uint8_t>(kind)) {
    return kSyntheticSegment | kUnknownCaller | static_cast<std::uint8_t>(kind);
  }
  if (header.process_id == state->process_id && header.table == state->ordinal) {
    if (header.serial == 0) {
      return NoScriptHandle(kind);
    }
    // Posted on this thread and still remembered: the same chain, no copy.
    const auto* posted = FindSegment(*state, header.serial, generation);
    if (posted && posted->kind == carried[0].kind && posted->digest == carried[0].digest) {
      return header.serial;
    }
  }
  // Another thread or process posted it: store copies, farthest first, so
  // each points at the one before it in the chain. A no-script last segment
  // stays a synthetic handle.
  std::size_t count = header.count;
  std::uint64_t parent = 0;
  bool cut = (header.flags & kNativeTaskOriginCut) != 0;
  if (carried[count - 1].state == static_cast<std::uint8_t>(NativeTaskSegmentState::kNoScript)) {
    parent = NoScriptHandle(static_cast<NativeAsyncTaskKind>(carried[count - 1].kind));
    --count;
  }
  for (std::size_t i = count; i-- > 0;) {
    NativeRequestStackTables::Segment segment;
    segment.parent = parent;
    segment.digest = carried[i].digest;
    segment.recorded = carried[i].recorded;
    segment.kind = carried[i].kind;
    segment.state = carried[i].state;
    segment.flags = carried[i].flags;
    segment.registration = carried[i].registration;
    segment.cut_after = cut;
    parent = StoreSegment(*state, segment, generation);
    cut = false;
  }
  return parent;
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
  NativeRequestStackTables* const state = ThreadTables(generation);
  if (!state) {
    return;
  }
  auto& slot =
      Slot(state->attributions, Mix(task_attribution), generation, state->attribution_evict);
  slot = {generation, task_attribution, segment};
}

bool NativeRequestStackWalk::PromiseRegistrationActive() noexcept {
  if (!g_promise_stacks.load(std::memory_order_acquire) ||
      !g_provider.load(std::memory_order_acquire) || g_walking) {
    return false;
  }
  NativeProbeSink& sink = NativeProbeSink::Get();
  const NativeRequestStackTables* const state = t_tables;
  return state && state->registrations &&
         (sink.config_generation_.load(std::memory_order_acquire) & 1U) == 0 && NetworkActive(sink);
}

void NativeRequestStackWalk::RecordPromiseRegistration(
    const std::uint32_t task_id,
    const NativePromiseRegistration kind) noexcept {
  const NativeRequestStackProvider provider = g_provider.load(std::memory_order_acquire);
  if (task_id == 0 || !provider || !PromiseRegistrationActive()) {
    return;
  }
  const std::uint64_t generation =
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire);
  NativeRequestStackTables* const state = ThreadTables(generation);
  g_walking = true;
  NativeRequestStackWalk walk(state, generation, 0, 0, RequestFrameId(),
                              NativeProbeType::kAsyncTaskStack, ScopeTail(state));
  walk.task_kind_ = NativeAsyncTaskKind::kMicrotask;
  walk.registration_ = kind;
  walk.task_id_ = task_id;
  static_cast<void>(provider(walk));
  g_walking = false;
}

void NativeRequestStackWalk::PromiseReactionStarted(const std::uint32_t task_id) noexcept {
  if (g_promise_stacks.load(std::memory_order_acquire)) {
    t_reaction = task_id;
  }
}

void NativeRequestStackWalk::PromiseReactionFinished(const std::uint32_t task_id) noexcept {
  if (t_reaction == task_id) {
    t_reaction = 0;
  }
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

void* NativeRequestStackWalk::embedder_frames() const noexcept {
  return state_ ? state_->embedder_frames : nullptr;
}

NativeStackScope NativeRequestStackWalk::scope() const noexcept {
  return state_ ? state_->scope : NativeStackScope{};
}

std::uint32_t NativeRequestStackWalk::task_frame_limit() const noexcept {
  return task_kind_ == NativeAsyncTaskKind::kMicrotask ? kNativePromiseRegistrationFrameLimit
                                                       : kNativeAsyncTaskFrameLimit;
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
  NativeRequestStackPayload record = payload;
  // Version 3 carries the scope in bytes 80-95; unsupported_thread names none.
  const bool scoped = payload.protocol_version == kNativeRequestStackScopePayloadVersion;
  if (scoped &&
      payload.state != static_cast<std::uint8_t>(NativeRequestStackState::kUnsupportedThread)) {
    record.reserved1 = tail_;
  }
  if (!IsValidNativeRequestStackPayload(record)) {
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
  if (!scoped) {
    record.reserved1 = tail_;
  }
  event.inline_payload = EncodeNativeRequestStackRecord(record);
  if (sink.EmitStatus(event, generation_) == NativeProbeEmitStatus::kAdmitted) {
    stack_sequence_ = event.header.sequence_number;
  }
}

NativeTaskSegment NativeRequestStackWalk::MicrotaskSegment() const noexcept {
  NativeTaskSegment segment;
  segment.kind = static_cast<std::uint8_t>(NativeAsyncTaskKind::kMicrotask);
  segment.state = static_cast<std::uint8_t>(NativeTaskSegmentState::kNotRecorded);
  const std::uint32_t id = t_reaction;
  if (id == 0 || !state_->registrations) {
    return segment;
  }
  const auto& entry = (*state_->registrations)[id & (kNativePromiseRegistrationRing - 1)];
  if (entry.generation != generation_ || entry.task_id != id) {
    return segment;
  }
  segment.state = entry.state;
  segment.flags = entry.flags;
  segment.registration = entry.registration;
  segment.recorded = entry.recorded;
  segment.digest = entry.digest;
  return segment;
}

// Nearest first: the running task, or the one a microtask's attribution names.
std::size_t NativeRequestStackWalk::AppendTaskChain(std::uint8_t* const out,
                                                    std::uint16_t& count,
                                                    std::uint8_t& flags) const noexcept {
  NativeRequestStackTables& state = *state_;
  count = 0;
  std::uint64_t next = g_current_segment;
  if (in_microtask_) {
    const NativeTaskSegment microtask = MicrotaskSegment();
    std::memcpy(out, &microtask, sizeof(microtask));
    count = 1;
    next = AttributedSegment(state, task_attribution_, generation_);
    if (next == 0) {
      flags |= kNativeRequestStackTaskChainCut;
    }
  }
  AppendChainFrom(state, next, generation_, out, count, flags);
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
  // Request stacks are version 3; navigation stacks keep version 2 for their
  // tail. Both write version 3 artifacts with the task chain.
  const bool request = type_ == NativeProbeType::kRequestInitiatorStack;
  const bool tasks = request || type_ == NativeProbeType::kNavigationInitiatorStack;
  NativeRequestStackPayload payload;
  if (request) {
    payload.protocol_version = kNativeRequestStackScopePayloadVersion;
  } else if (tasks) {
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

  const std::size_t header_size =
      tasks ? kNativeStackArtifactScopeHeaderSize : kNativeStackArtifactHeaderSize;
  const std::span<const NativeStackFrame> sync(state.frames.data(), recorded);
  const std::span<const NativeStackFrame> async(state.frames.data() + kNativeRequestStackSyncLimit,
                                                async_frames);
  std::size_t size = header_size;
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
  header.version = tasks ? kNativeStackArtifactScopeVersion : kNativeStackArtifactVersion;
  header.header_size = static_cast<std::uint16_t>(header_size);
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
  if (tasks) {
    NativeStackArtifactScope scope;
    scope.process_id = state.process_id;
    scope.thread = state.scope.thread;
    scope.isolate_key = state.scope.isolate_key;
    std::memcpy(state.artifact.data() + sizeof(header), &scope, sizeof(scope));
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
  const bool registration = task_kind_ == NativeAsyncTaskKind::kMicrotask;
  const std::uint32_t limit = task_frame_limit();
  recorded = std::min(recorded, limit);
  NativeAsyncTaskStackPayload payload;
  payload.protocol_version = kNativeAsyncTaskStackScopeVersion;
  payload.kind = static_cast<std::uint8_t>(task_kind_);
  payload.registration = registration ? static_cast<std::uint8_t>(registration_) : 0;
  payload.flags = bounded && recorded == limit ? kNativeTaskSegmentBounded : 0;
  payload.recorded = recorded;
  SetNativeStackScope(payload.reserved2, state.scope);
  const std::span<const NativeStackFrame> frames(state.frames.data(), recorded);
  std::size_t size = kNativeStackArtifactScopeHeaderSize;
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
  header.version = kNativeStackArtifactScopeVersion;
  header.header_size = static_cast<std::uint16_t>(kNativeStackArtifactScopeHeaderSize);
  header.total_depth = recorded;
  header.recorded = recorded;
  std::memcpy(state.artifact.data(), &header, sizeof(header));
  NativeStackArtifactScope scope;
  scope.process_id = state.process_id;
  scope.thread = state.scope.thread;
  scope.isolate_key = state.scope.isolate_key;
  std::memcpy(state.artifact.data() + sizeof(header), &scope, sizeof(scope));
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
  std::uint32_t& sent = registration ? state.promise_sent : state.async_sent;
  const std::uint32_t budget =
      registration ? kNativePromiseStackArtifactBudget : kNativeAsyncTaskArtifactBudget;
  auto segment_state = NativeTaskSegmentState::kCaptured;
  if (execution_context_id_ == 0 || !sink.IsArtifactCaptureEnabled()) {
    segment_state = NativeTaskSegmentState::kNotRetainedArtifactUnavailable;
  } else if (!known && sent >= budget) {
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
      ++sent;
    } else {
      // No record and no artifact left this renderer for this segment.
      segment_state = NativeTaskSegmentState::kNotRetainedArtifactUnavailable;
    }
  }
  if (registration) {
    // Looked up by V8's task ID when the reaction runs; nothing links it yet.
    if (state.registrations) {
      auto& entry = (*state.registrations)[task_id_ & (kNativePromiseRegistrationRing - 1)];
      entry = {generation_,
               task_id_,
               recorded,
               payload.digest,
               static_cast<std::uint8_t>(segment_state),
               payload.registration,
               payload.flags};
    }
    return;
  }
  NativeRequestStackTables::Segment segment;
  segment.digest = payload.digest;
  segment.recorded = recorded;
  segment.kind = payload.kind;
  segment.state = static_cast<std::uint8_t>(segment_state);
  segment.flags = payload.flags;
  if (in_microtask_) {
    // Scheduled from a promise reaction: a kind 9 hop, with its registration
    // stack when recorded, stands between this task and the one the
    // reaction's task attribution names.
    const NativeTaskSegment microtask = MicrotaskSegment();
    NativeRequestStackTables::Segment hop;
    hop.digest = microtask.digest;
    hop.recorded = microtask.recorded;
    hop.kind = microtask.kind;
    hop.state = microtask.state;
    hop.flags = microtask.flags;
    hop.registration = microtask.registration;
    hop.parent = AttributedSegment(state, task_attribution_, generation_);
    hop.cut_after = hop.parent == 0;
    segment.parent = StoreSegment(state, hop, generation_);
  } else {
    segment.parent = g_current_segment;
  }
  segment_ = StoreSegment(state, segment, generation_);
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
  // Named before the artifact leaves, so a refusal always finds its thread.
  QueuedOwner& owner =
      g_owners[g_owner_next.fetch_add(1, std::memory_order_relaxed) & (kNativeStackOwnerRing - 1)];
  owner.creator.store(0, std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_release);
  owner.table.store(state.ordinal, std::memory_order_relaxed);
  owner.creator.store(stack_sequence_, std::memory_order_release);
  sink.CaptureGeneratedArtifact(
      NativeArtifactKind::kStack, NativeArtifactCaptureOrigin::kRequestStack, stack_sequence_,
      execution_context_id_, frame_id_, std::string_view(url.data(), url.size()), content);
  NativeRequestStackTables::Digest& slot = Slot(state.digests, hash, generation_, state.evict);
  slot.generation = generation_;
  slot.value = digest;
  // Remembered so a browser refusal can forget this digest (StackArtifactRefused).
  using Budget = NativeRequestStackTables::QueuedStack::Budget;
  state.queued_stacks[state.queued_stack_next++ % state.queued_stacks.size()] = {
      generation_, stack_sequence_, digest,
      !async_task_walk()                              ? Budget::kRequest
      : task_kind_ == NativeAsyncTaskKind::kMicrotask ? Budget::kPromise
                                                      : Budget::kTask};
}

void NativeRequestStackWalk::StackArtifactRefused(const std::uint64_t creator_sequence) noexcept {
  if (creator_sequence == 0) {
    return;
  }
  // The owner ring names the thread whose walk queued this artifact. A
  // refusal usually follows its artifact closely, so search newest first.
  std::uint64_t table = 0;
  const std::uint64_t newest = g_owner_next.load(std::memory_order_relaxed);
  for (std::uint64_t back = 1; back <= kNativeStackOwnerRing && back <= newest; ++back) {
    const QueuedOwner& owner = g_owners[(newest - back) & (kNativeStackOwnerRing - 1)];
    if (owner.creator.load(std::memory_order_acquire) != creator_sequence) {
      continue;
    }
    const std::uint64_t candidate = owner.table.load(std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_acquire);
    if (owner.creator.load(std::memory_order_relaxed) == creator_sequence) {
      table = candidate;
      break;
    }
  }
  if (table == 0) {
    return;
  }
  base::AutoLock lock(RegistryLock());
  for (NativeRequestStackTables* state = g_registry; state; state = state->next) {
    if (state->ordinal != table) {
      continue;
    }
    // The only producer: this sequence holds the registry lock.
    const std::uint64_t head = state->refused_head.load(std::memory_order_relaxed);
    state->refused[head & (kNativeStackRefusalMailbox - 1)].store(creator_sequence,
                                                                  std::memory_order_relaxed);
    state->refused_head.store(head + 1, std::memory_order_release);
    return;
  }
}

void NativeRequestStackWalk::DescribeScript(const NativeStackScriptSource& script) noexcept {
  if (!state_ || stack_sequence_ == 0 || script.execution_context_id == 0 ||
      !ScriptNeeded(script.script_id)) {
    return;
  }
  NativeRequestStackTables& state = *state_;
  const bool javascript = script.kind == NativeScriptIdentityKind::kJavaScript;
  NativeScriptIdentityPayload payload;
  payload.protocol_version = kNativeScriptIdentityScopeVersion;
  payload.kind = static_cast<std::uint8_t>(script.kind);
  payload.flags = javascript && script.is_eval ? kNativeScriptIdentityEval : 0;
  payload.script_id = script.script_id;
  payload.start_line = script.start_line;
  payload.start_column = script.start_column;
  payload.execution_context_id = script.execution_context_id;
  SetNativeStackScope(payload.reserved2, state.scope);
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
      // Inline source can embed per-user data; only content capture retains it.
      queue = sink.IsArtifactCaptureEnabled() && sink.IsContentCaptureEnabled() &&
              !script.url.empty() && script.url.size() <= kNativeArtifactMaxUrlBytes &&
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
  state.source_bytes += script.bytes.size();
}

}  // namespace reb
