// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "base/component_export.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_request_stack.h"

namespace reb {

// Request initiator stacks, protocol/native-network-v3.md.
inline constexpr std::size_t kNativeRequestStackFrameCapacity =
    kNativeRequestStackSyncLimit + kNativeRequestStackAsyncLimit;
inline constexpr std::size_t kNativeRequestStackDigestTable = 256;
inline constexpr std::size_t kNativeRequestStackScriptTable = 1024;
inline constexpr std::uint32_t kNativeRequestStackArtifactBudget = 1024;
inline constexpr std::uint64_t kNativeRequestStackSourceBytes = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t kNativeAsyncTaskRing = 2048;
inline constexpr std::size_t kNativeTaskAttributionTable = 4096;
inline constexpr std::uint32_t kNativeAsyncTaskArtifactBudget = 1024;
inline constexpr std::size_t kNativeFormNavigationTable = 8;
// Promise registrations a thread remembers until their reactions run, and
// the registration stacks it sends per configuration (--reb-promise-stacks).
inline constexpr std::size_t kNativePromiseRegistrationRing = 2048;
inline constexpr std::uint32_t kNativePromiseStackArtifactBudget = 1024;
// Browser refusals a thread can fall behind on before it forgets every
// digest and stops calling any of its segments captured.
inline constexpr std::size_t kNativeStackRefusalMailbox = 256;
// Stack artifacts whose owning thread a refusal is routed to directly; an
// older one's refusal goes to every attached thread.
inline constexpr std::size_t kNativeStackOwnerRing = 8192;
// The artifacts a thread queued in this configuration whose refusal can
// still arrive. A power of two above the sum of the three artifact budgets,
// which bounds how many can be outstanding, so an entry is never displaced.
inline constexpr std::size_t kNativeStackQueuedIndex = 4096;
// Messages a thread remembers having posted, so a receipt on the same
// thread links the posting segment in place instead of copying.
inline constexpr std::size_t kNativeStackRecentPosts = 16;
// Worker threads per renderer process with stack tables (about 650 KiB each
// with Blink's frame buffer and a promise registration ring). The document
// main thread is not counted. A worker past the limit walks nothing; its
// request stacks read not_walked_thread_limit.
inline constexpr std::uint32_t kNativeStackThreadLimit = 32;

enum class NativeRequestStackWalkResult : std::uint8_t {
  kWalked,
  kNoScript,
  kUnsupportedThread,
};

// One script a recorded frame names. Every view is borrowed for the call.
struct NativeStackScriptSource final {
  std::uint32_t script_id = 0;
  NativeScriptIdentityKind kind = NativeScriptIdentityKind::kJavaScript;
  bool is_eval = false;
  // Longer than kNativeScriptIdentityMaxSourceBytes, so not converted.
  bool too_large = false;
  std::uint64_t too_large_length = 0;
  std::uint32_t start_line = 0;
  std::uint32_t start_column = 0;
  std::uint64_t execution_context_id = 0;
  // UTF-8 JavaScript source or Wasm wire bytes; empty when unavailable.
  std::span<const std::uint8_t> bytes;
  std::string_view url;
};

class NativeProbeSink;
struct NativeRequestStackTables;
class NativeRequestStackWalk;

// The kind a Location setter or window.open gives the navigation it starts.
class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeNavigationKindScope final {
 public:
  explicit NativeNavigationKindScope(NativeNavigationKind kind) noexcept;
  ~NativeNavigationKindScope();
  NativeNavigationKindScope(const NativeNavigationKindScope&) = delete;
  NativeNavigationKindScope& operator=(const NativeNavigationKindScope&) = delete;
  [[nodiscard]] static NativeNavigationKind Current() noexcept;

 private:
  const NativeNavigationKind previous_;
};

// Blink's walker. It runs on the calling thread and returns kWalked only on a
// thread with attached tables (the document main thread or a dedicated, shared
// or service worker), after calling FramesReady exactly once.
using NativeRequestStackProvider = NativeRequestStackWalkResult (*)(NativeRequestStackWalk& walk);

// The sink's side of one walk. Methods run on the walking thread inside the
// provider, touch only that thread's tables and never call into V8.
class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeRequestStackWalk final {
 public:
  // Installed once per renderer by Blink, only when V8 runs with
  // --reb-request-stacks. `allocate_frames` makes Blink's buffer for V8's
  // frames when a thread's tables are made, and `release_frames` frees it
  // with them; both may be null.
  static void SetProvider(NativeRequestStackProvider provider,
                          void* (*allocate_frames)() = nullptr,
                          void (*release_frames)(void*) = nullptr) noexcept;
  // Names the calling thread's isolate: two thread-local stores, nothing
  // allocated and no lock taken. Blink calls it, with or without
  // --reb-request-stacks, for the document main thread at V8 initialization
  // and for each dedicated, shared and service worker when its global scope
  // starts. The thread's tables and Blink's frame buffer are allocated by its
  // first walk while capture is active, never here. A second call keeps the
  // first scope.
  static void AttachThread(const NativeStackScope& scope) noexcept;
  // Frees the calling worker thread's tables, if any, at its shutdown and
  // forgets its scope; refusals for its artifacts are dropped from then on.
  // The main thread is never detached.
  static void DetachThread() noexcept;
  // The calling thread's scope, or zero when it was never attached (a
  // worklet, or a thread Blink does not run script on).
  [[nodiscard]] static NativeStackScope CurrentScope() noexcept;
  // --reb-promise-stacks: threads attached after this keep a registration ring.
  static void EnablePromiseRegistrations() noexcept;
  // Called by the loader with RecordRequestInitiated's admitted sequence.
  // Zero, or no provider, returns after at most one atomic load.
  static void Record(std::int32_t request_id, std::uint64_t initiated_sequence) noexcept;
  // The frame request_initiated names for a request this thread starts now.
  [[nodiscard]] static std::uint64_t RequestFrameId() noexcept;
  // One debugger observation, protocol/native-debugger-observation-v1.md:
  // the current stack plus a 48-byte tail. Without a provider the record
  // still goes out with stack state no_script. Main thread only.
  static void RecordObservation(NativeProbeType type,
                                std::int32_t request_id,
                                std::uint64_t parent_sequence,
                                std::uint64_t frame_id,
                                const std::array<std::uint8_t, 48>& tail) noexcept;
  // Walks a cookie write's stack without a stack record; its artifact names `cookie_sequence`.
  static bool RecordCookieStack(std::uint64_t cookie_sequence,
                                std::uint64_t frame_id,
                                std::array<std::uint8_t, 32>& digest,
                                NativeStackFrame& innermost) noexcept;
  // Whether the provider is installed: one atomic load.
  [[nodiscard]] static bool Enabled() noexcept;
  // A navigation_initiator_stack when script runs: its admitted sequence, else 0.
  [[nodiscard]] static std::uint64_t RecordNavigation(NativeNavigationKind kind,
                                                      std::uint64_t target_frame_id) noexcept;
  // Form submissions navigate from a later task, so their stack waits here.
  static void ScheduleFormNavigation(std::uint64_t target_frame_id) noexcept;
  [[nodiscard]] static std::uint64_t TakeFormNavigation(std::uint64_t target_frame_id) noexcept;
  // An async task scheduled now: its segment handle, or 0 while inactive or on a
  // thread without tables. With no script running nothing is walked or stored:
  // the handle names a no_script segment of that kind, which ends the chain.
  [[nodiscard]] static std::uint64_t RecordAsyncTask(NativeAsyncTaskKind kind,
                                                     bool script_running = true) noexcept;
  // A MessagePort, BroadcastChannel or worker postMessage: walks the posting
  // stack like RecordAsyncTask and writes the message's task origin, the
  // posting segment then the sender's chain, into `out`. Returns its size, or
  // 0 when nothing is carried (inactive, or a thread without tables).
  [[nodiscard]] static std::size_t PostMessageOrigin(
      NativeAsyncTaskKind kind,
      bool script_running,
      std::span<std::uint8_t, kNativeTaskOriginMaxBytes> out) noexcept;
  // The segment a received message's handler runs under: on the thread that
  // posted it, while its chain is unchanged, the posting segment itself;
  // elsewhere copies of the carried segments, stored in this thread's ring.
  // While capture is active,
  // an empty origin cuts the chain there (the sender carried nothing), and
  // one that does not validate ends it with an origin_rejected segment and a
  // message_task_origin_rejected gap. 0 while inactive or without tables.
  [[nodiscard]] static std::uint64_t ReceiveMessageOrigin(
      NativeAsyncTaskKind kind,
      std::span<const std::uint8_t> origin) noexcept;
  // V8's promise registration points (--reb-promise-stacks). Active is one
  // atomic load plus the session checks, with no V8 call.
  [[nodiscard]] static bool PromiseRegistrationActive() noexcept;
  // A user .then, .catch, .finally or await registered the reaction V8 tags
  // with task_id; the registering stack is the current one.
  static void RecordPromiseRegistration(std::uint32_t task_id,
                                        NativePromiseRegistration kind) noexcept;
  // The reaction for task_id runs between these on this thread. Blink runs a
  // microtask checkpoint only with no script on the stack, so reactions do
  // not nest; Finished clears only its own ID.
  static void PromiseReactionStarted(std::uint32_t task_id) noexcept;
  static void PromiseReactionFinished(std::uint32_t task_id) noexcept;
  // The segment of the async task running on this thread, set around its run.
  [[nodiscard]] static std::uint64_t EnterAsyncTask(std::uint64_t segment) noexcept;
  static void ExitAsyncTask(std::uint64_t previous) noexcept;
  [[nodiscard]] static std::uint64_t CurrentAsyncTask() noexcept;
  // Promise reactions registered under this task attribution ID continue that segment.
  static void AttributeAsyncTask(std::uint32_t task_attribution, std::uint64_t segment) noexcept;

  NativeRequestStackWalk(const NativeRequestStackWalk&) = delete;
  NativeRequestStackWalk& operator=(const NativeRequestStackWalk&) = delete;

  // kNativeRequestStackSyncLimit synchronous frames, then the async frames.
  [[nodiscard]] std::span<NativeStackFrame> frames() noexcept;
  // Blink's frame buffer for this thread, or null on a thread without tables.
  [[nodiscard]] void* embedder_frames() const noexcept;
  // The scope of the walking thread's isolate; zero without tables.
  [[nodiscard]] NativeStackScope scope() const noexcept;
  // The realm the request started in; the stack artifact's execution context.
  void SetExecutionContext(std::uint64_t execution_context_id) noexcept;
  // Whether a microtask is running, and the current task attribution ID or 0.
  void SetAsyncContext(bool in_microtask, std::uint32_t task_attribution) noexcept;
  // A scheduling-time walk: the innermost task_frame_limit() frames, no await chain.
  [[nodiscard]] bool async_task_walk() const noexcept;
  // kNativeAsyncTaskFrameLimit, or kNativePromiseRegistrationFrameLimit for a
  // promise registration.
  [[nodiscard]] std::uint32_t task_frame_limit() const noexcept;
  // Whether a frame's script still needs a description in this configuration.
  [[nodiscard]] bool ScriptNeeded(std::uint32_t script_id) const noexcept;
  // The browser refused the stack artifact this record created: the owning
  // thread forgets its digest at its next walk, so an identical later stack is
  // sent again. Called on the transport's sequence only (one producer). The
  // ordering that keeps every refusal applied or covered is in the .cc.
  static void StackArtifactRefused(std::uint64_t creator_sequence) noexcept;
  // Whether this walk's record was admitted. A walk with none keeps nothing, so
  // Blink skips the UTF-8 conversion of the scripts it would otherwise describe.
  [[nodiscard]] bool has_admitted_record() const noexcept { return stack_sequence_ != 0; }
  // Emits the stack record, and the stack artifact when it is new.
  void FramesReady(std::uint32_t total_depth,
                   std::uint32_t recorded,
                   std::uint32_t omitted,
                   std::uint32_t async_frames,
                   bool async_truncated,
                   bool bounded = false) noexcept;
  // Emits one script_identity child of the stack record and retains the source.
  void DescribeScript(const NativeStackScriptSource& script) noexcept;

 private:
  NativeRequestStackWalk(NativeRequestStackTables* state,
                         std::uint64_t generation,
                         std::int32_t request_id,
                         std::uint64_t parent_sequence,
                         std::uint64_t frame_id,
                         NativeProbeType type = NativeProbeType::kRequestInitiatorStack,
                         const std::array<std::uint8_t, 48>& tail = {}) noexcept;
  // The checks RecordRequestInitiated makes before admitting a network record.
  [[nodiscard]] static bool NetworkActive(const NativeProbeSink& sink) noexcept;
  // The calling thread's tables with its routed refusals applied, made on
  // its first walk while capture is active when `make`; null without. Emits
  // the gaps that counts: a mailbox overflow, and once per configuration a
  // worker past kNativeStackThreadLimit, which also sets `*limited`.
  [[nodiscard]] static NativeRequestStackTables* Tables(std::uint64_t generation,
                                                        bool make,
                                                        bool* limited = nullptr) noexcept;
  static void EmitGap(std::string_view reason,
                      std::uint64_t frame_id,
                      std::uint64_t generation) noexcept;
  void Emit(const NativeRequestStackPayload& payload) noexcept;
  void EmitMalformed() noexcept;
  void AsyncTaskFramesReady(std::uint32_t recorded, bool bounded) noexcept;
  [[nodiscard]] std::size_t AppendTaskChain(std::uint8_t* out,
                                            std::uint16_t& count,
                                            std::uint8_t& flags) const noexcept;
  // The kind 9 segment of the reaction running now: its registration stack
  // when recorded, else not_recorded.
  [[nodiscard]] NativeTaskSegment MicrotaskSegment() const noexcept;
  void QueueStackArtifact(NativeProbeSink& sink,
                          NativeRequestStackTables& state,
                          std::size_t hash,
                          const std::array<std::uint8_t, 32>& digest,
                          std::span<const std::uint8_t> content) noexcept;

  NativeRequestStackTables* const state_;
  const std::uint64_t generation_;
  const NativeProbeType type_;
  const std::array<std::uint8_t, 48> tail_;
  const std::int32_t request_id_;
  const std::uint64_t parent_sequence_;
  std::uint64_t frame_id_;
  std::uint64_t execution_context_id_ = 0;
  // The admitted stack record, parent of every script_identity of this walk.
  std::uint64_t stack_sequence_ = 0;
  std::array<std::uint8_t, 32> digest_{};
  NativeStackFrame innermost_;
  bool frames_ready_ = false;
  bool in_microtask_ = false;
  std::uint32_t task_attribution_ = 0;
  NativeAsyncTaskKind task_kind_ = NativeAsyncTaskKind::kEvent;
  // A promise registration walk: its call and V8's async task ID.
  NativePromiseRegistration registration_ = NativePromiseRegistration::kThen;
  std::uint32_t task_id_ = 0;
  std::uint64_t segment_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_H_
