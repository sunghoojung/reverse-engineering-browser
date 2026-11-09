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

// Blink's walker. It runs on the calling thread and returns kWalked only on
// the document main thread, after calling FramesReady exactly once.
using NativeRequestStackProvider = NativeRequestStackWalkResult (*)(NativeRequestStackWalk& walk);

// The sink's side of one walk. Methods run on the document main thread inside
// the provider and never call into V8.
class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeRequestStackWalk final {
 public:
  // Installed once per renderer by Blink, only when V8 runs with
  // --reb-request-stacks. Allocates the frame buffer and tables then.
  static void SetProvider(NativeRequestStackProvider provider) noexcept;
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
  // An async task scheduled now: its segment handle, or 0. Main thread only.
  [[nodiscard]] static std::uint64_t RecordAsyncTask(NativeAsyncTaskKind kind) noexcept;
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
  // The realm the request started in; the stack artifact's execution context.
  void SetExecutionContext(std::uint64_t execution_context_id) noexcept;
  // Whether a microtask is running, and the current task attribution ID or 0.
  void SetAsyncContext(bool in_microtask, std::uint32_t task_attribution) noexcept;
  // A scheduling-time walk: the innermost kNativeAsyncTaskFrameLimit frames, no await chain.
  [[nodiscard]] bool async_task_walk() const noexcept;
  // Whether a frame's script still needs a description in this configuration.
  [[nodiscard]] bool ScriptNeeded(std::uint32_t script_id) const noexcept;
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
  void Emit(const NativeRequestStackPayload& payload) noexcept;
  void EmitMalformed() noexcept;
  void AsyncTaskFramesReady(std::uint32_t recorded, bool bounded) noexcept;
  [[nodiscard]] std::size_t AppendTaskChain(std::uint8_t* out,
                                            std::uint16_t& count,
                                            std::uint8_t& flags) const noexcept;
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
  const std::uint64_t frame_id_;
  std::uint64_t execution_context_id_ = 0;
  // The admitted stack record, parent of every script_identity of this walk.
  std::uint64_t stack_sequence_ = 0;
  std::array<std::uint8_t, 32> digest_{};
  NativeStackFrame innermost_;
  bool frames_ready_ = false;
  bool in_microtask_ = false;
  std::uint32_t task_attribution_ = 0;
  NativeAsyncTaskKind task_kind_ = NativeAsyncTaskKind::kEvent;
  std::uint64_t segment_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_H_
