// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_BLINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_BLINK_H_

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

#include "base/containers/span.h"
#include "brave/components/reverse_engineering_browser/common/native_tab_link.h"
#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"
#include "brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h"
#include "third_party/blink/public/common/messaging/cloneable_message.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_info.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "v8/include/v8-context.h"
#include "v8/include/v8-isolate.h"
#include "v8/include/v8-microtask-queue.h"
#include "v8/include/v8-native-stack.h"

// Blink hooks for protocol/native-network-v3.md; one atomic load without --reb-request-stacks.
namespace reb::request_stack_blink {

using TaskScope = blink::scheduler::TaskAttributionTracker::TaskScope;

inline std::uint64_t FrameId(const blink::Frame* frame) {
  const auto* local = blink::DynamicTo<blink::LocalFrame>(frame);
  if (!local) {
    return 0;
  }
  const blink::LocalFrameToken token = local->GetLocalFrameToken();
  return NativeFrameIdOf(token.value().GetHighForSerialization(),
                         token.value().GetLowForSerialization());
}

// The Mojo traits bound an origin before reading it; see cloneable_message.h.
static_assert(blink::kRebTaskOriginMaxBytes == kNativeTaskOriginMaxBytes);
static_assert(blink::kRebTaskOriginOversize == kNativeTaskOriginOversize);

// Blink's buffer for V8's frames, made with a thread's tables by its first
// active walk and freed with them.
using V8StackFrames = std::array<v8::NativeStackFrame, kNativeRequestStackFrameCapacity>;
inline void* AllocateV8StackFrames() {
  return new V8StackFrames();
}
inline void ReleaseV8StackFrames(void* frames) {
  delete static_cast<V8StackFrames*>(frames);
}

// V8 initialization on the document main thread, with or without
// --reb-request-stacks: names its isolate and allocates nothing.
inline void AttachMainThread() {
  NativeStackScope scope;
  scope.thread = static_cast<std::uint8_t>(NativeStackThread::kDocument);
  NativeRequestStackWalk::AttachThread(scope);
}

// WorkerThread::InitializeOnWorkerThread, once the global scope exists, with
// or without --reb-request-stacks: dedicated, shared and service workers are
// named by the worker's context ID, the frame_id of its own requests and
// cookie records. Two thread-local stores under WorkerThread::lock_; the
// tables come later, from the first walk or message receipt while capture is
// active. Worklets get no scope, so
// their requests read unsupported_thread.
inline void AttachWorkerThread(blink::ExecutionContext* scope) {
  if (!scope) {
    return;
  }
  NativeStackThread thread;
  if (scope->IsDedicatedWorkerGlobalScope()) {
    thread = NativeStackThread::kDedicatedWorker;
  } else if (scope->IsSharedWorkerGlobalScope()) {
    thread = NativeStackThread::kSharedWorker;
  } else if (scope->IsServiceWorkerGlobalScope()) {
    thread = NativeStackThread::kServiceWorker;
  } else {
    return;
  }
  const auto [high, low] = scope->GetExecutionContextToken().Visit([](const auto& token) {
    return std::pair(token.value().GetHighForSerialization(),
                     token.value().GetLowForSerialization());
  });
  NativeStackScope key;
  key.thread = static_cast<std::uint8_t>(thread);
  key.isolate_key = NativeContextFold(high, low);
  // A zero fold cannot name an isolate; that worker reads unsupported_thread.
  if (key.isolate_key == 0) {
    return;
  }
  NativeRequestStackWalk::AttachThread(key);
}

inline std::uint32_t CurrentTaskAttribution(v8::Isolate* isolate) {
  auto* tracker = blink::scheduler::TaskAttributionTracker::From(isolate);
  blink::scheduler::TaskAttributionInfo* state = tracker ? tracker->CurrentTaskState() : nullptr;
  return state ? state->Id().value() : 0;
}

// Any other name is a queued event or an observer callback.
inline NativeAsyncTaskKind AsyncTaskKind(const blink::StringView& name) {
  if (name == blink::StringView("setTimeout")) {
    return NativeAsyncTaskKind::kSetTimeout;
  }
  if (name == blink::StringView("setInterval")) {
    return NativeAsyncTaskKind::kSetInterval;
  }
  if (name == blink::StringView("requestAnimationFrame")) {
    return NativeAsyncTaskKind::kRequestAnimationFrame;
  }
  if (name == blink::StringView("requestIdleCallback")) {
    return NativeAsyncTaskKind::kRequestIdleCallback;
  }
  if (name == blink::StringView("postMessage")) {
    return NativeAsyncTaskKind::kPostMessage;
  }
  if (name == blink::StringView("XMLHttpRequest.send")) {
    return NativeAsyncTaskKind::kXmlHttpRequest;
  }
  if (name == blink::StringView("postTask")) {
    return NativeAsyncTaskKind::kPostTask;
  }
  return NativeAsyncTaskKind::kEvent;
}

// probe::AsyncTaskContext::Schedule on the main thread or a worker: the
// scheduling stack, or a no_script segment when no script runs.
inline std::uint64_t ScheduleAsyncTask(blink::ExecutionContext* context,
                                       const blink::StringView& name) {
  if (!NativeRequestStackWalk::Enabled() || !context) {
    return 0;
  }
  v8::Isolate* const isolate = context->GetIsolate();
  return NativeRequestStackWalk::RecordAsyncTask(AsyncTaskKind(name),
                                                 isolate && isolate->InContext());
}

// The task origin a posted message carries (common/native_request_stack.h):
// MessagePort, BroadcastChannel or worker postMessage. Empty without a
// provider or while capture is inactive.
inline blink::Vector<std::uint8_t> PostMessageOrigin(blink::ExecutionContext* context,
                                                     const NativeAsyncTaskKind kind) {
  if (!NativeRequestStackWalk::Enabled() || !context) {
    return {};
  }
  v8::Isolate* const isolate = context->GetIsolate();
  std::array<std::uint8_t, kNativeTaskOriginMaxBytes> origin;
  const std::size_t size =
      NativeRequestStackWalk::PostMessageOrigin(kind, isolate && isolate->InContext(), origin);
  return blink::Vector<std::uint8_t>(base::span<const std::uint8_t>(origin).first(size));
}

// Around a received message's dispatch: its handler's task continues the
// posting stack's chain. The origin is untrusted bytes from the sender.
class MessageTaskScope final {
 public:
  MessageTaskScope(const NativeAsyncTaskKind kind, base::span<const std::uint8_t> origin) {
    if (!NativeRequestStackWalk::Enabled()) {
      return;
    }
    if (const std::uint64_t segment = NativeRequestStackWalk::ReceiveMessageOrigin(kind, origin)) {
      previous_ = NativeRequestStackWalk::EnterAsyncTask(segment);
      entered_ = true;
    }
  }
  ~MessageTaskScope() {
    if (entered_) {
      NativeRequestStackWalk::ExitAsyncTask(previous_);
    }
  }
  MessageTaskScope(const MessageTaskScope&) = delete;
  MessageTaskScope& operator=(const MessageTaskScope&) = delete;

 private:
  std::uint64_t previous_ = 0;
  bool entered_ = false;
};

// A fresh task state per top-level callback, so its promise reactions name its segment.
[[nodiscard]] inline std::optional<TaskScope> AttributeAsyncTask(v8::Isolate* isolate) {
  const std::uint64_t segment = NativeRequestStackWalk::CurrentAsyncTask();
  if (segment == 0) {
    return std::nullopt;
  }
  auto* tracker = blink::scheduler::TaskAttributionTracker::From(isolate);
  if (!tracker) {
    return std::nullopt;
  }
  blink::scheduler::TaskAttributionInfo* current = tracker->CurrentTaskState();
  // Forking with the current timing context keeps every other variable.
  blink::ResourceTimingContext* timing = current ? current->GetResourceTimingContext() : nullptr;
  std::optional<TaskScope> scope(tracker->SetTaskStateVariable(timing));
  if (blink::scheduler::TaskAttributionInfo* forked = tracker->CurrentTaskState()) {
    NativeRequestStackWalk::AttributeAsyncTask(forked->Id().value(), segment);
  }
  return scope;
}

// Blink agents may run their own microtask queues; the entered context names the running one.
inline void SetAsyncContext(NativeRequestStackWalk& walk, v8::Isolate* isolate) {
  v8::MicrotaskQueue* const queue = isolate->GetCurrentContext()->GetMicrotaskQueue();
  walk.SetAsyncContext(
      queue ? queue->IsRunningMicrotasks() : v8::MicrotasksScope::IsRunningMicrotasks(isolate),
      CurrentTaskAttribution(isolate));
}

// The navigation_initiator_stack the browser joins to this navigation, or 0.
inline std::uint64_t NavigationStack(const blink::LocalFrame* target, const bool form) {
  if (!NativeRequestStackWalk::Enabled()) {
    return 0;
  }
  const std::uint64_t target_id = FrameId(target);
  if (form) {
    if (const std::uint64_t scheduled = NativeRequestStackWalk::TakeFormNavigation(target_id)) {
      return scheduled;
    }
  }
  return NativeRequestStackWalk::RecordNavigation(NativeNavigationKindScope::Current(), target_id);
}

// HTMLFormElement::ScheduleFormSubmission, before the navigation task is posted.
inline void FormNavigationScheduled(const blink::Frame* target) {
  if (NativeRequestStackWalk::Enabled()) {
    NativeRequestStackWalk::ScheduleFormNavigation(FrameId(target));
  }
}

}  // namespace reb::request_stack_blink

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_BLINK_H_
