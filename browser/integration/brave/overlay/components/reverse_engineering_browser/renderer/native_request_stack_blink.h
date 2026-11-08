// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_BLINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_REQUEST_STACK_BLINK_H_

#include <cstdint>
#include <optional>

#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"
#include "brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_info.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "v8/include/v8-context.h"
#include "v8/include/v8-isolate.h"
#include "v8/include/v8-microtask-queue.h"

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

// probe::AsyncTaskContext::Schedule: the scheduling stack, when script runs.
inline std::uint64_t ScheduleAsyncTask(blink::ExecutionContext* context,
                                       const blink::StringView& name) {
  if (!NativeRequestStackWalk::Enabled() || !context || !blink::IsMainThread()) {
    return 0;
  }
  v8::Isolate* const isolate = context->GetIsolate();
  if (!isolate || !isolate->InContext()) {
    return 0;
  }
  return NativeRequestStackWalk::RecordAsyncTask(AsyncTaskKind(name));
}

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
