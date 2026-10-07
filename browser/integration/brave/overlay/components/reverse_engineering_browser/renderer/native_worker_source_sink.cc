// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_worker_source_sink.h"

#include "base/no_destructor.h"

namespace reb {
namespace {
// A disabled hook must not enter a function-local initialization guard. A future
// browser-owned controller must configure storage before publishing this gate.
constinit std::atomic<bool> enabled{false};

NativeWorkerSourceQueue& GetNativeWorkerSourceQueue() {
  static base::NoDestructor<NativeWorkerSourceQueue> queue;
  return *queue;
}

}  // namespace

bool IsNativeWorkerSourceCaptureEnabled() noexcept {
  return enabled.load(std::memory_order_acquire);
}

NativeWorkerCaptureStatus BeginNativeWorkerSourceCapture(
    const NativeWorkerToken worker,
    const std::uint64_t now_ns,
    NativeWorkerCaptureTicket& ticket) noexcept {
  ticket = {};
  if (!IsNativeWorkerSourceCaptureEnabled()) {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  return GetNativeWorkerSourceQueue().Begin(NativeWorkerKind::kDedicated, worker, now_ns, ticket);
}

NativeWorkerCaptureStatus CaptureNativeWorkerSource(const NativeWorkerCaptureTicket& ticket,
                                                    const NativeWorkerToken parent_context,
                                                    const NativeWorkerSourceKind kind,
                                                    const NativeWorkerText source,
                                                    const NativeWorkerText url,
                                                    const std::uint64_t now_ns) noexcept {
  if (!IsNativeWorkerSourceCaptureEnabled()) {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  return GetNativeWorkerSourceQueue().Capture(ticket, parent_context, kind, source, url, now_ns);
}

void RetireNativeWorkerSource(const NativeWorkerToken worker) noexcept {
  if (IsNativeWorkerSourceCaptureEnabled()) {
    GetNativeWorkerSourceQueue().RetireWorker(worker);
  }
}

}  // namespace reb
