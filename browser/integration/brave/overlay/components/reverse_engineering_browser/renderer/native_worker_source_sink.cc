// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_worker_source_sink.h"

#include "base/no_destructor.h"

namespace reb {
namespace {

NativeWorkerSourceQueue& GetNativeWorkerSourceQueue() {
  static base::NoDestructor<NativeWorkerSourceQueue> queue;
  return *queue;
}

}  // namespace

bool IsNativeWorkerSourceCaptureEnabled() noexcept {
  return GetNativeWorkerSourceQueue().IsEnabled();
}

NativeWorkerCaptureStatus BeginNativeWorkerSourceCapture(
    const NativeWorkerToken worker, const std::uint64_t now_ns,
    NativeWorkerCaptureTicket& ticket) noexcept {
  return GetNativeWorkerSourceQueue().Begin(NativeWorkerKind::kDedicated, worker, now_ns, ticket);
}

NativeWorkerCaptureStatus CaptureNativeWorkerSource(
    const NativeWorkerCaptureTicket& ticket, const NativeWorkerToken parent_context,
    const NativeWorkerSourceKind kind, const NativeWorkerText source, const NativeWorkerText url,
    const std::uint64_t now_ns) noexcept {
  return GetNativeWorkerSourceQueue().Capture(ticket, parent_context, kind, source, url, now_ns);
}

void RetireNativeWorkerSource(const NativeWorkerToken worker) noexcept {
  GetNativeWorkerSourceQueue().RetireWorker(worker);
}

}  // namespace reb
