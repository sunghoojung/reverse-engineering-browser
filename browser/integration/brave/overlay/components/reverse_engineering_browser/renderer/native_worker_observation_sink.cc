// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_worker_observation_sink.h"

#include "base/no_destructor.h"

namespace reb {
namespace {
// Never construct the queue from a disabled hot path. The future browser-owned
// control path must initialize/configure storage before publishing this gate.
constinit std::atomic<bool> enabled{false};
struct ProcessStorage final {
  NativeWorkerObservationQueue queue;
  // NoDestructor requires a non-trivial wrapper even on standard libraries
  // whose mutex is trivially destructible. Storage is never reclaimed in flight.
  ~ProcessStorage() {}
};
NativeWorkerObservationQueue& ObservationQueue() {
  static base::NoDestructor<ProcessStorage> storage;
  return storage->queue;
}
}  // namespace

bool IsNativeWorkerObservationEnabled() noexcept {
  return enabled.load(std::memory_order_acquire);
}
NativeWorkerCaptureStatus ObserveNativeWorker(const NativeWorkerToken worker,
                                              const NativeWorkerToken creator,
                                              const NativeWorkerCreatorKind creator_kind,
                                              const NativeWorkerObservationInput& input,
                                              const std::uint64_t now_ns,
                                              NativeWorkerMessageTag* accepted_tag) noexcept {
  if (accepted_tag) {
    *accepted_tag = {};
  }
  if (!IsNativeWorkerObservationEnabled()) {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  auto& queue = ObservationQueue();
  NativeWorkerCaptureTicket ticket;
  const auto status =
      queue.Begin(NativeWorkerKind::kDedicated, worker, creator, creator_kind, now_ns, ticket);
  if (status != NativeWorkerCaptureStatus::kAccepted) {
    return status;
  }
  const auto result = queue.Capture(ticket, input, now_ns, accepted_tag);
  if (input.operation == NativeWorkerOperation::kGlobalScopeDisposed) {
    // Preserve the final accepted record. If Capture lost to contention/full,
    // final Stats still expose that loss. A busy Begin cannot supply a ticket;
    // the future browser-owned lifecycle controller must revoke independently.
    queue.Retire(ticket);
  }
  return result;
}
}  // namespace reb
