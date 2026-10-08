// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_WORKER_TRANSFER_GATE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_WORKER_TRANSFER_GATE_H_

#include <functional>

#include "native_worker_authority.h"

namespace reb {

// Browser-side single-request/single-staging-slot gate. Every control and
// publication boundary revalidates against the live browser-owned authority.
// The authority outlives this gate; neither is callable from renderer messages.
class NativeWorkerTransferReceiver final {
 public:
  explicit NativeWorkerTransferReceiver(const NativeWorkerAuthority& authority) noexcept;
  NativeWorkerTransferReceiver(const NativeWorkerTransferReceiver&) = delete;
  NativeWorkerTransferReceiver& operator=(const NativeWorkerTransferReceiver&) = delete;
  NativeWorkerTransferReceiver(NativeWorkerTransferReceiver&&) = delete;
  NativeWorkerTransferReceiver& operator=(NativeWorkerTransferReceiver&&) = delete;
  [[nodiscard]] bool Configure(const NativeWorkerLease& lease, std::uint64_t now_ns) noexcept;
  [[nodiscard]] NativeWorkerTransferStatus Request(std::uint64_t now_ns,
                                                   NativeWorkerPull& request) noexcept;
  [[nodiscard]] NativeWorkerTransferStatus Receive(const NativeWorkerTransferReply& reply,
                                                   std::uint64_t now_ns) noexcept;
  // Borrow only during a bounded, non-reentrant publication on the owning
  // browser sequence. An asynchronous durable adapter must condition its commit
  // on this authority generation again; a later ack cannot undo a stale write.
  [[nodiscard]] const NativeWorkerBatch* PendingForPublication(std::uint64_t now_ns) noexcept;
  // Call only after bounded downstream acceptance/durable persistence, not Take.
  [[nodiscard]] bool AcknowledgePublished(const NativeWorkerBatchAck& batch,
                                          std::uint64_t now_ns) noexcept;
  void Revoke() noexcept;
  [[nodiscard]] std::uint64_t retired_records() const noexcept { return retired_records_; }
  [[nodiscard]] std::uint64_t abandoned_requests() const noexcept { return abandoned_requests_; }

 private:
  const std::reference_wrapper<const NativeWorkerAuthority> authority_;
  NativeWorkerLease lease_;
  NativeWorkerBatch pending_;
  NativeWorkerBatchAck last_ack_;
  std::uint64_t greatest_generation_ = 0;
  std::uint64_t next_request_id_ = 1;
  std::uint64_t outstanding_request_id_ = 0;
  std::uint64_t request_deadline_ns_ = 0;
  std::uint64_t next_request_not_before_ns_ = 0;
  std::uint64_t last_batch_id_ = 0;
  std::uint64_t last_sequence_ = 0;
  std::uint64_t retired_records_ = 0;
  std::uint64_t abandoned_requests_ = 0;
  bool active_ = false;
};

}  // namespace reb
#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_WORKER_TRANSFER_GATE_H_
