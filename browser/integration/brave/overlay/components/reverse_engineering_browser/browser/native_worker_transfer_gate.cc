// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "native_worker_transfer_gate.h"

#include <algorithm>
#include <limits>

namespace reb {
namespace {
void Increment(std::uint64_t& value, const std::uint64_t count = 1) noexcept {
  value += std::min(count, std::numeric_limits<std::uint64_t>::max() - value);
}
std::uint64_t Deadline(const NativeWorkerLease& lease,
                       const std::uint64_t now,
                       const std::uint64_t interval) noexcept {
  return now + std::min(interval, lease.policy.expires_at_monotonic_ns - now);
}
}  // namespace

bool NativeWorkerTransferReceiver::Configure(const NativeWorkerLease& lease,
                                             const std::uint64_t now_ns) noexcept {
  if (active_ || lease.policy.generation <= greatest_generation_ ||
      !authority_.IsCurrent(lease, now_ns)) {
    return false;
  }
  greatest_generation_ = lease.policy.generation;
  lease_ = lease;
  pending_ = {};
  last_ack_ = {};
  next_request_id_ = 1;
  outstanding_request_id_ = 0;
  next_request_not_before_ns_ = now_ns;
  last_batch_id_ = last_sequence_ = 0;
  active_ = true;
  return true;
}
void NativeWorkerTransferReceiver::Revoke() noexcept {
  Increment(retired_records_, pending_.count);
  if (outstanding_request_id_ != 0) {
    Increment(abandoned_requests_);
  }
  pending_ = {};
  outstanding_request_id_ = 0;
  active_ = false;
}
const NativeWorkerBatch* NativeWorkerTransferReceiver::PendingForPublication(
    const std::uint64_t now_ns) noexcept {
  if (!active_ || !authority_.IsCurrent(lease_, now_ns) ||
      (pending_.batch_id != 0 && now_ns >= pending_.acknowledgment_deadline_ns)) {
    Revoke();
    return nullptr;
  }
  return pending_.batch_id == 0 ? nullptr : &pending_;
}
NativeWorkerTransferStatus NativeWorkerTransferReceiver::Request(
    const std::uint64_t now_ns,
    NativeWorkerPull& request) noexcept {
  request = {};
  if (!active_) {
    return NativeWorkerTransferStatus::kDisabled;
  }
  if (!authority_.IsCurrent(lease_, now_ns)) {
    Revoke();
    return IsValidNativeWorkerLease(lease_, now_ns) ? NativeWorkerTransferStatus::kRevoked
                                                    : NativeWorkerTransferStatus::kExpired;
  }
  if ((outstanding_request_id_ != 0 && now_ns >= request_deadline_ns_) ||
      (pending_.batch_id != 0 && now_ns >= pending_.acknowledgment_deadline_ns)) {
    Revoke();
    return NativeWorkerTransferStatus::kTimedOut;
  }
  if (outstanding_request_id_ != 0 || pending_.batch_id != 0 ||
      now_ns < next_request_not_before_ns_) {
    return NativeWorkerTransferStatus::kBusy;
  }
  if (next_request_id_ == std::numeric_limits<std::uint64_t>::max()) {
    Revoke();
    return NativeWorkerTransferStatus::kSequenceExhausted;
  }
  request = {WorkerTransferEpoch(lease_), next_request_id_++, last_ack_};
  outstanding_request_id_ = request.request_id;
  request_deadline_ns_ = Deadline(lease_, now_ns, kNativeWorkerAckTimeoutNs);
  next_request_not_before_ns_ = Deadline(lease_, now_ns, kNativeWorkerMinPollIntervalNs);
  return NativeWorkerTransferStatus::kRequestReady;
}
NativeWorkerTransferStatus NativeWorkerTransferReceiver::Receive(
    const NativeWorkerTransferReply& reply,
    const std::uint64_t now_ns) noexcept {
  if (!active_) {
    return NativeWorkerTransferStatus::kDisabled;
  }
  if (reply.epoch != WorkerTransferEpoch(lease_) || outstanding_request_id_ == 0 ||
      reply.request_id != outstanding_request_id_) {
    return NativeWorkerTransferStatus::kStaleEpoch;
  }
  if (!authority_.IsCurrent(lease_, now_ns)) {
    Revoke();
    return IsValidNativeWorkerLease(lease_, now_ns) ? NativeWorkerTransferStatus::kRevoked
                                                    : NativeWorkerTransferStatus::kExpired;
  }
  if (now_ns >= request_deadline_ns_) {
    Revoke();
    return NativeWorkerTransferStatus::kTimedOut;
  }
  outstanding_request_id_ = 0;
  if (reply.status == NativeWorkerTransferStatus::kIdle ||
      reply.status == NativeWorkerTransferStatus::kBusy) {
    if (reply.batch != NativeWorkerBatch{}) {
      Revoke();
      return NativeWorkerTransferStatus::kInvalid;
    }
    return reply.status;
  }
  if (reply.status != NativeWorkerTransferStatus::kBatch &&
      reply.status != NativeWorkerTransferStatus::kAwaitingAcknowledgment) {
    Revoke();
    switch (reply.status) {
      case NativeWorkerTransferStatus::kDisabled:
      case NativeWorkerTransferStatus::kExpired:
      case NativeWorkerTransferStatus::kTimedOut:
      case NativeWorkerTransferStatus::kRevoked:
      case NativeWorkerTransferStatus::kDisconnected:
      case NativeWorkerTransferStatus::kSequenceExhausted:
      case NativeWorkerTransferStatus::kInvalid:
      case NativeWorkerTransferStatus::kStaleEpoch:
      case NativeWorkerTransferStatus::kInvalidAcknowledgment:
        return reply.status;
      default:
        return NativeWorkerTransferStatus::kInvalid;
    }
  }
  const auto& batch = reply.batch;
  if (batch.version != 1 || batch.reserved != 0 || batch.count > kNativeWorkerBatchCapacity ||
      batch.epoch != reply.epoch || batch.batch_id <= last_batch_id_ ||
      batch.acknowledgment_deadline_ns <= now_ns ||
      batch.acknowledgment_deadline_ns > Deadline(lease_, now_ns, kNativeWorkerAckTimeoutNs) ||
      batch.capture_stats.queued > kNativeWorkerObservationCapacity) {
    Revoke();
    return NativeWorkerTransferStatus::kInvalid;
  }
  auto sequence = last_sequence_;
  for (std::size_t index = 0; index < kNativeWorkerBatchCapacity; ++index) {
    const auto& record = batch.records[index];
    if (index < batch.count) {
      if (!IsValidNativeWorkerObservation(record, lease_.policy, now_ns) ||
          record.sequence <= sequence || record.monotonic_time_ns < lease_.issued_at_ns) {
        Revoke();
        return NativeWorkerTransferStatus::kInvalid;
      }
      sequence = record.sequence;
    } else if (record != NativeWorkerObservation{}) {
      Revoke();
      return NativeWorkerTransferStatus::kInvalid;
    }
  }
  pending_ = batch;
  last_batch_id_ = batch.batch_id;
  return NativeWorkerTransferStatus::kBatch;
}
bool NativeWorkerTransferReceiver::AcknowledgePublished(const NativeWorkerBatchAck& batch,
                                                        const std::uint64_t now_ns) noexcept {
  if (!active_ || !authority_.IsCurrent(lease_, now_ns) ||
      (pending_.batch_id != 0 && now_ns >= pending_.acknowledgment_deadline_ns)) {
    Revoke();
    return false;
  }
  if (pending_.batch_id == 0 || batch != NativeWorkerBatchAck{pending_.epoch, pending_.batch_id}) {
    return false;
  }
  if (pending_.count != 0) {
    last_sequence_ = pending_.records[pending_.count - 1].sequence;
  }
  last_ack_ = batch;
  pending_ = {};
  return true;
}
}  // namespace reb
