// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "native_worker_transfer.h"

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

bool IsValidNativeWorkerLease(const NativeWorkerLease& lease, const std::uint64_t now_ns) noexcept {
  const auto& policy = lease.policy;
  return policy.session_id != 0 && policy.generation != 0 && policy.browser_context.valid() &&
         policy.renderer_instance.valid() && policy.worker.valid() && policy.creator.valid() &&
         policy.worker != policy.creator &&
         (policy.creator_kind == NativeWorkerCreatorKind::kDocument ||
          policy.creator_kind == NativeWorkerCreatorKind::kDedicatedWorker) &&
         lease.storage_partition.valid() && lease.selected_frame.valid() &&
         lease.selected_document.valid() && lease.connection.valid() &&
         lease.document_generation != 0 && lease.observer_epoch != 0 &&
         lease.issued_at_ns <= now_ns && now_ns < policy.expires_at_monotonic_ns &&
         policy.expires_at_monotonic_ns - lease.issued_at_ns <= kNativeWorkerMaxLeaseNs;
}
NativeWorkerTransferEpoch WorkerTransferEpoch(const NativeWorkerLease& lease) noexcept {
  return {lease.connection, lease.policy.session_id, lease.policy.generation};
}

NativeWorkerTransferSender::NativeWorkerTransferSender(NativeWorkerObservationQueue& queue) noexcept
    : queue_(queue) {}

NativeWorkerTransferSender::~NativeWorkerTransferSender() noexcept {
  // The endpoint exclusively owns this queue's configured capture generation.
  // A closed endpoint must not revoke a later endpoint's configuration.
  if (active_) {
    queue_.get().Disable();
  }
}

NativeWorkerTransferStatus NativeWorkerTransferSender::Configure(
    const NativeWorkerLease& lease,
    const std::uint64_t now_ns) noexcept {
  if (active_ || queue_.get().IsEnabled() || queue_.get().Stats().queued != 0) {
    return NativeWorkerTransferStatus::kBusy;
  }
  if (!IsValidNativeWorkerLease(lease, now_ns) ||
      queue_.get().Configure(lease.policy, now_ns) != NativeWorkerCaptureStatus::kAccepted) {
    Increment(stats_.invalid_controls);
    return NativeWorkerTransferStatus::kInvalid;
  }
  lease_ = lease;
  pending_ = {};
  last_ack_ = {};
  last_reported_ = queue_.get().Stats();
  next_batch_id_ = 1;
  last_request_id_ = 0;
  terminal_reported_ = false;
  active_ = true;
  return NativeWorkerTransferStatus::kConfigured;
}
NativeWorkerTransferReply NativeWorkerTransferSender::Reply(
    const NativeWorkerTransferStatus status,
    const std::uint64_t request_id) noexcept {
  return {status, WorkerTransferEpoch(lease_), request_id, pending_, queue_.get().Stats(), stats_};
}
NativeWorkerTransferReply NativeWorkerTransferSender::Close(
    const NativeWorkerTransferStatus reason) noexcept {
  queue_.get().Disable();
  Increment(stats_.retired_inflight_records, pending_.count);
  pending_ = {};
  active_ = false;
  return Reply(reason);
}
NativeWorkerTransferReply NativeWorkerTransferSender::Revoke(
    const NativeWorkerTransferEpoch& epoch,
    const NativeWorkerTransferStatus reason) noexcept {
  if (epoch != WorkerTransferEpoch(lease_)) {
    Increment(stats_.invalid_controls);
    return Reply(NativeWorkerTransferStatus::kStaleEpoch);
  }
  if (reason != NativeWorkerTransferStatus::kRevoked &&
      reason != NativeWorkerTransferStatus::kDisconnected) {
    Increment(stats_.invalid_controls);
    return Reply(NativeWorkerTransferStatus::kInvalid);
  }
  return active_ ? Close(reason) : Reply(NativeWorkerTransferStatus::kDisabled);
}
NativeWorkerTransferReply NativeWorkerTransferSender::Tick(const std::uint64_t now_ns) noexcept {
  if (!active_) {
    return Reply(NativeWorkerTransferStatus::kDisabled);
  }
  if (now_ns < lease_.issued_at_ns || now_ns >= lease_.policy.expires_at_monotonic_ns) {
    return Close(NativeWorkerTransferStatus::kExpired);
  }
  if (pending_.batch_id != 0 && now_ns >= pending_.acknowledgment_deadline_ns) {
    Increment(stats_.timeouts);
    return Close(NativeWorkerTransferStatus::kTimedOut);
  }
  return Reply(NativeWorkerTransferStatus::kIdle);
}
NativeWorkerTransferReply NativeWorkerTransferSender::Pull(const NativeWorkerPull& request,
                                                           const std::uint64_t now_ns) noexcept {
  if (request.epoch != WorkerTransferEpoch(lease_)) {
    Increment(stats_.invalid_controls);
    return Reply(NativeWorkerTransferStatus::kStaleEpoch, request.request_id);
  }
  auto state = Tick(now_ns);
  if (state.status != NativeWorkerTransferStatus::kIdle) {
    state.request_id = request.request_id;
    return state;
  }
  if (request.request_id == 0 || request.request_id <= last_request_id_) {
    Increment(stats_.invalid_controls);
    return Reply(NativeWorkerTransferStatus::kInvalid, request.request_id);
  }
  last_request_id_ = request.request_id;
  const bool empty_ack = request.acknowledged == NativeWorkerBatchAck{};
  if (pending_.batch_id != 0) {
    if (empty_ack) {
      return Reply(NativeWorkerTransferStatus::kAwaitingAcknowledgment, request.request_id);
    }
    if (request.acknowledged != NativeWorkerBatchAck{pending_.epoch, pending_.batch_id}) {
      Increment(stats_.invalid_controls);
      return Reply(NativeWorkerTransferStatus::kInvalidAcknowledgment, request.request_id);
    }
    last_ack_ = request.acknowledged;
    Increment(stats_.acknowledged_batches);
    Increment(stats_.acknowledged_records, pending_.count);
    pending_ = {};
  } else if ((!empty_ack && request.acknowledged != last_ack_) ||
             (empty_ack && last_ack_.batch_id != 0)) {
    Increment(stats_.invalid_controls);
    return Reply(NativeWorkerTransferStatus::kInvalidAcknowledgment, request.request_id);
  }
  if (next_batch_id_ == std::numeric_limits<std::uint64_t>::max()) {
    auto reply = Close(NativeWorkerTransferStatus::kSequenceExhausted);
    reply.request_id = request.request_id;
    return reply;
  }

  NativeWorkerBatch batch;
  batch.epoch = WorkerTransferEpoch(lease_);
  bool busy = false;
  for (std::size_t index = 0; index < kNativeWorkerBatchCapacity; ++index) {
    NativeWorkerObservation record;
    const auto status = queue_.get().Take(record, now_ns);
    if (status != NativeWorkerCaptureStatus::kAccepted) {
      busy = status == NativeWorkerCaptureStatus::kBusy;
      break;
    }
    batch.records[batch.count++] = record;
  }
  batch.capture_stats = queue_.get().Stats();
  batch.worker_retired = !queue_.get().IsEnabled();
  if (batch.count == 0 && batch.capture_stats == last_reported_ &&
      (!batch.worker_retired || terminal_reported_)) {
    return Reply(busy ? NativeWorkerTransferStatus::kBusy : NativeWorkerTransferStatus::kIdle,
                 request.request_id);
  }
  batch.batch_id = next_batch_id_++;
  batch.acknowledgment_deadline_ns = Deadline(lease_, now_ns, kNativeWorkerAckTimeoutNs);
  last_reported_ = batch.capture_stats;
  terminal_reported_ = batch.worker_retired && batch.capture_stats.queued == 0;
  pending_ = batch;
  Increment(stats_.batches);
  Increment(stats_.staged_records, batch.count);
  return Reply(NativeWorkerTransferStatus::kBatch, request.request_id);
}

}  // namespace reb
