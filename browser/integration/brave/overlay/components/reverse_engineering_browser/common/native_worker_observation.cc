// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "native_worker_observation.h"

#include <algorithm>
#include <limits>

namespace reb {
namespace {
void Increment(std::uint64_t& value, const std::uint64_t amount = 1) noexcept {
  value += std::min(amount, std::numeric_limits<std::uint64_t>::max() - value);
}
bool ValidPolicy(const NativeWorkerObservationPolicy& policy) noexcept {
  return policy.session_id != 0 && policy.generation != 0 && policy.expires_at_monotonic_ns != 0 &&
         policy.browser_context.valid() && policy.renderer_instance.valid() &&
         policy.worker.valid() && policy.creator.valid() && policy.worker != policy.creator &&
         (policy.creator_kind == NativeWorkerCreatorKind::kDocument ||
          policy.creator_kind == NativeWorkerCreatorKind::kDedicatedWorker);
}
bool IsMessage(const NativeWorkerOperation operation) noexcept {
  return operation == NativeWorkerOperation::kMessageSent ||
         operation == NativeWorkerOperation::kMessageReceived ||
         operation == NativeWorkerOperation::kMessageError;
}
bool EmptyTag(const NativeWorkerMessageTag& tag) noexcept {
  return tag.session_id == 0 && tag.generation == 0 && tag.send_sequence == 0;
}
bool ValidInput(const NativeWorkerObservationInput& input) noexcept {
  if (input.operation < NativeWorkerOperation::kObjectCreated ||
      input.operation > NativeWorkerOperation::kGlobalScopeDisposed ||
      (input.source_kind != NativeWorkerSourceKind::kClassic &&
       input.source_kind != NativeWorkerSourceKind::kModule)) {
    return false;
  }
  if (IsMessage(input.operation)) {
    return (input.direction == NativeWorkerDirection::kToWorker ||
            input.direction == NativeWorkerDirection::kToCreator) &&
           input.script_id == 0 &&
           (input.operation != NativeWorkerOperation::kMessageSent || EmptyTag(input.message_tag));
  }
  return input.direction == NativeWorkerDirection::kNone && input.native_trace_id == 0 &&
         EmptyTag(input.message_tag) &&
         (input.operation == NativeWorkerOperation::kScriptCompiled ? input.script_id > 0
                                                                    : input.script_id == 0);
}
}  // namespace

NativeWorkerObservationQueue::NativeWorkerObservationQueue() noexcept = default;

NativeWorkerCaptureStatus NativeWorkerObservationQueue::Configure(
    const NativeWorkerObservationPolicy& policy,
    const std::uint64_t now_ns) noexcept {
  active_generation_.store(0, std::memory_order_release);
  readable_generation_.store(0, std::memory_order_release);
  const std::lock_guard lock(mutex_);
  ClearLocked();
  if (!ValidPolicy(policy) || policy.generation <= greatest_generation_ ||
      now_ns >= policy.expires_at_monotonic_ns) {
    return NativeWorkerCaptureStatus::kInvalid;
  }
  greatest_generation_ = policy.generation;
  policy_ = policy;
  session_id_.store(policy.session_id, std::memory_order_relaxed);
  worker_high_.store(policy.worker.high, std::memory_order_relaxed);
  worker_low_.store(policy.worker.low, std::memory_order_relaxed);
  // Release publishes policy after reset. No caller reads policy without mutex.
  readable_generation_.store(policy.generation, std::memory_order_release);
  active_generation_.store(policy.generation, std::memory_order_release);
  return NativeWorkerCaptureStatus::kAccepted;
}
void NativeWorkerObservationQueue::ClearLocked() noexcept {
  Increment(stats_.retired, stats_.queued);
  records_.fill({});
  stats_.queued = 0;
  stats_.pending_gap = 0;
  read_ = write_ = 0;
}
void NativeWorkerObservationQueue::Disable() noexcept {
  active_generation_.store(0, std::memory_order_release);
  readable_generation_.store(0, std::memory_order_release);
  const std::lock_guard lock(mutex_);
  ClearLocked();
}
void NativeWorkerObservationQueue::Retire(const NativeWorkerCaptureTicket& ticket) noexcept {
  // Each generation is published once. A successful CAS proves these relaxed
  // identity reads belong to the same still-active generation as Begin.
  auto generation = active_generation_.load(std::memory_order_acquire);
  if (generation == 0 || generation != ticket.generation ||
      ticket.session_id != session_id_.load(std::memory_order_relaxed) ||
      ticket.worker.high != worker_high_.load(std::memory_order_relaxed) ||
      ticket.worker.low != worker_low_.load(std::memory_order_relaxed) ||
      !active_generation_.compare_exchange_strong(generation, 0, std::memory_order_acq_rel)) {
    return;
  }
  // Keep metadata drainable, including dispose. The control path must poll Take
  // and final Stats until empty, then Disable; expiry remains an absolute bound.
}

void NativeWorkerObservationQueue::CountContention() noexcept {
  if (contended_.fetch_add(1, std::memory_order_relaxed) ==
      std::numeric_limits<std::uint64_t>::max()) {
    contention_overflow_.store(true, std::memory_order_release);
  }
}
NativeWorkerCaptureStatus NativeWorkerObservationQueue::Begin(
    const NativeWorkerKind kind,
    const NativeWorkerToken worker,
    const NativeWorkerToken creator,
    const NativeWorkerCreatorKind creator_kind,
    const std::uint64_t now_ns,
    NativeWorkerCaptureTicket& ticket) noexcept {
  ticket = {};
  const auto generation = active_generation_.load(std::memory_order_acquire);
  if (generation == 0) {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  if (kind != NativeWorkerKind::kDedicated) {
    return NativeWorkerCaptureStatus::kUnsupportedWorker;
  }
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    CountContention();
    return NativeWorkerCaptureStatus::kBusy;
  }
  if (active_generation_.load(std::memory_order_acquire) != generation) {
    Increment(stats_.stale);
    return NativeWorkerCaptureStatus::kStaleGeneration;
  }
  if (now_ns >= policy_.expires_at_monotonic_ns) {
    active_generation_.store(0, std::memory_order_release);
    readable_generation_.store(0, std::memory_order_release);
    ClearLocked();
    return NativeWorkerCaptureStatus::kExpired;
  }
  if (worker != policy_.worker || creator != policy_.creator ||
      creator_kind != policy_.creator_kind) {
    return NativeWorkerCaptureStatus::kWrongWorker;
  }
  ticket = {policy_.session_id, generation, worker};
  return NativeWorkerCaptureStatus::kAccepted;
}
NativeWorkerCaptureStatus NativeWorkerObservationQueue::DropLocked(
    const NativeWorkerCaptureStatus status) noexcept {
  Increment(stats_.dropped);
  Increment(stats_.pending_gap);
  return status;
}
NativeWorkerCaptureStatus NativeWorkerObservationQueue::Capture(
    const NativeWorkerCaptureTicket& ticket,
    const NativeWorkerObservationInput& input,
    const std::uint64_t now_ns,
    NativeWorkerMessageTag* accepted_tag) noexcept {
  if (accepted_tag) {
    *accepted_tag = {};
  }
  if (!IsEnabled()) {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    CountContention();
    return NativeWorkerCaptureStatus::kBusy;
  }
  if (ticket.generation != policy_.generation || ticket.session_id != policy_.session_id ||
      ticket.worker != policy_.worker ||
      active_generation_.load(std::memory_order_acquire) != ticket.generation) {
    Increment(stats_.stale);
    return NativeWorkerCaptureStatus::kStaleGeneration;
  }
  if (now_ns >= policy_.expires_at_monotonic_ns) {
    active_generation_.store(0, std::memory_order_release);
    readable_generation_.store(0, std::memory_order_release);
    ClearLocked();
    return NativeWorkerCaptureStatus::kExpired;
  }
  if (stats_.attempted == std::numeric_limits<std::uint64_t>::max()) {
    active_generation_.store(0, std::memory_order_release);
    return DropLocked(NativeWorkerCaptureStatus::kFull);
  }
  ++stats_.attempted;
  if (!ValidInput(input) ||
      (IsMessage(input.operation) && input.operation != NativeWorkerOperation::kMessageSent &&
       !EmptyTag(input.message_tag) &&
       (input.message_tag.session_id != ticket.session_id ||
        input.message_tag.generation != ticket.generation || input.message_tag.send_sequence == 0 ||
        input.message_tag.send_sequence >= stats_.attempted))) {
    return DropLocked(NativeWorkerCaptureStatus::kInvalid);
  }
  if (stats_.queued == records_.size()) {
    return DropLocked(NativeWorkerCaptureStatus::kFull);
  }
  NativeWorkerObservation record;
  record.operation = input.operation;
  record.direction = input.direction;
  record.source_kind = input.source_kind;
  record.session_id = policy_.session_id;
  record.generation = ticket.generation;
  record.sequence = stats_.attempted;
  record.monotonic_time_ns = now_ns;
  record.browser_context = policy_.browser_context;
  record.renderer_instance = policy_.renderer_instance;
  record.worker = policy_.worker;
  record.creator = policy_.creator;
  record.creator_kind = policy_.creator_kind;
  record.send_sequence = input.operation == NativeWorkerOperation::kMessageSent
                             ? record.sequence
                             : input.message_tag.send_sequence;
  record.native_trace_id = input.native_trace_id;
  record.script_id = input.script_id;
  record.dropped_before = stats_.pending_gap;
  if (active_generation_.load(std::memory_order_acquire) != ticket.generation) {
    Increment(stats_.stale);
    return DropLocked(NativeWorkerCaptureStatus::kStaleGeneration);
  }
  records_[write_] = record;
  write_ = (write_ + 1) % records_.size();
  ++stats_.queued;
  stats_.pending_gap = 0;
  if (accepted_tag && input.operation == NativeWorkerOperation::kMessageSent) {
    *accepted_tag = {record.session_id, record.generation, record.sequence};
  }
  return NativeWorkerCaptureStatus::kAccepted;
}
NativeWorkerCaptureStatus NativeWorkerObservationQueue::Take(NativeWorkerObservation& record,
                                                             const std::uint64_t now_ns) noexcept {
  record = {};
  if (readable_generation_.load(std::memory_order_acquire) == 0) {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    return NativeWorkerCaptureStatus::kBusy;
  }
  if (readable_generation_.load(std::memory_order_acquire) != policy_.generation) {
    return NativeWorkerCaptureStatus::kStaleGeneration;
  }
  if (now_ns >= policy_.expires_at_monotonic_ns) {
    active_generation_.store(0, std::memory_order_release);
    readable_generation_.store(0, std::memory_order_release);
    ClearLocked();
    return NativeWorkerCaptureStatus::kExpired;
  }
  if (stats_.queued == 0) {
    return NativeWorkerCaptureStatus::kEmpty;
  }
  record = records_[read_];
  records_[read_] = {};
  read_ = (read_ + 1) % records_.size();
  --stats_.queued;
  if (readable_generation_.load(std::memory_order_acquire) != record.generation) {
    record = {};
    Increment(stats_.retired);
    return NativeWorkerCaptureStatus::kStaleGeneration;
  }
  return NativeWorkerCaptureStatus::kAccepted;
}
NativeWorkerObservationStats NativeWorkerObservationQueue::Stats() noexcept {
  const std::lock_guard lock(mutex_);
  auto result = stats_;
  result.contended = contention_overflow_.load(std::memory_order_acquire)
                         ? std::numeric_limits<std::uint64_t>::max()
                         : contended_.load(std::memory_order_relaxed);
  return result;
}

bool IsValidNativeWorkerObservation(const NativeWorkerObservation& record,
                                    const NativeWorkerObservationPolicy& authority,
                                    const std::uint64_t now_ns) noexcept {
  if (!ValidPolicy(authority) || record.magic != 0x4f574252U || record.version != 1 ||
      record.record_size != sizeof(record) || record.worker_kind != NativeWorkerKind::kDedicated ||
      record.session_id != authority.session_id || record.generation != authority.generation ||
      record.browser_context != authority.browser_context ||
      record.renderer_instance != authority.renderer_instance ||
      record.worker != authority.worker || record.creator != authority.creator ||
      record.creator_kind != authority.creator_kind || record.monotonic_time_ns > now_ns ||
      record.sequence == 0 || record.monotonic_time_ns >= authority.expires_at_monotonic_ns ||
      std::any_of(record.reserved.begin(), record.reserved.end(),
                  [](std::byte byte) { return byte != std::byte{}; }) ||
      !ValidInput(
          {record.operation, record.direction, record.native_trace_id, record.script_id,
           record.source_kind,
           record.operation == NativeWorkerOperation::kMessageSent || record.send_sequence == 0
               ? NativeWorkerMessageTag{}
               : NativeWorkerMessageTag{record.session_id, record.generation,
                                        record.send_sequence}}) ||
      (record.operation == NativeWorkerOperation::kMessageSent &&
       record.send_sequence != record.sequence) ||
      (IsMessage(record.operation) && record.operation != NativeWorkerOperation::kMessageSent &&
       record.send_sequence >= record.sequence)) {
    return false;
  }
  return now_ns < authority.expires_at_monotonic_ns;
}

bool NativeWorkerObservationProjection::Reset(
    const NativeWorkerObservationPolicy& authority) noexcept {
  authority_ = {};
  stats_ = {};
  messages_.fill({});
  scripts_.fill({});
  message_count_ = script_count_ = 0;
  last_sequence_ = 0;
  if (!ValidPolicy(authority)) {
    return false;
  }
  authority_ = authority;
  return true;
}
void NativeWorkerObservationProjection::Retire() noexcept {
  Increment(stats_.retired_entries, message_count_ + script_count_);
  authority_ = {};
  messages_.fill({});
  scripts_.fill({});
  message_count_ = script_count_ = 0;
  last_sequence_ = 0;
}
bool NativeWorkerObservationProjection::Expire(const std::uint64_t now_ns) noexcept {
  if (authority_.generation != 0 && now_ns >= authority_.expires_at_monotonic_ns) {
    Retire();
    return true;
  }
  return false;
}
bool NativeWorkerObservationProjection::Apply(const NativeWorkerObservation& record,
                                              const std::uint64_t now_ns) noexcept {
  static_cast<void>(Expire(now_ns));
  if (!IsValidNativeWorkerObservation(record, authority_, now_ns)) {
    Increment(stats_.rejected);
    return false;
  }
  if (record.sequence <= last_sequence_) {
    Increment(stats_.out_of_order);
    return false;
  }
  // The first record may follow capture activation, so only infer gaps between
  // observed sequence numbers. Explicit dropped_before covers initial losses.
  if (last_sequence_ != 0) {
    Increment(stats_.missing_sequences, record.sequence - last_sequence_ - 1);
  }
  last_sequence_ = record.sequence;
  Increment(stats_.reported_drops, record.dropped_before);
  if (IsMessage(record.operation)) {
    if (record.send_sequence == 0) {
      Increment(stats_.untagged_receives);
      Increment(stats_.accepted);
      return true;
    }
    std::size_t index = 0;
    while (index < message_count_ && messages_[index].send_tag != record.send_sequence) {
      ++index;
    }
    if (index == message_count_) {
      if (message_count_ == messages_.size()) {
        Increment(stats_.capacity_drops);
        return false;
      }
      messages_[message_count_++] = {record.native_trace_id, record.direction,
                                     record.send_sequence};
    }
    auto& link = messages_[index];
    if (link.native_trace_id != record.native_trace_id || link.direction != record.direction) {
      if (!link.ambiguous) {
        Increment(stats_.ambiguous_ids);
      }
      link.ambiguous = true;
    }
    auto& sequence = record.operation == NativeWorkerOperation::kMessageSent
                         ? link.send_sequence
                         : link.receive_sequence;
    if (sequence != 0) {
      if (!link.ambiguous) {
        Increment(stats_.ambiguous_ids);
      }
      link.ambiguous = true;
    } else {
      sequence = record.sequence;
      if (record.operation != NativeWorkerOperation::kMessageSent) {
        link.receive_error = record.operation == NativeWorkerOperation::kMessageError;
      }
    }
  } else if (record.operation == NativeWorkerOperation::kScriptCompiled) {
    std::size_t index = 0;
    while (index < script_count_ && scripts_[index].script_id != record.script_id) {
      ++index;
    }
    if (index == script_count_) {
      if (script_count_ == scripts_.size()) {
        Increment(stats_.capacity_drops);
        return false;
      }
      scripts_[script_count_++] = {record.script_id, record.source_kind, record.sequence};
    } else {
      // No last-write-wins claim if an isolate-local script ID was reused.
      if (!scripts_[index].ambiguous) {
        Increment(stats_.ambiguous_ids);
      }
      scripts_[index].ambiguous = true;
    }
  } else {
    stats_.lifecycle_seen |= 1U << static_cast<std::uint16_t>(record.operation);
  }
  Increment(stats_.accepted);
  return true;
}
}  // namespace reb
