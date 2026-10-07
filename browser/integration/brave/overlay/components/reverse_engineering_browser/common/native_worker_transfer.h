// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_TRANSFER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_TRANSFER_H_

#include "native_worker_observation.h"

namespace reb {

inline constexpr std::size_t kNativeWorkerBatchCapacity = 16;
inline constexpr std::uint64_t kNativeWorkerMaxLeaseNs = 600'000'000'000ULL;
inline constexpr std::uint64_t kNativeWorkerAckTimeoutNs = 5'000'000'000ULL;
inline constexpr std::uint64_t kNativeWorkerMinPollIntervalNs = 20'000'000ULL;

// Issued only from browser-owned service/frame/process observations. The renderer
// receives this immutable lease; it never supplies the document/partition proof.
// Local values, not a raw-memory wire ABI. Mojo adapters must map fields explicitly.
struct NativeWorkerLease final {
  NativeWorkerObservationPolicy policy;
  NativeWorkerToken storage_partition;
  NativeWorkerToken selected_frame;
  NativeWorkerToken selected_document;
  NativeWorkerToken connection;
  std::uint64_t document_generation = 0;
  std::uint64_t observer_epoch = 0;
  std::uint64_t issued_at_ns = 0;
  bool operator==(const NativeWorkerLease&) const = default;
};
[[nodiscard]] bool IsValidNativeWorkerLease(const NativeWorkerLease& lease,
                                            std::uint64_t now_ns) noexcept;

struct NativeWorkerTransferEpoch final {
  NativeWorkerToken connection;
  std::uint64_t session_id = 0;
  std::uint64_t generation = 0;
  bool operator==(const NativeWorkerTransferEpoch&) const = default;
};
[[nodiscard]] NativeWorkerTransferEpoch WorkerTransferEpoch(
    const NativeWorkerLease& lease) noexcept;

struct NativeWorkerBatchAck final {
  NativeWorkerTransferEpoch epoch;
  std::uint64_t batch_id = 0;
  bool operator==(const NativeWorkerBatchAck&) const = default;
};
struct NativeWorkerPull final {
  NativeWorkerTransferEpoch epoch;
  std::uint64_t request_id = 0;
  // Empty until downstream explicitly accepts/persists a prior complete batch.
  NativeWorkerBatchAck acknowledged;
};
struct NativeWorkerBatch final {
  std::uint16_t version = 1;
  std::uint16_t count = 0;
  std::uint32_t reserved = 0;
  NativeWorkerTransferEpoch epoch;
  std::uint64_t batch_id = 0;
  std::uint64_t acknowledgment_deadline_ns = 0;
  NativeWorkerObservationStats capture_stats;
  bool worker_retired = false;
  std::array<NativeWorkerObservation, kNativeWorkerBatchCapacity> records{};
  bool operator==(const NativeWorkerBatch&) const = default;
};
static_assert(std::is_trivially_copyable_v<NativeWorkerBatch>);

enum class NativeWorkerTransferStatus : std::uint16_t {
  kConfigured = 1,
  kBatch = 2,
  kIdle = 3,
  kBusy = 4,
  kAwaitingAcknowledgment = 5,
  kInvalid = 6,
  kStaleEpoch = 7,
  kInvalidAcknowledgment = 8,
  kDisabled = 9,
  kExpired = 10,
  kTimedOut = 11,
  kRevoked = 12,
  kDisconnected = 13,
  kSequenceExhausted = 14,
  kRequestReady = 15,
};
struct NativeWorkerTransferStats final {
  std::uint64_t batches = 0;
  std::uint64_t staged_records = 0;
  std::uint64_t acknowledged_batches = 0;
  std::uint64_t acknowledged_records = 0;
  std::uint64_t retired_inflight_records = 0;
  std::uint64_t invalid_controls = 0;
  std::uint64_t timeouts = 0;
};
struct NativeWorkerTransferReply final {
  NativeWorkerTransferStatus status = NativeWorkerTransferStatus::kDisabled;
  NativeWorkerTransferEpoch epoch;
  std::uint64_t request_id = 0;
  NativeWorkerBatch batch;
  NativeWorkerObservationStats capture_stats;
  NativeWorkerTransferStats transfer_stats;
};

// One renderer control sequence, no hot-path IPC. Queue outlives this endpoint
// and every capture callback. A Pull drains at most 16 records; one immutable
// batch retains the only downstream credit until its exact browser ack. No
// mapped region, retry loop, callback queue or per-thread remote exists here.
class NativeWorkerTransferSender final {
 public:
  explicit NativeWorkerTransferSender(NativeWorkerObservationQueue& queue) noexcept
      : queue_(queue) {}
  ~NativeWorkerTransferSender() noexcept;
  NativeWorkerTransferSender(const NativeWorkerTransferSender&) = delete;
  NativeWorkerTransferSender& operator=(const NativeWorkerTransferSender&) = delete;
  NativeWorkerTransferSender(NativeWorkerTransferSender&&) = delete;
  NativeWorkerTransferSender& operator=(NativeWorkerTransferSender&&) = delete;
  [[nodiscard]] NativeWorkerTransferStatus Configure(const NativeWorkerLease& lease,
                                                     std::uint64_t now_ns) noexcept;
  [[nodiscard]] NativeWorkerTransferReply Pull(const NativeWorkerPull& request,
                                               std::uint64_t now_ns) noexcept;
  // Poll even when no events arrive. Reports terminal capture/transport loss.
  [[nodiscard]] NativeWorkerTransferReply Tick(std::uint64_t now_ns) noexcept;
  [[nodiscard]] NativeWorkerTransferReply Revoke(const NativeWorkerTransferEpoch& epoch,
                                                 NativeWorkerTransferStatus reason) noexcept;
  [[nodiscard]] const NativeWorkerTransferStats& stats() const noexcept { return stats_; }

 private:
  NativeWorkerTransferReply Reply(NativeWorkerTransferStatus status,
                                  std::uint64_t request_id = 0) noexcept;
  NativeWorkerTransferReply Close(NativeWorkerTransferStatus reason) noexcept;
  NativeWorkerObservationQueue& queue_;
  NativeWorkerLease lease_;
  NativeWorkerBatch pending_;
  NativeWorkerBatchAck last_ack_;
  NativeWorkerObservationStats last_reported_;
  NativeWorkerTransferStats stats_;
  std::uint64_t next_batch_id_ = 1;
  std::uint64_t last_request_id_ = 0;
  bool active_ = false;
  bool terminal_reported_ = false;
};

}  // namespace reb
#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_TRANSFER_H_
