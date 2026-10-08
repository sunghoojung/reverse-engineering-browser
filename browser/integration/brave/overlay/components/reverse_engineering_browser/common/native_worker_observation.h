// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_OBSERVATION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_OBSERVATION_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <mutex>
#include <span>
#include <type_traits>

#include "native_worker_types.h"

namespace reb {

inline constexpr std::size_t kNativeWorkerObservationCapacity = 128;
inline constexpr std::size_t kNativeWorkerProjectionCapacity = 64;
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
static_assert(std::atomic<bool>::is_always_lock_free);

enum class NativeWorkerOperation : std::uint16_t {
  kObjectCreated = 1,
  kGlobalScopeStarted = 2,
  kScriptCompiled = 3,
  kMessageSent = 4,
  kMessageReceived = 5,
  kMessageError = 6,
  kTerminateRequested = 7,
  kGlobalScopeDisposed = 8,
};
enum class NativeWorkerCreatorKind : std::uint16_t { kDocument = 1, kDedicatedWorker = 2 };
enum class NativeWorkerDirection : std::uint16_t { kNone = 0, kToWorker = 1, kToCreator = 2 };

// Browser-owned authority, not authentication of an untrusted renderer. This
// first local component selects one worker and its actual creator in one
// renderer incarnation. No URL, PID, or navigation guess grants ownership.
struct NativeWorkerObservationPolicy final {
  std::uint64_t session_id = 0;
  std::uint64_t generation = 0;
  std::uint64_t expires_at_monotonic_ns = 0;
  NativeWorkerToken browser_context;
  NativeWorkerToken renderer_instance;
  NativeWorkerToken worker;
  NativeWorkerToken creator;
  NativeWorkerCreatorKind creator_kind = NativeWorkerCreatorKind::kDocument;
  bool operator==(const NativeWorkerObservationPolicy&) const = default;
};

// Carried by the actual in-process message, never reconstructed from trace_id.
// All-zero means no accepted send. Partial or different-generation tags fail closed.
struct NativeWorkerMessageTag final {
  std::uint64_t session_id = 0;
  std::uint64_t generation = 0;
  std::uint64_t send_sequence = 0;
};
static_assert(sizeof(NativeWorkerMessageTag) == 24);
static_assert(std::is_trivially_copyable_v<NativeWorkerMessageTag>);

struct NativeWorkerObservationInput final {
  NativeWorkerOperation operation = NativeWorkerOperation::kObjectCreated;
  NativeWorkerDirection direction = NativeWorkerDirection::kNone;
  // Copied from Chromium's BlinkTransferableMessage, never manufactured here.
  std::uint64_t native_trace_id = 0;
  // V8 script IDs are isolate-local hints, scoped by the full worker identity.
  // Zero means unavailable; it never produces a source association.
  std::int32_t script_id = 0;
  NativeWorkerSourceKind source_kind = NativeWorkerSourceKind::kClassic;
  // Receiver copies this from the exact transferred message tag. Zero means
  // no accepted send observation, and cannot create a causal link.
  NativeWorkerMessageTag message_tag{};
};

// Versioned LOCAL record. Not a Mojo, socket, EventRecord, or artifact ABI.
// No payload, URL, origin string, arbitrary handle, or JS value is retained.
struct NativeWorkerObservation final {
  std::uint32_t magic = 0x4f574252U;
  std::uint16_t version = 1;
  std::uint16_t record_size = 160;
  NativeWorkerOperation operation = NativeWorkerOperation::kObjectCreated;
  NativeWorkerKind worker_kind = NativeWorkerKind::kDedicated;
  NativeWorkerDirection direction = NativeWorkerDirection::kNone;
  NativeWorkerSourceKind source_kind = NativeWorkerSourceKind::kClassic;
  std::uint64_t session_id = 0;
  std::uint64_t generation = 0;
  std::uint64_t sequence = 0;
  std::uint64_t monotonic_time_ns = 0;
  NativeWorkerToken browser_context;
  NativeWorkerToken renderer_instance;
  NativeWorkerToken worker;
  NativeWorkerToken creator;
  std::uint64_t native_trace_id = 0;
  std::uint64_t dropped_before = 0;
  std::uint64_t send_sequence = 0;
  std::int32_t script_id = 0;
  NativeWorkerCreatorKind creator_kind = NativeWorkerCreatorKind::kDocument;
  std::array<std::byte, 18> reserved{};
  bool operator==(const NativeWorkerObservation&) const = default;
};
static_assert(sizeof(NativeWorkerObservation) == 160);
static_assert(std::is_trivially_copyable_v<NativeWorkerObservation>);
static_assert(std::is_standard_layout_v<NativeWorkerObservation>);
static_assert(offsetof(NativeWorkerObservation, worker) == 80);
static_assert(offsetof(NativeWorkerObservation, native_trace_id) == 112);

// Structural/identity validation shared by the browser publication gate and local
// projection. Does not authenticate a renderer or authorize a browser document.
[[nodiscard]] bool IsValidNativeWorkerObservation(const NativeWorkerObservation& record,
                                                  const NativeWorkerObservationPolicy& authority,
                                                  std::uint64_t now_ns) noexcept;

struct NativeWorkerObservationStats final {
  std::uint64_t attempted = 0;
  std::uint64_t dropped = 0;
  std::uint64_t pending_gap = 0;
  std::uint64_t retired = 0;
  std::uint64_t stale = 0;
  std::uint64_t contended = 0;
  std::size_t queued = 0;
  bool operator==(const NativeWorkerObservationStats&) const = default;
};

// Configure/Disable/Stats are serialized control-path operations. Begin,
// Capture and Take only try-lock. Tickets cannot cross a generation change.
// Retirement takes the exact ticket, so a stale worker callback cannot revoke
// a newer authorization for the same worker token.
class NativeWorkerObservationQueue final {
 public:
  [[nodiscard]] bool IsEnabled() const noexcept {
    return active_generation_.load(std::memory_order_acquire) != 0;
  }
  [[nodiscard]] NativeWorkerCaptureStatus Configure(const NativeWorkerObservationPolicy& policy,
                                                    std::uint64_t now_ns) noexcept;
  void Disable() noexcept;
  // Stops new capture but preserves queued metadata, including the final dispose
  // record, until drained or explicitly revoked/expired. Never waits for a lock.
  void Retire(const NativeWorkerCaptureTicket& ticket) noexcept;
  [[nodiscard]] NativeWorkerCaptureStatus Begin(NativeWorkerKind kind,
                                                NativeWorkerToken worker,
                                                NativeWorkerToken creator,
                                                NativeWorkerCreatorKind creator_kind,
                                                std::uint64_t now_ns,
                                                NativeWorkerCaptureTicket& ticket) noexcept;
  [[nodiscard]] NativeWorkerCaptureStatus Capture(
      const NativeWorkerCaptureTicket& ticket,
      const NativeWorkerObservationInput& input,
      std::uint64_t now_ns,
      NativeWorkerMessageTag* accepted_tag = nullptr) noexcept;
  [[nodiscard]] NativeWorkerCaptureStatus Take(NativeWorkerObservation& record,
                                               std::uint64_t now_ns) noexcept;
  [[nodiscard]] NativeWorkerObservationStats Stats() noexcept;

 private:
  void ClearLocked() noexcept;
  NativeWorkerCaptureStatus DropLocked(NativeWorkerCaptureStatus status) noexcept;
  void CountContention() noexcept;
  std::atomic<std::uint64_t> active_generation_{0};
  // Retirement only stops producers. Disable/reconfigure/expiry revoke reads.
  std::atomic<std::uint64_t> readable_generation_{0};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> worker_high_{0};
  std::atomic<std::uint64_t> worker_low_{0};
  std::atomic<std::uint64_t> contended_{0};
  std::atomic<bool> contention_overflow_{false};
  std::mutex mutex_;
  std::array<NativeWorkerObservation, kNativeWorkerObservationCapacity> records_{};
  NativeWorkerObservationPolicy policy_;
  NativeWorkerObservationStats stats_;
  std::uint64_t greatest_generation_ = 0;
  std::size_t read_ = 0;
  std::size_t write_ = 0;
};

// Bounded, single-consumer projection. A pair is observed only when the same
// copied send tag occurs once at both endpoints in the exact authorized identity.
// Duplicate IDs are permanently ambiguous within this projection; completed
// keys are not evicted and reused. Missing endpoints remain explicitly missing.
struct NativeWorkerMessageLink final {
  std::uint64_t native_trace_id = 0;
  NativeWorkerDirection direction = NativeWorkerDirection::kNone;
  std::uint64_t send_tag = 0;
  std::uint64_t send_sequence = 0;
  std::uint64_t receive_sequence = 0;
  bool receive_error = false;
  bool ambiguous = false;
  [[nodiscard]] bool observed() const noexcept {
    return send_tag != 0 && send_sequence != 0 && receive_sequence != 0 && !ambiguous;
  }
};
struct NativeWorkerScriptObservation final {
  std::int32_t script_id = 0;
  NativeWorkerSourceKind source_kind = NativeWorkerSourceKind::kClassic;
  std::uint64_t compile_sequence = 0;
  bool ambiguous = false;
};
struct NativeWorkerProjectionStats final {
  std::uint64_t accepted = 0;
  std::uint64_t rejected = 0;
  std::uint64_t out_of_order = 0;
  std::uint64_t capacity_drops = 0;
  std::uint64_t missing_sequences = 0;
  std::uint64_t reported_drops = 0;
  std::uint64_t ambiguous_ids = 0;
  std::uint64_t untagged_receives = 0;
  std::uint64_t retired_entries = 0;
  std::uint32_t lifecycle_seen = 0;
};
class NativeWorkerObservationProjection final {
 public:
  // A new explicit authority resets the bounded view. An invalid authority
  // clears it and leaves it disabled. This never authorizes browser capture.
  [[nodiscard]] bool Reset(const NativeWorkerObservationPolicy& authority) noexcept;
  [[nodiscard]] bool Apply(const NativeWorkerObservation& record, std::uint64_t now_ns) noexcept;
  void Retire() noexcept;
  [[nodiscard]] bool Expire(std::uint64_t now_ns) noexcept;
  [[nodiscard]] std::span<const NativeWorkerMessageLink> messages() const noexcept {
    return {messages_.data(), message_count_};
  }
  [[nodiscard]] std::span<const NativeWorkerScriptObservation> scripts() const noexcept {
    return {scripts_.data(), script_count_};
  }
  [[nodiscard]] const NativeWorkerProjectionStats& stats() const noexcept { return stats_; }

 private:
  NativeWorkerObservationPolicy authority_;
  NativeWorkerProjectionStats stats_;
  std::array<NativeWorkerMessageLink, kNativeWorkerProjectionCapacity> messages_{};
  std::array<NativeWorkerScriptObservation, kNativeWorkerProjectionCapacity> scripts_{};
  std::size_t message_count_ = 0;
  std::size_t script_count_ = 0;
  std::uint64_t last_sequence_ = 0;
};

}  // namespace reb
#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_OBSERVATION_H_
