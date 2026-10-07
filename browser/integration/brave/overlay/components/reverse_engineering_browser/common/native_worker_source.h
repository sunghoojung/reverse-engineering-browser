// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_SOURCE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_SOURCE_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <type_traits>

namespace reb {

inline constexpr std::size_t kNativeWorkerSourceMaxBytes = 2U * 1024U * 1024U;
inline constexpr std::size_t kNativeWorkerSourceMaxUrlBytes = 8192;
inline constexpr std::size_t kNativeWorkerSourceCapacity = 4;

struct NativeWorkerToken final {
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  [[nodiscard]] bool valid() const noexcept { return high != 0 || low != 0; }
  bool operator==(const NativeWorkerToken&) const = default;
};

enum class NativeWorkerKind : std::uint16_t { kDedicated = 1, kShared = 2, kService = 3 };
enum class NativeWorkerSourceKind : std::uint16_t { kClassic = 1, kModule = 2 };
enum class NativeWorkerUrlStatus : std::uint32_t {
  kAbsent = 0,
  // Redacted metadata within the supported syntax subset, not URL validity or
  // authority. The browser must still validate with its canonical URL parser.
  kSanitized = 1,
  kOpaqueOmitted = 2,
  kInvalidOmitted = 3,
  kUnsupportedAuthorityOmitted = 4,
};
enum class NativeWorkerCaptureStatus {
  kAccepted,
  kDisabled,
  kBusy,
  kExpired,
  kWrongWorker,
  kUnsupportedWorker,
  kStaleGeneration,
  kInvalid,
  kTooLarge,
  kFull,
  kEmpty,
  kOutputTooSmall,
  kAllocationFailed,
  kSourceUnavailable,
};

// Browser-supplied, exact-worker authority is required before any source copy.
// Category masks or renderer-supplied URLs cannot substitute for this policy.
struct NativeWorkerSourcePolicy final {
  std::uint64_t session_id = 0;
  std::uint64_t generation = 0;
  std::uint64_t expires_at_monotonic_ns = 0;
  NativeWorkerToken browser_context;
  NativeWorkerToken renderer_instance;
  NativeWorkerToken worker;
  bool sensitive_source_approved = false;
};

// Local queue ABI only. This is deliberately NOT an artifact/socket header.
// The browser must verify ownership and hash the complete UTF-8 source before
// constructing a normalized artifact. A V8 script number is not a global ID.
struct NativeWorkerSourceHeader final {
  std::uint32_t magic = 0x53574252U;
  std::uint16_t version = 1;
  std::uint16_t header_size = 144;
  NativeWorkerSourceKind source_kind = NativeWorkerSourceKind::kClassic;
  NativeWorkerKind worker_kind = NativeWorkerKind::kDedicated;
  NativeWorkerUrlStatus url_status = NativeWorkerUrlStatus::kAbsent;
  std::uint64_t session_id = 0;
  std::uint64_t generation = 0;
  std::uint64_t sequence = 0;
  std::uint64_t monotonic_time_ns = 0;
  NativeWorkerToken browser_context;
  NativeWorkerToken renderer_instance;
  // At the pinned Blink revision the dedicated-worker token is also its
  // execution-context token. Preserve all 128 bits instead of folding them.
  NativeWorkerToken worker;
  NativeWorkerToken parent_context;
  std::uint64_t dropped_before = 0;
  std::uint32_t source_size = 0;
  std::uint32_t url_size = 0;
  std::uint32_t source_code_units = 0;
  std::uint32_t sensitive = 1;
  std::array<std::byte, 8> reserved{};
};
static_assert(sizeof(NativeWorkerSourceHeader) == 144);
static_assert(std::is_trivially_copyable_v<NativeWorkerSourceHeader>);
static_assert(std::is_standard_layout_v<NativeWorkerSourceHeader>);
static_assert(offsetof(NativeWorkerSourceHeader, session_id) == 16);
static_assert(offsetof(NativeWorkerSourceHeader, worker) == 80);
static_assert(offsetof(NativeWorkerSourceHeader, dropped_before) == 112);

// Blink's 8-bit strings are Latin-1, not UTF-8. A view borrows memory only for
// the synchronous call; neither a V8 handle nor a Blink object is retained.
struct NativeWorkerText final {
  std::span<const std::uint8_t> latin1;
  std::span<const char16_t> utf16;
  // A hook must report a gap rather than synchronously unpark/read a source.
  bool unavailable = false;
};

struct NativeWorkerCaptureTicket final {
  std::uint64_t session_id = 0;
  std::uint64_t generation = 0;
  NativeWorkerToken worker;
};

struct NativeWorkerSourceStats final {
  std::uint64_t attempted = 0;
  std::uint64_t dropped = 0;
  std::uint64_t pending_gap = 0;
  std::uint64_t retired = 0;
  std::uint64_t stale = 0;
  // Process-lifetime and unattributed: contention can race policy changes.
  std::uint64_t contended = 0;
  std::size_t queued = 0;
};

// Dormant foundation: no production controller configures or drains this queue
// yet. Configure/Disable are control-path operations; probes only try-lock.
// All payload storage is allocated on Configure, never on a capture path.
class NativeWorkerSourceQueue final {
 public:
  NativeWorkerSourceQueue();
  ~NativeWorkerSourceQueue();
  NativeWorkerSourceQueue(const NativeWorkerSourceQueue&) = delete;
  NativeWorkerSourceQueue& operator=(const NativeWorkerSourceQueue&) = delete;

  [[nodiscard]] bool IsEnabled() const noexcept {
    return active_generation_.load(std::memory_order_acquire) != 0;
  }
  [[nodiscard]] NativeWorkerCaptureStatus Configure(const NativeWorkerSourcePolicy& policy,
                                                    std::uint64_t now_ns) noexcept;
  void Disable() noexcept;
  // Worker teardown immediately revokes the matching generation without
  // waiting for a producer/consumer. Pending storage is cleared when possible.
  void RetireWorker(NativeWorkerToken worker) noexcept;
  [[nodiscard]] NativeWorkerCaptureStatus Begin(NativeWorkerKind kind,
                                                NativeWorkerToken worker,
                                                std::uint64_t now_ns,
                                                NativeWorkerCaptureTicket& ticket) noexcept;
  [[nodiscard]] NativeWorkerCaptureStatus Capture(const NativeWorkerCaptureTicket& ticket,
                                                  NativeWorkerToken parent_context,
                                                  NativeWorkerSourceKind kind,
                                                  NativeWorkerText source,
                                                  NativeWorkerText url,
                                                  std::uint64_t now_ns) noexcept;
  [[nodiscard]] NativeWorkerCaptureStatus Take(NativeWorkerSourceHeader& header,
                                               std::span<std::uint8_t> source,
                                               std::span<char> url,
                                               std::uint64_t now_ns) noexcept;
  [[nodiscard]] NativeWorkerSourceStats Stats() noexcept;

 private:
  struct Slot;
  void ClearLocked() noexcept;
  NativeWorkerCaptureStatus DropLocked(NativeWorkerCaptureStatus status) noexcept;
  void CountContention() noexcept;

  std::atomic<std::uint64_t> active_generation_{0};
  std::atomic<std::uint64_t> worker_high_{0};
  std::atomic<std::uint64_t> worker_low_{0};
  std::mutex mutex_;
  std::unique_ptr<Slot[]> slots_;
  NativeWorkerSourcePolicy policy_;
  NativeWorkerSourceStats stats_;
  std::atomic<std::uint64_t> contended_{0};
  std::atomic<bool> contention_overflow_{false};
  std::size_t read_ = 0;
  std::size_t write_ = 0;
  std::uint64_t greatest_generation_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_SOURCE_H_
