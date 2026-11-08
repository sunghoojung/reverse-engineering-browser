// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_CAPTURE_BUFFER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_CAPTURE_BUFFER_H_

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace reb {

// Captured bytes held in the browser until the writer drops their transfer.
inline constexpr std::size_t kNativeArtifactInFlightBytes = 32U * 1024U * 1024U;
// One forwarding pipe: the first share of a body without a Content-Length.
inline constexpr std::size_t kNativeArtifactInitialReservation = 64U * 1024U;

class NativeArtifactMemoryPool final {
 public:
  explicit constexpr NativeArtifactMemoryPool(const std::size_t capacity) noexcept
      : capacity_(capacity) {}
  NativeArtifactMemoryPool(const NativeArtifactMemoryPool&) = delete;
  NativeArtifactMemoryPool& operator=(const NativeArtifactMemoryPool&) = delete;

  // Relaxed: the counter publishes no other memory.
  [[nodiscard]] bool TryAcquire(const std::size_t bytes) noexcept {
    std::size_t current = used_.load(std::memory_order_relaxed);
    while (current <= capacity_ && bytes <= capacity_ - current) {
      if (used_.compare_exchange_weak(current, current + bytes, std::memory_order_relaxed)) {
        return true;
      }
    }
    return false;
  }
  void Release(const std::size_t bytes) noexcept {
    used_.fetch_sub(bytes, std::memory_order_relaxed);
  }
  [[nodiscard]] std::size_t used() const noexcept { return used_.load(std::memory_order_relaxed); }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

 private:
  const std::size_t capacity_;
  std::atomic<std::size_t> used_{0};
};

// Returned to the pool on whichever thread destroys it.
class NativeArtifactReservation final {
 public:
  NativeArtifactReservation() = default;
  NativeArtifactReservation(const NativeArtifactReservation&) = delete;
  NativeArtifactReservation& operator=(const NativeArtifactReservation&) = delete;
  NativeArtifactReservation(NativeArtifactReservation&& other) noexcept
      : pool_(std::exchange(other.pool_, nullptr)), bytes_(std::exchange(other.bytes_, 0)) {}
  NativeArtifactReservation& operator=(NativeArtifactReservation&& other) noexcept {
    if (this != &other) {
      Reset();
      pool_ = std::exchange(other.pool_, nullptr);
      bytes_ = std::exchange(other.bytes_, 0);
    }
    return *this;
  }
  ~NativeArtifactReservation() { Reset(); }

  [[nodiscard]] static NativeArtifactReservation Acquire(NativeArtifactMemoryPool& pool,
                                                         const std::size_t bytes) noexcept {
    NativeArtifactReservation reservation;
    if (pool.TryAcquire(bytes)) {
      reservation.pool_ = &pool;
      reservation.bytes_ = bytes;
    }
    return reservation;
  }

  [[nodiscard]] bool is_valid() const noexcept { return pool_ != nullptr; }
  [[nodiscard]] std::size_t bytes() const noexcept { return bytes_; }

  [[nodiscard]] bool GrowTo(const std::size_t total) noexcept {
    if (!pool_) {
      return false;
    }
    if (total <= bytes_) {
      return true;
    }
    if (!pool_->TryAcquire(total - bytes_)) {
      return false;
    }
    bytes_ = total;
    return true;
  }
  void ShrinkTo(const std::size_t total) noexcept {
    if (pool_ && total < bytes_) {
      pool_->Release(bytes_ - total);
      bytes_ = total;
    }
  }
  void Reset() noexcept {
    if (pool_) {
      pool_->Release(bytes_);
    }
    pool_ = nullptr;
    bytes_ = 0;
  }

 private:
  NativeArtifactMemoryPool* pool_ = nullptr;
  std::size_t bytes_ = 0;
};

enum class NativeArtifactCaptureStatus : std::uint8_t {
  kCapturing,
  kTooLarge,
  kMemoryLimit,
  // keep_prefix only: the first `limit` bytes are kept.
  kTruncated,
};

// Capacity tracks the reservation; after a refusal it holds nothing. observed()
// counts every appended byte, kept or not.
class NativeArtifactCaptureBuffer final {
 public:
  NativeArtifactCaptureBuffer() = default;
  NativeArtifactCaptureBuffer(NativeArtifactReservation reservation,
                              const std::size_t limit,
                              const bool keep_prefix = false)
      : reservation_(std::move(reservation)), limit_(limit), keep_prefix_(keep_prefix) {
    if (!reservation_.is_valid()) {
      status_ = NativeArtifactCaptureStatus::kMemoryLimit;
      return;
    }
    if (reservation_.bytes() > limit_) {
      reservation_.ShrinkTo(limit_);
    }
    bytes_.reserve(reservation_.bytes());
  }
  NativeArtifactCaptureBuffer(NativeArtifactCaptureBuffer&&) noexcept = default;
  NativeArtifactCaptureBuffer& operator=(NativeArtifactCaptureBuffer&&) noexcept = default;

  void Append(std::span<const std::uint8_t> data) {
    observed_ += data.size();
    if (status_ != NativeArtifactCaptureStatus::kCapturing || data.empty()) {
      return;
    }
    bool truncated = false;
    if (data.size() > limit_ - bytes_.size()) {
      if (!keep_prefix_) {
        Fail(NativeArtifactCaptureStatus::kTooLarge);
        return;
      }
      data = data.first(limit_ - bytes_.size());
      truncated = true;
    }
    const std::size_t needed = bytes_.size() + data.size();
    if (needed > reservation_.bytes()) {
      const std::size_t doubled =
          reservation_.bytes() > limit_ / 2 ? limit_ : 2 * reservation_.bytes();
      const std::size_t target = std::max(needed, doubled);
      if (!reservation_.GrowTo(target) && !reservation_.GrowTo(needed)) {
        Fail(NativeArtifactCaptureStatus::kMemoryLimit);
        return;
      }
      bytes_.reserve(reservation_.bytes());
    }
    bytes_.insert(bytes_.end(), data.begin(), data.end());
    if (truncated) {
      status_ = NativeArtifactCaptureStatus::kTruncated;
    }
  }

  [[nodiscard]] NativeArtifactCaptureStatus status() const noexcept { return status_; }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
  [[nodiscard]] std::uint64_t observed() const noexcept { return observed_; }
  [[nodiscard]] std::span<const std::uint8_t> content() const noexcept { return bytes_; }
  [[nodiscard]] std::size_t reserved() const noexcept { return reservation_.bytes(); }

  // Returns the slack of a body shorter than its reservation.
  void Finish() {
    if (bytes_.capacity() > bytes_.size()) {
      bytes_.shrink_to_fit();
    }
    reservation_.ShrinkTo(std::max(bytes_.capacity(), bytes_.size()));
  }
  [[nodiscard]] std::vector<std::uint8_t> TakeContent() noexcept { return std::move(bytes_); }
  [[nodiscard]] NativeArtifactReservation TakeReservation() noexcept {
    return std::move(reservation_);
  }

 private:
  void Fail(const NativeArtifactCaptureStatus status) noexcept {
    status_ = status;
    bytes_ = {};
    reservation_.Reset();
  }

  NativeArtifactReservation reservation_;
  std::vector<std::uint8_t> bytes_;
  std::size_t limit_ = 0;
  std::uint64_t observed_ = 0;
  bool keep_prefix_ = false;
  NativeArtifactCaptureStatus status_ = NativeArtifactCaptureStatus::kCapturing;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_CAPTURE_BUFFER_H_
