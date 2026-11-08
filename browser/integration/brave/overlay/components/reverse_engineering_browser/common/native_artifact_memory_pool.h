// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_MEMORY_POOL_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_MEMORY_POOL_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace reb {

// Captured bytes held in the browser until the writer drops their transfer.
inline constexpr std::size_t kNativeArtifactInFlightBytes = 32U * 1024U * 1024U;

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

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_MEMORY_POOL_H_
