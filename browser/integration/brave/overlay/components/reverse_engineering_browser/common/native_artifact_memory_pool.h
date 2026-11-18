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

#include "base/memory/raw_ptr.h"

namespace reb {

// Captured bytes held in the browser until the writer drops their transfer:
// every queued frame's content and metadata. It is the only bound on that
// memory; the writer's queue has none of its own. Streams queue what they are
// offered at once, so every byte charged here is draining to the receiver and
// a waiting stream is always woken.
inline constexpr std::size_t kNativeArtifactInFlightBytes = 32U * 1024U * 1024U;

enum class NativeArtifactPoolUse : std::uint8_t {
  // A stream whose source can wait: a body still arriving through a pipe, or
  // one still held where it came from. It stops at the stream mark and waits.
  kStream,
  // Content that already arrived whole in this process, such as a header block
  // or a renderer's artifact message. Refusing it would lose it, so it may use
  // the quarter above the stream mark that waiting streams leave free.
  kWhole,
};

// Runs on the releasing thread, at most once per ArmSpaceHook().
using NativeArtifactSpaceHook = void (*)() noexcept;

class NativeArtifactMemoryPool final {
 public:
  explicit constexpr NativeArtifactMemoryPool(const std::size_t capacity,
                                              const NativeArtifactSpaceHook hook = nullptr) noexcept
      : capacity_(capacity),
        stream_mark_(capacity - capacity / 4),
        // A waiting stream is woken once a sixteenth is free below its mark,
        // so a drained 64 KiB frame does not wake every waiter.
        wake_mark_(stream_mark_ - capacity / 16),
        hook_(hook) {}
  NativeArtifactMemoryPool(const NativeArtifactMemoryPool&) = delete;
  NativeArtifactMemoryPool& operator=(const NativeArtifactMemoryPool&) = delete;

  // Relaxed: the counter publishes no other memory.
  [[nodiscard]] bool TryAcquire(const std::size_t bytes,
                                const NativeArtifactPoolUse use) noexcept {
    const std::size_t limit = use == NativeArtifactPoolUse::kStream ? stream_mark_ : capacity_;
    std::size_t current = used_.load(std::memory_order_relaxed);
    while (current <= limit && bytes <= limit - current) {
      if (used_.compare_exchange_weak(current, current + bytes, std::memory_order_relaxed)) {
        return true;
      }
    }
    return false;
  }
  // Sequentially consistent with ArmSpaceHook(): either the release sees the
  // hook armed, or the arming sees the release's room.
  void Release(const std::size_t bytes) noexcept {
    const std::size_t left = used_.fetch_sub(bytes, std::memory_order_seq_cst) - bytes;
    if (left <= wake_mark_ && armed_.load(std::memory_order_seq_cst) &&
        armed_.exchange(false, std::memory_order_seq_cst) && hook_) {
      hook_();
    }
  }
  // Asks for the hook at the next release that leaves a stream room to grow.
  // False when a stream already has that room, so the caller retries now.
  [[nodiscard]] bool ArmSpaceHook() noexcept {
    armed_.store(true, std::memory_order_seq_cst);
    return used_.load(std::memory_order_seq_cst) > wake_mark_;
  }
  [[nodiscard]] std::size_t used() const noexcept { return used_.load(std::memory_order_relaxed); }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] std::size_t stream_mark() const noexcept { return stream_mark_; }

 private:
  const std::size_t capacity_;
  const std::size_t stream_mark_;
  const std::size_t wake_mark_;
  const NativeArtifactSpaceHook hook_;
  std::atomic<std::size_t> used_{0};
  std::atomic<bool> armed_{false};
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
                                                         const std::size_t bytes,
                                                         const NativeArtifactPoolUse use) noexcept {
    NativeArtifactReservation reservation;
    if (pool.TryAcquire(bytes, use)) {
      reservation.pool_ = &pool;
      reservation.bytes_ = bytes;
    }
    return reservation;
  }

  [[nodiscard]] bool is_valid() const noexcept { return pool_ != nullptr; }
  [[nodiscard]] std::size_t bytes() const noexcept { return bytes_; }

  [[nodiscard]] bool GrowTo(const std::size_t total, const NativeArtifactPoolUse use) noexcept {
    if (!pool_) {
      return false;
    }
    if (total <= bytes_) {
      return true;
    }
    if (!pool_->TryAcquire(total - bytes_, use)) {
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
  raw_ptr<NativeArtifactMemoryPool> pool_ = nullptr;
  std::size_t bytes_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_MEMORY_POOL_H_
