// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_QUEUE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_QUEUE_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>

#if __has_include("brave/components/reverse_engineering_browser/common/native_probe_event.h")
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#else
#include "native_probe_event.h"
#endif

namespace reb {

inline constexpr std::uint32_t kNativeProbeQueueMagic = 0x52454251;
inline constexpr std::uint16_t kNativeProbeQueueVersion = 1;
inline constexpr std::size_t kNativeProbeQueueCapacity = 256;

inline NativeProbeEvent MakeNativeProbeGapEvent(const NativeProbeEvent& reference,
                                                const std::uint64_t dropped) noexcept {
  NativeProbeEvent gap;
  gap.header.category = reference.header.category;
  gap.header.type = NativeProbeType::kGap;
  gap.header.sequence_number = reference.header.sequence_number;
  gap.header.monotonic_time_ns = reference.header.monotonic_time_ns;
  gap.header.session_id = reference.header.session_id;
  gap.header.process_id = reference.header.process_id;
  gap.header.thread_id = reference.header.thread_id;

  std::array<char, 20> reversed{};
  std::uint64_t remaining = dropped;
  std::size_t size = 0;
  do {
    reversed[size] = static_cast<char>('0' + remaining % 10);
    remaining /= 10;
    ++size;
  } while (remaining != 0);
  for (std::size_t index = 0; index < size; ++index) {
    gap.inline_payload[index] = static_cast<std::byte>(reversed[size - index - 1]);
  }
  gap.header.payload_size = static_cast<std::uint32_t>(size);
  return gap;
}

// A bounded multi-producer, single-consumer queue stored directly in shared
// memory. Renderer probes can run on the render thread or worker threads, so a
// single-producer queue would introduce a data race. The browser process is the
// only consumer.
//
// Construct this object once in the browser process before sharing the mapped
// region. Both processes must map exactly sizeof(NativeProbeQueue) bytes.
class alignas(64) NativeProbeQueue final {
 public:
  NativeProbeQueue() noexcept;

  NativeProbeQueue(const NativeProbeQueue&) = delete;
  NativeProbeQueue& operator=(const NativeProbeQueue&) = delete;

  [[nodiscard]] bool IsValid() const noexcept {
    return magic_ == kNativeProbeQueueMagic && version_ == kNativeProbeQueueVersion &&
           record_size_ == sizeof(NativeProbeEvent) && capacity_ == kNativeProbeQueueCapacity;
  }

  [[nodiscard]] bool TryPush(const NativeProbeEvent& event) noexcept {
    std::uint64_t position = enqueue_position_.load(std::memory_order_relaxed);

    for (;;) {
      Slot& slot = slots_[static_cast<std::size_t>(position) & kIndexMask];
      const std::uint64_t sequence = slot.sequence.load(std::memory_order_acquire);
      const std::int64_t difference = static_cast<std::int64_t>(sequence - position);

      if (difference == 0) {
        if (enqueue_position_.compare_exchange_weak(
                position, position + 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
          slot.event = event;
          slot.sequence.store(position + 1, std::memory_order_release);
          return true;
        }
        continue;
      }

      if (difference < 0) {
        IncrementDroppedCount();
        return false;
      }

      position = enqueue_position_.load(std::memory_order_relaxed);
    }
  }

  [[nodiscard]] bool TryPop(NativeProbeEvent& event) noexcept {
    const std::uint64_t position = dequeue_position_.load(std::memory_order_relaxed);
    Slot& slot = slots_[static_cast<std::size_t>(position) & kIndexMask];
    const std::uint64_t sequence = slot.sequence.load(std::memory_order_acquire);
    const std::int64_t difference = static_cast<std::int64_t>(sequence - (position + 1));

    if (difference != 0) {
      return false;
    }

    event = slot.event;
    slot.sequence.store(position + kNativeProbeQueueCapacity, std::memory_order_release);
    dequeue_position_.store(position + 1, std::memory_order_relaxed);
    return true;
  }

  // Returns true only for the producer that changes the queue from an
  // unannounced to an announced state. That producer should send one Mojo
  // wake-up. Other producers only copy their record into shared memory.
  [[nodiscard]] bool MarkNotificationPending() noexcept {
    if (notification_pending_.load(std::memory_order_acquire)) {
      return false;
    }
    bool expected = false;
    return notification_pending_.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                         std::memory_order_acquire);
  }

  void ClearNotificationPending() noexcept {
    notification_pending_.store(false, std::memory_order_release);
  }

  [[nodiscard]] bool Empty() const noexcept {
    const std::uint64_t position = dequeue_position_.load(std::memory_order_relaxed);
    const Slot& slot = slots_[static_cast<std::size_t>(position) & kIndexMask];
    return slot.sequence.load(std::memory_order_acquire) != position + 1;
  }

  [[nodiscard]] std::uint64_t DroppedCount() const noexcept {
    return dropped_.load(std::memory_order_relaxed);
  }

 private:
  struct alignas(64) Slot final {
    std::atomic<std::uint64_t> sequence{0};
    std::array<std::byte, 56> sequence_padding{};
    NativeProbeEvent event{};
  };

  void IncrementDroppedCount() noexcept {
    std::uint64_t dropped = dropped_.load(std::memory_order_relaxed);
    while (dropped != std::numeric_limits<std::uint64_t>::max() &&
           !dropped_.compare_exchange_weak(dropped, dropped + 1, std::memory_order_relaxed,
                                           std::memory_order_relaxed)) {
    }
  }

  static constexpr std::size_t kIndexMask = kNativeProbeQueueCapacity - 1;
  static_assert((kNativeProbeQueueCapacity & kIndexMask) == 0,
                "Queue capacity must be a power of two");
  static_assert(std::atomic<std::uint64_t>::is_always_lock_free,
                "Probe queue counters must be lock-free");

  const std::uint32_t magic_ = kNativeProbeQueueMagic;
  const std::uint16_t version_ = kNativeProbeQueueVersion;
  const std::uint16_t record_size_ = static_cast<std::uint16_t>(sizeof(NativeProbeEvent));
  const std::uint32_t capacity_ = kNativeProbeQueueCapacity;
  [[maybe_unused]] std::array<std::byte, 52> metadata_padding_{};

  alignas(64) std::atomic<std::uint64_t> enqueue_position_{0};
  [[maybe_unused]] std::array<std::byte, 56> enqueue_padding_{};
  alignas(64) std::atomic<std::uint64_t> dequeue_position_{0};
  [[maybe_unused]] std::array<std::byte, 56> dequeue_padding_{};
  alignas(64) std::atomic<std::uint64_t> dropped_{0};
  [[maybe_unused]] std::array<std::byte, 56> dropped_padding_{};
  alignas(64) std::atomic<bool> notification_pending_{false};
  [[maybe_unused]] std::array<std::byte, 63> notification_padding_{};
  alignas(64) std::array<Slot, kNativeProbeQueueCapacity> slots_{};
};

static_assert(sizeof(NativeProbeQueue) == 98624);
static_assert(alignof(NativeProbeQueue) == 64);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_QUEUE_H_
