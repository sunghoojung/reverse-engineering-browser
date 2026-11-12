// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SERVICE_WORKER_STARTS_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SERVICE_WORKER_STARTS_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "brave/components/reverse_engineering_browser/renderer/native_renderer_request.h"

namespace reb {

// Recorded http(s) starts by request ID, for content::ServiceWorkerSubresourceLoader,
// which knows only that ID ("Service worker ends without a response" in
// protocol/native-network-v3.md). A slot is the request ID's low 10 bits, so a
// later start whose ID is a multiple of 1,024 away replaces it.
//
// Each slot is a Boehm-style sequence lock: the version is odd while a writer
// fills the slot. The fields stay std::atomic so a reader that races a writer
// reads stale values, never a data race, and discards them when the version
// moved. Fixed storage that constinit can zero: no constructor runs.
class NativeServiceWorkerStarts final {
 public:
  static constexpr std::size_t kSlots = 1024;

  constexpr NativeServiceWorkerStarts() = default;
  NativeServiceWorkerStarts(const NativeServiceWorkerStarts&) = delete;
  NativeServiceWorkerStarts& operator=(const NativeServiceWorkerStarts&) = delete;

  // A writer that finds the slot busy skips it; that request's end is then
  // reported lost. Lock-free; any thread.
  void Keep(const NativeRendererRequest& start) noexcept {
    Slot& slot = slots_[start.request_id & (kSlots - 1)];
    std::uint32_t version = slot.version.load(std::memory_order_relaxed);
    // Acquire on success orders this write after the previous writer's release.
    if ((version & 1U) != 0 ||
        !slot.version.compare_exchange_strong(version, version + 1, std::memory_order_acquire,
                                              std::memory_order_relaxed)) {
      return;
    }
    // Readers that see any field below also see the odd version.
    std::atomic_thread_fence(std::memory_order_release);
    slot.request_id.store(start.request_id, std::memory_order_relaxed);
    slot.generation.store(start.generation, std::memory_order_relaxed);
    slot.sequence.store(start.initiated_sequence, std::memory_order_relaxed);
    slot.time_ns.store(start.initiated_time_ns, std::memory_order_relaxed);
    slot.frame_id.store(start.frame_id, std::memory_order_relaxed);
    slot.thread_id.store(start.thread_id, std::memory_order_relaxed);
    slot.scheme_class.store(static_cast<std::uint8_t>(start.scheme_class),
                            std::memory_order_relaxed);
    slot.version.store(version + 2, std::memory_order_release);
  }

  // A consistent copy of request_id's slot, or false while a writer fills it.
  [[nodiscard]] bool Read(const std::uint32_t request_id,
                          NativeRendererRequest& out) const noexcept {
    const Slot& slot = slots_[request_id & (kSlots - 1)];
    const std::uint32_t version = slot.version.load(std::memory_order_acquire);
    if ((version & 1U) != 0) {
      return false;
    }
    out.request_id = slot.request_id.load(std::memory_order_relaxed);
    out.generation = slot.generation.load(std::memory_order_relaxed);
    out.initiated_sequence = slot.sequence.load(std::memory_order_relaxed);
    out.initiated_time_ns = slot.time_ns.load(std::memory_order_relaxed);
    out.frame_id = slot.frame_id.load(std::memory_order_relaxed);
    out.thread_id = slot.thread_id.load(std::memory_order_relaxed);
    out.scheme_class =
        static_cast<NativeSchemeClass>(slot.scheme_class.load(std::memory_order_relaxed));
    std::atomic_thread_fence(std::memory_order_acquire);
    return slot.version.load(std::memory_order_relaxed) == version;
  }

 private:
  struct Slot final {
    std::atomic<std::uint32_t> version{0};
    std::atomic<std::uint32_t> request_id{0};
    std::atomic<std::uint64_t> generation{0};
    std::atomic<std::uint64_t> sequence{0};
    std::atomic<std::uint64_t> time_ns{0};
    std::atomic<std::uint64_t> frame_id{0};
    std::atomic<std::uint32_t> thread_id{0};
    std::atomic<std::uint8_t> scheme_class{0};
  };
  static_assert((kSlots & (kSlots - 1)) == 0);
  static_assert(sizeof(Slot) == 48);

  std::array<Slot, kSlots> slots_{};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SERVICE_WORKER_STARTS_H_
