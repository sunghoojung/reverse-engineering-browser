// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_DISPATCH_EMIT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_DISPATCH_EMIT_H_

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>

#include "native_probe_event.h"
#include "native_vm_dispatch.h"

namespace reb {

// One capture configuration may publish this many observed guest steps.
// Matches the owned fixture budget. Further observations stay off the probe
// queue until one vm gap carries their exact count.
inline constexpr std::uint32_t kNativeVmDispatchSampleBudget = 16;

// Each slot records its owning configuration generation. Never reset these
// claims: a delayed old reader must not consume a replacement configuration's
// budget. Generations are even, strictly increasing, and never wrap in the sink.
class NativeVmDispatchBudget {
 public:
  [[nodiscard]] std::uint32_t TryReserve(const std::uint64_t generation) noexcept {
    if (generation == 0 || (generation & 1U) != 0) {
      return kNativeVmDispatchSampleBudget;
    }
    for (std::uint32_t slot = 0; slot < kNativeVmDispatchSampleBudget; ++slot) {
      auto claimed = generations_[slot].load(std::memory_order_relaxed);
      // One strong CAS per slot bounds probe work, including under contention.
      // A newer generation can reclaim an old claim, never the reverse.
      // Contention may conservatively reject this observation; later calls
      // can reclaim old slots. This is not an exhaustive sampling guarantee.
      if (claimed < generation && generations_[slot].compare_exchange_strong(
                                      claimed, generation, std::memory_order_relaxed)) {
        return slot;
      }
    }
    return kNativeVmDispatchSampleBudget;
  }

  // Return a claim after an emit that did not retain the sample. The slot
  // becomes generation - 1, which is odd. The same even generation can reclaim
  // it. An older even generation cannot, and a newer one still can. Releasing
  // to zero would let a stale reader spend a replacement configuration's budget.
  void Release(const std::uint32_t slot, const std::uint64_t generation) noexcept {
    if (slot >= kNativeVmDispatchSampleBudget || generation == 0 || (generation & 1U) != 0) {
      return;
    }
    auto claimed = generation;
    static_cast<void>(generations_[slot].compare_exchange_strong(
        claimed, generation - 1, std::memory_order_relaxed));
  }

 private:
  static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
  std::array<std::atomic<std::uint64_t>, kNativeVmDispatchSampleBudget> generations_{};
};

enum class NativeVmDispatchPrepareStatus : std::uint8_t {
  kReady = 0,
  kMalformed = 1,
  kBudgetExhausted = 2,
};

// A sample is emittable only when every reserved field is zero, the finding
// and investigation ids are present, and the interpreter artifact id is
// present. The instruction pointer, opcode, and handler index are copied
// through unchanged. This function does not read a guest interpreter.
[[nodiscard]] inline bool IsEmittableVmDispatchSample(
    const NativeVmDispatchSamplePayload& sample) noexcept {
  if (sample.protocol_version != kNativeVmDispatchSampleProtocolVersion ||
      sample.payload_size != sizeof(NativeVmDispatchSamplePayload) || sample.flags != 0 ||
      sample.reserved_alignment != 0 || sample.reserved0 != 0 || sample.reserved1 != 0 ||
      sample.reserved2 != 0 || sample.finding_id == 0 || sample.investigation_id == 0 ||
      sample.interpreter_artifact_id == 0) {
    return false;
  }
  for (const std::byte value : sample.reserved) {
    if (value != std::byte{}) {
      return false;
    }
  }
  for (const std::byte value : sample.reserved_tail) {
    if (value != std::byte{}) {
      return false;
    }
  }
  return true;
}

// Fills one probe record from an already observed sample. samples_already_recorded
// is the count accepted for this capture configuration before this call.
[[nodiscard]] inline NativeVmDispatchPrepareStatus PrepareVmDispatchProbeEvent(
    const NativeVmDispatchSamplePayload& sample,
    const std::uint32_t samples_already_recorded,
    const std::uint64_t sequence_number,
    const std::uint64_t monotonic_time_ns,
    const std::uint64_t session_id,
    const std::uint32_t process_id,
    const std::uint32_t thread_id,
    const std::uint64_t frame_id,
    NativeProbeEvent& event) noexcept {
  event = {};
  if (samples_already_recorded >= kNativeVmDispatchSampleBudget) {
    return NativeVmDispatchPrepareStatus::kBudgetExhausted;
  }
  if (!IsEmittableVmDispatchSample(sample)) {
    return NativeVmDispatchPrepareStatus::kMalformed;
  }
  event.header.protocol_version = kNativeProbeProtocolVersion;
  event.header.header_size = sizeof(NativeProbeHeader);
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = NativeProbeType::kVmDispatchSample;
  event.header.payload_size = sizeof(NativeVmDispatchSamplePayload);
  event.header.sequence_number = sequence_number;
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.session_id = session_id;
  event.header.process_id = process_id;
  event.header.thread_id = thread_id;
  event.header.frame_id = frame_id;
  event.header.artifact_id = sample.interpreter_artifact_id;
  static_assert(sizeof(sample) <= kNativeProbeInlinePayloadSize);
  const auto sample_bytes = std::bit_cast<std::array<std::byte, sizeof(sample)>>(sample);
  std::ranges::copy(sample_bytes, event.inline_payload.begin());
  return NativeVmDispatchPrepareStatus::kReady;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_DISPATCH_EMIT_H_
