// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SOCKET_CLIENT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SOCKET_CLIENT_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "base/memory/scoped_refptr.h"
#include "base/no_destructor.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/thread_annotations.h"
#include "base/threading/thread.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"

namespace base {
class SequencedTaskRunner;
}

namespace reb {

class NativeProbeSocketClient final {
 public:
  static NativeProbeSocketClient& Get();

  NativeProbeSocketClient(const NativeProbeSocketClient&) = delete;
  NativeProbeSocketClient& operator=(const NativeProbeSocketClient&) = delete;

  // Does nothing and returns false when no broker switches are present. A
  // partial or invalid configuration also returns false and leaves probes off.
  [[nodiscard]] bool StartFromCommandLine();

  // Tests lower the spill's bound to reach it, restore the bound it returns,
  // and read how many chunks the spill holds.
  [[nodiscard]] std::size_t SetSpillChunkLimitForTesting(std::size_t chunks);
  [[nodiscard]] std::size_t SpillChunkCountForTesting();

 private:
  friend class base::NoDestructor<NativeProbeSocketClient>;

  // Each chunk is its own mapping of ten 16 KiB pages, unmapped as soon as
  // the writer has sent it, so a burst's memory goes back to the system when
  // the burst ends instead of staying with the allocator. It holds 511
  // records and their count, sent in one write.
  static constexpr std::size_t kSpillChunkBytes = 160 * 1024;
  static constexpr std::size_t kSpillChunkRecords =
      (kSpillChunkBytes - sizeof(std::size_t)) / sizeof(NativeProbeEvent);
  struct SpillChunk final {
    std::size_t size = 0;
    std::array<NativeProbeEvent, kSpillChunkRecords> records;
  };
  static_assert(sizeof(SpillChunk) <= kSpillChunkBytes);
  struct SpillChunkUnmapper final {
    void operator()(SpillChunk* chunk) const noexcept;
  };
  using SpillChunkPointer = std::unique_ptr<SpillChunk, SpillChunkUnmapper>;
  using Spill = std::vector<SpillChunkPointer>;

  NativeProbeSocketClient();
  ~NativeProbeSocketClient();

  static void Emit(const NativeProbeEvent& event) noexcept;
  static void ArtifactChannelLost() noexcept;
  void Enqueue(const NativeProbeEvent& event) noexcept;
  void SpillRecord(const NativeProbeEvent& event) noexcept;
  // Null when the system has no pages to give.
  [[nodiscard]] static SpillChunkPointer MapSpillChunk() noexcept;
  [[nodiscard]] NativeProbeEvent MakeTransportGap(std::uint64_t dropped) const noexcept;
  void Run();
  [[nodiscard]] bool SendQueued();
  [[nodiscard]] bool SendRing(std::uint64_t fence);
  void PollWasmBudgetReset();
  void PollJsInvocationSites();
  void HandleDisconnect();

  // The fast path. Records are copied here without a lock or an allocation
  // while the writer keeps up with the browser's forwarding.
  NativeProbeQueue queue_;
  // A burst that outruns the broker waits here once queue_ is full, so a page
  // that floods the renderer rings keeps every record the browser could
  // forward. Chunks are allocated only while a burst outruns the writer and
  // freed once it has sent them. Records the bound refuses are counted in
  // spill_dropped_ and reported as a transport gap.
  base::Lock spill_lock_;
  Spill spill_ GUARDED_BY(spill_lock_);
  // Chunks alive in spill_ and in the batch the writer is sending; the memory
  // bound applies to both.
  std::size_t spill_chunks_ GUARDED_BY(spill_lock_) = 0;
  // 256 MiB, about 800,000 records. It bounds the browser's memory when a
  // page outruns the broker for longer than a burst.
  std::size_t spill_chunk_limit_ GUARDED_BY(spill_lock_) = (256u << 20) / kSpillChunkBytes;
  std::uint64_t spill_dropped_ GUARDED_BY(spill_lock_) = 0;
  // Set by every record that spills and cleared by the writer only after it
  // has sent everything spilled. While it is set, every record spills, so a
  // thread's later record never overtakes its spilled one through queue_.
  std::atomic<bool> spilling_{false};
  base::WaitableEvent wakeup_{base::WaitableEvent::ResetPolicy::AUTOMATIC,
                              base::WaitableEvent::InitialState::NOT_SIGNALED};
  base::Thread writer_thread_{"REB broker writer"};
  scoped_refptr<base::SequencedTaskRunner> browser_task_runner_;
  std::atomic<bool> connected_{false};
  // Written on the starting sequence before the writer starts. Only the
  // writer reads it until it posts HandleDisconnect() and returns, so the
  // descriptor is closed only after the writer has stopped using it.
  int socket_descriptor_ = -1;
  // Written before the writer starts. Only the writer reads and advances it.
  // Empty means this launch has no reset file.
  std::string wasm_budget_reset_file_;
  std::uint64_t applied_wasm_budget_reset_ = 0;
  // Written before the writer starts. Only the writer reads and advances
  // them. An empty generation file means the startup sites stay for the
  // session.
  std::string js_invocation_sites_file_;
  std::string js_invocation_generation_file_;
  std::uint64_t applied_js_invocation_generation_ = 0;
  std::uint64_t session_id_ = 0;
  // Category of the most recent record the spill refused. Every queued record
  // passed the session's category filter, so a gap that names it is admitted.
  std::atomic<NativeProbeCategory> last_dropped_category_{NativeProbeCategory::kUnknown};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SOCKET_CLIENT_H_
