// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_WORKER_AUTHORITY_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_WORKER_AUTHORITY_H_

#include "../common/native_worker_transfer.h"

namespace reb {

inline constexpr std::size_t kNativeWorkerAuthorityCapacity = 64;
static_assert(kNativeWorkerAuthorityCapacity <= 64);  // Resolve uses a fixed visited bitset.
struct NativeWorkerAuthorityScope final {
  std::uint64_t observer_epoch = 0;
  std::uint64_t session_id = 0;
  std::uint64_t document_generation = 0;
  std::uint64_t expires_at_ns = 0;
  NativeWorkerToken browser_context;
  NativeWorkerToken storage_partition;
  NativeWorkerToken selected_frame;
  NativeWorkerToken selected_document;
};
// Browser-service observation, never a renderer-supplied ownership assertion.
// For a document creator, resolve RFH->frame token AND current document token at
// the creation callback. A LocalFrameToken alone survives document replacement.
struct NativeWorkerOwner final {
  NativeWorkerToken worker;
  NativeWorkerToken renderer_instance;
  NativeWorkerToken creator;
  NativeWorkerCreatorKind creator_kind = NativeWorkerCreatorKind::kDocument;
  NativeWorkerToken creator_document;
  std::uint64_t document_generation = 0;
  bool operator==(const NativeWorkerOwner&) const = default;
};
enum class NativeWorkerAuthorityStatus {
  kAllowed,
  kRecorded,
  kDuplicate,
  kDisabled,
  kStaleEpoch,
  kInvalid,
  kExpired,
  kFull,
  kUnknownWorker,
  kUnresolvedParent,
  kRetired,
  kAmbiguous,
  kCycle,
  kWrongDocument,
  kSequenceExhausted,
};
struct NativeWorkerAuthorityStats final {
  std::uint64_t created = 0;
  std::uint64_t destroyed = 0;
  std::uint64_t rejected = 0;
  std::uint64_t capacity_drops = 0;
  std::uint64_t ambiguous = 0;
  std::size_t retained_workers = 0;
  std::size_t retired_renderers = 0;
};

// Browser UI/control sequence only. One selected document, one current lease.
// Fixed tombstones are never evicted/reused during an observer epoch. Missing
// parents and cycles stay unproven; enumeration order does not create ancestry.
// Not registered with DedicatedWorkerService yet; there is no activation route.
class NativeWorkerAuthority final {
 public:
  NativeWorkerAuthority() = default;
  NativeWorkerAuthority(const NativeWorkerAuthority&) = delete;
  NativeWorkerAuthority& operator=(const NativeWorkerAuthority&) = delete;
  NativeWorkerAuthority(NativeWorkerAuthority&&) = delete;
  NativeWorkerAuthority& operator=(NativeWorkerAuthority&&) = delete;
  [[nodiscard]] bool Reset(const NativeWorkerAuthorityScope& scope, std::uint64_t now_ns) noexcept;
  [[nodiscard]] NativeWorkerAuthorityStatus Created(std::uint64_t observer_epoch,
                                                    const NativeWorkerOwner& owner,
                                                    std::uint64_t now_ns) noexcept;
  [[nodiscard]] NativeWorkerAuthorityStatus Destroyed(std::uint64_t observer_epoch,
                                                      NativeWorkerToken worker) noexcept;
  [[nodiscard]] NativeWorkerAuthorityStatus RendererDestroyed(std::uint64_t observer_epoch,
                                                              NativeWorkerToken renderer) noexcept;
  // Exact expected document/epoch prevents an old teardown revoking a new scope.
  [[nodiscard]] bool DocumentDestroyed(std::uint64_t observer_epoch,
                                       NativeWorkerToken document,
                                       std::uint64_t document_generation) noexcept;
  [[nodiscard]] bool Revoke(std::uint64_t observer_epoch) noexcept;
  [[nodiscard]] NativeWorkerAuthorityStatus Resolve(NativeWorkerToken worker,
                                                    std::uint64_t now_ns) const noexcept;
  [[nodiscard]] NativeWorkerAuthorityStatus Issue(NativeWorkerToken worker,
                                                  NativeWorkerToken connection,
                                                  std::uint64_t now_ns,
                                                  NativeWorkerLease& lease) noexcept;
  [[nodiscard]] bool IsCurrent(const NativeWorkerLease& lease, std::uint64_t now_ns) const noexcept;
  [[nodiscard]] const NativeWorkerAuthorityStats& stats() const noexcept { return stats_; }

 private:
  struct Entry final {
    NativeWorkerOwner owner;
    bool retired = false;
    bool ambiguous = false;
  };
  std::size_t Find(NativeWorkerToken worker) const noexcept;
  NativeWorkerAuthorityScope scope_;
  NativeWorkerLease current_;
  NativeWorkerAuthorityStats stats_;
  std::array<Entry, kNativeWorkerAuthorityCapacity> entries_{};
  std::array<NativeWorkerToken, kNativeWorkerAuthorityCapacity> retired_renderers_{};
  std::uint64_t greatest_epoch_ = 0;
  std::uint64_t generation_ = 0;
  bool active_ = false;
};

}  // namespace reb
#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_WORKER_AUTHORITY_H_
