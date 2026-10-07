// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "native_worker_authority.h"

#include <algorithm>
#include <limits>

namespace reb {
namespace {
void Increment(std::uint64_t& value) noexcept {
  if (value != std::numeric_limits<std::uint64_t>::max())
    ++value;
}
}  // namespace

bool NativeWorkerAuthority::Reset(const NativeWorkerAuthorityScope& scope,
                                  const std::uint64_t now_ns) noexcept {
  active_ = false;
  current_ = {};
  if (scope.observer_epoch <= greatest_epoch_ || scope.session_id == 0 ||
      scope.document_generation == 0 || !scope.browser_context.valid() ||
      !scope.storage_partition.valid() || !scope.selected_frame.valid() ||
      !scope.selected_document.valid() || now_ns >= scope.expires_at_ns ||
      scope.expires_at_ns - now_ns > kNativeWorkerMaxLeaseNs) {
    Increment(stats_.rejected);
    return false;
  }
  greatest_epoch_ = scope.observer_epoch;
  scope_ = scope;
  entries_.fill({});
  retired_renderers_.fill({});
  stats_.retained_workers = stats_.retired_renderers = 0;
  active_ = true;
  return true;
}
std::size_t NativeWorkerAuthority::Find(const NativeWorkerToken worker) const noexcept {
  std::size_t index = 0;
  while (index < stats_.retained_workers && entries_[index].owner.worker != worker)
    ++index;
  return index;
}
NativeWorkerAuthorityStatus NativeWorkerAuthority::Created(const std::uint64_t observer_epoch,
                                                           const NativeWorkerOwner& owner,
                                                           const std::uint64_t now_ns) noexcept {
  if (observer_epoch != scope_.observer_epoch)
    return NativeWorkerAuthorityStatus::kStaleEpoch;
  if (!active_)
    return NativeWorkerAuthorityStatus::kDisabled;
  if (now_ns >= scope_.expires_at_ns) {
    static_cast<void>(Revoke(observer_epoch));
    return NativeWorkerAuthorityStatus::kExpired;
  }
  if (!owner.worker.valid() || !owner.renderer_instance.valid() || !owner.creator.valid() ||
      owner.worker == owner.creator ||
      (owner.creator_kind != NativeWorkerCreatorKind::kDocument &&
       owner.creator_kind != NativeWorkerCreatorKind::kDedicatedWorker) ||
      (owner.creator_kind == NativeWorkerCreatorKind::kDocument
           ? !owner.creator_document.valid() || owner.document_generation == 0
           : owner.creator_document.valid() || owner.document_generation != 0)) {
    Increment(stats_.rejected);
    return NativeWorkerAuthorityStatus::kInvalid;
  }
  for (std::size_t index = 0; index < stats_.retired_renderers; ++index) {
    if (retired_renderers_[index] == owner.renderer_instance)
      return NativeWorkerAuthorityStatus::kRetired;
  }
  const auto index = Find(owner.worker);
  if (index < stats_.retained_workers) {
    auto& entry = entries_[index];
    if (entry.retired)
      return NativeWorkerAuthorityStatus::kRetired;
    if (entry.ambiguous)
      return NativeWorkerAuthorityStatus::kAmbiguous;
    if (entry.owner == owner)
      return NativeWorkerAuthorityStatus::kDuplicate;
    entry.ambiguous = true;
    Increment(stats_.ambiguous);
    return NativeWorkerAuthorityStatus::kAmbiguous;
  }
  if (stats_.retained_workers == entries_.size()) {
    Increment(stats_.capacity_drops);
    return NativeWorkerAuthorityStatus::kFull;
  }
  entries_[stats_.retained_workers++].owner = owner;
  Increment(stats_.created);
  return NativeWorkerAuthorityStatus::kRecorded;
}
NativeWorkerAuthorityStatus NativeWorkerAuthority::Destroyed(
    const std::uint64_t observer_epoch,
    const NativeWorkerToken worker) noexcept {
  if (observer_epoch != scope_.observer_epoch)
    return NativeWorkerAuthorityStatus::kStaleEpoch;
  if (!active_)
    return NativeWorkerAuthorityStatus::kDisabled;
  if (!worker.valid())
    return NativeWorkerAuthorityStatus::kInvalid;
  auto index = Find(worker);
  if (index == stats_.retained_workers) {
    if (index == entries_.size()) {
      Increment(stats_.capacity_drops);
      return NativeWorkerAuthorityStatus::kFull;
    }
    entries_[stats_.retained_workers++].owner.worker = worker;
  }
  if (entries_[index].retired)
    return NativeWorkerAuthorityStatus::kDuplicate;
  entries_[index].retired = true;
  Increment(stats_.destroyed);
  return NativeWorkerAuthorityStatus::kRecorded;
}
NativeWorkerAuthorityStatus NativeWorkerAuthority::RendererDestroyed(
    const std::uint64_t observer_epoch,
    const NativeWorkerToken renderer) noexcept {
  if (observer_epoch != scope_.observer_epoch)
    return NativeWorkerAuthorityStatus::kStaleEpoch;
  if (!active_)
    return NativeWorkerAuthorityStatus::kDisabled;
  if (!renderer.valid())
    return NativeWorkerAuthorityStatus::kInvalid;
  for (std::size_t index = 0; index < stats_.retired_renderers; ++index) {
    if (retired_renderers_[index] == renderer)
      return NativeWorkerAuthorityStatus::kDuplicate;
  }
  if (stats_.retired_renderers == retired_renderers_.size()) {
    Increment(stats_.capacity_drops);
    static_cast<void>(Revoke(observer_epoch));
    return NativeWorkerAuthorityStatus::kFull;
  }
  retired_renderers_[stats_.retired_renderers++] = renderer;
  for (std::size_t index = 0; index < stats_.retained_workers; ++index) {
    auto& entry = entries_[index];
    if (entry.owner.renderer_instance == renderer && !entry.retired) {
      entry.retired = true;
      Increment(stats_.destroyed);
    }
  }
  return NativeWorkerAuthorityStatus::kRecorded;
}
bool NativeWorkerAuthority::DocumentDestroyed(const std::uint64_t observer_epoch,
                                              const NativeWorkerToken document,
                                              const std::uint64_t document_generation) noexcept {
  return scope_.selected_document == document &&
         scope_.document_generation == document_generation && Revoke(observer_epoch);
}
bool NativeWorkerAuthority::Revoke(const std::uint64_t observer_epoch) noexcept {
  if (observer_epoch != scope_.observer_epoch || !active_)
    return false;
  active_ = false;
  current_ = {};
  return true;
}
NativeWorkerAuthorityStatus NativeWorkerAuthority::Resolve(
    const NativeWorkerToken worker,
    const std::uint64_t now_ns) const noexcept {
  if (!active_)
    return NativeWorkerAuthorityStatus::kDisabled;
  if (now_ns >= scope_.expires_at_ns)
    return NativeWorkerAuthorityStatus::kExpired;
  auto index = Find(worker);
  if (index == stats_.retained_workers)
    return NativeWorkerAuthorityStatus::kUnknownWorker;
  std::uint64_t visited = 0;
  for (std::size_t hop = 0; hop < entries_.size(); ++hop) {
    const auto bit = std::uint64_t{1} << index;
    if ((visited & bit) != 0)
      return NativeWorkerAuthorityStatus::kCycle;
    visited |= bit;
    const auto& entry = entries_[index];
    if (entry.retired)
      return NativeWorkerAuthorityStatus::kRetired;
    if (entry.ambiguous)
      return NativeWorkerAuthorityStatus::kAmbiguous;
    if (entry.owner.creator_kind == NativeWorkerCreatorKind::kDocument) {
      return entry.owner.creator == scope_.selected_frame &&
                     entry.owner.creator_document == scope_.selected_document &&
                     entry.owner.document_generation == scope_.document_generation
                 ? NativeWorkerAuthorityStatus::kAllowed
                 : NativeWorkerAuthorityStatus::kWrongDocument;
    }
    index = Find(entry.owner.creator);
    if (index == stats_.retained_workers)
      return NativeWorkerAuthorityStatus::kUnresolvedParent;
  }
  return NativeWorkerAuthorityStatus::kCycle;
}
NativeWorkerAuthorityStatus NativeWorkerAuthority::Issue(const NativeWorkerToken worker,
                                                         const NativeWorkerToken connection,
                                                         const std::uint64_t now_ns,
                                                         NativeWorkerLease& lease) noexcept {
  lease = {};
  const auto status = Resolve(worker, now_ns);
  if (status != NativeWorkerAuthorityStatus::kAllowed)
    return status;
  if (!connection.valid())
    return NativeWorkerAuthorityStatus::kInvalid;
  if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
    static_cast<void>(Revoke(scope_.observer_epoch));
    return NativeWorkerAuthorityStatus::kSequenceExhausted;
  }
  const auto& owner = entries_[Find(worker)].owner;
  lease = {{scope_.session_id, ++generation_, scope_.expires_at_ns, scope_.browser_context,
            owner.renderer_instance, owner.worker, owner.creator, owner.creator_kind},
           scope_.storage_partition,
           scope_.selected_frame,
           scope_.selected_document,
           connection,
           scope_.document_generation,
           scope_.observer_epoch,
           now_ns};
  current_ = lease;
  return NativeWorkerAuthorityStatus::kAllowed;
}
bool NativeWorkerAuthority::IsCurrent(const NativeWorkerLease& lease,
                                      const std::uint64_t now_ns) const noexcept {
  return active_ && lease == current_ && IsValidNativeWorkerLease(lease, now_ns) &&
         Resolve(lease.policy.worker, now_ns) == NativeWorkerAuthorityStatus::kAllowed;
}
}  // namespace reb
