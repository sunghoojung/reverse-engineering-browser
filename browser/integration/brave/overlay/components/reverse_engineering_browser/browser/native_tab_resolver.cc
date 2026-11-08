// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_tab_resolver.h"

#include <algorithm>
#include <utility>

namespace reb {

namespace {

std::uint64_t FrameKey(const int child_id, const std::uint64_t fold) noexcept {
  return fold ^
         (static_cast<std::uint64_t>(static_cast<std::uint32_t>(child_id)) * 0x9e3779b97f4a7c15ULL);
}

template <typename Key, typename Value>
void Bound(std::unordered_map<Key, Value>& map,
           std::deque<Key>& order,
           const std::size_t capacity) {
  while (map.size() > capacity && !order.empty()) {
    map.erase(order.front());
    order.pop_front();
  }
}

}  // namespace

NativeTabResolver& NativeTabResolver::Get() {
  static NativeTabResolver* const resolver = new NativeTabResolver();
  return *resolver;
}

void NativeTabResolver::NoteFrame(const int child_id,
                                  const NativeToken128 frame,
                                  const std::uint32_t tab_id) {
  if (child_id < 0 || !frame.valid() || tab_id == 0) {
    return;
  }
  const std::uint64_t key = FrameKey(child_id, frame.fold());
  const auto [entry, inserted] = frames_.try_emplace(key);
  if (inserted) {
    entry->second = {child_id, frame, tab_id, false};
    frame_order_.push_back(key);
    Bound(frames_, frame_order_, kFrameCapacity);
    return;
  }
  if (entry->second.child_id != child_id || entry->second.token != frame) {
    entry->second.ambiguous = true;
    return;
  }
  entry->second.tab = tab_id;
}

std::uint32_t NativeTabResolver::FrameTab(const int child_id,
                                          const std::uint64_t frame_fold) const {
  const auto entry = frames_.find(FrameKey(child_id, frame_fold));
  if (entry == frames_.end() || entry->second.ambiguous || entry->second.child_id != child_id ||
      entry->second.token.fold() != frame_fold) {
    return 0;
  }
  return entry->second.tab;
}

NativeTabResolver::Worker* NativeTabResolver::FindWorker(const std::uint64_t fold) {
  const auto entry = workers_.find(fold);
  return entry == workers_.end() ? nullptr : &entry->second;
}

NativeTabResolver::Worker& NativeTabResolver::AddWorker(const NativeLoaderKind kind,
                                                        const NativeToken128 token,
                                                        const bool extension) {
  const auto [entry, inserted] = workers_.try_emplace(token.fold());
  Worker& worker = entry->second;
  if (inserted) {
    worker.kind = kind;
    worker.token = token;
    worker_order_.push_back(token.fold());
  } else if (worker.token != token || worker.kind != kind) {
    worker.ambiguous = true;
  }
  worker.extension = worker.extension || extension;
  // Erasing older entries leaves this reference valid.
  Bound(workers_, worker_order_, kWorkerCapacity);
  return worker;
}

NativeTabResolver::Version& NativeTabResolver::VersionOf(const std::int64_t version) {
  const auto [entry, inserted] = versions_.try_emplace(version);
  if (inserted) {
    version_order_.push_back(version);
    Bound(versions_, version_order_, kWorkerCapacity);
  }
  return entry->second;
}

void NativeTabResolver::Rebuild(TabSet& set, std::vector<std::uint32_t> tabs) {
  std::ranges::sort(tabs);
  tabs.erase(std::unique(tabs.begin(), tabs.end()), tabs.end());
  std::erase(tabs, 0U);
  if (tabs == set.tabs && set.id != 0) {
    return;
  }
  set.tabs = std::move(tabs);
  set.id = 0;
  set.emitted_session = 0;
}

std::vector<std::uint32_t> NativeTabResolver::SharedTabs(const Worker& worker) {
  std::vector<std::uint32_t> tabs;
  tabs.reserve(worker.clients.size());
  for (const auto& [client, tab] : worker.clients) {
    tabs.push_back(tab);
  }
  return tabs;
}

std::vector<std::uint32_t> NativeTabResolver::ControlleeTabs(const Version& version) {
  std::vector<std::uint32_t> tabs;
  for (const auto& [client, client_tabs] : version.controllees) {
    tabs.insert(tabs.end(), client_tabs.begin(), client_tabs.end());
  }
  return tabs;
}

void NativeTabResolver::DedicatedWorkerCreated(const NativeToken128 worker,
                                               const bool extension,
                                               const std::uint32_t creator_tab,
                                               const NativeToken128 creator_worker) {
  if (!worker.valid()) {
    return;
  }
  // A nested worker takes its parent's tab now; the parent may be gone later.
  std::uint32_t tab = creator_tab;
  bool inherited_extension = false;
  if (tab == 0 && creator_worker.valid()) {
    if (const Worker* parent = FindWorker(creator_worker.fold());
        parent && !parent->ambiguous && parent->token == creator_worker &&
        parent->kind == NativeLoaderKind::kDedicatedWorker) {
      tab = parent->tab;
      inherited_extension = parent->extension;
    }
  }
  Worker& entry =
      AddWorker(NativeLoaderKind::kDedicatedWorker, worker, extension || inherited_extension);
  if (entry.tab == 0) {
    entry.tab = tab;
  }
}

void NativeTabResolver::SharedWorkerCreated(const NativeToken128 worker, const bool extension) {
  if (worker.valid()) {
    static_cast<void>(AddWorker(NativeLoaderKind::kSharedWorker, worker, extension));
  }
}

void NativeTabResolver::SharedWorkerClientAdded(const NativeToken128 worker,
                                                const std::uint64_t client,
                                                const std::uint32_t tab) {
  Worker* entry = FindWorker(worker.fold());
  if (!entry || entry->token != worker || entry->kind != NativeLoaderKind::kSharedWorker ||
      tab == 0 || (entry->clients.size() >= kClientCapacity && !entry->clients.contains(client))) {
    return;
  }
  entry->clients.insert_or_assign(client, tab);
  Rebuild(entry->current, SharedTabs(*entry));
}

void NativeTabResolver::SharedWorkerClientRemoved(const NativeToken128 worker,
                                                  const std::uint64_t client) {
  Worker* entry = FindWorker(worker.fold());
  if (!entry || entry->token != worker || entry->kind != NativeLoaderKind::kSharedWorker ||
      entry->clients.erase(client) == 0) {
    return;
  }
  if (entry->clients.empty()) {
    entry->last = {};
    Rebuild(entry->last, entry->current.tabs);
  }
  Rebuild(entry->current, SharedTabs(*entry));
}

void NativeTabResolver::ServiceWorkerStarted(const std::int64_t version,
                                             const NativeToken128 token,
                                             const bool extension,
                                             const std::string_view scope) {
  if (!token.valid()) {
    return;
  }
  Worker& entry = AddWorker(NativeLoaderKind::kServiceWorker, token, extension);
  entry.version = version;
  ServiceWorkerScope(version, scope);
}

void NativeTabResolver::ServiceWorkerScope(const std::int64_t version,
                                           const std::string_view scope) {
  Version& entry = VersionOf(version);
  if (entry.scope.empty() && !scope.empty()) {
    entry.scope = std::string(scope);
  }
}

void NativeTabResolver::ServiceWorkerControlleeAdded(const std::int64_t version,
                                                     const std::string_view client,
                                                     const std::span<const std::uint32_t> tabs) {
  Version& entry = VersionOf(version);
  if (tabs.empty() ||
      (entry.controllees.size() >= kClientCapacity && !entry.controllees.contains(client))) {
    return;
  }
  entry.controllees.insert_or_assign(std::string(client),
                                     std::vector<std::uint32_t>(tabs.begin(), tabs.end()));
  Rebuild(entry.current, ControlleeTabs(entry));
}

void NativeTabResolver::ServiceWorkerControlleeRemoved(const std::int64_t version,
                                                       const std::string_view client) {
  const auto found = versions_.find(version);
  if (found == versions_.end()) {
    return;
  }
  Version& entry = found->second;
  const auto controllee = entry.controllees.find(client);
  if (controllee == entry.controllees.end()) {
    return;
  }
  entry.controllees.erase(controllee);
  if (entry.controllees.empty() && !entry.current.tabs.empty()) {
    entry.last = {};
    Rebuild(entry.last, entry.current.tabs);
    if (!entry.scope.empty() &&
        (last_by_scope_.size() < kWorkerCapacity || last_by_scope_.contains(entry.scope))) {
      TabSet& scoped = last_by_scope_[entry.scope];
      scoped = {};
      Rebuild(scoped, entry.current.tabs);
    }
  }
  Rebuild(entry.current, ControlleeTabs(entry));
}

std::vector<std::uint32_t> NativeTabResolver::WorkerTabs(const NativeToken128 worker) const {
  const auto entry = workers_.find(worker.fold());
  if (entry == workers_.end() || entry->second.ambiguous || entry->second.token != worker) {
    return {};
  }
  if (entry->second.kind == NativeLoaderKind::kDedicatedWorker) {
    return entry->second.tab ? std::vector<std::uint32_t>{entry->second.tab}
                             : std::vector<std::uint32_t>{};
  }
  return entry->second.kind == NativeLoaderKind::kSharedWorker ? SharedTabs(entry->second)
                                                               : std::vector<std::uint32_t>{};
}

NativeTabResolution NativeTabResolver::Linked(const NativeTabLinkKind kind,
                                              const NativeLoaderKind owner_kind,
                                              const bool last_clients,
                                              TabSet& set,
                                              const std::uint64_t session_id) {
  NativeTabResolution resolution;
  if (set.tabs.empty()) {
    return resolution;
  }
  if (set.id == 0) {
    set.id = next_set_id_++;
  }
  resolution.status = NativeTabResolution::Status::kLinked;
  resolution.kind = kind;
  resolution.owner_kind = owner_kind;
  resolution.last_clients = last_clients;
  resolution.set_id = set.id;
  resolution.tabs = set.tabs;
  resolution.emit_set = set.emitted_session != session_id;
  set.emitted_session = session_id;
  return resolution;
}

NativeTabResolution NativeTabResolver::Resolve(const NativeLoaderKind owner_kind,
                                               const std::uint64_t owner_fold,
                                               const std::uint64_t session_id) {
  Worker* worker = IsNativeWorkerOwner(owner_kind) ? FindWorker(owner_fold) : nullptr;
  if (!worker || worker->ambiguous || worker->kind != owner_kind) {
    return {};
  }
  if (worker->extension) {
    NativeTabResolution excluded;
    excluded.status = NativeTabResolution::Status::kExtension;
    return excluded;
  }
  switch (owner_kind) {
    case NativeLoaderKind::kDedicatedWorker:
      Rebuild(worker->current, {worker->tab});
      return Linked(NativeTabLinkKind::kDedicatedWorker, owner_kind, false, worker->current,
                    session_id);
    case NativeLoaderKind::kSharedWorker:
      return worker->current.tabs.empty() ? Linked(NativeTabLinkKind::kSharedWorkerClients,
                                                   owner_kind, true, worker->last, session_id)
                                          : Linked(NativeTabLinkKind::kSharedWorkerClients,
                                                   owner_kind, false, worker->current, session_id);
    case NativeLoaderKind::kServiceWorker: {
      const auto found = versions_.find(worker->version);
      if (found == versions_.end()) {
        return {};
      }
      Version& version = found->second;
      if (!version.current.tabs.empty()) {
        return Linked(NativeTabLinkKind::kServiceWorkerClients, owner_kind, false, version.current,
                      session_id);
      }
      if (!version.last.tabs.empty()) {
        return Linked(NativeTabLinkKind::kServiceWorkerLastClients, owner_kind, true, version.last,
                      session_id);
      }
      const auto scoped = last_by_scope_.find(version.scope);
      return scoped == last_by_scope_.end() ? NativeTabResolution{}
                                            : Linked(NativeTabLinkKind::kServiceWorkerLastClients,
                                                     owner_kind, true, scoped->second, session_id);
    }
    default:
      return {};
  }
}

}  // namespace reb
