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

const NativeTabResolver::Worker* NativeTabResolver::DedicatedParent(
    const NativeToken128 token) const {
  const auto entry = workers_.find(token.fold());
  return entry != workers_.end() && !entry->second.ambiguous && entry->second.token == token &&
                 entry->second.kind == NativeLoaderKind::kDedicatedWorker
             ? &entry->second
             : nullptr;
}

NativeTabResolver::DedicatedOwner NativeTabResolver::DedicatedOwnerOf(const Worker& worker) const {
  const Worker* current = &worker;
  for (std::uint32_t walked = 0;; ++walked) {
    if (current->extension) {
      return {current, 0, 0};
    }
    if (current->tab != 0) {
      const std::uint32_t hops = walked + current->hops;
      return {current, hops < kCreatorDepth ? current->tab : 0, hops};
    }
    const Worker* parent = walked + 1 < kCreatorDepth && current->creator.valid()
                               ? DedicatedParent(current->creator)
                               : nullptr;
    if (!parent) {
      return {current, 0, 0};
    }
    current = parent;
  }
}

NativeTabResolver::Worker& NativeTabResolver::AddWorker(const NativeLoaderKind kind,
                                                        const NativeToken128 token,
                                                        const std::string_view extension) {
  const auto [entry, inserted] = workers_.try_emplace(token.fold());
  Worker& worker = entry->second;
  if (inserted) {
    worker.kind = kind;
    worker.token = token;
    worker_order_.push_back(token.fold());
  } else if (worker.token != token || worker.kind != kind) {
    worker.ambiguous = true;
  }
  if (!extension.empty() && !worker.extension) {
    worker.extension = true;
    NativeExtensionId id;
    if (ParseNativeExtensionId(extension, id)) {
      worker.extension_id = id;
    }
  }
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
                                               const std::string_view extension,
                                               const std::uint32_t creator_tab,
                                               const NativeToken128 creator_worker) {
  if (!worker.valid()) {
    return;
  }
  // A nested worker takes its parent's tab now when the parent is known; the
  // parent may be gone later. Enumeration can report a child before its
  // parent, so the creator is kept and resolved when a request is linked.
  std::uint32_t tab = creator_tab;
  std::uint32_t hops = 0;
  bool inherited = false;
  std::optional<NativeExtensionId> inherited_id;
  if (tab == 0 && creator_worker.valid()) {
    if (const Worker* parent = DedicatedParent(creator_worker)) {
      const DedicatedOwner owner = DedicatedOwnerOf(*parent);
      if (owner.tab != 0 && owner.hops + 1 < kCreatorDepth) {
        tab = owner.tab;
        hops = owner.hops + 1;
      }
      inherited = extension.empty() && owner.root->extension;
      inherited_id = inherited ? owner.root->extension_id : std::nullopt;
    }
  }
  Worker& entry = AddWorker(NativeLoaderKind::kDedicatedWorker, worker, extension);
  if (inherited && !entry.extension) {
    entry.extension = true;
    entry.extension_id = inherited_id;
  }
  if (entry.tab == 0 && tab != 0) {
    entry.tab = tab;
    entry.hops = hops;
  }
  if (entry.tab == 0 && !entry.creator.valid()) {
    entry.creator = creator_worker;
  }
}

void NativeTabResolver::SharedWorkerCreated(const NativeToken128 worker,
                                            const std::string_view extension) {
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
                                             const std::string_view extension,
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
  // A client is a page even before its navigation commits and names a tab.
  entry.had_page = true;
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

void NativeTabResolver::ServiceWorkerJobStarted(const std::int64_t version,
                                                const bool caller,
                                                const std::uint32_t caller_tab,
                                                const std::int64_t active) {
  std::vector<std::uint32_t> tabs;
  bool active_page = false;
  std::string active_scope;
  if (caller_tab != 0) {
    tabs.push_back(caller_tab);
  } else if (const auto found = versions_.find(active); found != versions_.end()) {
    tabs = VersionPageTabs(found->second);
    active_page = found->second.had_page;
    active_scope = found->second.scope;
  }
  Version& entry = VersionOf(version);
  entry.had_page |= caller || active_page || !tabs.empty();
  if (entry.scope.empty()) {
    entry.scope = std::move(active_scope);
  }
  if (!tabs.empty()) {
    entry.registrant = {};
    Rebuild(entry.registrant, std::move(tabs));
  }
}

std::vector<std::uint32_t> NativeTabResolver::VersionPageTabs(const Version& version) const {
  for (const TabSet* set : {&version.current, &version.last, &version.registrant}) {
    if (!set->tabs.empty()) {
      return set->tabs;
    }
  }
  const auto scoped = last_by_scope_.find(version.scope);
  return scoped == last_by_scope_.end() ? std::vector<std::uint32_t>{} : scoped->second.tabs;
}

bool NativeTabResolver::ServiceWorkerHasNoPage(const std::int64_t version) const {
  const auto found = versions_.find(version);
  return found == versions_.end() ||
         (!found->second.had_page && !last_by_scope_.contains(found->second.scope));
}

std::vector<std::uint32_t> NativeTabResolver::WorkerTabs(const NativeToken128 worker) const {
  const auto entry = workers_.find(worker.fold());
  if (entry == workers_.end() || entry->second.ambiguous || entry->second.token != worker) {
    return {};
  }
  if (entry->second.kind == NativeLoaderKind::kDedicatedWorker) {
    const std::uint32_t tab = DedicatedOwnerOf(entry->second).tab;
    return tab ? std::vector<std::uint32_t>{tab} : std::vector<std::uint32_t>{};
  }
  return entry->second.kind == NativeLoaderKind::kSharedWorker ? SharedTabs(entry->second)
                                                               : std::vector<std::uint32_t>{};
}

NativeTabResolution NativeTabResolver::Linked(const NativeTabLinkKind kind,
                                              const NativeLoaderKind owner_kind,
                                              const std::uint64_t owner_fold,
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
  resolution.owner_fold = owner_fold;
  resolution.last_clients = last_clients;
  resolution.set_id = set.id;
  resolution.tabs = set.tabs;
  resolution.emit_set = set.emitted_session != session_id;
  set.emitted_session = session_id;
  return resolution;
}

bool NativeTabResolver::SharedServiceWorkerNoPage(const RendererRequest request,
                                                  const std::int64_t version) {
  const std::uint64_t key =
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(request.child_id)) << 32) |
      request.request_id;
  if (const auto found = shared_decisions_.find(key); found != shared_decisions_.end()) {
    const bool no_page = found->second.no_page;
    shared_decisions_.erase(found);
    return no_page;
  }
  const bool no_page = version >= 0 && ServiceWorkerHasNoPage(version);
  shared_decisions_[key] = {no_page, no_page || version < 0, ++shared_serial_};
  shared_order_.emplace_back(key, shared_serial_);
  while (shared_order_.size() > kSharedDecisionCapacity) {
    const auto [oldest, serial] = shared_order_.front();
    shared_order_.pop_front();
    const auto entry = shared_decisions_.find(oldest);
    if (entry != shared_decisions_.end() && entry->second.serial == serial) {
      shared_evicted_ += entry->second.changeable ? 1U : 0U;
      shared_decisions_.erase(entry);
    }
  }
  return no_page;
}

std::uint64_t NativeTabResolver::TakeEvictedSharedDecisions() {
  return std::exchange(shared_evicted_, std::uint64_t{0});
}

NativeTabResolution NativeTabResolver::Resolve(const NativeLoaderKind owner_kind,
                                               const std::uint64_t owner_fold,
                                               const std::uint64_t session_id,
                                               const RendererRequest* const request) {
  Worker* worker = IsNativeWorkerOwner(owner_kind) ? FindWorker(owner_fold) : nullptr;
  if (!worker || worker->ambiguous || worker->kind != owner_kind) {
    // A worker the browser does not know: its browser half follows the drain's keep.
    NativeTabResolution unknown;
    if (request && owner_kind == NativeLoaderKind::kServiceWorker &&
        SharedServiceWorkerNoPage(*request, -1)) {
      unknown.status = NativeTabResolution::Status::kNoPage;
    }
    return unknown;
  }
  // A nested worker of an extension worker is extension traffic too.
  const DedicatedOwner dedicated = owner_kind == NativeLoaderKind::kDedicatedWorker
                                       ? DedicatedOwnerOf(*worker)
                                       : DedicatedOwner{worker, 0, 0};
  const Worker& owner = *dedicated.root;
  if (owner.extension) {
    NativeTabResolution excluded;
    excluded.status = NativeTabResolution::Status::kExtension;
    excluded.extension = owner.extension_id;
    return excluded;
  }
  switch (owner_kind) {
    case NativeLoaderKind::kDedicatedWorker:
      // The cached tab keeps its hops, so a deeper child is judged the same way.
      if (worker->tab == 0 && dedicated.tab != 0) {
        worker->tab = dedicated.tab;
        worker->hops = dedicated.hops;
      }
      Rebuild(worker->current, {dedicated.tab});
      return Linked(NativeTabLinkKind::kDedicatedWorker, owner_kind, owner_fold, false,
                    worker->current, session_id);
    case NativeLoaderKind::kSharedWorker:
      return worker->current.tabs.empty()
                 ? Linked(NativeTabLinkKind::kSharedWorkerClients, owner_kind, owner_fold, true,
                          worker->last, session_id)
                 : Linked(NativeTabLinkKind::kSharedWorkerClients, owner_kind, owner_fold, false,
                          worker->current, session_id);
    case NativeLoaderKind::kServiceWorker: {
      // Before linking: the browser half may already have been left out.
      if (request ? SharedServiceWorkerNoPage(*request, worker->version)
                  : ServiceWorkerHasNoPage(worker->version)) {
        NativeTabResolution no_page;
        no_page.status = NativeTabResolution::Status::kNoPage;
        return no_page;
      }
      const auto found = versions_.find(worker->version);
      return found == versions_.end() ? NativeTabResolution{}
                                      : VersionTabs(found->second, owner_fold, session_id);
    }
    default:
      return {};
  }
}

NativeTabResolution NativeTabResolver::VersionTabs(Version& version,
                                                   const std::uint64_t fold,
                                                   const std::uint64_t session_id) {
  constexpr NativeLoaderKind kOwner = NativeLoaderKind::kServiceWorker;
  if (!version.current.tabs.empty()) {
    return Linked(NativeTabLinkKind::kServiceWorkerClients, kOwner, fold, false, version.current,
                  session_id);
  }
  if (!version.last.tabs.empty()) {
    return Linked(NativeTabLinkKind::kServiceWorkerLastClients, kOwner, fold, true, version.last,
                  session_id);
  }
  if (!version.registrant.tabs.empty()) {
    return Linked(NativeTabLinkKind::kServiceWorkerRegistrant, kOwner, fold, false,
                  version.registrant, session_id);
  }
  const auto scoped = last_by_scope_.find(version.scope);
  return scoped == last_by_scope_.end() ? NativeTabResolution{}
                                        : Linked(NativeTabLinkKind::kServiceWorkerLastClients,
                                                 kOwner, fold, true, scoped->second, session_id);
}

NativeTabResolution NativeTabResolver::ResolveVersion(const std::int64_t version,
                                                      const std::uint64_t session_id) {
  const auto found = versions_.find(version);
  if (found == versions_.end()) {
    return {};
  }
  // The version's worker fold when it has run; 0 names no worker.
  std::uint64_t fold = 0;
  for (const auto& [key, worker] : workers_) {
    if (worker.kind == NativeLoaderKind::kServiceWorker && worker.version == version &&
        !worker.ambiguous) {
      fold = key;
      break;
    }
  }
  return VersionTabs(found->second, fold, session_id);
}

}  // namespace reb
