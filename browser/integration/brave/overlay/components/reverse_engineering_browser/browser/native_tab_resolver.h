// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_RESOLVER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_RESOLVER_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_tab_link.h"

namespace reb {

struct NativeToken128 final {
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  [[nodiscard]] bool valid() const noexcept { return high != 0 || low != 0; }
  [[nodiscard]] std::uint64_t fold() const noexcept { return NativeContextFold(high, low); }
  bool operator==(const NativeToken128&) const = default;
};

struct NativeTabResolution final {
  // kNoPage: a service worker no page ever used (class 68).
  enum class Status { kUnresolved, kLinked, kExtension, kNoPage };
  Status status = Status::kUnresolved;
  NativeTabLinkKind kind = NativeTabLinkKind::kDedicatedWorker;
  NativeLoaderKind owner_kind = NativeLoaderKind::kNotRecorded;
  std::uint64_t owner_fold = 0;
  bool last_clients = false;
  std::uint64_t set_id = 0;
  // Ascending and distinct; valid until the next resolver call.
  std::span<const std::uint32_t> tabs;
  // True when this session has not received the set yet.
  bool emit_set = false;
  // kExtension: the owner's extension id, when its origin names a valid one.
  std::optional<NativeExtensionId> extension;
};

// The sets this session lacks, then the link (protocol/native-network-v3.md).
template <class NextSequence, class Emit>
void EmitNativeTabLink(const NativeTabResolution& resolution,
                       const NativeProbeHeader& linked,
                       const bool browser_record,
                       NativeProbeHeader identity,
                       NextSequence&& next_sequence,
                       Emit&& emit) {
  if (resolution.emit_set) {
    std::uint64_t previous = 0;
    for (std::size_t part = 0; part < NativeTabSetParts(resolution.tabs.size()); ++part) {
      identity.sequence_number = next_sequence();
      emit(MakeNativeTabSetPart(identity, resolution.owner_kind, resolution.owner_fold,
                                resolution.last_clients, resolution.set_id, resolution.tabs, part,
                                previous));
      previous = identity.sequence_number;
    }
  }
  identity.sequence_number = next_sequence();
  emit(MakeNativeRequestTabLink(linked, identity, resolution.kind, resolution.set_id,
                                resolution.tabs, browser_record));
}

// Browser UI sequence only. Frames and workers are recorded where Chromium
// names their owner and kept as bounded tombstones after they are destroyed,
// so records drained or started late still resolve. Nothing is inferred from
// hosts, URLs or timing.
class NativeTabResolver final {
 public:
  static constexpr std::size_t kFrameCapacity = 16384;
  static constexpr std::size_t kWorkerCapacity = 4096;
  static constexpr std::size_t kClientCapacity = 4096;
  // Class 68 answers kept for the second half of a renderer-issued request.
  static constexpr std::size_t kSharedDecisionCapacity = 4096;
  // A dedicated worker resolves only when it is one of the first
  // kCreatorDepth workers from its document: its chain holds at most this many.
  static constexpr std::uint32_t kCreatorDepth = 64;

  static NativeTabResolver& Get();

  NativeTabResolver() = default;
  NativeTabResolver(const NativeTabResolver&) = delete;
  NativeTabResolver& operator=(const NativeTabResolver&) = delete;

  void NoteFrame(int child_id, NativeToken128 frame, std::uint32_t tab_id);
  // 0 when the frame is unknown, or two frame tokens of the process share the fold.
  [[nodiscard]] std::uint32_t FrameTab(int child_id, std::uint64_t frame_fold) const;

  // `extension` is the host of a chrome-extension origin, else empty.
  void DedicatedWorkerCreated(NativeToken128 worker,
                              std::string_view extension,
                              std::uint32_t creator_tab,
                              NativeToken128 creator_worker);
  void SharedWorkerCreated(NativeToken128 worker, std::string_view extension);
  // client is the frame's process and routing id; its tab is kept for removal.
  void SharedWorkerClientAdded(NativeToken128 worker, std::uint64_t client, std::uint32_t tab);
  void SharedWorkerClientRemoved(NativeToken128 worker, std::uint64_t client);
  void ServiceWorkerStarted(std::int64_t version,
                            NativeToken128 token,
                            std::string_view extension,
                            std::string_view scope);
  void ServiceWorkerScope(std::int64_t version, std::string_view scope);
  void ServiceWorkerControlleeAdded(std::int64_t version,
                                    std::string_view client,
                                    std::span<const std::uint32_t> tabs);
  void ServiceWorkerControlleeRemoved(std::int64_t version, std::string_view client);
  // A service-worker job starts `version`: `caller` when it named a frame,
  // whose tab is `caller_tab` (0 once the frame was gone), and the active
  // version it updates, else -1. Its registrant is the caller's tab, else the
  // active version's tabs now.
  void ServiceWorkerJobStarted(std::int64_t version,
                               bool caller,
                               std::uint32_t caller_tab,
                               std::int64_t active);
  // Nothing in this browser named a page for the version or its registration:
  // no caller, client, last client or registrant. True for -1 and for a
  // version never seen.
  [[nodiscard]] bool ServiceWorkerHasNoPage(std::int64_t version) const;
  // Current client tabs of a dedicated or shared worker, for a worker client.
  [[nodiscard]] std::vector<std::uint32_t> WorkerTabs(NativeToken128 worker) const;

  // A renderer-issued request: its renderer's child process id and request id.
  struct RendererRequest final {
    int child_id = 0;
    std::uint32_t request_id = 0;
  };
  // Class 68 for one renderer-issued service-worker request, taken once for
  // both halves: the proxy asks for its browser half and the drain for its
  // renderer record. The first to ask decides from the version's state, -1
  // being a version it does not know, which keeps the request; the second
  // takes that answer, so both halves are kept or both counted.
  [[nodiscard]] bool SharedServiceWorkerNoPage(RendererRequest request, std::int64_t version);
  // Answers evicted before their second half asked that it could have
  // answered otherwise: a no-page answer, or a keep for an unknown version.
  // Counted since the last call.
  [[nodiscard]] std::uint64_t TakeEvictedSharedDecisions();
  // Session start: no answer or eviction count of an earlier session carries
  // over, since every request of a session asks within it.
  void ResetSharedDecisions();

  // A linked set the session has not received is marked sent here; the
  // caller emits it before the link. A renderer record of a service worker
  // names `request`, so its class 68 answer is the one its browser half takes.
  [[nodiscard]] NativeTabResolution Resolve(NativeLoaderKind owner_kind,
                                            std::uint64_t owner_fold,
                                            std::uint64_t session_id,
                                            const RendererRequest* request = nullptr);
  // The client tabs of one service-worker version, for a script it fetches.
  [[nodiscard]] NativeTabResolution ResolveVersion(std::int64_t version, std::uint64_t session_id);

 private:
  struct TabSet final {
    std::uint64_t id = 0;
    std::uint64_t emitted_session = 0;
    std::vector<std::uint32_t> tabs;
  };
  struct Worker final {
    NativeLoaderKind kind = NativeLoaderKind::kNotRecorded;
    NativeToken128 token;
    bool extension = false;
    std::optional<NativeExtensionId> extension_id;
    bool ambiguous = false;
    // Dedicated: the creator document's tab. Shared: client frame -> tab.
    std::uint32_t tab = 0;
    // Dedicated: the parent worker, kept while the tab is not known yet.
    NativeToken128 creator;
    // Dedicated: creators between this worker and the document whose tab it
    // holds, so an inherited or cached tab keeps the depth rule.
    std::uint32_t hops = 0;
    std::map<std::uint64_t, std::uint32_t> clients;
    std::int64_t version = 0;
    TabSet current;
    TabSet last;
  };
  struct Version final {
    std::string scope;
    std::map<std::string, std::vector<std::uint32_t>, std::less<>> controllees;
    TabSet current;
    TabSet last;
    // The tabs of the job that installed the version.
    TabSet registrant;
    // Sticky: a client, a caller or a registrant tab once named a page.
    bool had_page = false;
  };

  Worker* FindWorker(std::uint64_t fold);
  const Worker* DedicatedParent(NativeToken128 token) const;
  struct DedicatedOwner final {
    // Where the walk stopped: a worker with a tab or an extension, or the last reached.
    const Worker* root = nullptr;
    // Nonzero only when the worker is fewer than kCreatorDepth creators from it.
    std::uint32_t tab = 0;
    std::uint32_t hops = 0;
  };
  // Walks the creator chain from `worker`, at most kCreatorDepth workers.
  DedicatedOwner DedicatedOwnerOf(const Worker& worker) const;
  // Current, last, registrant, then the registration's last tabs.
  std::vector<std::uint32_t> VersionPageTabs(const Version& version) const;
  Worker& AddWorker(NativeLoaderKind kind, NativeToken128 token, std::string_view extension);
  Version& VersionOf(std::int64_t version);
  static void Rebuild(TabSet& set, std::vector<std::uint32_t> tabs);
  static std::vector<std::uint32_t> SharedTabs(const Worker& worker);
  static std::vector<std::uint32_t> ControlleeTabs(const Version& version);
  NativeTabResolution Linked(NativeTabLinkKind kind,
                             NativeLoaderKind owner_kind,
                             std::uint64_t owner_fold,
                             bool last_clients,
                             TabSet& set,
                             std::uint64_t session_id);
  NativeTabResolution VersionTabs(Version& version, std::uint64_t fold, std::uint64_t session_id);

  struct FrameEntry final {
    int child_id = 0;
    NativeToken128 token;
    std::uint32_t tab = 0;
    bool ambiguous = false;
  };
  std::unordered_map<std::uint64_t, FrameEntry> frames_;
  std::deque<std::uint64_t> frame_order_;
  std::unordered_map<std::uint64_t, Worker> workers_;
  std::deque<std::uint64_t> worker_order_;
  std::unordered_map<std::int64_t, Version> versions_;
  std::deque<std::int64_t> version_order_;
  // A registration keeps its last client tabs after its versions change.
  std::map<std::string, TabSet, std::less<>> last_by_scope_;
  std::uint64_t next_set_id_ = 1;
  struct SharedDecision final {
    bool no_page = false;
    // The other half could answer otherwise if it decided alone.
    bool changeable = false;
    std::uint64_t serial = 0;
  };
  std::unordered_map<std::uint64_t, SharedDecision> shared_decisions_;
  std::deque<std::pair<std::uint64_t, std::uint64_t>> shared_order_;
  std::uint64_t shared_serial_ = 0;
  std::uint64_t shared_evicted_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_RESOLVER_H_
