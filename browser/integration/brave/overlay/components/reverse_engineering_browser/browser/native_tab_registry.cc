// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_tab_registry.h"

#include <array>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "base/unguessable_token.h"
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_tab_of.h"
#include "brave/components/reverse_engineering_browser/browser/native_tab_resolver.h"
#include "brave/components/reverse_engineering_browser/common/native_factory_owner_hook.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/dedicated_worker_service.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/service_worker_context.h"
#include "content/public/browser/service_worker_context_observer.h"
#include "content/public/browser/service_worker_running_info.h"
#include "content/public/browser/shared_worker_service.h"
#include "content/public/browser/storage_partition.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace reb {

namespace {

constexpr char kExtensionScheme[] = "chrome-extension";

std::string_view ExtensionOf(const url::Origin& origin) {
  return origin.scheme() == kExtensionScheme ? std::string_view(origin.host()) : std::string_view();
}

NativeToken128 TokenOf(const base::UnguessableToken& token) {
  return {token.GetHighForSerialization(), token.GetLowForSerialization()};
}

// A job's caller is read when the job starts the version, while its frame is
// most likely alive; the version keeps the tab after the frame is gone.
void NoteServiceWorkerVersion(content::BrowserContext* context,
                              const std::int64_t version_id,
                              const NativeFactoryOwner& cause) {
  if (!NativeNetworkCaptureSink::Get().IsOwnedContext(context)) {
    return;
  }
  const bool caller = cause.frame_process_id >= 0;
  const std::uint32_t tab =
      caller ? NativeTabRegistry::Get().NoteFrame(
                   content::RenderFrameHost::FromID(cause.frame_process_id, cause.frame_routing_id))
             : 0;
  NativeTabResolver::Get().ServiceWorkerJobStarted(version_id, caller, tab,
                                                   cause.service_worker_version_id);
}

std::uint64_t ClientKey(const content::GlobalRenderFrameHostId& id) {
  return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(id.child_id.GetUnsafeValue()))
          << 32) |
         static_cast<std::uint32_t>(id.frame_routing_id);
}

}  // namespace

class NativeTabRegistry::DedicatedWorkers final : public content::DedicatedWorkerService::Observer {
 public:
  void OnWorkerCreated(const blink::DedicatedWorkerToken& worker_token,
                       content::ChildProcessId,
                       const url::Origin& security_origin,
                       content::DedicatedWorkerCreator creator) override {
    std::uint32_t creator_tab = 0;
    NativeToken128 creator_worker;
    if (const auto* frame = std::get_if<content::GlobalRenderFrameHostId>(&creator)) {
      creator_tab = NativeTabOf(content::RenderFrameHost::FromID(*frame));
    } else if (const auto* parent = std::get_if<blink::DedicatedWorkerToken>(&creator)) {
      creator_worker = TokenOf(parent->value());
    }
    NativeTabResolver::Get().DedicatedWorkerCreated(
        TokenOf(worker_token.value()), ExtensionOf(security_origin), creator_tab, creator_worker);
  }
  void OnBeforeWorkerDestroyed(const blink::DedicatedWorkerToken&,
                               content::DedicatedWorkerCreator) override {}
  void OnFinalResponseURLDetermined(const blink::DedicatedWorkerToken&, const GURL&) override {}
};

class NativeTabRegistry::SharedWorkers final : public content::SharedWorkerService::Observer {
 public:
  void OnWorkerCreated(const blink::SharedWorkerToken& token,
                       content::ChildProcessId,
                       const url::Origin& security_origin,
                       const base::UnguessableToken&) override {
    NativeTabResolver::Get().SharedWorkerCreated(TokenOf(token.value()),
                                                 ExtensionOf(security_origin));
  }
  void OnBeforeWorkerDestroyed(const blink::SharedWorkerToken&) override {}
  void OnClientAdded(const blink::SharedWorkerToken& token,
                     content::GlobalRenderFrameHostId render_frame_host_id) override {
    NativeTabResolver::Get().SharedWorkerClientAdded(
        TokenOf(token.value()), ClientKey(render_frame_host_id),
        NativeTabOf(content::RenderFrameHost::FromID(render_frame_host_id)));
  }
  void OnClientRemoved(const blink::SharedWorkerToken& token,
                       content::GlobalRenderFrameHostId render_frame_host_id) override {
    NativeTabResolver::Get().SharedWorkerClientRemoved(TokenOf(token.value()),
                                                       ClientKey(render_frame_host_id));
  }
};

class NativeTabRegistry::ServiceWorkers final : public content::ServiceWorkerContextObserver {
 public:
  void Started(const int64_t version_id, const content::ServiceWorkerRunningInfo& info) {
    NativeTabResolver::Get().ServiceWorkerStarted(
        version_id, TokenOf(info.token.value()),
        info.scope.SchemeIs(kExtensionScheme) ? info.scope.host() : std::string_view(),
        info.scope.spec());
  }
  void OnVersionStartedRunning(int64_t version_id,
                               const content::ServiceWorkerRunningInfo& running_info) override {
    Started(version_id, running_info);
  }
  void OnVersionActivated(int64_t version_id, const GURL& scope) override {
    NativeTabResolver::Get().ServiceWorkerScope(version_id, scope.spec());
  }
  void OnControlleeAdded(int64_t version_id,
                         const std::string& client_uuid,
                         const content::ServiceWorkerClientInfo& client_info) override {
    std::vector<std::uint32_t> tabs;
    if (const auto* frame = std::get_if<content::GlobalRenderFrameHostId>(&client_info)) {
      if (const std::uint32_t tab = NativeTabOf(content::RenderFrameHost::FromID(*frame))) {
        tabs.push_back(tab);
      }
    } else if (const auto* dedicated = std::get_if<blink::DedicatedWorkerToken>(&client_info)) {
      tabs = NativeTabResolver::Get().WorkerTabs(TokenOf(dedicated->value()));
    } else if (const auto* shared = std::get_if<blink::SharedWorkerToken>(&client_info)) {
      tabs = NativeTabResolver::Get().WorkerTabs(TokenOf(shared->value()));
    }
    NativeTabResolver::Get().ServiceWorkerControlleeAdded(version_id, client_uuid, tabs);
  }
  // A window client gets its frame id only at commit, after OnControlleeAdded.
  void OnControlleeNavigationCommitted(int64_t version_id,
                                       const std::string& client_uuid,
                                       content::GlobalRenderFrameHostId frame_id) override {
    if (const std::uint32_t tab = NativeTabOf(content::RenderFrameHost::FromID(frame_id))) {
      const std::array<std::uint32_t, 1> tabs = {tab};
      NativeTabResolver::Get().ServiceWorkerControlleeAdded(version_id, client_uuid, tabs);
    }
  }
  void OnControlleeRemoved(int64_t version_id, const std::string& client_uuid) override {
    NativeTabResolver::Get().ServiceWorkerControlleeRemoved(version_id, client_uuid);
  }
  void OnNoControllees(int64_t version_id, const GURL& scope) override {
    NativeTabResolver::Get().ServiceWorkerScope(version_id, scope.spec());
  }
  void OnDestruct(content::ServiceWorkerContext* context) override {
    // The context's observer list must be empty when it is destroyed.
    context->RemoveObserver(this);
  }
};

NativeTabRegistry& NativeTabRegistry::Get() {
  static base::NoDestructor<NativeTabRegistry> registry;
  return *registry;
}

NativeTabRegistry::NativeTabRegistry()
    : dedicated_(std::make_unique<DedicatedWorkers>()),
      shared_(std::make_unique<SharedWorkers>()),
      service_(std::make_unique<ServiceWorkers>()) {
  SetNativeServiceWorkerVersionObserver(&NoteServiceWorkerVersion);
}

NativeTabRegistry::~NativeTabRegistry() = default;

std::uint32_t NativeTabRegistry::NoteFrame(content::RenderFrameHost* frame) {
  const std::uint32_t tab = NativeTabOf(frame);
  if (tab != 0) {
    const content::GlobalRenderFrameHostToken token = frame->GetGlobalFrameToken();
    NativeTabResolver::Get().NoteFrame(token.child_id, TokenOf(token.frame_token.value()), tab);
  }
  return tab;
}

NativeFactoryOwnerTab NativeTabRegistry::NoteFactory(content::RenderFrameHost* frame) {
  if (frame) {
    return {.tab = NoteFrame(frame)};
  }
  const NativeFactoryOwner owner = CurrentNativeFactoryOwner();
  const bool caller = owner.frame_process_id >= 0;
  const std::uint32_t tab = caller ? NoteFrame(content::RenderFrameHost::FromID(
                                         owner.frame_process_id, owner.frame_routing_id))
                                   : 0;
  return {.tab = tab,
          .service_worker_version = tab ? -1 : owner.service_worker_version_id,
          .service_worker_without_caller =
              !caller && owner.cause == NativeFactoryOwnerCause::kServiceWorker,
          .prefetch_without_page = owner.cause == NativeFactoryOwnerCause::kPrefetchWithoutPage};
}

void NativeTabRegistry::ObserveContext(content::BrowserContext* context) {
  content::StoragePartition* const partition =
      context ? context->GetDefaultStoragePartition() : nullptr;
  if (!partition || !observed_.insert(partition).second) {
    return;
  }
  if (content::DedicatedWorkerService* service = partition->GetDedicatedWorkerService()) {
    service->AddObserver(dedicated_.get());
    service->EnumerateDedicatedWorkers(dedicated_.get());
  }
  if (content::SharedWorkerService* service = partition->GetSharedWorkerService()) {
    service->AddObserver(shared_.get());
    service->EnumerateSharedWorkers(shared_.get());
  }
  if (content::ServiceWorkerContext* service = partition->GetServiceWorkerContext()) {
    service->AddObserver(service_.get());
    for (const auto& [version_id, info] : service->GetRunningServiceWorkerInfos()) {
      service_->Started(version_id, info);
    }
  }
}

}  // namespace reb
