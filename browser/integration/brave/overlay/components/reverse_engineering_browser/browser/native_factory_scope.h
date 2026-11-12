// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_FACTORY_SCOPE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_FACTORY_SCOPE_H_

#include <cstdint>
#include <string_view>

#include "brave/components/reverse_engineering_browser/browser/native_tab_resolver.h"
#include "brave/components/reverse_engineering_browser/common/native_network_scope.h"
#include "brave/components/reverse_engineering_browser/common/native_request_namespace.h"
#include "brave/components/reverse_engineering_browser/common/native_tab_link.h"

namespace content {
class BrowserContext;
class RenderFrameHost;
}  // namespace content

namespace url {
class Origin;
}

namespace reb {

// Fixed when Chromium creates the factory; protocol/native-network-v3.md.
struct NativeFactoryScope final {
  // 65, 66, 67 or 69 counts the factory's requests instead of recording them.
  std::uint8_t exclusion = 0;
  std::uint32_t tab_id = 0;
  NativeBrowserRequestOwner owner;
  bool record_browser_internal = false;
};

struct NativeFactoryPolicy final {
  bool record_browser_internal = false;
  bool record_extensions = false;
};

[[nodiscard]] inline NativeFactoryScope DecideNativeFactoryScope(
    const int factory_type,
    const std::string_view initiator_scheme,
    const std::string_view initiator_host,
    const bool browser_internal_process,
    const NativeFactoryPolicy policy) noexcept {
  using Kind = NativeUrlLoaderFactoryKind;
  const auto kind = static_cast<Kind>(factory_type);
  NativeFactoryScope scope;
  scope.record_browser_internal = policy.record_browser_internal;
  if (kind == Kind::kDevTools) {
    scope.exclusion = kNativeDevToolsLoadExclusion;
    return scope;
  }
  const bool browser_fetched =
      kind == Kind::kWorkerMainResource || kind == Kind::kServiceWorkerScript;
  const bool worker = browser_fetched || kind == Kind::kWorkerSubResource ||
                      kind == Kind::kServiceWorkerSubResource;
  if (worker && initiator_scheme == "chrome-extension") {
    NativeExtensionId id;
    if (!policy.record_extensions || !ParseNativeExtensionId(initiator_host, id)) {
      scope.exclusion = kNativeExtensionWorkerExclusion;
    } else if (browser_fetched) {
      // A renderer-issued request is linked through its renderer record.
      scope.owner.extension = id;
    }
    return scope;
  }
  // Navigations belong to the document they load, whatever frame starts them.
  if (browser_internal_process && !policy.record_browser_internal &&
      (NativeRendererIssuedRequestId(factory_type) || kind == Kind::kWorkerMainResource)) {
    scope.exclusion = kNativeWebUiRequestExclusion;
  }
  return scope;
}

// Only renderer-issued subresource loads name a renderer whose access decides a
// file part. A navigation's paths were checked when it began, for the initiator
// rather than this factory's commit process. No other factory carries a page's
// upload, so the browser reads nothing for them.
[[nodiscard]] inline NativeBodyFileAccess DecideNativeBodyFileAccess(
    const int factory_type) noexcept {
  if (factory_type == static_cast<int>(NativeUrlLoaderFactoryKind::kNavigation)) {
    return NativeBodyFileAccess::kNavigationValidated;
  }
  return NativeRendererIssuedRequestId(factory_type) ? NativeBodyFileAccess::kRendererChecked
                                                     : NativeBodyFileAccess::kRefused;
}

// The drain counts renderer-issued extension, no-page service-worker and
// internal-scheme requests.
struct NativeRequestExclusion final {
  std::uint8_t exclusion_class = 0;
  bool counted_here = false;
};

// Called once per request, while capture runs: for a renderer-issued
// service-worker request it takes the class 68 answer the drain shares.
// `request` is the factory's renderer and the request's renderer id.
[[nodiscard]] inline NativeRequestExclusion NativeProxyRequestExclusion(
    const NativeFactoryScope& scope,
    const int factory_type,
    const std::string_view url_scheme,
    const NativeTabResolver::RendererRequest request) noexcept {
  const bool renderer_issued = NativeRendererIssuedRequestId(factory_type);
  if (scope.exclusion != 0) {
    return {scope.exclusion,
            scope.exclusion != kNativeExtensionWorkerExclusion || !renderer_issued};
  }
  // Decided per request: a version stops being pageless when a page first uses
  // it. A renderer-issued request shares one answer with its renderer record.
  if (scope.owner.service_worker_without_caller && scope.tab_id == 0 &&
      (renderer_issued
           ? NativeTabResolver::Get().SharedServiceWorkerNoPage(request,
                                                                scope.owner.service_worker_version)
           : NativeTabResolver::Get().ServiceWorkerHasNoPage(scope.owner.service_worker_version))) {
    return {kNativeServiceWorkerNoPageExclusion, !renderer_issued};
  }
  const NativeSchemeClass scheme = ClassifyNativeScheme(url_scheme);
  if (IsBrowserInternalSchemeClass(scheme) && !scope.record_browser_internal) {
    return {static_cast<std::uint8_t>(scheme), !renderer_issued};
  }
  return {};
}

// UI thread: observes the owned profile and fixes one factory's scope.
NativeFactoryScope NativeFactoryScopeOf(content::BrowserContext* context,
                                        content::RenderFrameHost* frame,
                                        int render_process_id,
                                        int factory_type,
                                        const url::Origin& initiator);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_FACTORY_SCOPE_H_
