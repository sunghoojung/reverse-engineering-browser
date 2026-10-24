// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_REQUEST_NAMESPACE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_REQUEST_NAMESPACE_H_

namespace reb {

// Ordinals of content::ContentBrowserClient::URLLoaderFactoryType at pinned
// Chromium 151.0.7922.108. The Brave proxy patch static_asserts each value.
// Renderer-issued subresource factories are the only ones whose
// CreateLoaderAndStart request id is the renderer's GenerateRequestId().
enum class NativeUrlLoaderFactoryKind : int {
  kNavigation = 0,
  kDownload = 1,
  kDocumentSubResource = 2,
  kWorkerMainResource = 3,
  kWorkerSubResource = 4,
  kServiceWorkerScript = 5,
  kServiceWorkerSubResource = 6,
  kPrefetch = 7,
  kDevTools = 8,
  kEarlyHints = 9,
};

inline bool NativeRendererIssuedRequestId(int factory_type) noexcept {
  return factory_type == static_cast<int>(NativeUrlLoaderFactoryKind::kDocumentSubResource) ||
         factory_type == static_cast<int>(NativeUrlLoaderFactoryKind::kWorkerSubResource) ||
         factory_type == static_cast<int>(NativeUrlLoaderFactoryKind::kServiceWorkerSubResource);
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_REQUEST_NAMESPACE_H_
