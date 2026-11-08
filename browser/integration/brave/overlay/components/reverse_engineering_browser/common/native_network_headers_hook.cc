// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/common/native_network_headers_hook.h"

#include <atomic>

namespace reb {

namespace {
std::atomic<NativeNetworkHeadersObserver> g_observer{nullptr};
}  // namespace

void SetNativeNetworkHeadersObserver(const NativeNetworkHeadersObserver observer) noexcept {
  g_observer.store(observer, std::memory_order_release);
}

void NotifyNativeNetworkHeaders(const NativeNetworkHeadersKind kind,
                                const std::string_view devtools_request_id,
                                const std::vector<network::mojom::HttpRawHeaderPairPtr>& headers,
                                const NativeNetworkCookies cookies) {
  if (const NativeNetworkHeadersObserver observer = g_observer.load(std::memory_order_acquire))
      [[unlikely]] {
    observer(kind, devtools_request_id, headers, cookies);
  }
}

}  // namespace reb
