// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/common/native_network_headers_hook.h"

#include <atomic>

#include "base/time/time.h"

namespace reb {

namespace {
std::atomic<NativeNetworkHeadersObserver> g_observer{nullptr};
std::atomic<std::uint64_t> g_expires_at_monotonic_ns{0};
}  // namespace

void SetNativeNetworkHeadersObserver(const NativeNetworkHeadersObserver observer,
                                     const std::uint64_t expires_at_monotonic_ns) noexcept {
  // The expiry is published first, so a reader that sees the observer sees it.
  g_expires_at_monotonic_ns.store(observer ? expires_at_monotonic_ns : 0,
                                  std::memory_order_relaxed);
  g_observer.store(observer, std::memory_order_release);
}

bool NativeNetworkHeadersObserved() noexcept {
  if (!g_observer.load(std::memory_order_acquire)) {
    return false;
  }
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  return now < g_expires_at_monotonic_ns.load(std::memory_order_relaxed);
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
