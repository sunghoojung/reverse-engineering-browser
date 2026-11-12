// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_HEADERS_HOOK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_HEADERS_HOOK_H_

#include <cstdint>
#include <string_view>
#include <vector>

#include "base/component_export.h"
#include "services/network/public/mojom/http_raw_headers.mojom.h"

namespace net {
struct CookieWithAccessResult;
struct CookieAndLineWithAccessResult;
}  // namespace net

namespace reb {

// The raw header notifications the network service sends content's
// NetworkServiceDevToolsObserver (protocol/native-network-v3.md). Content calls
// Notify before its DevTools dispatch; the browser sink registers an observer
// only for content-capture sessions. Both run on the UI thread.
enum class NativeNetworkHeadersKind : std::uint8_t {
  kRawRequest = 1,
  kEarlyHints = 2,
  kRawResponse = 3,
};

// The cookie list of a raw request (sent) or raw response (received), with
// each cookie's inclusion status; null for other notifications.
struct NativeNetworkCookies final {
  const std::vector<net::CookieWithAccessResult>* sent = nullptr;
  const std::vector<net::CookieAndLineWithAccessResult>* received = nullptr;
};

using NativeNetworkHeadersObserver =
    void (*)(NativeNetworkHeadersKind kind,
             std::string_view devtools_request_id,
             const std::vector<network::mojom::HttpRawHeaderPairPtr>& headers,
             NativeNetworkCookies cookies);

// `expires_at_monotonic_ns` is the session's expiry on the TimeTicks clock.
COMPONENT_EXPORT(REB_NETWORK_HEADERS_HOOK)
void SetNativeNetworkHeadersObserver(NativeNetworkHeadersObserver observer,
                                     std::uint64_t expires_at_monotonic_ns = 0) noexcept;

// Whether a current, unexpired content-capture session with the Network
// category registered an observer. Chromium patch 0058 gives the early-hints
// preload factory an agentless DevTools observer only then, so a factory
// created outside such a session is built exactly as without the patch.
COMPONENT_EXPORT(REB_NETWORK_HEADERS_HOOK)
bool NativeNetworkHeadersObserved() noexcept;

// One atomic load when no observer is registered.
COMPONENT_EXPORT(REB_NETWORK_HEADERS_HOOK)
void NotifyNativeNetworkHeaders(NativeNetworkHeadersKind kind,
                                std::string_view devtools_request_id,
                                const std::vector<network::mojom::HttpRawHeaderPairPtr>& headers,
                                NativeNetworkCookies cookies = {});

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_HEADERS_HOOK_H_
