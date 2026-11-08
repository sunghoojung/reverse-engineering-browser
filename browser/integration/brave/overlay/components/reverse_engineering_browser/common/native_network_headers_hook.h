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

namespace reb {

// The raw header notifications the network service sends content's
// NetworkServiceDevToolsObserver (protocol/native-network-v3.md). Content calls
// Notify before its DevTools dispatch; the browser sink registers an observer
// only for content-capture sessions. Both run on the UI thread.
enum class NativeNetworkHeadersKind : std::uint8_t {
  kRawRequest = 1,
  kEarlyHints = 2,
};

using NativeNetworkHeadersObserver =
    void (*)(NativeNetworkHeadersKind kind,
             std::string_view devtools_request_id,
             const std::vector<network::mojom::HttpRawHeaderPairPtr>& headers);

COMPONENT_EXPORT(REB_NETWORK_HEADERS_HOOK)
void SetNativeNetworkHeadersObserver(NativeNetworkHeadersObserver observer) noexcept;

// One atomic load when no observer is registered.
COMPONENT_EXPORT(REB_NETWORK_HEADERS_HOOK)
void NotifyNativeNetworkHeaders(NativeNetworkHeadersKind kind,
                                std::string_view devtools_request_id,
                                const std::vector<network::mojom::HttpRawHeaderPairPtr>& headers);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_HEADERS_HOOK_H_
