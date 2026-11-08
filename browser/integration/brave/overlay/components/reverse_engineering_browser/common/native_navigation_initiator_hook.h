// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NAVIGATION_INITIATOR_HOOK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NAVIGATION_INITIATOR_HOOK_H_

#include <cstdint>
#include <string_view>

#include "base/component_export.h"

namespace reb {

// Content's navigation loader to the browser sink, UI thread; see protocol/native-network-v3.md.
using NativeNavigationInitiatorObserver = bool (*)(std::string_view devtools_request_id,
                                                   std::uint32_t renderer_process_id,
                                                   std::uint64_t renderer_sequence);

COMPONENT_EXPORT(REB_NETWORK_HEADERS_HOOK)
void SetNativeNavigationInitiatorObserver(NativeNavigationInitiatorObserver observer) noexcept;

// False, after one atomic load, when nothing observes.
COMPONENT_EXPORT(REB_NETWORK_HEADERS_HOOK)
bool NotifyNativeNavigationInitiator(std::string_view devtools_request_id,
                                     std::uint32_t renderer_process_id,
                                     std::uint64_t renderer_sequence);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NAVIGATION_INITIATOR_HOOK_H_
