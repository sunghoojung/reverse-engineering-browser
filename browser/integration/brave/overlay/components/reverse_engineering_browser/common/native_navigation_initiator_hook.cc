// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/common/native_navigation_initiator_hook.h"

#include <atomic>

namespace reb {

namespace {
std::atomic<NativeNavigationInitiatorObserver> g_observer{nullptr};
}  // namespace

void SetNativeNavigationInitiatorObserver(
    const NativeNavigationInitiatorObserver observer) noexcept {
  g_observer.store(observer, std::memory_order_release);
}

bool NotifyNativeNavigationInitiator(const std::string_view devtools_request_id,
                                     const std::uint32_t renderer_process_id,
                                     const std::uint64_t renderer_sequence) {
  const NativeNavigationInitiatorObserver observer = g_observer.load(std::memory_order_acquire);
  return observer && observer(devtools_request_id, renderer_process_id, renderer_sequence);
}

}  // namespace reb
