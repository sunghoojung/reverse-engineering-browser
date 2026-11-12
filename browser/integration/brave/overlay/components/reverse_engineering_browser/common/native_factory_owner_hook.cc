// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/common/native_factory_owner_hook.h"

namespace reb {

namespace {
constinit thread_local NativeFactoryOwner g_owner;
// Set once on the UI thread, which is the only thread that notes versions.
constinit NativeServiceWorkerVersionObserver g_version_observer = nullptr;
}  // namespace

ScopedNativeFactoryOwner::ScopedNativeFactoryOwner(const NativeFactoryOwner& owner) noexcept
    : previous_(g_owner) {
  g_owner = owner;
}

ScopedNativeFactoryOwner::~ScopedNativeFactoryOwner() {
  g_owner = previous_;
}

NativeFactoryOwner CurrentNativeFactoryOwner() noexcept {
  return g_owner;
}

void SetNativeServiceWorkerVersionObserver(
    const NativeServiceWorkerVersionObserver observer) noexcept {
  g_version_observer = observer;
}

void NoteNativeServiceWorkerVersion(content::BrowserContext* context,
                                    const std::int64_t version_id,
                                    const NativeFactoryOwner& cause) {
  if (g_version_observer) {
    g_version_observer(context, version_id, cause);
  }
}

}  // namespace reb
