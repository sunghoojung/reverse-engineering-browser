// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/common/native_factory_owner_hook.h"

namespace reb {

namespace {
constinit thread_local NativeFactoryOwner g_owner;
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

}  // namespace reb
