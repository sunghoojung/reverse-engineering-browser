// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_FACTORY_OWNER_HOOK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_FACTORY_OWNER_HOOK_H_

#include <cstdint>

#include "base/component_export.h"

namespace reb {

// Whom a frameless factory's fetch serves, scoped by content. UI thread.
struct NativeFactoryOwner final {
  int frame_process_id = -1;
  int frame_routing_id = -2;
  std::int64_t service_worker_version_id = -1;
};

class COMPONENT_EXPORT(REB_FACTORY_OWNER_HOOK) ScopedNativeFactoryOwner final {
 public:
  explicit ScopedNativeFactoryOwner(const NativeFactoryOwner& owner) noexcept;
  ScopedNativeFactoryOwner(const ScopedNativeFactoryOwner&) = delete;
  ScopedNativeFactoryOwner& operator=(const ScopedNativeFactoryOwner&) = delete;
  ~ScopedNativeFactoryOwner();

 private:
  const NativeFactoryOwner previous_;
};

COMPONENT_EXPORT(REB_FACTORY_OWNER_HOOK)
NativeFactoryOwner CurrentNativeFactoryOwner() noexcept;

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_FACTORY_OWNER_HOOK_H_
