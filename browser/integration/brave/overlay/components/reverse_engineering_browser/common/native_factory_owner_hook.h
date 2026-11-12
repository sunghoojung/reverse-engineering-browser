// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_FACTORY_OWNER_HOOK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_FACTORY_OWNER_HOOK_H_

#include <cstdint>

#include "base/component_export.h"

namespace content {
class BrowserContext;
}

namespace reb {

// What content knows about a frameless factory's fetch beyond its frame.
enum class NativeFactoryOwnerCause : std::uint8_t {
  // Only the frame and version below name the owner.
  kNamed,
  // A service-worker job or worker start: with no caller frame and no tab for
  // its version, no page caused the fetch (protocol/native-network-v3.md).
  kServiceWorker,
  // A browser-initiated prefetch with no live referring WebContents.
  kPrefetchWithoutPage,
};

// Whom a frameless factory's fetch serves, scoped by content. UI thread.
struct NativeFactoryOwner final {
  int frame_process_id = -1;
  int frame_routing_id = -2;
  std::int64_t service_worker_version_id = -1;
  NativeFactoryOwnerCause cause = NativeFactoryOwnerCause::kNamed;
  // A starting service worker's ServiceWorkerToken, scoped with its factory
  // bundles so the worker is known before its first fetch is drained.
  std::uint64_t service_worker_token_high = 0;
  std::uint64_t service_worker_token_low = 0;
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

// A service-worker job names the version it starts and the cause it scoped
// around its script fetch, so that version's own fetches can name the same
// tabs once the frame may be gone. UI thread; a no-op until the browser sets
// an observer.
using NativeServiceWorkerVersionObserver = void (*)(content::BrowserContext* context,
                                                    std::int64_t version_id,
                                                    const NativeFactoryOwner& cause);

COMPONENT_EXPORT(REB_FACTORY_OWNER_HOOK)
void SetNativeServiceWorkerVersionObserver(NativeServiceWorkerVersionObserver observer) noexcept;

COMPONENT_EXPORT(REB_FACTORY_OWNER_HOOK)
void NoteNativeServiceWorkerVersion(content::BrowserContext* context,
                                    std::int64_t version_id,
                                    const NativeFactoryOwner& cause);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_FACTORY_OWNER_HOOK_H_
