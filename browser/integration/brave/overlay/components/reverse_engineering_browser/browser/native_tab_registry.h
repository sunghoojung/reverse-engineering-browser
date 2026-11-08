// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_REGISTRY_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_REGISTRY_H_

#include <cstdint>
#include <memory>
#include <set>

#include "base/no_destructor.h"

namespace content {
class BrowserContext;
class RenderFrameHost;
class StoragePartition;
}  // namespace content

namespace reb {

// Feeds NativeTabResolver from the Chromium services that know each owner
// (protocol/native-network-v3.md "Request owners and tabs"). UI thread only.
class NativeTabRegistry final {
 public:
  static NativeTabRegistry& Get();

  NativeTabRegistry(const NativeTabRegistry&) = delete;
  NativeTabRegistry& operator=(const NativeTabRegistry&) = delete;

  // Records the frame for late lookups and returns its NativeTabOf.
  std::uint32_t NoteFrame(content::RenderFrameHost* frame);
  // Starts observing the context's default partition once. Workers that
  // already run are enumerated; clients added before this call are not.
  void ObserveContext(content::BrowserContext* context);

  class DedicatedWorkers;
  class SharedWorkers;
  class ServiceWorkers;

 private:
  friend class base::NoDestructor<NativeTabRegistry>;
  NativeTabRegistry();
  ~NativeTabRegistry();

  const std::unique_ptr<DedicatedWorkers> dedicated_;
  const std::unique_ptr<SharedWorkers> shared_;
  const std::unique_ptr<ServiceWorkers> service_;
  // A partition lives as long as its BrowserContext; the owned profile's lives
  // until shutdown, so pointer identity is enough to observe it once.
  std::set<const content::StoragePartition*> observed_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_TAB_REGISTRY_H_
