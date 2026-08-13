// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_

#include <cstdint>

#include "base/memory/raw_ptr.h"
#include "base/memory/raw_ref.h"
#include "base/memory/shared_memory_mapping.h"
#include "base/memory/unsafe_shared_memory_region.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h"
#include "mojo/public/cpp/bindings/remote.h"

namespace reb {

class NativeProbeQueue;
class NativeProbeSession;

class NativeProbeHost final : public mojom::NativeProbeHost {
 public:
  explicit NativeProbeHost(NativeProbeSession& session);
  NativeProbeHost(const NativeProbeHost&) = delete;
  NativeProbeHost& operator=(const NativeProbeHost&) = delete;
  ~NativeProbeHost() override;

  // mojom::NativeProbeHost:
  void BindClient(mojo::PendingRemote<mojom::NativeProbeClient> client) override;
  void EventsAvailable() override;

  void Configure(std::uint64_t session_id);
  void Disable();

 private:
  void Drain();

  const raw_ref<NativeProbeSession> session_;
  mojo::Remote<mojom::NativeProbeClient> client_;
  base::UnsafeSharedMemoryRegion queue_region_;
  base::WritableSharedMemoryMapping queue_mapping_;
  raw_ptr<NativeProbeQueue> queue_ = nullptr;
  std::uint64_t reported_dropped_events_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_
