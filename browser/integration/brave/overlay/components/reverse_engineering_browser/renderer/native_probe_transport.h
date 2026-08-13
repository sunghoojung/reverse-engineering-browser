// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_TRANSPORT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_TRANSPORT_H_

#include <atomic>
#include <cstdint>
#include <vector>

#include "base/memory/shared_memory_mapping.h"
#include "base/memory/unsafe_shared_memory_region.h"
#include "base/no_destructor.h"
#include "base/threading/thread_local.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/shared_remote.h"

namespace reb {

class NativeProbeQueue;

class NativeProbeTransport final : public mojom::NativeProbeClient {
 public:
  static NativeProbeTransport& Get();

  NativeProbeTransport(const NativeProbeTransport&) = delete;
  NativeProbeTransport& operator=(const NativeProbeTransport&) = delete;

  // Called once on the renderer main thread after Mojo is available.
  void Connect();

  // mojom::NativeProbeClient:
  void Configure(std::uint64_t session_id, base::UnsafeSharedMemoryRegion queue_region) override;
  void Disable() override;

 private:
  friend class base::NoDestructor<NativeProbeTransport>;

  NativeProbeTransport();
  ~NativeProbeTransport() override;

  static void Emit(const NativeProbeEvent& event) noexcept;
  void EmitEvent(const NativeProbeEvent& event) noexcept;

  mojo::SharedRemote<mojom::NativeProbeHost> host_;
  base::ThreadLocalOwnedPointer<mojo::SharedRemote<mojom::NativeProbeHost>> thread_hosts_;
  mojo::Receiver<mojom::NativeProbeClient> receiver_{this};
  // Mappings are retained for process lifetime so Disable cannot unmap a queue
  // after a worker has loaded its pointer but before that worker finishes its
  // non-blocking copy.
  std::vector<base::WritableSharedMemoryMapping> queue_mappings_;
  std::atomic<NativeProbeQueue*> queue_{nullptr};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_TRANSPORT_H_
