// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_probe_transport.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/task/sequenced_task_runner.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "content/public/renderer/render_thread.h"

namespace reb {

NativeProbeTransport& NativeProbeTransport::Get() {
  static base::NoDestructor<NativeProbeTransport> transport;
  return *transport;
}

NativeProbeTransport::NativeProbeTransport() = default;

NativeProbeTransport::~NativeProbeTransport() = default;

void NativeProbeTransport::Connect() {
  if (host_.is_bound()) {
    return;
  }

  mojo::PendingRemote<mojom::NativeProbeHost> pending_host;
  content::RenderThread::Get()->BindHostReceiver(pending_host.InitWithNewPipeAndPassReceiver());
  host_.Bind(std::move(pending_host), base::SequencedTaskRunner::GetCurrentDefault());
  host_.set_disconnect_handler(
      base::BindOnce(&NativeProbeTransport::Disable, base::Unretained(this)),
      base::SequencedTaskRunner::GetCurrentDefault());
  host_->BindClient(receiver_.BindNewPipeAndPassRemote());
}

void NativeProbeTransport::Configure(const std::uint64_t session_id,
                                     base::UnsafeSharedMemoryRegion queue_region) {
  Disable();
  if (session_id == 0 || !queue_region.IsValid() ||
      queue_region.GetSize() != sizeof(NativeProbeQueue)) {
    return;
  }

  base::WritableSharedMemoryMapping mapping = queue_region.Map();
  if (!mapping.IsValid() || mapping.size() != sizeof(NativeProbeQueue)) {
    return;
  }

  auto* const queue = static_cast<NativeProbeQueue*>(mapping.memory());
  if (!queue->IsValid()) {
    return;
  }

  queue_mappings_.push_back(std::move(mapping));
  queue_.store(queue, std::memory_order_release);
  NativeProbeSink::Get().SetEmitter(&NativeProbeTransport::Emit, session_id);
}

void NativeProbeTransport::Disable() {
  NativeProbeSink::Get().SetEmitter(nullptr, 0);
  queue_.store(nullptr, std::memory_order_release);
}

void NativeProbeTransport::Emit(const NativeProbeEvent& event) noexcept {
  Get().EmitEvent(event);
}

void NativeProbeTransport::EmitEvent(const NativeProbeEvent& event) noexcept {
  NativeProbeQueue* const queue = queue_.load(std::memory_order_acquire);
  if (!queue || !queue->TryPush(event)) {
    return;
  }

  if (!queue->MarkNotificationPending()) {
    return;
  }

  auto* thread_host = thread_hosts_.Get();
  if (!thread_host) {
    thread_hosts_.Set(std::make_unique<mojo::SharedRemote<mojom::NativeProbeHost>>(host_));
    thread_host = thread_hosts_.Get();
  }
  if (*thread_host) {
    (*thread_host)->EventsAvailable();
  }
}

}  // namespace reb
