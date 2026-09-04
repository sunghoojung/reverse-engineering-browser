// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_probe_transport.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "mojo/public/cpp/base/big_buffer.h"

namespace reb {

NativeProbeTransport& NativeProbeTransport::Get() {
  static base::NoDestructor<NativeProbeTransport> transport;
  return *transport;
}

NativeProbeTransport::NativeProbeTransport() = default;

NativeProbeTransport::~NativeProbeTransport() = default;

void NativeProbeTransport::Connect(mojo::PendingRemote<mojom::NativeProbeHost> pending_host) {
  if (host_.is_bound() || !pending_host.is_valid()) {
    return;
  }

  host_.Bind(std::move(pending_host), base::SequencedTaskRunner::GetCurrentDefault());
  host_.set_disconnect_handler(
      base::BindOnce(&NativeProbeTransport::Disable, base::Unretained(this)),
      base::SequencedTaskRunner::GetCurrentDefault());
  host_->BindClient(receiver_.BindNewPipeAndPassRemote());
}

void NativeProbeTransport::Configure(const std::uint64_t session_id,
                                     const std::uint64_t category_mask,
                                     const std::uint64_t expires_at_monotonic_ns,
                                     base::UnsafeSharedMemoryRegion queue_region) {
  Disable();
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (session_id == 0 || !IsValidNativeProbeCategoryMask(category_mask) ||
      expires_at_monotonic_ns <= now || !queue_region.IsValid() ||
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
  NativeProbeSink::Get().SetEmitters(&NativeProbeTransport::Emit,
                                     &NativeProbeTransport::EmitArtifact, session_id, category_mask,
                                     expires_at_monotonic_ns);
}

void NativeProbeTransport::Disable() {
  NativeProbeSink::Get().SetEmitters(nullptr, nullptr, 0, 0, 0);
  queue_.store(nullptr, std::memory_order_release);
}

void NativeProbeTransport::Emit(const NativeProbeEvent& event) noexcept {
  Get().EmitEvent(event);
}

void NativeProbeTransport::EmitArtifact(const NativeArtifactKind kind,
                                        const NativeArtifactCaptureOrigin capture_origin,
                                        const std::uint64_t execution_context_id,
                                        const std::uint64_t frame_id,
                                        const std::string_view source_url,
                                        const std::span<const std::uint8_t> content) noexcept {
  Get().EmitGeneratedArtifact(kind, capture_origin, execution_context_id, frame_id, source_url,
                              content);
}

void NativeProbeTransport::EmitEvent(const NativeProbeEvent& event) noexcept {
  NativeProbeQueue* const queue = queue_.load(std::memory_order_acquire);
  if (!queue || !queue->TryPush(event)) {
    return;
  }

  if (!queue->MarkNotificationPending()) {
    return;
  }

  auto* const thread_host = HostForCurrentSequence();
  if (*thread_host) {
    (*thread_host)->EventsAvailable();
  }
}

void NativeProbeTransport::EmitGeneratedArtifact(
    const NativeArtifactKind kind,
    const NativeArtifactCaptureOrigin capture_origin,
    const std::uint64_t execution_context_id,
    const std::uint64_t frame_id,
    const std::string_view source_url,
    const std::span<const std::uint8_t> content) noexcept {
  auto* const thread_host = HostForCurrentSequence();
  if (*thread_host) {
    (*thread_host)
        ->CaptureGeneratedArtifact(
            static_cast<std::uint16_t>(kind), static_cast<std::uint16_t>(capture_origin),
            execution_context_id, frame_id, std::string(source_url), mojo_base::BigBuffer(content));
  }
}

mojo::SharedRemote<mojom::NativeProbeHost>* NativeProbeTransport::HostForCurrentSequence() {
  auto* thread_host = thread_hosts_.Get();
  if (!thread_host) {
    thread_hosts_.Set(std::make_unique<mojo::SharedRemote<mojom::NativeProbeHost>>(host_));
    thread_host = thread_hosts_.Get();
  }
  return thread_host;
}

}  // namespace reb
