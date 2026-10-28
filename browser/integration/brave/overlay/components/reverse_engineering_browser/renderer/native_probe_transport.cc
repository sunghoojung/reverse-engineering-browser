// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_probe_transport.h"

#include <bit>
#include <cstring>
#include <memory>
#include <utility>
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest_adapter.h"

#include "base/functional/bind.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "third_party/blink/public/web/web_local_frame.h"

namespace reb {

namespace {

std::uint64_t CurrentFrameId() noexcept {
  const blink::WebLocalFrame* const frame = blink::WebLocalFrame::FrameForCurrentContext();
  if (!frame) {
    return 0;
  }
  const base::UnguessableToken& token = frame->GetLocalFrameToken().value();
  return std::rotl(token.GetHighForSerialization(), 17) ^ token.GetLowForSerialization();
}

}  // namespace

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
                                     const bool capture_canvas_images,
                                     base::UnsafeSharedMemoryRegion queue_region,
                                     const std::uint64_t wasm_capture_epoch,
                                     const std::string& guest_adapter_json) {
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
  wasm_capture_epoch_.store(wasm_capture_epoch, std::memory_order_release);
  NativeProbeSink::Get().SetNativeWasmDispatchEmitter(&EmitWasmDispatch);
  NativeProbeSink::Get().SetEmitters(
      &NativeProbeTransport::EmitStatus, &NativeProbeTransport::EmitArtifact, session_id,
      category_mask, expires_at_monotonic_ns, capture_canvas_images, &CurrentFrameId);
  if (!guest_adapter_json.empty())
    NativeProbeSink::Get().ConfigureNativeWasmGuest(ParseNativeWasmGuestAdapter(guest_adapter_json),
                                                    &EmitNativeGuest, &EmitNativeGuestHost);
}

void NativeProbeTransport::Disable() {
  wasm_capture_epoch_.store(0, std::memory_order_release);
  NativeProbeSink::Get().SetEmitters(nullptr, nullptr, 0, 0, 0, false);
  queue_.store(nullptr, std::memory_order_release);
}

void NativeProbeTransport::NativeGuestModuleStatus(const std::uint64_t wasm_capture_epoch,
                                                   const std::uint64_t module_token,
                                                   const bool accepted) {
  // A verdict for a retired configuration must not release a newer binding.
  const auto epoch = wasm_capture_epoch_.load(std::memory_order_acquire);
  if (!epoch || epoch != wasm_capture_epoch || !module_token)
    return;
  NativeProbeSink::Get().NoteNativeGuestModuleStatus(module_token, accepted);
}

NativeProbeEmitStatus NativeProbeTransport::EmitStatus(
    const NativeProbeEvent& event,
    const std::uint64_t config_generation) noexcept {
  return Get().EmitEvent(event, config_generation);
}

bool NativeProbeTransport::EmitWasmDispatch(const NativeWasmDispatchObservation& observation,
                                            const std::uint64_t generation) noexcept {
  auto& transport = Get();
  const auto epoch = transport.wasm_capture_epoch_.load(std::memory_order_acquire);
  NativeProbeEvent event;
  event.header = observation.header;
  if (!epoch || !NativeProbeSink::Get().CanAdmitEvent(event, generation))
    return false;
  auto* host = transport.HostForCurrentSequence();
  if (!*host || !NativeProbeSink::Get().CanAdmitEvent(event, generation) ||
      epoch != transport.wasm_capture_epoch_.load(std::memory_order_acquire))
    return false;
  (*host)->CaptureWasmDispatch(
      epoch, event.header.session_id, event.header.sequence_number, event.header.monotonic_time_ns,
      event.header.process_id, event.header.thread_id, event.header.frame_id,
      observation.execution_context_id, observation.document_token_high,
      observation.document_token_low, observation.function_index, observation.module_byte_offset,
      observation.selector, observation.table_count, observation.sample_index,
      std::string(observation.source_url), mojo_base::BigBuffer(observation.module_bytes));
  return true;
}

bool NativeProbeTransport::EmitNativeGuest(const NativeGuestCapture& capture,
                                           std::uint64_t generation) noexcept {
  auto& transport = Get();
  const auto epoch = transport.wasm_capture_epoch_.load(std::memory_order_acquire);
  if (!epoch || !NativeProbeSink::Get().CanAdmitEvent(capture.dispatch, generation) ||
      capture.module_bytes.size() > kNativeArtifactMaxContentBytes ||
      capture.bytecode_bytes.size() > kNativeGuestSnapshotLimit ||
      capture.adapter_json.size() > kNativeGuestAdapterLimit)
    return false;
  auto* host = transport.HostForCurrentSequence();
  if (!*host || epoch != transport.wasm_capture_epoch_.load(std::memory_order_acquire) ||
      !NativeProbeSink::Get().CanAdmitEvent(capture.dispatch, generation))
    return false;
  std::vector<std::uint8_t> invocation(sizeof(NativeProbeEvent)),
      dispatch(sizeof(NativeProbeEvent));
  std::memcpy(invocation.data(), &capture.invocation, sizeof(NativeProbeEvent));
  std::memcpy(dispatch.data(), &capture.dispatch, sizeof(NativeProbeEvent));
  (*host)->CaptureNativeGuest(epoch, invocation, dispatch, capture.execution_context_id,
                              capture.document_token_high, capture.document_token_low,
                              std::string(capture.source_url), std::string(capture.adapter_json),
                              mojo_base::BigBuffer(capture.module_bytes),
                              mojo_base::BigBuffer(capture.bytecode_bytes));
  return true;
}
bool NativeProbeTransport::EmitNativeGuestHost(const NativeProbeEvent& event,
                                               std::uint64_t generation) noexcept {
  auto& transport = Get();
  const auto epoch = transport.wasm_capture_epoch_.load(std::memory_order_acquire);
  if (!epoch || !event.header.parent_event_id ||
      !NativeProbeSink::Get().CanAdmitEvent(event, generation))
    return false;
  auto* host = transport.HostForCurrentSequence();
  if (!*host || epoch != transport.wasm_capture_epoch_.load(std::memory_order_acquire) ||
      !NativeProbeSink::Get().CanAdmitEvent(event, generation))
    return false;
  std::vector<std::uint8_t> record(sizeof(NativeProbeEvent));
  std::memcpy(record.data(), &event, sizeof(NativeProbeEvent));
  (*host)->CaptureNativeGuestHost(epoch, record);
  return true;
}

void NativeProbeTransport::EmitArtifact(const NativeArtifactKind kind,
                                        const NativeArtifactCaptureOrigin capture_origin,
                                        const std::uint64_t creator_event_id,
                                        const std::uint64_t execution_context_id,
                                        const std::uint64_t frame_id,
                                        const std::string_view source_url,
                                        const std::span<const std::uint8_t> content,
                                        const NativeRuntimeScript& script) noexcept {
  Get().EmitGeneratedArtifact(kind, capture_origin, creator_event_id, execution_context_id,
                              frame_id, source_url, content, script);
}

NativeProbeEmitStatus NativeProbeTransport::EmitEvent(
    const NativeProbeEvent& event,
    const std::uint64_t config_generation) noexcept {
  NativeProbeQueue* const queue = queue_.load(std::memory_order_acquire);
  // Acquire the mapping before validating its policy generation. Configure
  // clears the old sink generation before publishing a replacement queue, and
  // publishes that queue before enabling its new sink generation. A stale
  // producer can therefore finish only in the retained old mapping, never in
  // a replacement mapping (including reconfiguration with the same session ID).
  if (!queue || !NativeProbeSink::Get().CanAdmitEvent(event, config_generation)) {
    return NativeProbeEmitStatus::kRejected;
  }
  if (!queue->TryPush(event, NativeProbeDropWeight(event))) {
    return NativeProbeEmitStatus::kQueueFull;
  }

  if (!queue->MarkNotificationPending()) {
    return NativeProbeEmitStatus::kAdmitted;
  }

  auto* const thread_host = HostForCurrentSequence();
  if (*thread_host) {
    (*thread_host)->EventsAvailable();
  }
  return NativeProbeEmitStatus::kAdmitted;
}

void NativeProbeTransport::EmitGeneratedArtifact(const NativeArtifactKind kind,
                                                 const NativeArtifactCaptureOrigin capture_origin,
                                                 const std::uint64_t creator_event_id,
                                                 const std::uint64_t execution_context_id,
                                                 const std::uint64_t frame_id,
                                                 const std::string_view source_url,
                                                 const std::span<const std::uint8_t> content,
                                                 const NativeRuntimeScript& script) noexcept {
  if (script.capture_generation != 0 &&
      script.capture_generation != NativeProbeSink::Get().RuntimeCaptureGeneration()) {
    return;
  }
  auto* const thread_host = HostForCurrentSequence();
  if (*thread_host) {
    (*thread_host)
        ->CaptureGeneratedArtifact(static_cast<std::uint16_t>(kind),
                                   static_cast<std::uint16_t>(capture_origin), creator_event_id,
                                   execution_context_id, frame_id, std::string(source_url),
                                   mojo_base::BigBuffer(content), script.script_id, script.is_eval,
                                   mojo_base::BigBuffer(script.source), script.session_id);
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
