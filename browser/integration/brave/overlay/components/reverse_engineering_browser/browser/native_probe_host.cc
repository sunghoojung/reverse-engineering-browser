// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_host.h"

#include <bit>
#include <cstring>
#include <limits>
#include <memory>
#include <unordered_map>
#include <utility>
#include "base/time/time.h"
#include "content/public/browser/weak_document_ptr.h"

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest_adapter.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/web_contents.h"

namespace reb {

namespace {

std::unordered_map<std::uint64_t, std::uint32_t> CurrentFrameTabs(const int renderer_process_id) {
  std::unordered_map<std::uint64_t, std::uint32_t> tabs;
  content::RenderProcessHost* const process =
      content::RenderProcessHost::FromID(renderer_process_id);
  if (!process) {
    return tabs;
  }
  process->ForEachRenderFrameHost([&tabs](content::RenderFrameHost* frame) {
    content::WebContents* const contents = content::WebContents::FromRenderFrameHost(frame);
    content::RenderFrameHost* const main_frame =
        contents ? contents->GetPrimaryMainFrame() : nullptr;
    if (!main_frame) {
      return;
    }
    const base::UnguessableToken& token = frame->GetFrameToken().value();
    const std::uint64_t frame_id =
        std::rotl(token.GetHighForSerialization(), 17) ^ token.GetLowForSerialization();
    const content::FrameTreeNodeId tab_id = main_frame->GetFrameTreeNodeId();
    if (frame_id != 0 && tab_id) {
      const auto [entry, inserted] =
          tabs.emplace(frame_id, static_cast<std::uint32_t>(tab_id.value()));
      if (!inserted && entry->second != static_cast<std::uint32_t>(tab_id.value())) {
        entry->second = 0;
      }
    }
  });
  return tabs;
}

}  // namespace

NativeProbeHost::NativeProbeHost(NativeProbeSession& session, const int renderer_process_id)
    : session_(session), renderer_process_id_(renderer_process_id) {
  session_->AddHost(*this);
}

NativeProbeHost::~NativeProbeHost() {
  Disable();
  session_->RemoveHost(*this);
}

void NativeProbeHost::BindClient(mojo::PendingRemote<mojom::NativeProbeClient> client) {
  client_.Bind(std::move(client));
  if (session_->IsActive()) {
    Configure(session_->session_id(), session_->category_mask(),
              session_->expires_at_monotonic_ns(), session_->capture_canvas_images());
  }
}

void NativeProbeHost::EventsAvailable() {
  Drain();
}

void NativeProbeHost::CaptureWasmDispatch(const std::uint64_t capture_epoch,
                                          const std::uint64_t session_id,
                                          const std::uint64_t sequence_number,
                                          const std::uint64_t monotonic_time_ns,
                                          const std::uint32_t process_id,
                                          const std::uint32_t thread_id,
                                          const std::uint64_t frame_id,
                                          const std::uint64_t execution_context_id,
                                          const std::uint64_t document_token_high,
                                          const std::uint64_t document_token_low,
                                          const std::uint32_t function_index,
                                          const std::uint32_t module_byte_offset,
                                          const std::uint32_t selector,
                                          const std::uint32_t table_count,
                                          const std::uint32_t sample_index,
                                          const std::string& source_url,
                                          mojo_base::BigBuffer content) {
  constexpr auto mask = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                        NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (!queue_ || !wasm_epoch_lifetime_ || capture_epoch != wasm_capture_epoch_ ||
      !session_->IsActive() || session_id != session_->session_id() ||
      (session_->category_mask() & mask) != mask || !sequence_number || !monotonic_time_ns ||
      monotonic_time_ns > now || now >= session_->expires_at_monotonic_ns() || !thread_id ||
      !frame_id || !execution_context_id || sample_index >= 16 || wasm_capture_count_ >= 16 ||
      content.size() > 16U * 1024U * 1024U)
    return;
  auto* process = content::RenderProcessHost::FromID(renderer_process_id_);
  if (!process || process_id != static_cast<std::uint32_t>(process->GetProcess().Pid()))
    return;
  ++wasm_capture_count_;
  content::RenderFrameHost* owner = nullptr;
  process->ForEachRenderFrameHost([&](content::RenderFrameHost* frame) {
    if (!frame->IsActive())
      return;
    const auto& token = frame->GetFrameToken().value();
    const auto& document = frame->GetDocumentToken().value();
    if ((std::rotl(token.GetHighForSerialization(), 17) ^ token.GetLowForSerialization()) ==
            frame_id &&
        document.GetHighForSerialization() == document_token_high &&
        document.GetLowForSerialization() == document_token_low)
      owner = frame;
  });
  NativeWasmDispatchObservation observation;
  observation.header.category = NativeProbeCategory::kVm;
  observation.header.type = NativeProbeType::kWasmDispatchObservation;
  observation.header.session_id = session_id;
  observation.header.sequence_number = sequence_number;
  observation.header.monotonic_time_ns = monotonic_time_ns;
  observation.header.process_id = process_id;
  observation.header.thread_id = thread_id;
  observation.header.frame_id = frame_id;
  if (!owner) {
    if (!wasm_document_gap_emitted_) {
      wasm_document_gap_emitted_ = true;
      NativeProbeEvent gap;
      gap.header = observation.header;
      gap.header.type = NativeProbeType::kGap;
      constexpr std::string_view reason = "native_wasm_dispatch_document_unavailable";
      gap.header.payload_size = reason.size();
      for (std::size_t i = 0; i < reason.size(); ++i)
        gap.inline_payload[i] = static_cast<std::byte>(reason[i]);
      session_->Emit(gap);
    }
    return;
  }
  auto* contents = content::WebContents::FromRenderFrameHost(owner);
  auto* main_frame = contents ? contents->GetPrimaryMainFrame() : nullptr;
  if (main_frame)
    observation.header.tab_id =
        static_cast<std::uint32_t>(main_frame->GetFrameTreeNodeId().value());
  observation.execution_context_id = execution_context_id;
  observation.document_token_high = document_token_high;
  observation.document_token_low = document_token_low;
  observation.function_index = function_index;
  observation.module_byte_offset = module_byte_offset;
  observation.selector = selector;
  observation.table_count = table_count;
  observation.sample_index = sample_index;
  observation.source_url = source_url;
  const auto document = owner->GetWeakDocumentPtr();
  const std::weak_ptr<const std::uint64_t> lifetime = wasm_epoch_lifetime_;
  NativeArtifactCaptureSink::Get().CaptureWasmDispatch(
      observation, std::move(content), [document, lifetime]() {
        return !lifetime.expired() && document.AsRenderFrameHostIfValid() != nullptr;
      });
}

void NativeProbeHost::CaptureNativeGuest(const std::uint64_t capture_epoch,
                                         const std::vector<std::uint8_t>& invocation_record,
                                         const std::vector<std::uint8_t>& dispatch_record,
                                         const std::uint64_t execution_context_id,
                                         const std::uint64_t document_token_high,
                                         const std::uint64_t document_token_low,
                                         const std::string& source_url,
                                         const std::string& adapter_json,
                                         mojo_base::BigBuffer module,
                                         mojo_base::BigBuffer bytecode) {
  const auto mask = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                    NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  if (!queue_ || !capture_epoch || capture_epoch != wasm_capture_epoch_ || !session_->IsActive() ||
      (session_->category_mask() & mask) != mask ||
      guest_capture_count_ >= kNativeGuestSampleLimit ||
      invocation_record.size() != sizeof(NativeProbeEvent) ||
      dispatch_record.size() != sizeof(NativeProbeEvent) ||
      (module.size() != 0 && module.size() < 8) || module.size() > kNativeArtifactMaxContentBytes ||
      bytecode.size() == 0 || bytecode.size() > kNativeGuestSnapshotLimit || adapter_json.empty() ||
      adapter_json != session_->guest_adapter_json())
    return;
  ++guest_capture_count_;
  NativeGuestCapture capture;
  std::memcpy(&capture.invocation, invocation_record.data(), sizeof(capture.invocation));
  std::memcpy(&capture.dispatch, dispatch_record.data(), sizeof(capture.dispatch));
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  const auto& h = capture.dispatch.header;
  auto* process = content::RenderProcessHost::FromID(renderer_process_id_);
  if (!process || h.session_id != session_->session_id() ||
      h.process_id != static_cast<std::uint32_t>(process->GetProcess().Pid()) ||
      !h.monotonic_time_ns || h.monotonic_time_ns > now ||
      capture.invocation.header.monotonic_time_ns > h.monotonic_time_ns)
    return;
  content::RenderFrameHost* owner = nullptr;
  process->ForEachRenderFrameHost([&](content::RenderFrameHost* frame) {
    if (!frame->IsActive())
      return;
    const auto& token = frame->GetFrameToken().value();
    const auto& document = frame->GetDocumentToken().value();
    if ((std::rotl(token.GetHighForSerialization(), 17) ^ token.GetLowForSerialization()) ==
            h.frame_id &&
        document.GetHighForSerialization() == document_token_high &&
        document.GetLowForSerialization() == document_token_low)
      owner = frame;
  });
  if (!owner)
    return;
  auto* contents = content::WebContents::FromRenderFrameHost(owner);
  auto* main_frame = contents ? contents->GetPrimaryMainFrame() : nullptr;
  const auto tab =
      main_frame ? static_cast<std::uint32_t>(main_frame->GetFrameTreeNodeId().value()) : 0;
  capture.invocation.header.tab_id = tab;
  capture.dispatch.header.tab_id = tab;
  // Private copies defeat shared BigBuffer mutation between hashing and transfer.
  const std::vector<std::uint8_t> module_copy(module.begin(), module.end());
  const std::vector<std::uint8_t> bytecode_copy(bytecode.begin(), bytecode.end());
  const auto adapter = ParseNativeWasmGuestAdapter(adapter_json);
  if (!adapter ||
      (!module_copy.empty() && NativeGuestDigest(module_copy) != adapter->module_sha256))
    return;
  const auto field = [&](std::size_t offset, std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t n = 0; n < width; ++n)
      value |= std::to_integer<std::uint64_t>(capture.dispatch.inline_payload[offset + n])
               << (n * 8U);
    return value;
  };
  if (guest_capture_count_ > adapter->sample_limit || field(20, 4) >= adapter->sample_limit ||
      field(4, 4) != adapter->function_index || field(8, 4) != adapter->dispatch_module_offset ||
      field(76, 4) != adapter->pc_local_index || field(88, 4) != adapter->memory_index ||
      field(80, 8) != static_cast<std::uint64_t>(adapter->pc_adjustment) ||
      bytecode_copy.size() < adapter->opcode_width ||
      field(40, 8) > bytecode_copy.size() - adapter->opcode_width)
    return;
  std::uint32_t opcode = 0;
  for (std::uint32_t n = 0; n < adapter->opcode_width; ++n) {
    const auto shift = adapter->opcode_big_endian ? 8U * (adapter->opcode_width - n - 1U) : 8U * n;
    opcode |= static_cast<std::uint32_t>(bytecode_copy[static_cast<std::size_t>(field(40, 8)) + n])
              << shift;
  }
  if (field(92, 4) != opcode)
    return;
  capture.execution_context_id = execution_context_id;
  capture.document_token_high = document_token_high;
  capture.document_token_low = document_token_low;
  capture.source_url = source_url;
  capture.adapter_json = adapter_json;
  capture.module_bytes = module_copy;
  capture.bytecode_bytes = bytecode_copy;
  const auto document = owner->GetWeakDocumentPtr();
  const std::weak_ptr<const std::uint64_t> lifetime = wasm_epoch_lifetime_;
  NativeArtifactCaptureSink::Get().CaptureNativeGuest(
      capture, capture_epoch, [document, lifetime]() {
        auto* current = document.AsRenderFrameHostIfValid();
        return !lifetime.expired() && current && current->IsActive();
      });
}

void NativeProbeHost::CaptureNativeGuestHost(const std::uint64_t capture_epoch,
                                             const std::vector<std::uint8_t>& event_record) {
  // The 65th attempt reaches the sink so its 64-host cap emits a bounded loss marker.
  if (!queue_ || !capture_epoch || capture_epoch != wasm_capture_epoch_ || !session_->IsActive() ||
      guest_host_count_ >= 65 || event_record.size() != sizeof(NativeProbeEvent))
    return;
  ++guest_host_count_;
  NativeProbeEvent event;
  std::memcpy(&event, event_record.data(), sizeof(event));
  auto* process = content::RenderProcessHost::FromID(renderer_process_id_);
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (!process || event.header.session_id != session_->session_id() ||
      event.header.process_id != static_cast<std::uint32_t>(process->GetProcess().Pid()) ||
      !event.header.monotonic_time_ns || event.header.monotonic_time_ns > now)
    return;
  NativeArtifactCaptureSink::Get().CaptureNativeGuestHost(event, capture_epoch);
}

void NativeProbeHost::CaptureGeneratedArtifact(const std::uint16_t kind,
                                               const std::uint16_t capture_origin,
                                               const std::uint64_t creator_event_id,
                                               const std::uint64_t execution_context_id,
                                               const std::uint64_t frame_id,
                                               const std::string& source_url,
                                               mojo_base::BigBuffer content,
                                               std::uint64_t allocating_script_id,
                                               bool allocating_script_is_eval,
                                               mojo_base::BigBuffer allocating_script_source,
                                               std::uint64_t allocating_script_session_id) {
  if (kind == static_cast<std::uint16_t>(NativeArtifactKind::kBytecodeBuffer) &&
      capture_origin ==
          static_cast<std::uint16_t>(NativeArtifactCaptureOrigin::kRuntimeTypedArray)) {
    NativeArtifactCaptureSink::Get().CaptureRuntimeTypedArray(
        renderer_process_id_, allocating_script_session_id, allocating_script_id,
        allocating_script_is_eval, creator_event_id, execution_context_id, frame_id, source_url,
        std::move(allocating_script_source), std::move(content));
    return;
  }
  NativeArtifactCaptureSink::Get().CaptureGeneratedArtifact(
      static_cast<NativeArtifactKind>(kind),
      static_cast<NativeArtifactCaptureOrigin>(capture_origin), creator_event_id,
      execution_context_id, frame_id, source_url, std::move(content));
}

void NativeProbeHost::Configure(const std::uint64_t session_id,
                                const std::uint64_t category_mask,
                                const std::uint64_t expires_at_monotonic_ns,
                                const bool capture_canvas_images) {
  Disable();
  if (!client_.is_bound() || session_id == 0 ||
      wasm_capture_epoch_ == std::numeric_limits<std::uint64_t>::max()) {
    return;
  }

  queue_region_ = base::UnsafeSharedMemoryRegion::Create(sizeof(NativeProbeQueue));
  if (!queue_region_.IsValid()) {
    return;
  }
  queue_mapping_ = queue_region_.Map();
  if (!queue_mapping_.IsValid()) {
    queue_region_ = base::UnsafeSharedMemoryRegion();
    return;
  }

  queue_ = std::construct_at(static_cast<NativeProbeQueue*>(queue_mapping_.memory()));
  reported_dropped_events_ = 0;
  base::UnsafeSharedMemoryRegion renderer_region = queue_region_.Duplicate();
  if (!renderer_region.IsValid()) {
    Disable();
    return;
  }
  wasm_epoch_lifetime_ = std::make_shared<const std::uint64_t>(wasm_capture_epoch_);
  client_->Configure(session_id, category_mask, expires_at_monotonic_ns, capture_canvas_images,
                     std::move(renderer_region), wasm_capture_epoch_,
                     session_->guest_adapter_json());
}

void NativeProbeHost::Disable() {
  wasm_epoch_lifetime_.reset();
  if (wasm_capture_epoch_ != std::numeric_limits<std::uint64_t>::max())
    ++wasm_capture_epoch_;
  wasm_capture_count_ = 0;
  guest_capture_count_ = 0;
  guest_host_count_ = 0;
  wasm_document_gap_emitted_ = false;
  if (client_.is_bound()) {
    client_->Disable();
  }
  queue_ = nullptr;
  reported_dropped_events_ = 0;
  queue_mapping_ = base::WritableSharedMemoryMapping();
  queue_region_ = base::UnsafeSharedMemoryRegion();
}

void NativeProbeHost::Drain() {
  if (!queue_) {
    return;
  }

  const auto frame_tabs = CurrentFrameTabs(renderer_process_id_);
  for (;;) {
    NativeProbeEvent event;
    NativeProbeEvent last_event;
    bool drained_event = false;
    while (queue_->TryPop(event)) {
      if (const auto tab = frame_tabs.find(event.header.frame_id);
          tab != frame_tabs.end() && tab->second != 0) {
        event.header.tab_id = tab->second;
      }
      session_->Emit(event);
      last_event = event;
      drained_event = true;
    }

    const std::uint64_t dropped = queue_->DroppedCount();
    if (drained_event && dropped > reported_dropped_events_) {
      session_->Emit(MakeNativeProbeGapEvent(last_event, dropped - reported_dropped_events_));
      reported_dropped_events_ = dropped;
    }

    queue_->ClearNotificationPending();
    if (queue_->Empty() || !queue_->MarkNotificationPending()) {
      return;
    }
  }
}

}  // namespace reb
