// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_host.h"

#include <bit>
#include <limits>
#include <memory>
#include <unordered_map>
#include <utility>
#include "base/time/time.h"
#include "content/public/browser/weak_document_ptr.h"

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
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
                     std::move(renderer_region), wasm_capture_epoch_);
}

void NativeProbeHost::Disable() {
  wasm_epoch_lifetime_.reset();
  if (wasm_capture_epoch_ != std::numeric_limits<std::uint64_t>::max())
    ++wasm_capture_epoch_;
  wasm_capture_count_ = 0;
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
