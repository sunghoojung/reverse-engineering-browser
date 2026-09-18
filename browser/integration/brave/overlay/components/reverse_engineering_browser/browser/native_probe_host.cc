// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_host.h"

#include <bit>
#include <memory>
#include <unordered_map>
#include <utility>

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

void NativeProbeHost::CaptureGeneratedArtifact(const std::uint16_t kind,
                                               const std::uint16_t capture_origin,
                                               const std::uint64_t creator_event_id,
                                               const std::uint64_t execution_context_id,
                                               const std::uint64_t frame_id,
                                               const std::string& source_url,
                                               mojo_base::BigBuffer content) {
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
  if (!client_.is_bound() || session_id == 0) {
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
  client_->Configure(session_id, category_mask, expires_at_monotonic_ns, capture_canvas_images,
                     std::move(renderer_region));
}

void NativeProbeHost::Disable() {
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
