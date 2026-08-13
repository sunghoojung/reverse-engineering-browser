// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_host.h"

#include <memory>
#include <utility>

#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"

namespace reb {

NativeProbeHost::NativeProbeHost(NativeProbeSession& session) : session_(session) {
  session_->AddHost(*this);
}

NativeProbeHost::~NativeProbeHost() {
  Disable();
  session_->RemoveHost(*this);
}

void NativeProbeHost::BindClient(mojo::PendingRemote<mojom::NativeProbeClient> client) {
  client_.Bind(std::move(client));
  if (session_->IsActive()) {
    Configure(session_->session_id());
  }
}

void NativeProbeHost::EventsAvailable() {
  Drain();
}

void NativeProbeHost::Configure(const std::uint64_t session_id) {
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
  client_->Configure(session_id, std::move(renderer_region));
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

  for (;;) {
    NativeProbeEvent event;
    NativeProbeEvent last_event;
    bool drained_event = false;
    while (queue_->TryPop(event)) {
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
