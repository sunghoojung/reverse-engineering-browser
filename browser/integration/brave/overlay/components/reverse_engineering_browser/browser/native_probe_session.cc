// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/no_destructor.h"
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_host.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"

namespace reb {

NativeProbeSession& NativeProbeSession::Get() {
  static base::NoDestructor<NativeProbeSession> session;
  return *session;
}

NativeProbeSession::NativeProbeSession() = default;

NativeProbeSession::~NativeProbeSession() = default;

void NativeProbeSession::BindHost(
    mojo::PendingReceiver<mojom::NativeProbeHost> receiver) {
  mojo::MakeSelfOwnedReceiver(std::make_unique<NativeProbeHost>(*this),
                              std::move(receiver));
}

bool NativeProbeSession::StartSession(
    const std::uint64_t session_id,
    const NativeProbeEmitter downstream) noexcept {
  if (session_id == 0 || !downstream || IsActive()) {
    return false;
  }

  downstream_.store(downstream, std::memory_order_release);
  session_id_.store(session_id, std::memory_order_release);
  NativeNetworkCaptureSink::Get().SetEmitter(
      &NativeProbeSession::EmitBrowserEvent, session_id);
  for (NativeProbeHost* const host : hosts_) {
    host->Configure(session_id);
  }
  return true;
}

void NativeProbeSession::StopSession() noexcept {
  NativeNetworkCaptureSink::Get().SetEmitter(nullptr, 0);
  session_id_.store(0, std::memory_order_release);
  for (NativeProbeHost* const host : hosts_) {
    host->Disable();
  }
  downstream_.store(nullptr, std::memory_order_release);
}

bool NativeProbeSession::IsActive() const noexcept {
  return downstream_.load(std::memory_order_acquire) != nullptr &&
         session_id() != 0;
}

std::uint64_t NativeProbeSession::session_id() const noexcept {
  return session_id_.load(std::memory_order_acquire);
}

void NativeProbeSession::Emit(const NativeProbeEvent& event) const noexcept {
  const NativeProbeEmitter downstream =
      downstream_.load(std::memory_order_acquire);
  if (downstream) {
    downstream(event);
  }
}

void NativeProbeSession::AddHost(NativeProbeHost& host) {
  hosts_.push_back(&host);
}

void NativeProbeSession::RemoveHost(NativeProbeHost& host) {
  std::erase(hosts_, &host);
}

void NativeProbeSession::EmitBrowserEvent(
    const NativeProbeEvent& event) noexcept {
  Get().Emit(event);
}

}  // namespace reb
