// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/no_destructor.h"
#include "base/time/time.h"
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

void NativeProbeSession::BindHost(mojo::PendingReceiver<mojom::NativeProbeHost> receiver) {
  mojo::MakeSelfOwnedReceiver(std::make_unique<NativeProbeHost>(*this), std::move(receiver));
}

bool NativeProbeSession::StartSession(const std::uint64_t session_id,
                                      const std::uint64_t category_mask,
                                      const std::uint64_t expires_at_monotonic_ns,
                                      const NativeProbeEmitter downstream) noexcept {
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (session_id == 0 || !IsValidNativeProbeCategoryMask(category_mask) ||
      expires_at_monotonic_ns <= now || !downstream || IsActive()) {
    return false;
  }

  category_mask_.store(category_mask, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(expires_at_monotonic_ns, std::memory_order_relaxed);
  downstream_.store(downstream, std::memory_order_release);
  session_id_.store(session_id, std::memory_order_release);
  NativeNetworkCaptureSink::Get().SetEmitter(&NativeProbeSession::EmitBrowserEvent, session_id,
                                             category_mask, expires_at_monotonic_ns);
  for (NativeProbeHost* const host : hosts_) {
    host->Configure(session_id, category_mask, expires_at_monotonic_ns);
  }
  return true;
}

void NativeProbeSession::StopSession() noexcept {
  NativeNetworkCaptureSink::Get().SetEmitter(nullptr, 0, 0, 0);
  session_id_.store(0, std::memory_order_release);
  category_mask_.store(0, std::memory_order_release);
  expires_at_monotonic_ns_.store(0, std::memory_order_release);
  for (NativeProbeHost* const host : hosts_) {
    host->Disable();
  }
  downstream_.store(nullptr, std::memory_order_release);
}

bool NativeProbeSession::IsActive() const noexcept {
  return downstream_.load(std::memory_order_acquire) != nullptr && session_id() != 0;
}

std::uint64_t NativeProbeSession::session_id() const noexcept {
  return session_id_.load(std::memory_order_acquire);
}

std::uint64_t NativeProbeSession::category_mask() const noexcept {
  return category_mask_.load(std::memory_order_acquire);
}

std::uint64_t NativeProbeSession::expires_at_monotonic_ns() const noexcept {
  return expires_at_monotonic_ns_.load(std::memory_order_acquire);
}

void NativeProbeSession::Emit(const NativeProbeEvent& event) const noexcept {
  const NativeProbeEmitter downstream = downstream_.load(std::memory_order_acquire);
  if (!downstream) {
    return;
  }
  const std::uint64_t category_bit = NativeProbeCategoryMask(event.header.category);
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (category_bit != 0 && (category_mask_.load(std::memory_order_relaxed) & category_bit) != 0 &&
      now < expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    downstream(event);
  }
}

void NativeProbeSession::AddHost(NativeProbeHost& host) {
  hosts_.push_back(&host);
}

void NativeProbeSession::RemoveHost(NativeProbeHost& host) {
  std::erase(hosts_, &host);
}

void NativeProbeSession::EmitBrowserEvent(const NativeProbeEvent& event) noexcept {
  Get().Emit(event);
}

}  // namespace reb
