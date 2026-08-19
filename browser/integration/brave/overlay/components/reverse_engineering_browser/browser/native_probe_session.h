// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_

#include <atomic>
#include <cstdint>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h"

namespace reb {

class NativeProbeHost;

// Owns browser-process probe activation and fans one immutable session policy
// out to every connected renderer. The authenticated socket client starts the
// session. Without a complete valid policy every probe remains dormant.
class NativeProbeSession final {
 public:
  static NativeProbeSession& Get();

  NativeProbeSession(const NativeProbeSession&) = delete;
  NativeProbeSession& operator=(const NativeProbeSession&) = delete;

  void BindHost(mojo::PendingReceiver<mojom::NativeProbeHost> receiver);

  [[nodiscard]] bool StartSession(std::uint64_t session_id,
                                  std::uint64_t category_mask,
                                  std::uint64_t expires_at_monotonic_ns,
                                  NativeProbeEmitter downstream) noexcept;
  void StopSession() noexcept;

  [[nodiscard]] bool IsActive() const noexcept;
  [[nodiscard]] std::uint64_t session_id() const noexcept;
  [[nodiscard]] std::uint64_t category_mask() const noexcept;
  [[nodiscard]] std::uint64_t expires_at_monotonic_ns() const noexcept;
  [[nodiscard]] std::uint64_t NextBrowserSequence() noexcept;
  void Emit(const NativeProbeEvent& event) const noexcept;

  void AddHost(NativeProbeHost& host);
  void RemoveHost(NativeProbeHost& host);

 private:
  friend class base::NoDestructor<NativeProbeSession>;

  NativeProbeSession();
  ~NativeProbeSession();

  static void EmitBrowserEvent(const NativeProbeEvent& event) noexcept;

  std::vector<raw_ptr<NativeProbeHost>> hosts_;
  std::atomic<NativeProbeEmitter> downstream_{nullptr};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<std::uint64_t> next_browser_sequence_{1};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_
