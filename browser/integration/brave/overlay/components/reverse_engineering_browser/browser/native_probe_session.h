// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_sample_budget.h"

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

  void BindHost(int renderer_process_id, mojo::PendingReceiver<mojom::NativeProbeHost> receiver);

  [[nodiscard]] bool StartSession(std::uint64_t session_id,
                                  std::uint64_t category_mask,
                                  std::uint64_t expires_at_monotonic_ns,
                                  bool capture_canvas_images,
                                  NativeProbeEmitter downstream,
                                  bool capture_request_content = false) noexcept;
  void StopSession() noexcept;

  [[nodiscard]] const std::string& guest_adapter_json() const noexcept {
    return guest_adapter_json_;
  }
  // Fixed 44-byte native JavaScript dispatch site records for this session;
  // empty unless a valid --reb-js-dispatch-sites file was supplied.
  [[nodiscard]] const std::vector<std::uint8_t>& js_dispatch_sites() const noexcept {
    return js_dispatch_sites_;
  }
  // Fixed 44-byte function-entry site records; empty unless a valid
  // --reb-js-invocation-sites file was supplied.
  [[nodiscard]] const std::vector<std::uint8_t>& js_invocation_sites() const noexcept {
    return js_invocation_sites_;
  }
  // --reb-js-invocation-digests: the session's sensitive opt-in for
  // settled-value digests. Only meaningful with invocation sites.
  [[nodiscard]] bool js_invocation_digests() const noexcept { return js_invocation_digests_; }
  // Empty lists and zero caps are the historical 16-record stream budgets.
  [[nodiscard]] const NativeWasmSampleBudgetPolicy& wasm_sample_budget() const noexcept {
    return wasm_sample_budget_;
  }
  // Restarts both sample indexes in this browser session. The profile, the
  // session id, and the capture configuration stay.
  void ResetWasmSampleBudgets() noexcept;
  [[nodiscard]] bool IsActive() const noexcept;
  [[nodiscard]] std::uint64_t session_id() const noexcept;
  [[nodiscard]] std::uint64_t category_mask() const noexcept;
  [[nodiscard]] std::uint64_t expires_at_monotonic_ns() const noexcept;
  [[nodiscard]] bool capture_canvas_images() const noexcept;
  [[nodiscard]] bool capture_request_content() const noexcept;
  // --reb-capture-browser-internal: admit WebUI renderers and record internal
  // schemes instead of counting them.
  [[nodiscard]] bool capture_browser_internal() const noexcept;
  // One more WebUI renderer process this session does not admit.
  void NoteWebUiRendererExcluded() noexcept;
  // One more proxy request of a class no tab caused (65 or 66). UI sequence.
  void NoteBrowserRequestExcluded(std::uint8_t exclusion_class) noexcept;
  // Cumulative count of one exclusion class; protocol/native-network-v3.md.
  void EmitExclusion(std::uint32_t excluded_process_id,
                     std::uint8_t exclusion_class,
                     std::uint64_t count) noexcept;
  [[nodiscard]] std::uint64_t NextBrowserSequence() noexcept;
  void Emit(const NativeProbeEvent& event) const noexcept;

  void AddHost(NativeProbeHost& host);
  void RemoveHost(NativeProbeHost& host);

 private:
  friend class base::NoDestructor<NativeProbeSession>;

  NativeProbeSession();
  ~NativeProbeSession();

  static void EmitBrowserEvent(const NativeProbeEvent& event) noexcept;

  std::string guest_adapter_json_, guest_startup_adapter_json_;
  std::string js_dispatch_startup_sites_json_;
  std::vector<std::uint8_t> js_dispatch_sites_;
  std::string js_invocation_startup_sites_json_;
  std::vector<std::uint8_t> js_invocation_sites_;
  bool js_invocation_digests_ = false;
  NativeWasmSampleBudgetPolicy wasm_sample_budget_{};
  std::vector<raw_ptr<NativeProbeHost>> hosts_;
  std::atomic<NativeProbeEmitter> downstream_{nullptr};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<bool> capture_canvas_images_{false};
  std::atomic<bool> capture_request_content_{false};
  std::atomic<bool> capture_browser_internal_{false};
  std::uint64_t webui_renderers_excluded_ = 0;
  std::uint64_t extension_requests_excluded_ = 0;
  std::uint64_t devtools_requests_excluded_ = 0;
  std::atomic<std::uint64_t> next_browser_sequence_{1};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_
