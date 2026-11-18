// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "base/scoped_multi_source_observation.h"
#include "brave/components/reverse_engineering_browser/common/native_js_invocation.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_sample_budget.h"
#include "content/public/browser/render_process_host_observer.h"

namespace content {
class RenderProcessHost;
}  // namespace content

namespace reb {

class NativeProbeHost;

// Owns browser-process probe activation and fans one immutable session policy
// out to every connected renderer. The authenticated socket client starts the
// session. Without a complete valid policy every probe remains dormant.
class NativeProbeSession final : public content::RenderProcessHostObserver {
 public:
  static NativeProbeSession& Get();

  NativeProbeSession(const NativeProbeSession&) = delete;
  NativeProbeSession& operator=(const NativeProbeSession&) = delete;

  // Creates the host of an admitted renderer before its process starts. Its
  // configuration travels on the process's IPC channel, ahead of any
  // navigation commit, so a new process's first document is captured from
  // its first script. This relies on frames sharing the process channel,
  // which holds while MBI mode is off (the default).
  void RenderProcessWillLaunch(content::RenderProcessHost& process);
  // The renderer's own connection to the host its launch created.
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
  // Fixed 44-byte function-entry site records, one per slot; null unless a
  // valid --reb-js-invocation-sites file was supplied, and empty when that
  // file arms no function yet.
  [[nodiscard]] const std::optional<std::vector<std::uint8_t>>& js_invocation_sites()
      const noexcept {
    return js_invocation_sites_;
  }
  // --reb-js-invocation-digests: the session's sensitive opt-in for
  // settled-value digests. Only meaningful with invocation sites.
  [[nodiscard]] bool js_invocation_digests() const noexcept { return js_invocation_digests_; }
  // A revision of the session's --reb-js-invocation-sites file, sent to every
  // renderer. Every slot keeps its site for the browser lifetime; a revision
  // that renumbers one, or that cannot be read, changes nothing and is the
  // `native_js_invocation_sites_revision_refused` gap.
  void UpdateJsInvocationSites(const std::string& json) noexcept;
  // samples_per_function is kNativeWasmDefaultSamplesPerFunction unless the
  // session sets it. Empty lists do not filter.
  [[nodiscard]] const NativeWasmSampleBudgetPolicy& wasm_sample_budget() const noexcept {
    return wasm_sample_budget_;
  }
  // Starts a new sample window in every renderer now, as each one does every
  // kNativeWasmSampleWindowNs. The profile, the session id, the capture
  // configuration and sample indexes stay.
  void ResetWasmSampleBudgets() noexcept;
  // The Console's kept debugger watch scope, sent to every renderer now and to
  // each one configured later; null clears it. The Console session owns it, so
  // a capture session ending leaves it for the next configuration.
  void SetDebuggerWatchScope(mojom::NativeWatchScopePtr scope);
  [[nodiscard]] const mojom::NativeWatchScopePtr& debugger_watch_scope() const noexcept {
    return debugger_watch_scope_;
  }
  [[nodiscard]] bool IsActive() const noexcept;
  [[nodiscard]] std::uint64_t session_id() const noexcept;
  [[nodiscard]] std::uint64_t category_mask() const noexcept;
  [[nodiscard]] std::uint64_t expires_at_monotonic_ns() const noexcept;
  [[nodiscard]] bool capture_canvas_images() const noexcept;
  [[nodiscard]] bool capture_request_content() const noexcept;
  // --reb-capture-browser-internal: admit WebUI renderers and record internal
  // schemes instead of counting them.
  [[nodiscard]] bool capture_browser_internal() const noexcept;
  // --reb-capture-extension-traffic: record extension worker traffic under its
  // extension id instead of counting it.
  [[nodiscard]] bool capture_extension_traffic() const noexcept;
  // One more browser-internal renderer process this session does not admit.
  void NoteWebUiRendererExcluded() noexcept;
  // One more request the proxy counts instead of recording. UI sequence.
  void NoteBrowserRequestExcluded(std::uint8_t exclusion_class) noexcept;
  // Cumulative count of one exclusion class; protocol/native-network-v3.md.
  void EmitExclusion(std::uint32_t excluded_process_id,
                     std::uint8_t exclusion_class,
                     std::uint64_t count) noexcept;
  // One named loss in the browser's own sequence: a gap record whose payload
  // is `reason`, a lowercase identifier.
  void EmitNamedGap(NativeProbeCategory category, std::string_view reason) noexcept;
  [[nodiscard]] std::uint64_t NextBrowserSequence() noexcept;
  void Emit(const NativeProbeEvent& event) const noexcept;

  void AddHost(NativeProbeHost& host);
  void RemoveHost(NativeProbeHost& host);

 private:
  friend class base::NoDestructor<NativeProbeSession>;

  NativeProbeSession();
  ~NativeProbeSession() override;

  // content::RenderProcessHostObserver:
  void RenderProcessExited(content::RenderProcessHost* process,
                           const content::ChildProcessTerminationInfo& info) override;
  void RenderProcessHostDestroyed(content::RenderProcessHost* process) override;

  static void EmitBrowserEvent(const NativeProbeEvent& event) noexcept;
  // Whether sites keeps the site of every slot this browser has sent.
  [[nodiscard]] bool KeepsJsInvocationSlots(
      const std::vector<NativeJsInvocationSite>& sites) const noexcept;
  void AdoptJsInvocationSlots(const std::vector<NativeJsInvocationSite>& sites) noexcept;

  std::string guest_adapter_json_, guest_startup_adapter_json_;
  std::string js_dispatch_startup_sites_json_;
  std::vector<std::uint8_t> js_dispatch_sites_;
  // Every slot's site that this browser has sent a renderer. Renderers keep
  // their slots across sessions, so no later file may renumber one.
  std::vector<NativeJsInvocationSite> js_invocation_slots_;
  std::optional<std::vector<std::uint8_t>> js_invocation_sites_;
  bool js_invocation_digests_ = false;
  NativeWasmSampleBudgetPolicy wasm_sample_budget_{};
  mojom::NativeWatchScopePtr debugger_watch_scope_;
  std::vector<raw_ptr<NativeProbeHost>> hosts_;
  std::atomic<NativeProbeEmitter> downstream_{nullptr};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<bool> capture_canvas_images_{false};
  std::atomic<bool> capture_request_content_{false};
  std::atomic<bool> capture_browser_internal_{false};
  std::atomic<bool> capture_extension_traffic_{false};
  std::uint64_t webui_renderers_excluded_ = 0;
  std::map<std::uint8_t, std::uint64_t> browser_requests_excluded_;
  std::atomic<std::uint64_t> next_browser_sequence_{1};
  // Each admitted renderer's host, from its process launch until that process
  // exits. A relaunch of the same process host replaces it.
  std::map<int, std::unique_ptr<NativeProbeHost>> launched_hosts_;
  base::ScopedMultiSourceObservation<content::RenderProcessHost, content::RenderProcessHostObserver>
      observed_processes_{this};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SESSION_H_
