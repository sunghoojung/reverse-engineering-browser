// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/no_destructor.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_host.h"
#include "brave/components/reverse_engineering_browser/common/native_js_dispatch_sites.h"
#include "brave/components/reverse_engineering_browser/common/native_js_invocation_sites.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest_adapter.h"
#include "content/public/browser/render_process_host.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"

namespace reb {

namespace {

bool ReadRequestContentBudget(const base::CommandLine& command_line, std::uint64_t& budget) {
  budget = kNativeRequestContentDefaultBudgetBytes;
  return !command_line.HasSwitch("reb-request-content-budget-bytes") ||
         (base::StringToUint64(command_line.GetSwitchValueASCII("reb-request-content-budget-bytes"),
                               &budget) &&
          budget >= kNativeRequestContentMinBudgetBytes &&
          budget <= kNativeRequestContentMaxBudgetBytes);
}

bool ReadNativeWasmSampleBudget(const base::CommandLine& command_line,
                                const std::uint64_t category_mask,
                                NativeWasmSampleBudgetPolicy& policy) {
  policy = {};
  const bool present = command_line.HasSwitch("reb-wasm-samples-per-function") ||
                       command_line.HasSwitch("reb-wasm-samples-per-indirect-site") ||
                       command_line.HasSwitch("reb-wasm-function-allow") ||
                       command_line.HasSwitch("reb-wasm-function-deny") ||
                       command_line.HasSwitch("reb-wasm-module-allowlist");
  if (!present)
    return true;
  constexpr auto required = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                            NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  if ((category_mask & required) != required)
    return false;
  if (command_line.HasSwitch("reb-wasm-samples-per-function")) {
    unsigned value = 0;
    if (!base::StringToUint(command_line.GetSwitchValueASCII("reb-wasm-samples-per-function"),
                            &value) ||
        value < 1 || value > kNativeWasmDispatchSampleBudget)
      return false;
    policy.samples_per_function = value;
  }
  if (command_line.HasSwitch("reb-wasm-samples-per-indirect-site")) {
    unsigned value = 0;
    if (!base::StringToUint(command_line.GetSwitchValueASCII("reb-wasm-samples-per-indirect-site"),
                            &value) ||
        value < 1 || value > kNativeWasmIndirectSampleBudget)
      return false;
    policy.samples_per_indirect_site = value;
  }
  if (command_line.HasSwitch("reb-wasm-function-allow") &&
      !ParseNativeWasmFunctionList(command_line.GetSwitchValueASCII("reb-wasm-function-allow"),
                                   policy.function_allow, policy.function_allow_count))
    return false;
  if (command_line.HasSwitch("reb-wasm-function-deny") &&
      !ParseNativeWasmFunctionList(command_line.GetSwitchValueASCII("reb-wasm-function-deny"),
                                   policy.function_deny, policy.function_deny_count))
    return false;
  if (command_line.HasSwitch("reb-wasm-module-allowlist")) {
    const auto path = command_line.GetSwitchValuePath("reb-wasm-module-allowlist");
    std::string text;
    if (path.empty() || !base::ReadFileToStringWithMaxSize(path, &text, 1024) || text.empty() ||
        text.size() > 1024 || !ParseNativeWasmModuleAllowlist(text, policy))
      return false;
  }
  return IsValidNativeWasmSampleBudgetPolicy(policy);
}

}  // namespace

NativeProbeSession& NativeProbeSession::Get() {
  static base::NoDestructor<NativeProbeSession> session;
  return *session;
}

NativeProbeSession::NativeProbeSession() = default;

NativeProbeSession::~NativeProbeSession() = default;

void NativeProbeSession::BindHost(const int renderer_process_id,
                                  mojo::PendingReceiver<mojom::NativeProbeHost> receiver) {
  auto* process = content::RenderProcessHost::FromID(renderer_process_id);
  if (!process || !NativeNetworkCaptureSink::Get().IsOwnedContext(process->GetBrowserContext())) {
    return;
  }
  mojo::MakeSelfOwnedReceiver(std::make_unique<NativeProbeHost>(*this, renderer_process_id),
                              std::move(receiver));
}

bool NativeProbeSession::StartSession(const std::uint64_t session_id,
                                      const std::uint64_t category_mask,
                                      const std::uint64_t expires_at_monotonic_ns,
                                      const bool capture_canvas_images,
                                      const NativeProbeEmitter downstream,
                                      const bool capture_request_content) noexcept {
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (session_id == 0 || !IsValidNativeProbeCategoryMask(category_mask) ||
      expires_at_monotonic_ns <= now || !downstream || IsActive()) {
    return false;
  }

  guest_adapter_json_.clear();
  const auto* command_line = base::CommandLine::ForCurrentProcess();
  if (command_line->HasSwitch("reb-wasm-guest-adapter")) {
    const auto path = command_line->GetSwitchValuePath("reb-wasm-guest-adapter");
    if (path.empty() ||
        !base::ReadFileToStringWithMaxSize(path, &guest_adapter_json_, kNativeGuestAdapterLimit) ||
        !ParseNativeWasmGuestAdapter(guest_adapter_json_)) {
      guest_adapter_json_.clear();
      return false;
    }
    if (!guest_startup_adapter_json_.empty() &&
        guest_startup_adapter_json_ != guest_adapter_json_) {
      guest_adapter_json_.clear();
      return false;
    }
    guest_startup_adapter_json_ = guest_adapter_json_;
    constexpr auto required = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                              NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
    if ((category_mask & required) != required) {
      guest_adapter_json_.clear();
      return false;
    }
  }
  js_dispatch_sites_.clear();
  if (command_line->HasSwitch("reb-js-dispatch-sites")) {
    // Armed bytecode cannot be retargeted, so the file is fixed for the
    // browser lifetime and a changed or invalid file refuses the session.
    const auto path = command_line->GetSwitchValuePath("reb-js-dispatch-sites");
    std::string json;
    if (path.empty() ||
        !base::ReadFileToStringWithMaxSize(path, &json, kNativeJsDispatchSitesFileLimit) ||
        (!js_dispatch_startup_sites_json_.empty() && js_dispatch_startup_sites_json_ != json) ||
        (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kVm)) == 0) {
      guest_adapter_json_.clear();
      return false;
    }
    js_dispatch_sites_ = ParseNativeJsDispatchSites(json);
    if (js_dispatch_sites_.empty()) {
      guest_adapter_json_.clear();
      return false;
    }
    js_dispatch_startup_sites_json_ = std::move(json);
  }
  js_invocation_sites_.clear();
  js_invocation_digests_ = false;
  if (command_line->HasSwitch("reb-js-invocation-sites")) {
    // Same lifetime rule as dispatch sites: armed entries cannot be
    // retargeted, so a changed or invalid file refuses the session.
    const auto path = command_line->GetSwitchValuePath("reb-js-invocation-sites");
    std::string json;
    if (path.empty() ||
        !base::ReadFileToStringWithMaxSize(path, &json, kNativeJsInvocationSitesFileLimit) ||
        (!js_invocation_startup_sites_json_.empty() && js_invocation_startup_sites_json_ != json) ||
        (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kVm)) == 0) {
      guest_adapter_json_.clear();
      js_dispatch_sites_.clear();
      return false;
    }
    js_invocation_sites_ = ParseNativeJsInvocationSites(json);
    if (js_invocation_sites_.empty()) {
      guest_adapter_json_.clear();
      js_dispatch_sites_.clear();
      return false;
    }
    js_invocation_startup_sites_json_ = std::move(json);
    // Digests are a sensitive capture path; the launcher passes this switch
    // only with a visible sensitive-capture label.
    js_invocation_digests_ = command_line->HasSwitch("reb-js-invocation-digests");
  }
  NativeWasmSampleBudgetPolicy budget;
  std::uint64_t request_content_budget = 0;
  if (!ReadNativeWasmSampleBudget(*command_line, category_mask, budget) ||
      !ReadRequestContentBudget(*command_line, request_content_budget)) {
    guest_adapter_json_.clear();
    js_dispatch_sites_.clear();
    js_invocation_sites_.clear();
    js_invocation_digests_ = false;
    return false;
  }
  wasm_sample_budget_ = budget;
  category_mask_.store(category_mask, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(expires_at_monotonic_ns, std::memory_order_relaxed);
  capture_canvas_images_.store(capture_canvas_images, std::memory_order_relaxed);
  // Raw request targets and bodies need both the Network category and an
  // artifact channel; without the latter the body records say so explicitly.
  capture_request_content_.store(
      capture_request_content &&
          (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) != 0,
      std::memory_order_relaxed);
  next_browser_sequence_.store(1, std::memory_order_relaxed);
  downstream_.store(downstream, std::memory_order_release);
  session_id_.store(session_id, std::memory_order_release);
  NativeNetworkCaptureSink::Get().SetEmitter(&NativeProbeSession::EmitBrowserEvent, session_id,
                                             category_mask, expires_at_monotonic_ns,
                                             capture_request_content_.load());
  NativeArtifactCaptureSink::Get().SetEmitter(&NativeProbeSession::EmitBrowserEvent, session_id,
                                              category_mask, expires_at_monotonic_ns,
                                              request_content_budget);
  // SetEmitter restores the unrestricted policy. Publish this session's copy.
  NativeArtifactCaptureSink::Get().SetWasmSampleBudgetPolicy(wasm_sample_budget_);
  for (NativeProbeHost* const host : hosts_) {
    host->Configure(session_id, category_mask, expires_at_monotonic_ns, capture_canvas_images);
  }
  return true;
}

void NativeProbeSession::ResetWasmSampleBudgets() noexcept {
  if (!IsActive())
    return;
  NativeArtifactCaptureSink::Get().ResetWasmSampleBudgets();
  for (NativeProbeHost* const host : hosts_)
    host->ResetWasmSampleBudgets();
}

void NativeProbeSession::StopSession() noexcept {
  guest_adapter_json_.clear();
  js_dispatch_sites_.clear();
  js_invocation_sites_.clear();
  js_invocation_digests_ = false;
  wasm_sample_budget_ = {};
  // Hosts drain records their renderers already queued, and the artifact sink
  // turns unresolved work into gaps, while the session can still record them.
  for (NativeProbeHost* const host : hosts_) {
    host->Disable();
  }
  NativeArtifactCaptureSink::Get().SetEmitter(nullptr, 0, 0, 0);
  NativeNetworkCaptureSink::Get().SetEmitter(nullptr, 0, 0, 0);
  session_id_.store(0, std::memory_order_release);
  category_mask_.store(0, std::memory_order_release);
  expires_at_monotonic_ns_.store(0, std::memory_order_release);
  capture_canvas_images_.store(false, std::memory_order_release);
  capture_request_content_.store(false, std::memory_order_release);
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

bool NativeProbeSession::capture_canvas_images() const noexcept {
  return capture_canvas_images_.load(std::memory_order_acquire);
}

bool NativeProbeSession::capture_request_content() const noexcept {
  return capture_request_content_.load(std::memory_order_acquire);
}

std::uint64_t NativeProbeSession::NextBrowserSequence() noexcept {
  return next_browser_sequence_.fetch_add(1, std::memory_order_relaxed);
}

void NativeProbeSession::Emit(const NativeProbeEvent& event) const noexcept {
  const NativeProbeEmitter downstream = downstream_.load(std::memory_order_acquire);
  if (!downstream) {
    return;
  }
  const std::uint64_t category_bit = NativeProbeCategoryMask(event.header.category);
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (event.header.session_id == session_id_.load(std::memory_order_acquire) && category_bit != 0 &&
      (category_mask_.load(std::memory_order_relaxed) & category_bit) != 0 &&
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
