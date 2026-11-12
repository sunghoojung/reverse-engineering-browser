// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_host.h"

#include <algorithm>
#include <array>
#include <bit>
#include <functional>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>
#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "content/public/browser/weak_document_ptr.h"

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_capture_scope.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "brave/components/reverse_engineering_browser/browser/native_tab_of.h"
#include "brave/components/reverse_engineering_browser/browser/native_tab_resolver.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest_adapter.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/web_contents.h"

namespace reb {

namespace {

// Callers have checked that the record holds exactly one fixed-layout event.
NativeProbeEvent EventFromRecord(std::span<const std::uint8_t> record) {
  std::array<std::uint8_t, sizeof(NativeProbeEvent)> bytes{};
  std::ranges::copy(record.first(bytes.size()), bytes.begin());
  return std::bit_cast<NativeProbeEvent>(bytes);
}

// Live frames of the process, also kept by the resolver for later drains.
std::unordered_map<std::uint64_t, std::uint32_t> CurrentFrameTabs(const int renderer_process_id) {
  std::unordered_map<std::uint64_t, std::uint32_t> tabs;
  content::RenderProcessHost* const process =
      content::RenderProcessHost::FromID(renderer_process_id);
  if (!process) {
    return tabs;
  }
  process->ForEachRenderFrameHost([&tabs, renderer_process_id](content::RenderFrameHost* frame) {
    const std::uint32_t tab_id = NativeTabOf(frame);
    if (tab_id == 0) {
      return;
    }
    const base::UnguessableToken& token = frame->GetFrameToken().value();
    const NativeToken128 full{token.GetHighForSerialization(), token.GetLowForSerialization()};
    NativeTabResolver::Get().NoteFrame(renderer_process_id, full, tab_id);
    if (full.fold() != 0) {
      const auto [entry, inserted] = tabs.emplace(full.fold(), tab_id);
      if (!inserted && entry->second != tab_id) {
        entry->second = 0;
      }
    }
  });
  return tabs;
}

// A gap that takes the refused record's own renderer sequence slot, so the
// broker sees an explicit omission instead of a provisional hole. Callers
// have checked the record's session, process and nonzero sequence; a time
// the record could not have had is replaced by the refusal time.
NativeProbeEvent RendererGap(const NativeProbeEvent& source, const std::string_view reason) {
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  NativeProbeEvent gap;
  gap.header.category = NativeProbeCategory::kVm;
  gap.header.type = NativeProbeType::kGap;
  gap.header.session_id = source.header.session_id;
  gap.header.process_id = source.header.process_id;
  gap.header.thread_id = source.header.thread_id;
  gap.header.frame_id = source.header.frame_id;
  gap.header.sequence_number = source.header.sequence_number;
  gap.header.monotonic_time_ns =
      source.header.monotonic_time_ns && source.header.monotonic_time_ns <= now
          ? source.header.monotonic_time_ns
          : now;
  const auto size = std::min(reason.size(), gap.inline_payload.size());
  for (std::size_t i = 0; i < size; ++i)
    gap.inline_payload[i] = static_cast<std::byte>(static_cast<unsigned char>(reason[i]));
  gap.header.payload_size = static_cast<std::uint32_t>(size);
  return gap;
}

// The active frame whose live document a renderer observation names, if any.
content::RenderFrameHost* ActiveDocumentOwner(content::RenderProcessHost& process,
                                              const std::uint64_t frame_id,
                                              const std::uint64_t document_token_high,
                                              const std::uint64_t document_token_low) {
  content::RenderFrameHost* owner = nullptr;
  process.ForEachRenderFrameHost([&](content::RenderFrameHost* frame) {
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
  return owner;
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
              session_->expires_at_monotonic_ns(), session_->capture_canvas_images(),
              session_->capture_request_content());
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
                                          const bool caller_observed,
                                          const std::uint8_t caller_kind,
                                          const std::uint32_t caller_function_index,
                                          const std::uint32_t sample_index,
                                          const std::uint8_t js_invocation_state,
                                          const std::uint32_t js_invocation_id,
                                          const std::string& source_url,
                                          mojo_base::BigBuffer content) {
  constexpr auto mask = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                        NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  // A retired configuration or another session has nothing to record into.
  if (!queue_ || !wasm_epoch_lifetime_ || capture_epoch != wasm_capture_epoch_ ||
      !session_->IsActive() || session_id != session_->session_id() ||
      (session_->category_mask() & mask) != mask || now >= session_->expires_at_monotonic_ns())
    return;
  auto* process = content::RenderProcessHost::FromID(renderer_process_id_);
  if (!process || process_id != static_cast<std::uint32_t>(process->GetProcess().Pid()) ||
      !sequence_number)
    return;
  NativeWasmDispatchObservation observation;
  observation.header.category = NativeProbeCategory::kVm;
  observation.header.type = NativeProbeType::kWasmDispatchObservation;
  observation.header.session_id = session_id;
  observation.header.sequence_number = sequence_number;
  observation.header.monotonic_time_ns = monotonic_time_ns;
  observation.header.process_id = process_id;
  observation.header.thread_id = thread_id;
  observation.header.frame_id = frame_id;
  // This renderer's own sequence slot: every refusal fills it with a gap.
  const auto refuse = [&](std::string_view reason) {
    session_->Emit(RendererGap(NativeProbeEvent{.header = observation.header}, reason));
  };
  // Kind 0 with an index would publish a guessed function. An unwalked
  // record stays version 2: zero caller bytes are not an observed host.
  const bool caller_clear = caller_kind == kWasmDirectCallerUnknown && caller_function_index == 0;
  const bool caller_named =
      caller_kind == kWasmDirectCallerSameInstance && caller_function_index < 16U * 1024U * 1024U;
  const bool caller_ok = caller_observed ? (caller_clear || caller_named) : caller_clear;
  if (!monotonic_time_ns || monotonic_time_ns > now || !thread_id || !frame_id ||
      !execution_context_id || sample_index >= 16 || !caller_ok ||
      content.size() > 16U * 1024U * 1024U || function_index >= kNativeWasmFunctionIndexLimit ||
      table_count >= kNativeWasmFunctionIndexLimit) {
    refuse("native_wasm_dispatch_limit_or_invalid");
    return;
  }
  observation.execution_context_id = execution_context_id;
  observation.document_token_high = document_token_high;
  observation.document_token_low = document_token_low;
  observation.function_index = function_index;
  observation.module_byte_offset = module_byte_offset;
  observation.selector = selector;
  observation.table_count = table_count;
  observation.caller_observed = caller_observed;
  observation.caller_kind = caller_kind;
  observation.caller_function_index = caller_function_index;
  observation.sample_index = sample_index;
  observation.js_invocation_state = js_invocation_state;
  observation.js_invocation_id = js_invocation_id;
  observation.source_url = source_url;
  // The Mojo buffer is already a copy. Reject it before any sample slot is taken.
  observation.module_bytes = std::span<const std::uint8_t>(content.data(), content.size());
  if (!IsValidNativeWasmDispatchInput(observation)) {
    refuse("native_wasm_dispatch_module_invalid");
    return;
  }
  content::RenderFrameHost* owner =
      ActiveDocumentOwner(*process, frame_id, document_token_high, document_token_low);
  if (!owner) {
    refuse("native_wasm_dispatch_document_unavailable");
    return;
  }
  std::array<std::uint8_t, 32> module_digest{};
  const std::uint8_t* module_digest_bytes = nullptr;
  const auto& policy = session_->wasm_sample_budget();
  if (policy.module_allow_count != 0) {
    module_digest =
        NativeGuestDigest(std::span<const std::uint8_t>(content.data(), content.size()));
    module_digest_bytes = module_digest.data();
  }
  const auto budget =
      AdmitNativeWasmBudgetKeys(policy, wasm_dispatch_function_keys_, {}, wasm_budget_epoch_,
                                function_index, 0, module_digest_bytes);
  if (const char* reason = NativeWasmBrowserBudgetReason(budget.status, false)) {
    refuse(reason);
    return;
  }
  if (wasm_capture_count_ >= 16) {
    ReleaseNativeWasmBudgetAdmission(budget, wasm_dispatch_function_keys_, {}, wasm_budget_epoch_);
    refuse("native_wasm_dispatch_browser_budget_incomplete");
    return;
  }
  ++wasm_capture_count_;
  observation.module_bytes = {};
  auto* contents = content::WebContents::FromRenderFrameHost(owner);
  auto* main_frame = contents ? contents->GetPrimaryMainFrame() : nullptr;
  if (main_frame)
    observation.header.tab_id =
        static_cast<std::uint32_t>(main_frame->GetFrameTreeNodeId().value());
  const auto document = owner->GetWeakDocumentPtr();
  const std::weak_ptr<const std::uint64_t> lifetime = wasm_epoch_lifetime_;
  NativeArtifactCaptureSink::Get().CaptureWasmDispatch(
      observation, std::move(content), [document, lifetime]() {
        return !lifetime.expired() && document.AsRenderFrameHostIfValid() != nullptr;
      });
}

void NativeProbeHost::CaptureWasmIndirect(const std::uint64_t capture_epoch,
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
                                          const std::uint32_t table_index,
                                          const std::uint32_t slot,
                                          const std::uint32_t callee_function_index,
                                          const std::uint32_t resolution,
                                          const std::uint32_t sample_index,
                                          const std::uint8_t js_invocation_state,
                                          const std::uint32_t js_invocation_id,
                                          const std::string& source_url,
                                          mojo_base::BigBuffer content) {
  constexpr auto mask = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                        NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  // A retired configuration or another session has nothing to record into.
  if (!queue_ || !wasm_epoch_lifetime_ || capture_epoch != wasm_capture_epoch_ ||
      !session_->IsActive() || session_id != session_->session_id() ||
      (session_->category_mask() & mask) != mask || now >= session_->expires_at_monotonic_ns())
    return;
  auto* process = content::RenderProcessHost::FromID(renderer_process_id_);
  if (!process || process_id != static_cast<std::uint32_t>(process->GetProcess().Pid()) ||
      !sequence_number)
    return;
  NativeWasmIndirectObservation observation;
  observation.header.category = NativeProbeCategory::kVm;
  observation.header.type = NativeProbeType::kWasmIndirectObservation;
  observation.header.session_id = session_id;
  observation.header.sequence_number = sequence_number;
  observation.header.monotonic_time_ns = monotonic_time_ns;
  observation.header.process_id = process_id;
  observation.header.thread_id = thread_id;
  observation.header.frame_id = frame_id;
  // This renderer's own sequence slot: every refusal fills it with a gap.
  const auto refuse = [&](std::string_view reason) {
    session_->Emit(RendererGap(NativeProbeEvent{.header = observation.header}, reason));
  };
  if (!monotonic_time_ns || monotonic_time_ns > now || !thread_id || !frame_id ||
      !execution_context_id || sample_index >= kNativeWasmIndirectSampleBudget ||
      resolution >= kNativeWasmIndirectResolutionCount ||
      content.size() > kNativeArtifactMaxContentBytes ||
      function_index >= kNativeWasmFunctionIndexLimit ||
      table_index >= kNativeWasmFunctionIndexLimit || slot >= kNativeWasmFunctionIndexLimit ||
      callee_function_index >= kNativeWasmFunctionIndexLimit) {
    refuse("native_wasm_indirect_limit_or_invalid");
    return;
  }
  observation.execution_context_id = execution_context_id;
  observation.document_token_high = document_token_high;
  observation.document_token_low = document_token_low;
  observation.function_index = function_index;
  observation.module_byte_offset = module_byte_offset;
  observation.table_index = table_index;
  observation.slot = slot;
  observation.callee_function_index = callee_function_index;
  observation.resolution = static_cast<NativeWasmIndirectResolution>(resolution);
  observation.sample_index = sample_index;
  observation.js_invocation_state = js_invocation_state;
  observation.js_invocation_id = js_invocation_id;
  observation.source_url = source_url;
  observation.module_bytes = std::span<const std::uint8_t>(content.data(), content.size());
  if (!IsValidNativeWasmIndirectInput(observation)) {
    refuse("native_wasm_indirect_module_invalid");
    return;
  }
  content::RenderFrameHost* owner =
      ActiveDocumentOwner(*process, frame_id, document_token_high, document_token_low);
  if (!owner) {
    refuse("native_wasm_indirect_document_unavailable");
    return;
  }
  std::array<std::uint8_t, 32> module_digest{};
  const std::uint8_t* module_digest_bytes = nullptr;
  const auto& policy = session_->wasm_sample_budget();
  if (policy.module_allow_count != 0) {
    module_digest =
        NativeGuestDigest(std::span<const std::uint8_t>(content.data(), content.size()));
    module_digest_bytes = module_digest.data();
  }
  const auto budget = AdmitNativeWasmBudgetKeys(
      policy, wasm_indirect_function_keys_, wasm_indirect_site_keys_, wasm_budget_epoch_,
      function_index, module_byte_offset, module_digest_bytes);
  if (const char* reason = NativeWasmBrowserBudgetReason(budget.status, true)) {
    refuse(reason);
    return;
  }
  if (wasm_indirect_capture_count_ >= kNativeWasmIndirectSampleBudget) {
    ReleaseNativeWasmBudgetAdmission(budget, wasm_indirect_function_keys_, wasm_indirect_site_keys_,
                                     wasm_budget_epoch_);
    refuse("native_wasm_indirect_browser_budget_incomplete");
    return;
  }
  ++wasm_indirect_capture_count_;
  observation.module_bytes = {};
  auto* contents = content::WebContents::FromRenderFrameHost(owner);
  auto* main_frame = contents ? contents->GetPrimaryMainFrame() : nullptr;
  if (main_frame)
    observation.header.tab_id =
        static_cast<std::uint32_t>(main_frame->GetFrameTreeNodeId().value());
  const auto document = owner->GetWeakDocumentPtr();
  const std::weak_ptr<const std::uint64_t> lifetime = wasm_epoch_lifetime_;
  NativeArtifactCaptureSink::Get().CaptureWasmIndirect(
      observation, std::move(content), [document, lifetime]() {
        return !lifetime.expired() && document.AsRenderFrameHostIfValid() != nullptr;
      });
}

void NativeProbeHost::CaptureWasmExecution(const std::uint64_t capture_epoch,
                                           const std::uint64_t session_id,
                                           const std::uint64_t sequence_number,
                                           const std::uint64_t monotonic_time_ns,
                                           const std::uint32_t process_id,
                                           const std::uint32_t thread_id,
                                           const std::uint64_t frame_id,
                                           const std::uint64_t execution_context_id,
                                           const std::uint64_t document_token_high,
                                           const std::uint64_t document_token_low,
                                           const std::uint32_t invocation_id,
                                           const std::uint32_t function_index,
                                           const std::uint32_t module_byte_offset,
                                           const std::uint32_t related_sample_index,
                                           const std::uint8_t kind,
                                           const std::uint8_t reason,
                                           const std::uint8_t bounds,
                                           const std::uint8_t known,
                                           const std::uint8_t related_stream,
                                           const std::uint8_t js_invocation_state,
                                           const std::uint32_t js_invocation_id,
                                           const std::string& source_url,
                                           mojo_base::BigBuffer content) {
  constexpr auto mask = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                        NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (!queue_ || !wasm_epoch_lifetime_ || capture_epoch != wasm_capture_epoch_ ||
      !session_->IsActive() || session_id != session_->session_id() ||
      (session_->category_mask() & mask) != mask || now >= session_->expires_at_monotonic_ns())
    return;
  auto* process = content::RenderProcessHost::FromID(renderer_process_id_);
  if (!process || process_id != static_cast<std::uint32_t>(process->GetProcess().Pid()) ||
      !sequence_number)
    return;
  NativeWasmExecutionObservation observation;
  observation.header.category = NativeProbeCategory::kVm;
  observation.header.type = NativeProbeType::kWasmExecutionOutcome;
  observation.header.session_id = session_id;
  observation.header.sequence_number = sequence_number;
  observation.header.monotonic_time_ns = monotonic_time_ns;
  observation.header.process_id = process_id;
  observation.header.thread_id = thread_id;
  observation.header.frame_id = frame_id;
  const auto refuse = [&](std::string_view reason_name) {
    session_->Emit(RendererGap(NativeProbeEvent{.header = observation.header}, reason_name));
  };
  if (!monotonic_time_ns || monotonic_time_ns > now || !thread_id || !frame_id ||
      !execution_context_id || !invocation_id || kind > 1 ||
      reason >= kNativeWasmExecutionReasonCount ||
      content.size() > kNativeArtifactMaxContentBytes) {
    refuse("native_wasm_execution_limit_or_invalid");
    return;
  }
  if (wasm_execution_capture_count_ >= kNativeWasmExecutionBudget) {
    refuse("native_wasm_execution_browser_budget_incomplete");
    return;
  }
  ++wasm_execution_capture_count_;
  content::RenderFrameHost* owner =
      ActiveDocumentOwner(*process, frame_id, document_token_high, document_token_low);
  if (!owner) {
    refuse("native_wasm_execution_document_unavailable");
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
  observation.invocation_id = invocation_id;
  observation.function_index = function_index;
  observation.module_byte_offset = module_byte_offset;
  observation.related_sample_index = related_sample_index;
  observation.kind = static_cast<NativeWasmExecutionKind>(kind);
  observation.reason = static_cast<NativeWasmExecutionReason>(reason);
  observation.bounds = static_cast<NativeWasmExecutionBounds>(bounds);
  observation.known = known;
  observation.related_stream = static_cast<NativeWasmExecutionStream>(related_stream);
  observation.js_invocation_state = js_invocation_state;
  observation.js_invocation_id = js_invocation_id;
  observation.source_url = source_url;
  const auto document = owner->GetWeakDocumentPtr();
  const std::weak_ptr<const std::uint64_t> lifetime = wasm_epoch_lifetime_;
  NativeArtifactCaptureSink::Get().CaptureWasmExecution(
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
                                         mojo_base::BigBuffer wasm_module,
                                         mojo_base::BigBuffer bytecode) {
  const auto mask = NativeProbeCategoryMask(NativeProbeCategory::kVm) |
                    NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  // A retired configuration's records are discarded like its queue records.
  if (!queue_ || !capture_epoch || capture_epoch != wasm_capture_epoch_ || !session_->IsActive() ||
      (session_->category_mask() & mask) != mask ||
      invocation_record.size() != sizeof(NativeProbeEvent) ||
      dispatch_record.size() != sizeof(NativeProbeEvent))
    return;
  auto* process = content::RenderProcessHost::FromID(renderer_process_id_);
  if (!process)
    return;
  NativeGuestCapture capture;
  capture.invocation = EventFromRecord(invocation_record);
  capture.dispatch = EventFromRecord(dispatch_record);
  const auto& h = capture.dispatch.header;
  const bool own_identity = h.session_id == session_->session_id() && h.sequence_number &&
                            h.process_id == static_cast<std::uint32_t>(process->GetProcess().Pid());
  const bool carries_module = wasm_module.size() != 0;
  // Every refusal is explicit: the dispatch slot becomes a gap and a refused
  // module transfer is reported so the renderer can resend those bytes.
  const auto refuse = [&](std::string_view reason) {
    if (own_identity)
      session_->Emit(RendererGap(capture.dispatch, reason));
    if (carries_module && own_identity)
      SendNativeGuestModuleStatus(capture_epoch, h.sequence_number, false);
  };
  if (guest_capture_count_ >= kNativeGuestSampleLimit) {
    refuse("native_guest_browser_sample_budget");
    return;
  }
  ++guest_capture_count_;
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (!own_identity || !h.monotonic_time_ns || h.monotonic_time_ns > now ||
      capture.invocation.header.monotonic_time_ns > h.monotonic_time_ns ||
      (carries_module && wasm_module.size() < 8) ||
      wasm_module.size() > kNativeArtifactMaxContentBytes || bytecode.size() == 0 ||
      bytecode.size() > kNativeGuestSnapshotLimit) {
    refuse("native_guest_capture_invalid");
    return;
  }
  if (adapter_json.empty() || adapter_json != session_->guest_adapter_json()) {
    refuse("native_guest_adapter_mismatch");
    return;
  }
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
  if (!owner) {
    refuse("native_guest_document_unavailable");
    return;
  }
  auto* contents = content::WebContents::FromRenderFrameHost(owner);
  auto* main_frame = contents ? contents->GetPrimaryMainFrame() : nullptr;
  const auto tab =
      main_frame ? static_cast<std::uint32_t>(main_frame->GetFrameTreeNodeId().value()) : 0;
  capture.invocation.header.tab_id = tab;
  capture.dispatch.header.tab_id = tab;
  // Private copies defeat shared BigBuffer mutation between hashing and transfer.
  const std::vector<std::uint8_t> module_copy(wasm_module.begin(), wasm_module.end());
  const std::vector<std::uint8_t> bytecode_copy(bytecode.begin(), bytecode.end());
  const auto adapter = ParseNativeWasmGuestAdapter(adapter_json);
  if (!adapter ||
      (!module_copy.empty() && NativeGuestDigest(module_copy) != adapter->module_sha256)) {
    refuse("native_guest_module_mismatch");
    return;
  }
  const auto field = [&](std::size_t offset, std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t n = 0; n < width; ++n)
      value |= std::to_integer<std::uint64_t>(capture.dispatch.inline_payload[offset + n])
               << (n * 8U);
    return value;
  };
  // The dispatch must be at the configured site its invocation marker names.
  // All sites count against the one browser sample budget above.
  std::uint32_t site_index = 0;
  const auto* site = FindNativeGuestSite(*adapter, static_cast<std::uint32_t>(field(4, 4)),
                                         static_cast<std::uint32_t>(field(8, 4)), &site_index);
  std::uint64_t marker_site = 0;
  for (std::size_t n = 0; n < 4; ++n)
    marker_site |= std::to_integer<std::uint64_t>(capture.invocation.inline_payload[80 + n])
                   << (n * 8U);
  if (!site || marker_site != site_index || guest_capture_count_ > adapter->sample_limit ||
      field(20, 4) >= adapter->sample_limit || field(76, 4) != site->pc_local_index ||
      field(88, 4) != site->memory_index ||
      field(80, 8) != static_cast<std::uint64_t>(site->pc_adjustment) ||
      bytecode_copy.size() < site->opcode_width ||
      field(40, 8) > bytecode_copy.size() - site->opcode_width) {
    refuse("native_guest_capture_invalid");
    return;
  }
  std::uint32_t opcode = 0;
  for (std::uint32_t n = 0; n < site->opcode_width; ++n) {
    const auto shift = site->opcode_big_endian ? 8U * (site->opcode_width - n - 1U) : 8U * n;
    opcode |= static_cast<std::uint32_t>(bytecode_copy[static_cast<std::size_t>(field(40, 8)) + n])
              << shift;
  }
  if (field(92, 4) != opcode) {
    refuse("native_guest_capture_invalid");
    return;
  }
  capture.execution_context_id = execution_context_id;
  capture.document_token_high = document_token_high;
  capture.document_token_low = document_token_low;
  capture.source_url = source_url;
  capture.adapter_json = adapter_json;
  capture.module_bytes = module_copy;
  capture.bytecode_bytes = bytecode_copy;
  const auto document = owner->GetWeakDocumentPtr();
  const std::weak_ptr<const std::uint64_t> lifetime = wasm_epoch_lifetime_;
  std::function<void(bool)> module_status;
  if (carries_module) {
    module_status = [host = weak_factory_.GetWeakPtr(), capture_epoch,
                     token = h.sequence_number](bool accepted) {
      if (host)
        host->SendNativeGuestModuleStatus(capture_epoch, token, accepted);
    };
  }
  NativeArtifactCaptureSink::Get().CaptureNativeGuest(
      capture, capture_epoch,
      [document, lifetime]() {
        auto* current = document.AsRenderFrameHostIfValid();
        return !lifetime.expired() && current && current->IsActive();
      },
      std::move(module_status));
}

void NativeProbeHost::SendNativeGuestModuleStatus(const std::uint64_t capture_epoch,
                                                  const std::uint64_t module_token,
                                                  const bool accepted) {
  if (client_.is_bound() && capture_epoch && capture_epoch == wasm_capture_epoch_)
    client_->NativeGuestModuleStatus(capture_epoch, module_token, accepted);
}

void NativeProbeHost::CaptureNativeGuestHost(const std::uint64_t capture_epoch,
                                             const std::vector<std::uint8_t>& event_record) {
  // The renderer bounds parent-routed hosts per configuration and the sink
  // bounds what it holds; every admitted host is published, with or without
  // its parent link.
  if (!queue_ || !capture_epoch || capture_epoch != wasm_capture_epoch_ || !session_->IsActive() ||
      event_record.size() != sizeof(NativeProbeEvent))
    return;
  NativeProbeEvent event = EventFromRecord(event_record);
  auto* process = content::RenderProcessHost::FromID(renderer_process_id_);
  if (!process)
    return;
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  const bool own_identity =
      event.header.session_id == session_->session_id() && event.header.sequence_number &&
      event.header.process_id == static_cast<std::uint32_t>(process->GetProcess().Pid());
  if (own_identity && (!event.header.monotonic_time_ns || event.header.monotonic_time_ns > now)) {
    session_->Emit(RendererGap(event, "native_guest_host_malformed"));
    return;
  }
  if (!own_identity) {
    // Another identity's slot is not this renderer's to fill.
    if (!guest_host_malformed_gap_emitted_) {
      guest_host_malformed_gap_emitted_ = true;
      NativeProbeEvent gap;
      gap.header.category = NativeProbeCategory::kVm;
      gap.header.type = NativeProbeType::kGap;
      gap.header.session_id = session_->session_id();
      gap.header.sequence_number = NativeProbeSession::Get().NextBrowserSequence();
      gap.header.monotonic_time_ns = now;
      gap.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
      gap.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
      constexpr std::string_view reason = "native_guest_host_malformed";
      gap.header.payload_size = reason.size();
      for (std::size_t i = 0; i < reason.size(); ++i)
        gap.inline_payload[i] = static_cast<std::byte>(reason[i]);
      session_->Emit(gap);
    }
    return;
  }
  event.header.tab_id = FrameTab(CurrentFrameTabs(renderer_process_id_), event.header.frame_id);
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
  const bool stack_artifact =
      kind == static_cast<std::uint16_t>(NativeArtifactKind::kStack) &&
      capture_origin == static_cast<std::uint16_t>(NativeArtifactCaptureOrigin::kRequestStack);
  std::function<void()> on_refused;
  if (stack_artifact) {
    on_refused = [host = weak_factory_.GetWeakPtr(), creator_event_id] {
      if (host) {
        host->SendNativeStackArtifactRefused(creator_event_id);
      }
    };
  }
  NativeArtifactCaptureSink::Get().CaptureGeneratedArtifact(
      static_cast<NativeArtifactKind>(kind),
      static_cast<NativeArtifactCaptureOrigin>(capture_origin), creator_event_id,
      execution_context_id, frame_id, source_url, std::move(content), 0, std::move(on_refused));
}

void NativeProbeHost::SendNativeStackArtifactRefused(const std::uint64_t creator_event_id) {
  if (client_.is_bound()) {
    client_->NativeStackArtifactRefused(creator_event_id);
  }
}

void NativeProbeHost::Configure(const std::uint64_t session_id,
                                const std::uint64_t category_mask,
                                const std::uint64_t expires_at_monotonic_ns,
                                const bool capture_canvas_images,
                                const bool capture_request_content) {
  Disable();
  if (!client_.is_bound() || session_id == 0 ||
      wasm_capture_epoch_ == std::numeric_limits<std::uint64_t>::max() || IsBrowserInternal()) {
    return;
  }
  auto* const process = content::RenderProcessHost::FromID(renderer_process_id_);
  renderer_os_pid_ = process && process->GetProcess().IsValid()
                         ? static_cast<std::uint32_t>(process->GetProcess().Pid())
                         : 0;
  reported_exclusions_ = {};
  extension_requests_excluded_ = 0;
  no_page_requests_excluded_ = 0;

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
  const auto encoded = EncodeNativeWasmSampleBudgetPolicy(session_->wasm_sample_budget());
  client_->SetWasmSampleBudget(std::vector<std::uint8_t>(encoded.begin(), encoded.end()));
  client_->Configure(session_id, category_mask, expires_at_monotonic_ns, capture_canvas_images,
                     std::move(renderer_region), wasm_capture_epoch_,
                     session_->guest_adapter_json(), session_->js_dispatch_sites(),
                     session_->js_invocation_sites(), session_->js_invocation_digests(),
                     capture_request_content, session_->capture_browser_internal());
}

void NativeProbeHost::Disable() {
  // Records the renderer already queued, and drops it has not reported, are
  // this configuration's evidence: publish them before the mapping goes.
  disabling_ = true;
  Drain();
  disabling_ = false;
  wasm_epoch_lifetime_.reset();
  if (wasm_capture_epoch_ != std::numeric_limits<std::uint64_t>::max())
    ++wasm_capture_epoch_;
  wasm_capture_count_ = 0;
  wasm_indirect_capture_count_ = 0;
  if ((wasm_budget_epoch_ & 1U) == 0 &&
      wasm_budget_epoch_ <= std::numeric_limits<std::uint64_t>::max() - 2)
    wasm_budget_epoch_ += 2;
  wasm_execution_capture_count_ = 0;
  guest_capture_count_ = 0;
  guest_host_malformed_gap_emitted_ = false;
  if (client_.is_bound()) {
    client_->Disable();
  }
  queue_ = nullptr;
  reported_dropped_events_ = 0;
  queue_mapping_ = base::WritableSharedMemoryMapping();
  queue_region_ = base::UnsafeSharedMemoryRegion();
}

void NativeProbeHost::ResetWasmSampleBudgets() {
  wasm_capture_count_ = 0;
  wasm_indirect_capture_count_ = 0;
  if ((wasm_budget_epoch_ & 1U) == 0 &&
      wasm_budget_epoch_ <= std::numeric_limits<std::uint64_t>::max() - 2)
    wasm_budget_epoch_ += 2;
  if (client_.is_bound())
    client_->ResetWasmSampleBudgets();
}

bool NativeProbeHost::IsBrowserInternal() {
  if (!browser_internal_ && !session_->capture_browser_internal() &&
      IsNativeBrowserInternalProcess(renderer_process_id_)) {
    browser_internal_ = true;
    session_->NoteWebUiRendererExcluded();
  }
  return browser_internal_;
}

void NativeProbeHost::ReportExclusions() {
  for (std::size_t slot = 0; slot < reported_exclusions_.size(); ++slot) {
    const std::uint64_t count = queue_->ExclusionCount(slot);
    if (count > reported_exclusions_[slot]) {
      reported_exclusions_[slot] = count;
      session_->EmitExclusion(renderer_os_pid_, NativeRendererExclusionClass(slot), count);
    }
  }
}

std::uint32_t NativeProbeHost::FrameTab(
    const std::unordered_map<std::uint64_t, std::uint32_t>& live,
    const std::uint64_t frame_id) const {
  if (frame_id == 0) {
    return 0;
  }
  if (const auto tab = live.find(frame_id); tab != live.end()) {
    return tab->second;
  }
  return NativeTabResolver::Get().FrameTab(renderer_process_id_, frame_id);
}

bool NativeProbeHost::IsWorkerRequestStart(const NativeProbeEvent& event) {
  // A memory-cache reuse starts its own row, so it links like a start.
  return event.header.category == NativeProbeCategory::kNetwork &&
         (event.header.type == NativeProbeType::kRequestInitiated ||
          event.header.type == NativeProbeType::kMemoryCacheReuse) &&
         IsNativeWorkerOwner(static_cast<NativeLoaderKind>(event.header.loader_kind));
}

bool NativeProbeHost::IsExcludedRequestRecord(const NativeProbeEvent& event) const {
  return event.header.category == NativeProbeCategory::kNetwork && event.header.request_id != 0 &&
         std::ranges::find(excluded_requests_, event.header.request_id) != excluded_requests_.end();
}

// protocol/native-network-v3.md: the record, its tab set the first time this
// session names it, then the link.
void NativeProbeHost::EmitWorkerRequest(NativeProbeEvent& event) {
  const auto kind = static_cast<NativeLoaderKind>(event.header.loader_kind);
  // A service worker's http(s) and ws(s) requests reach the proxy, whose
  // browser half takes the same class 68 answer as this record.
  const NativeTabResolver::RendererRequest request{
      renderer_process_id_, static_cast<std::uint32_t>(event.header.request_id)};
  const bool shared = kind == NativeLoaderKind::kServiceWorker && event.header.scheme_class >= 1 &&
                      event.header.scheme_class <= 4;
  const NativeTabResolution resolution = NativeTabResolver::Get().Resolve(
      kind, event.header.frame_id, event.header.session_id, shared ? &request : nullptr);
  const bool extension = resolution.status == NativeTabResolution::Status::kExtension;
  if (extension && !(session_->capture_extension_traffic() && resolution.extension)) {
    excluded_requests_[excluded_next_++ % excluded_requests_.size()] = event.header.request_id;
    session_->EmitExclusion(renderer_os_pid_, kNativeExtensionWorkerExclusion,
                            ++extension_requests_excluded_);
    return;
  }
  if (resolution.status == NativeTabResolution::Status::kNoPage) {
    excluded_requests_[excluded_next_++ % excluded_requests_.size()] = event.header.request_id;
    session_->EmitExclusion(renderer_os_pid_, kNativeServiceWorkerNoPageExclusion,
                            ++no_page_requests_excluded_);
    return;
  }
  if (!extension && resolution.status != NativeTabResolution::Status::kLinked) {
    session_->Emit(event);
    return;
  }
  if (!extension && resolution.tabs.size() == 1) {
    event.header.tab_id = resolution.tabs[0];
  }
  session_->Emit(event);
  NativeProbeHeader identity;
  identity.session_id = event.header.session_id;
  identity.monotonic_time_ns = event.header.monotonic_time_ns;
  identity.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  identity.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  if (extension) {
    identity.sequence_number = session_->NextBrowserSequence();
    session_->Emit(MakeNativeRequestExtensionLink(
        event.header, identity, static_cast<NativeLoaderKind>(event.header.loader_kind),
        *resolution.extension));
    return;
  }
  EmitNativeTabLink(
      resolution, event.header, false, identity, [this] { return session_->NextBrowserSequence(); },
      [this](const NativeProbeEvent& record) { session_->Emit(record); });
}

// Shared class 68 answers the resolver evicted before their other half asked,
// whichever side inserted the newer answer.
void NativeProbeHost::ReportUnsharedDecisions() {
  for (std::uint64_t evicted = NativeTabResolver::Get().TakeEvictedSharedDecisions(); evicted;
       --evicted) {
    session_->EmitNamedGap(NativeProbeCategory::kNetwork, kNativeSharedDecisionEvictedGap);
  }
}

void NativeProbeHost::Drain() {
  if (!queue_) {
    return;
  }
  // The renderer is counted once as excluded; what it queued leaves with it.
  if (browser_internal_ || IsBrowserInternal()) {
    NativeProbeEvent discarded;
    while (queue_->TryPop(discarded)) {
    }
    queue_->ClearNotificationPending();
    if (!disabling_) {
      Disable();
    }
    return;
  }

  const auto frame_tabs = CurrentFrameTabs(renderer_process_id_);
  for (;;) {
    NativeProbeEvent event;
    NativeProbeEvent last_event;
    bool drained_event = false;
    while (queue_->TryPop(event)) {
      last_event = event;
      drained_event = true;
      if (IsWorkerRequestStart(event)) {
        EmitWorkerRequest(event);
        ReportUnsharedDecisions();
        continue;
      }
      if (IsExcludedRequestRecord(event)) {
        continue;
      }
      if (const std::uint32_t tab = FrameTab(frame_tabs, event.header.frame_id)) {
        event.header.tab_id = tab;
      }
      session_->Emit(event);
    }

    const std::uint64_t dropped = queue_->DroppedCount();
    if (drained_event && dropped > reported_dropped_events_) {
      session_->Emit(MakeNativeProbeGapEvent(last_event, dropped - reported_dropped_events_));
      reported_dropped_events_ = dropped;
    }

    queue_->ClearNotificationPending();
    // After the clear, so a later count either is read here or wakes again.
    ReportExclusions();
    if (queue_->Empty() || !queue_->MarkNotificationPending()) {
      return;
    }
  }
}

}  // namespace reb
