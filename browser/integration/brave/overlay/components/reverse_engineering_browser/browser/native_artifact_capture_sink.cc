// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/process/process_handle.h"
#include "base/task/sequenced_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "url/gurl.h"

namespace reb {
namespace {

constexpr std::size_t kMaxArtifactBytes = kNativeArtifactMaxContentBytes;
constexpr std::size_t kMaxActiveCaptureBytes = 32U * 1024U * 1024U;
constexpr std::size_t kRuntimeTypedArrayMinBytes = 32;
constexpr std::size_t kRuntimeTypedArrayMaxSnapshots = 16;
constexpr std::uint64_t kExpiryFlushLeadNs = 250'000'000;
// Synced with blink.mojom.ResourceType.kScript. MIME classification below also
// covers module and worker script requests that use another resource type.
constexpr int kScriptResourceType = 3;

bool IsJavaScriptMimeType(const std::string_view mime_type) noexcept {
  return mime_type == "application/ecmascript" || mime_type == "application/javascript" ||
         mime_type == "application/x-ecmascript" || mime_type == "application/x-javascript" ||
         mime_type == "text/ecmascript" || mime_type == "text/javascript" ||
         mime_type == "text/javascript1.0" || mime_type == "text/javascript1.1" ||
         mime_type == "text/javascript1.2" || mime_type == "text/javascript1.3" ||
         mime_type == "text/javascript1.4" || mime_type == "text/javascript1.5" ||
         mime_type == "text/jscript" || mime_type == "text/livescript" ||
         mime_type == "text/x-ecmascript" || mime_type == "text/x-javascript";
}

NativeArtifactKind Classify(const network::ResourceRequest& request,
                            const network::mojom::URLResponseHead& response_head) {
  if (response_head.mime_type == "application/wasm") {
    return NativeArtifactKind::kWasm;
  }
  if (request.resource_type == kScriptResourceType ||
      IsJavaScriptMimeType(response_head.mime_type)) {
    return NativeArtifactKind::kJavaScript;
  }
  return NativeArtifactKind::kUnknown;
}

std::string StatusName(const NativeArtifactReceiveStatus status) {
  switch (status) {
    case NativeArtifactReceiveStatus::kAccepted:
      return "accepted";
    case NativeArtifactReceiveStatus::kEndOfStream:
      return "end_of_stream";
    case NativeArtifactReceiveStatus::kInvalid:
      return "invalid";
    case NativeArtifactReceiveStatus::kTooLarge:
      return "too_large";
    case NativeArtifactReceiveStatus::kSensitiveCaptureDisabled:
      return "sensitive_capture_disabled";
    case NativeArtifactReceiveStatus::kConflict:
      return "conflict";
    case NativeArtifactReceiveStatus::kIoError:
      return "io_error";
  }
  return "unknown";
}

}  // namespace

NativeArtifactCaptureSink& NativeArtifactCaptureSink::Get() {
  static base::NoDestructor<NativeArtifactCaptureSink> sink;
  return *sink;
}

NativeArtifactCaptureSink::NativeArtifactCaptureSink() = default;
NativeArtifactCaptureSink::~NativeArtifactCaptureSink() = default;

bool NativeArtifactCaptureSink::IsEnabled() const noexcept {
  return IsEnabledFor(NativeProbeCategory::kArtifact);
}

bool NativeArtifactCaptureSink::IsEnabledFor(const NativeProbeCategory category) const noexcept {
  if (emitter_.load(std::memory_order_acquire) == nullptr ||
      !NativeArtifactSocketClient::Get().IsConnected() ||
      (category_mask_.load(std::memory_order_relaxed) & NativeProbeCategoryMask(category)) == 0) {
    return false;
  }
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  return now < expires_at_monotonic_ns_.load(std::memory_order_relaxed);
}

void NativeArtifactCaptureSink::SetEmitter(const NativeProbeEmitter emitter,
                                           const std::uint64_t session_id,
                                           const std::uint64_t category_mask,
                                           const std::uint64_t expires_at_monotonic_ns) noexcept {
  emitter_.store(nullptr, std::memory_order_release);
  generation_.fetch_add(1, std::memory_order_acq_rel);
  session_id_.store(emitter ? session_id : 0, std::memory_order_relaxed);
  category_mask_.store(emitter ? category_mask : 0, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(emitter ? expires_at_monotonic_ns : 0, std::memory_order_relaxed);
  pending_.clear();
  guest_groups_.clear();
  guest_invocations_.clear();
  guest_dispatches_.clear();
  guest_receipts_.clear();
  guest_routed_host_count_ = 0;
  guest_held_host_count_ = 0;
  guest_capture_count_ = 0;
  guest_host_identities_.clear();
  guest_host_malformed_gap_emitted_ = false;
  guest_host_parent_lost_gap_emitted_ = false;
  guest_host_parent_omitted_gap_emitted_ = false;
  guest_budget_gap_emitted_ = false;
  wasm_dispatch_modules_.clear();
  wasm_dispatch_count_ = 0;
  wasm_dispatch_budget_gap_emitted_ = false;
  runtime_typed_array_count_.store(0, std::memory_order_relaxed);
  allocating_scripts_.clear();
  emitter_.store(emitter, std::memory_order_release);
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (emitter && expires_at_monotonic_ns > now && base::SequencedTaskRunner::HasCurrentDefault()) {
    // The session refuses every record after expiry, so pending guest work is
    // turned into explicit gaps slightly earlier. The generation check makes a
    // replaced configuration's flush a no-op.
    const auto lead = std::min<std::uint64_t>(kExpiryFlushLeadNs, expires_at_monotonic_ns - now);
    const auto delay = expires_at_monotonic_ns - now - lead;
    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce([](std::uint64_t generation) { Get().FlushBeforeExpiry(generation); },
                       generation_.load(std::memory_order_acquire)),
        base::Nanoseconds(static_cast<std::int64_t>(delay)));
  }
}

mojo::ScopedDataPipeConsumerHandle NativeArtifactCaptureSink::MaybeCaptureResponse(
    const std::uint64_t request_id,
    const std::uint64_t frame_id,
    const std::uint64_t creator_event_id,
    const network::ResourceRequest& request,
    const network::mojom::URLResponseHead& response_head,
    mojo::ScopedDataPipeConsumerHandle body) {
  if (!IsEnabled() || !body.is_valid()) {
    return body;
  }
  const NativeArtifactKind kind = Classify(request, response_head);
  if (kind == NativeArtifactKind::kUnknown) {
    return body;
  }

  const std::uint64_t artifact_id = next_artifact_id_.fetch_add(1, std::memory_order_relaxed);
  const std::size_t declared_size =
      response_head.content_length > 0 &&
              static_cast<std::uint64_t>(response_head.content_length) <=
                  std::numeric_limits<std::size_t>::max()
          ? static_cast<std::size_t>(response_head.content_length)
          : 0;
  if (declared_size > kMaxArtifactBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, request_id, frame_id,
               "declared_size_limit");
    return body;
  }
  const std::size_t reservation = kMaxArtifactBytes;
  if (!Reserve(reservation)) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, request_id, frame_id,
               "active_memory_limit");
    return body;
  }

  auto context = std::make_unique<CaptureContext>();
  context->header.kind = kind;
  context->header.session_id = session_id_.load(std::memory_order_relaxed);
  context->header.frame_id = frame_id;
  context->header.artifact_id = artifact_id;
  context->header.creator_event_id = creator_event_id;
  context->header.capture_origin = NativeArtifactCaptureOrigin::kNetworkResponse;
  context->url = request.url.spec();
  context->mime_type = response_head.mime_type;
  context->reservation_bytes = reservation;
  context->request_id = request_id;
  context->frame_id = frame_id;
  context->generation = generation_.load(std::memory_order_acquire);
  if (context->url.empty() || context->url.size() > kNativeArtifactMaxUrlBytes ||
      context->mime_type.empty() || context->mime_type.size() > kNativeArtifactMaxMimeTypeBytes) {
    Release(reservation);
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, request_id, frame_id,
               "metadata_limit");
    return body;
  }

  bool started = false;
  body = NativeArtifactBodyTee::Create(std::move(body), kMaxArtifactBytes, declared_size,
                                       base::BindOnce(&NativeArtifactCaptureSink::OnBodyComplete,
                                                      base::Unretained(this), std::move(context)),
                                       started);
  if (!started) {
    Release(reservation);
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, request_id, frame_id,
               "tee_unavailable");
  }
  return body;
}

void NativeArtifactCaptureSink::CaptureRuntimeTypedArray(const int renderer_process_id,
                                                         const std::uint64_t capture_session_id,
                                                         const std::uint64_t script_id,
                                                         const bool is_eval,
                                                         const std::uint64_t creator_event_id,
                                                         const std::uint64_t execution_context_id,
                                                         const std::uint64_t frame_id,
                                                         const std::string_view source_url,
                                                         mojo_base::BigBuffer script_source,
                                                         mojo_base::BigBuffer content) {
  if (!IsEnabledFor(NativeProbeCategory::kVm) || capture_session_id == 0 ||
      capture_session_id != session_id_.load(std::memory_order_relaxed)) {
    return;
  }
  if (script_id == 0 || execution_context_id == 0 || script_source.size() > kMaxArtifactBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, 0, 0, frame_id,
               "allocating_script_unavailable", NativeProbeCategory::kVm);
    return;
  }
  const ScriptKey key{renderer_process_id, execution_context_id, frame_id, script_id};
  auto parent = allocating_scripts_.find(key);
  if (parent == allocating_scripts_.end()) {
    if (script_source.size() == 0) {
      EmitResult(NativeProbeType::kArtifactCaptureFailed, 0, 0, frame_id,
                 "allocating_script_unavailable", NativeProbeCategory::kVm);
      return;
    }
    if (allocating_scripts_.size() >= kRuntimeTypedArrayMaxSnapshots) {
      EmitResult(NativeProbeType::kArtifactCaptureFailed, 0, 0, frame_id,
                 "allocating_script_registry_limit", NativeProbeCategory::kVm);
      return;
    }
    // Eval source uses the same exact-script capture path. is_eval is kept on
    // the submission for admission; it never changes the identity relation.
    static_cast<void>(is_eval);
    const std::uint64_t artifact_id = CaptureGeneratedArtifact(
        NativeArtifactKind::kJavaScript, NativeArtifactCaptureOrigin::kRuntimeAllocatingScript, 0,
        execution_context_id, frame_id, source_url, std::move(script_source));
    if (artifact_id == 0) {
      EmitResult(NativeProbeType::kArtifactCaptureFailed, 0, 0, frame_id,
                 "allocating_script_unavailable", NativeProbeCategory::kVm);
      return;
    }
    parent = allocating_scripts_.emplace(key, artifact_id).first;
  }
  CaptureGeneratedArtifact(NativeArtifactKind::kBytecodeBuffer,
                           NativeArtifactCaptureOrigin::kRuntimeTypedArray, creator_event_id,
                           execution_context_id, frame_id, source_url, std::move(content),
                           parent->second);
}

namespace {
std::uint64_t GuestField(const NativeProbeEvent& event, std::size_t offset, std::size_t width = 8) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i)
    value |= std::to_integer<std::uint64_t>(event.inline_payload[offset + i]) << (i * 8U);
  return value;
}
bool GuestEnvelope(const NativeProbeEvent& event) {
  const auto& h = event.header;
  return h.protocol_version == kNativeProbeProtocolVersion && h.header_size == sizeof(h) &&
         h.category == NativeProbeCategory::kVm && h.payload_size == 128 && h.flags == 0 &&
         h.reserved1 == 0 && h.session_id && h.process_id && h.thread_id && h.frame_id &&
         h.sequence_number && h.monotonic_time_ns && h.artifact_id == 0 && h.navigation_id == 0 &&
         GuestField(event, 0, 2) == 1 && GuestField(event, 2, 2) == 128 &&
         std::all_of(event.reserved.begin(), event.reserved.end(),
                     [](auto b) { return b == std::byte{0}; });
}
bool GuestSameScope(const NativeProbeEvent& a, const NativeProbeEvent& b) {
  return a.header.session_id == b.header.session_id && a.header.process_id == b.header.process_id &&
         a.header.thread_id == b.header.thread_id && a.header.frame_id == b.header.frame_id &&
         a.header.navigation_id == b.header.navigation_id;
}
}  // namespace

void NativeArtifactCaptureSink::EmitRendererGap(const NativeProbeEvent& source,
                                                const std::string_view reason) noexcept {
  const auto emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter)
    return;
  NativeProbeEvent gap;
  gap.header.category = NativeProbeCategory::kVm;
  gap.header.type = NativeProbeType::kGap;
  gap.header.session_id = source.header.session_id;
  gap.header.process_id = source.header.process_id;
  gap.header.thread_id = source.header.thread_id;
  gap.header.frame_id = source.header.frame_id;
  gap.header.tab_id = source.header.tab_id;
  gap.header.sequence_number = source.header.sequence_number;
  gap.header.monotonic_time_ns = source.header.monotonic_time_ns;
  const auto size = std::min(reason.size(), gap.inline_payload.size());
  for (std::size_t i = 0; i < size; ++i)
    gap.inline_payload[i] = static_cast<std::byte>(static_cast<unsigned char>(reason[i]));
  gap.header.payload_size = static_cast<std::uint32_t>(size);
  emitter(gap);
}

void NativeArtifactCaptureSink::PublishUnparentedHost(NativeProbeEvent host,
                                                      bool& gap_emitted,
                                                      const std::string_view reason) {
  const auto emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter)
    return;
  host.header.parent_event_id = 0;
  host.header.artifact_id = 0;
  emitter(host);
  if (!gap_emitted) {
    gap_emitted = true;
    EmitResult(NativeProbeType::kGap, 0, 0, host.header.frame_id, std::string(reason),
               NativeProbeCategory::kVm);
  }
}

void NativeArtifactCaptureSink::CaptureNativeGuest(const NativeGuestCapture& capture,
                                                   const std::uint64_t epoch,
                                                   std::function<bool()> is_current_document,
                                                   std::function<void(bool)> module_status) {
  DrainGuestDependencies();
  const auto& dispatch = capture.dispatch;
  const auto& invocation = capture.invocation;
  const bool carries_module = !capture.module_bytes.empty();
  // Every refusal fills the dispatch's renderer sequence slot with an explicit
  // gap, and a refused module transfer lets the renderer resend those bytes.
  const auto refuse = [&](std::string_view reason) {
    EmitRendererGap(dispatch, reason);
    if (carries_module && module_status)
      module_status(false);
  };
  if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled() ||
      dispatch.header.session_id != session_id_.load(std::memory_order_relaxed))
    return;
  if (guest_capture_count_ >= kNativeGuestSampleLimit) {
    if (carries_module && module_status)
      module_status(false);
    if (!guest_budget_gap_emitted_) {
      guest_budget_gap_emitted_ = true;
      EmitRendererGap(dispatch, "native_guest_browser_sample_budget");
    }
    return;
  }
  ++guest_capture_count_;
  if (!epoch || !is_current_document || !is_current_document() || !GuestEnvelope(dispatch) ||
      !GuestEnvelope(invocation) || !GuestSameScope(dispatch, invocation) ||
      dispatch.header.type != NativeProbeType::kWasmGuestDispatch ||
      invocation.header.type != NativeProbeType::kWasmGuestInvocation ||
      invocation.header.parent_event_id ||
      dispatch.header.parent_event_id != invocation.header.sequence_number ||
      dispatch.header.sequence_number <= invocation.header.sequence_number ||
      !capture.execution_context_id ||
      !(capture.document_token_high || capture.document_token_low) ||
      (carries_module && capture.module_bytes.size() < 8) ||
      capture.module_bytes.size() > kMaxArtifactBytes || capture.adapter_json.empty() ||
      capture.adapter_json.size() > kNativeGuestAdapterLimit || capture.bytecode_bytes.empty() ||
      capture.bytecode_bytes.size() > kNativeGuestSnapshotLimit || capture.source_url.empty() ||
      capture.source_url.size() > kNativeArtifactMaxUrlBytes ||
      GuestField(dispatch, 72, 4) != capture.bytecode_bytes.size() ||
      GuestField(dispatch, 40) >= capture.bytecode_bytes.size() || GuestField(dispatch, 56) ||
      !GuestField(dispatch, 24) || !GuestField(dispatch, 32) ||
      GuestField(dispatch, 24) != GuestField(invocation, 8) ||
      GuestField(dispatch, 32) != GuestField(invocation, 16) ||
      GuestField(dispatch, 4, 4) != GuestField(invocation, 4, 4) || GuestField(invocation, 24) ||
      GuestField(dispatch, 20, 4) >= kNativeGuestSampleLimit ||
      !std::all_of(invocation.inline_payload.begin() + 64, invocation.inline_payload.end(),
                   [](auto b) { return b == std::byte{0}; })) {
    refuse("native_guest_dependency_rejected");
    return;
  }
  const GuestEventKey key{dispatch.header.process_id, dispatch.header.sequence_number};
  if (guest_dispatches_.contains(key) || guest_invocations_.contains(key) ||
      guest_dispatches_.contains(
          {invocation.header.process_id, invocation.header.sequence_number}) ||
      guest_dispatches_.size() >= kNativeGuestSampleLimit) {
    refuse("native_guest_dependency_rejected");
    return;
  }
  const auto module_digest = NativeGuestDigest(capture.module_bytes);
  const auto recipe_bytes =
      std::span(reinterpret_cast<const std::uint8_t*>(capture.adapter_json.data()),
                capture.adapter_json.size());
  const auto recipe_digest = NativeGuestDigest(recipe_bytes);
  for (std::size_t i = 0; i < recipe_digest.size(); ++i) {
    if (dispatch.inline_payload[96 + i] != static_cast<std::byte>(recipe_digest[i]) ||
        invocation.inline_payload[32 + i] != static_cast<std::byte>(recipe_digest[i])) {
      refuse("native_guest_dependency_rejected");
      return;
    }
  }
  GuestGroup* group = nullptr;
  for (auto& candidate : guest_groups_) {
    if (candidate.epoch == epoch && candidate.process_id == dispatch.header.process_id &&
        candidate.document_high == capture.document_token_high &&
        candidate.document_low == capture.document_token_low &&
        candidate.context_id == capture.execution_context_id &&
        candidate.frame_id == dispatch.header.frame_id &&
        candidate.recipe_digest == recipe_digest) {
      group = &candidate;
      break;
    }
  }
  if (!group) {
    if (!carries_module) {
      refuse("native_guest_module_unbound");
      return;
    }
    if (guest_groups_.size() >= 16) {
      refuse("native_guest_document_limit");
      return;
    }
    GuestGroup created;
    created.epoch = epoch;
    created.process_id = dispatch.header.process_id;
    created.document_high = capture.document_token_high;
    created.document_low = capture.document_token_low;
    created.context_id = capture.execution_context_id;
    created.frame_id = dispatch.header.frame_id;
    created.recipe_digest = recipe_digest;
    created.failed = true;  // Not yet bound to transferred artifacts.
    guest_groups_.push_back(std::move(created));
    group = &guest_groups_.back();
  }
  if (group->failed) {
    // A failed binding is revived only by freshly sent module bytes.
    if (!carries_module || group->attempts >= kNativeGuestModuleAttemptLimit) {
      refuse(carries_module ? "native_guest_module_unavailable" : "native_guest_module_lost");
      return;
    }
    ++group->attempts;
    group->failed = false;
    group->status_reported = false;
    group->module_digest = module_digest;
    const auto transfer_binding = [&](NativeArtifactKind kind, NativeArtifactCaptureOrigin origin,
                                      std::span<const std::uint8_t> bytes, std::uint64_t parent,
                                      std::uint64_t creator) {
      const auto id = CaptureGeneratedArtifactInternal(
          kind, origin, creator, capture.execution_context_id, dispatch.header.frame_id,
          capture.source_url, mojo_base::BigBuffer(bytes), parent, true);
      if (id)
        guest_receipts_.emplace(id, 0);
      return id;
    };
    group->module_id =
        transfer_binding(NativeArtifactKind::kWasm, NativeArtifactCaptureOrigin::kUnknown,
                         capture.module_bytes, 0, 0);
    group->adapter_id =
        group->module_id
            ? transfer_binding(NativeArtifactKind::kWasmGuestAdapter,
                               NativeArtifactCaptureOrigin::kNativeWasmGuest, recipe_bytes,
                               group->module_id, invocation.header.sequence_number)
            : 0;
    if (!group->adapter_id) {
      group->failed = true;
      refuse("native_guest_module_unavailable");
      return;
    }
    if (module_status)
      group->status_waiters.push_back(std::move(module_status));
  } else if (carries_module) {
    // The renderer resent bytes before it observed this binding's verdict.
    if (group->module_digest != module_digest) {
      refuse("native_guest_dependency_rejected");
      return;
    }
    if (module_status) {
      if (group->status_reported)
        module_status(true);
      else
        group->status_waiters.push_back(std::move(module_status));
    }
  }
  const GuestEventKey invocation_key{invocation.header.process_id,
                                     invocation.header.sequence_number};
  auto canonical_invocation = invocation;
  canonical_invocation.header.artifact_id = group->module_id;
  NativeGuestPut(canonical_invocation.inline_payload, 24, group->adapter_id, 8);
  if (auto prior = guest_invocations_.find(invocation_key); prior != guest_invocations_.end()) {
    // An unpublished invocation may move to a retried module binding.
    if (!prior->second.published && prior->second.module_id != group->module_id) {
      prior->second = GuestInvocation{canonical_invocation, group->module_id, group->adapter_id,
                                      is_current_document, false};
    } else if (prior->second.module_id != group->module_id ||
               std::memcmp(&prior->second.event, &canonical_invocation,
                           sizeof(canonical_invocation)) != 0) {
      refuse("native_guest_dependency_rejected");
      return;
    }
  } else {
    guest_invocations_.emplace(
        invocation_key, GuestInvocation{canonical_invocation, group->module_id, group->adapter_id,
                                        is_current_document, false});
  }
  const auto bytecode_id = CaptureGeneratedArtifactInternal(
      NativeArtifactKind::kBytecodeBuffer, NativeArtifactCaptureOrigin::kNativeWasmGuest,
      dispatch.header.sequence_number, capture.execution_context_id, dispatch.header.frame_id,
      capture.source_url, mojo_base::BigBuffer(capture.bytecode_bytes), group->module_id, true);
  if (!bytecode_id) {
    EmitRendererGap(dispatch, "native_guest_snapshot_unavailable");
    return;
  }
  guest_receipts_.emplace(bytecode_id, 0);
  GuestDispatch pending;
  pending.event = dispatch;
  pending.event.header.artifact_id = group->module_id;
  NativeGuestPut(pending.event.inline_payload, 56, bytecode_id, 8);
  pending.invocation = invocation_key;
  pending.epoch = epoch;
  pending.module_id = group->module_id;
  pending.adapter_id = group->adapter_id;
  pending.bytecode_id = bytecode_id;
  pending.current_document = std::move(is_current_document);
  guest_dispatches_.emplace(key, std::move(pending));
  DrainGuestDependencies();
}

void NativeArtifactCaptureSink::CaptureNativeGuestHost(const NativeProbeEvent& event,
                                                       const std::uint64_t epoch) {
  DrainGuestDependencies();
  if (!IsEnabled() || !IsEnabledFor(event.header.category) ||
      event.header.session_id != session_id_.load(std::memory_order_relaxed))
    return;
  const auto& h = event.header;
  if (h.protocol_version != kNativeProbeProtocolVersion ||
      h.header_size != sizeof(NativeProbeHeader) || h.flags || h.reserved1 || h.artifact_id ||
      !h.parent_event_id || !h.sequence_number || !h.monotonic_time_ns ||
      h.payload_size > kNativeProbeInlinePayloadSize ||
      !std::all_of(event.reserved.begin(), event.reserved.end(),
                   [](auto b) { return b == std::byte{0}; }) ||
      (h.type != NativeProbeType::kApiCall && h.type != NativeProbeType::kPropertyRead) ||
      h.category == NativeProbeCategory::kVm || h.category == NativeProbeCategory::kArtifact ||
      h.category == NativeProbeCategory::kUnknown) {
    if (!guest_host_malformed_gap_emitted_) {
      guest_host_malformed_gap_emitted_ = true;
      EmitResult(NativeProbeType::kGap, 0, 0, h.frame_id, "native_guest_host_malformed",
                 NativeProbeCategory::kVm);
    }
    return;
  }
  const GuestEventKey identity{h.process_id, h.sequence_number};
  if (guest_host_identities_.contains(identity) || guest_dispatches_.contains(identity) ||
      guest_invocations_.contains(identity))
    return;  // A replayed record is not new evidence.
  if (guest_routed_host_count_ >= kNativeGuestHostParentLimit) {
    PublishUnparentedHost(event, guest_host_parent_omitted_gap_emitted_,
                          "native_guest_host_parent_omitted");
    return;
  }
  ++guest_routed_host_count_;
  guest_host_identities_.insert(identity);
  const auto found = guest_dispatches_.find({h.process_id, h.parent_event_id});
  if (found == guest_dispatches_.end() || found->second.failed || epoch != found->second.epoch ||
      !found->second.current_document || !found->second.current_document() ||
      !GuestSameScope(event, found->second.event) ||
      h.sequence_number <= found->second.event.header.sequence_number ||
      h.monotonic_time_ns < found->second.event.header.monotonic_time_ns) {
    // Lost parents are never retargeted; the host itself is still evidence.
    PublishUnparentedHost(event, guest_host_parent_lost_gap_emitted_,
                          "native_guest_host_parent_lost");
    return;
  }
  auto& dispatch = found->second;
  auto host = event;
  host.header.artifact_id = dispatch.module_id;
  host.header.tab_id = dispatch.event.header.tab_id;
  if (dispatch.published) {
    if (const auto emitter = emitter_.load(std::memory_order_acquire))
      emitter(host);
    return;
  }
  if (guest_held_host_count_ >= kNativeGuestHeldHostLimit) {
    PublishUnparentedHost(event, guest_host_parent_omitted_gap_emitted_,
                          "native_guest_host_parent_omitted");
    return;
  }
  dispatch.hosts.push_back(host);
  ++guest_held_host_count_;
}

void NativeArtifactCaptureSink::DrainGuestDependencies() {
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (now >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    // FlushBeforeExpiry already reported this work while the session could
    // still record it; nothing can be published after expiry.
    guest_dispatches_.clear();
    guest_invocations_.clear();
    guest_receipts_.clear();
    guest_groups_.clear();
    guest_held_host_count_ = 0;
    return;
  }
  if (!IsEnabled() || !IsEnabledFor(NativeProbeCategory::kVm))
    return;
  const auto emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter)
    return;
  const auto receipt = [&](std::uint64_t id) {
    const auto found = guest_receipts_.find(id);
    return found == guest_receipts_.end() ? std::uint8_t{2} : found->second;
  };
  for (auto& group : guest_groups_) {
    if (group.failed || group.status_reported)
      continue;
    const bool rejected = receipt(group.module_id) == 2 || receipt(group.adapter_id) == 2;
    const bool accepted = receipt(group.module_id) == 1 && receipt(group.adapter_id) == 1;
    if (!rejected && !accepted)
      continue;
    group.failed = rejected;
    group.status_reported = accepted;
    auto waiters = std::move(group.status_waiters);
    group.status_waiters.clear();
    for (auto& waiter : waiters)
      waiter(accepted);
  }
  // Invocation is observed independently of successful bytecode capture.
  // Retain the first invocation that created a shared adapter artifact.
  for (auto& [identity, invocation] : guest_invocations_) {
    static_cast<void>(identity);
    if (!invocation.published && invocation.current_document && invocation.current_document() &&
        receipt(invocation.module_id) == 1 && receipt(invocation.adapter_id) == 1) {
      emitter(invocation.event);
      invocation.published = true;
    }
  }
  for (auto& [key, pending] : guest_dispatches_) {
    static_cast<void>(key);
    if (pending.failed || pending.published)
      continue;
    if (!pending.current_document || !pending.current_document() ||
        receipt(pending.module_id) == 2 || receipt(pending.adapter_id) == 2 ||
        receipt(pending.bytecode_id) == 2) {
      pending.failed = true;
      EmitRendererGap(pending.event, "native_guest_dependency_lost");
      for (const auto& host : pending.hosts)
        PublishUnparentedHost(host, guest_host_parent_lost_gap_emitted_,
                              "native_guest_host_parent_lost");
      guest_held_host_count_ -= pending.hosts.size();
      pending.hosts.clear();
      continue;
    }
    if (receipt(pending.module_id) != 1 || receipt(pending.adapter_id) != 1 ||
        receipt(pending.bytecode_id) != 1)
      continue;
    auto& invocation = guest_invocations_.at(pending.invocation);
    if (!invocation.published) {
      emitter(invocation.event);
      invocation.published = true;
    }
    emitter(pending.event);
    pending.published = true;
    for (const auto& host : pending.hosts)
      emitter(host);
    guest_held_host_count_ -= pending.hosts.size();
    pending.hosts.clear();
  }
}

void NativeArtifactCaptureSink::FlushBeforeExpiry(const std::uint64_t generation) {
  if (generation != generation_.load(std::memory_order_acquire))
    return;
  DrainGuestDependencies();
  for (auto& [key, pending] : guest_dispatches_) {
    static_cast<void>(key);
    if (pending.failed || pending.published)
      continue;
    pending.failed = true;
    EmitRendererGap(pending.event, "native_guest_pending_at_expiry");
    for (const auto& host : pending.hosts)
      PublishUnparentedHost(host, guest_host_parent_lost_gap_emitted_,
                            "native_guest_host_parent_lost");
    guest_held_host_count_ -= pending.hosts.size();
    pending.hosts.clear();
  }
  for (auto& [artifact_id, context] : pending_) {
    static_cast<void>(artifact_id);
    for (const auto& [observation, unused] : context.wasm_observations) {
      static_cast<void>(unused);
      EmitRendererGap(observation, "native_wasm_dispatch_pending_at_expiry");
    }
    context.wasm_observations.clear();
  }
}

void NativeArtifactCaptureSink::CaptureWasmDispatch(
    const NativeWasmDispatchObservation& observation,
    mojo_base::BigBuffer content,
    std::function<bool()> is_current_document) {
  if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled() ||
      observation.header.session_id != session_id_.load(std::memory_order_relaxed) ||
      !is_current_document || !is_current_document())
    return;
  const auto gap = [&](const char* reason) {
    EmitResult(NativeProbeType::kGap, 0, 0, observation.header.frame_id, reason,
               NativeProbeCategory::kVm);
  };
  if (wasm_dispatch_count_ >= kNativeWasmDispatchSampleBudget) {
    if (!wasm_dispatch_budget_gap_emitted_) {
      wasm_dispatch_budget_gap_emitted_ = true;
      gap("native_wasm_dispatch_browser_budget_incomplete");
    }
    return;
  }
  ++wasm_dispatch_count_;
  if (content.size() < 8 || content.size() > 16U * 1024U * 1024U ||
      !observation.header.sequence_number || !observation.header.monotonic_time_ns ||
      !observation.header.process_id || !observation.header.thread_id ||
      observation.function_index >= 16U * 1024U * 1024U ||
      observation.table_count >= 16U * 1024U * 1024U) {
    gap("native_wasm_dispatch_limit_or_invalid");
    return;
  }
  // Renderer shared memory remains writable: validate a private immutable copy.
  std::vector<std::uint8_t> bytes(content.begin(), content.end());
  auto checked = observation;
  checked.module_bytes = bytes;
  if (!IsValidNativeWasmDispatchInput(checked)) {
    gap("native_wasm_dispatch_module_invalid");
    return;
  }
  NativeProbeEvent event;
  event.header = observation.header;
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = NativeProbeType::kWasmDispatchObservation;
  event.header.parent_event_id = 0;
  event.header.payload_size = 128;
  const NativeWasmDispatchObservationPayload sample{
      .function_index = observation.function_index,
      .module_byte_offset = observation.module_byte_offset,
      .selector = observation.selector,
      .table_count = observation.table_count,
      .sample_index = observation.sample_index};
  event.inline_payload = EncodeNativeWasmDispatchObservationPayload(sample);
  // Observations of one module in one document share a single artifact.
  const WasmModuleKey module_key{observation.header.process_id,    observation.header.frame_id,
                                 observation.execution_context_id, observation.document_token_high,
                                 observation.document_token_low,   NativeGuestDigest(bytes)};
  if (const auto known = wasm_dispatch_modules_.find(module_key);
      known != wasm_dispatch_modules_.end()) {
    event.header.artifact_id = known->second.first;
    if (known->second.second) {
      if (const auto emitter = emitter_.load(std::memory_order_acquire))
        emitter(event);
      return;
    }
    if (const auto pending = pending_.find(known->second.first); pending != pending_.end()) {
      pending->second.wasm_observations.emplace_back(event, std::move(is_current_document));
      return;
    }
  }
  const auto artifact_id = CaptureGeneratedArtifactInternal(
      NativeArtifactKind::kWasm, NativeArtifactCaptureOrigin::kUnknown, 0,
      observation.execution_context_id, observation.header.frame_id, observation.source_url,
      mojo_base::BigBuffer(bytes), 0, true);
  const auto found = pending_.find(artifact_id);
  if (!artifact_id || found == pending_.end()) {
    EmitRendererGap(event, "native_wasm_dispatch_artifact_unavailable");
    return;
  }
  event.header.artifact_id = artifact_id;
  wasm_dispatch_modules_[module_key] = {artifact_id, false};
  found->second.wasm_observations.emplace_back(event, std::move(is_current_document));
}

std::uint64_t NativeArtifactCaptureSink::CaptureGeneratedArtifact(
    NativeArtifactKind kind,
    NativeArtifactCaptureOrigin capture_origin,
    std::uint64_t creator_event_id,
    std::uint64_t execution_context_id,
    std::uint64_t frame_id,
    std::string_view source_url,
    mojo_base::BigBuffer content,
    std::uint64_t parent_artifact_id) {
  return CaptureGeneratedArtifactInternal(kind, capture_origin, creator_event_id,
                                          execution_context_id, frame_id, source_url,
                                          std::move(content), parent_artifact_id, false);
}

std::uint64_t NativeArtifactCaptureSink::CaptureGeneratedArtifactInternal(
    const NativeArtifactKind kind,
    const NativeArtifactCaptureOrigin capture_origin,
    const std::uint64_t creator_event_id,
    const std::uint64_t execution_context_id,
    const std::uint64_t frame_id,
    const std::string_view source_url,
    mojo_base::BigBuffer content,
    const std::uint64_t parent_artifact_id,
    const bool native_wasm_runtime) {
  const bool is_runtime_typed_array =
      kind == NativeArtifactKind::kBytecodeBuffer &&
      capture_origin == NativeArtifactCaptureOrigin::kRuntimeTypedArray;
  const bool is_allocating_script =
      kind == NativeArtifactKind::kJavaScript &&
      capture_origin == NativeArtifactCaptureOrigin::kRuntimeAllocatingScript;
  const NativeProbeCategory result_category = (is_runtime_typed_array || is_allocating_script)
                                                  ? NativeProbeCategory::kVm
                                                  : NativeProbeCategory::kArtifact;
  if (!IsEnabledFor(result_category)) {
    return 0;
  }
  const std::uint64_t capture_session_id = session_id_.load(std::memory_order_relaxed);
  const std::uint64_t capture_generation = generation_.load(std::memory_order_acquire);
  const std::uint64_t artifact_id = next_artifact_id_.fetch_add(1, std::memory_order_relaxed);
  const bool valid_kind_and_origin =
      (native_wasm_runtime &&
       ((kind == NativeArtifactKind::kWasm &&
         capture_origin == NativeArtifactCaptureOrigin::kUnknown) ||
        ((kind == NativeArtifactKind::kWasmGuestAdapter ||
          kind == NativeArtifactKind::kBytecodeBuffer) &&
         capture_origin == NativeArtifactCaptureOrigin::kNativeWasmGuest))) ||
      (kind == NativeArtifactKind::kJavaScript &&
       capture_origin == NativeArtifactCaptureOrigin::kDynamicJavaScript) ||
      (kind == NativeArtifactKind::kWasm &&
       (capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyCompile ||
        capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyModule ||
        capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyInstantiate)) ||
      (kind == NativeArtifactKind::kCanvasDataUrl &&
       capture_origin == NativeArtifactCaptureOrigin::kCanvasToDataUrl && creator_event_id != 0 &&
       execution_context_id == 0) ||
      is_runtime_typed_array || is_allocating_script;
  if (!valid_kind_and_origin ||
      (kind != NativeArtifactKind::kCanvasDataUrl && execution_context_id == 0) ||
      content.size() == 0 || content.size() > kMaxArtifactBytes ||
      (is_runtime_typed_array && content.size() < kRuntimeTypedArrayMinBytes) ||
      source_url.empty() || source_url.size() > kNativeArtifactMaxUrlBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "generated_metadata_or_size_limit", result_category);
    return 0;
  }
  if (is_runtime_typed_array &&
      runtime_typed_array_count_.fetch_add(1, std::memory_order_relaxed) >=
          kRuntimeTypedArrayMaxSnapshots) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "runtime_typed_array_session_limit", result_category);
    return 0;
  }

  const std::string captured_url(source_url);
  const std::string mime_type = kind == NativeArtifactKind::kJavaScript         ? "text/javascript"
                                : kind == NativeArtifactKind::kWasm             ? "application/wasm"
                                : kind == NativeArtifactKind::kWasmGuestAdapter ? "application/json"
                                : kind == NativeArtifactKind::kBytecodeBuffer
                                    ? "application/octet-stream"
                                    : "text/plain";
  if (captured_url.empty() || captured_url.size() > kNativeArtifactMaxUrlBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "generated_url_invalid", result_category);
    return 0;
  }

  // BigBuffer may be shared writable memory owned by the renderer. Copy once
  // in the browser before validation and transfer to avoid a TOCTOU race.
  const std::span<const std::uint8_t> received(content);
  auto transfer = std::make_unique<NativeArtifactTransfer>();
  transfer->header.kind = kind;
  transfer->header.session_id = capture_session_id;
  transfer->header.frame_id = frame_id;
  transfer->header.artifact_id = artifact_id;
  transfer->header.creator_event_id = creator_event_id;
  transfer->header.parent_artifact_id = parent_artifact_id;
  if (kind == NativeArtifactKind::kCanvasDataUrl) {
    transfer->header.flags |= kNativeArtifactFlagSensitive;
  }
  transfer->header.content_size = received.size();
  transfer->header.url_size = static_cast<std::uint32_t>(captured_url.size());
  transfer->header.mime_type_size = static_cast<std::uint32_t>(mime_type.size());
  transfer->header.execution_context_id = execution_context_id;
  transfer->header.capture_origin = capture_origin;
  transfer->url = captured_url;
  transfer->mime_type = mime_type;
  transfer->content.assign(received.begin(), received.end());
  if (!NativeArtifactSocketClient::Get().Enqueue(std::move(transfer))) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "transfer_queue_full_or_disconnected", result_category);
    return 0;
  }
  pending_.emplace(artifact_id, PendingContext{.frame_id = frame_id,
                                               .session_id = capture_session_id,
                                               .generation = capture_generation,
                                               .result_category = result_category});
  return artifact_id;
}

void NativeArtifactCaptureSink::OnBodyComplete(std::unique_ptr<CaptureContext> context,
                                               const bool complete,
                                               std::vector<std::uint8_t> content) {
  Release(context->reservation_bytes);
  if (!IsCurrentCapture(context->header.session_id, context->generation)) {
    // Do not enqueue old bytes or relabel a failed old body under a new session.
    return;
  }
  if (!complete || !IsEnabled()) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, context->header.artifact_id,
               context->request_id, context->frame_id,
               complete ? "session_inactive" : "body_incomplete_or_too_large");
    return;
  }
  context->header.content_size = content.size();
  context->header.url_size = static_cast<std::uint32_t>(context->url.size());
  context->header.mime_type_size = static_cast<std::uint32_t>(context->mime_type.size());
  auto transfer = std::make_unique<NativeArtifactTransfer>();
  transfer->header = context->header;
  transfer->url = std::move(context->url);
  transfer->mime_type = std::move(context->mime_type);
  transfer->content = std::move(content);
  if (!NativeArtifactSocketClient::Get().Enqueue(std::move(transfer))) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, context->header.artifact_id,
               context->request_id, context->frame_id, "transfer_queue_full_or_disconnected");
    return;
  }
  pending_.emplace(context->header.artifact_id,
                   PendingContext{.request_id = context->request_id,
                                  .frame_id = context->frame_id,
                                  .session_id = context->header.session_id,
                                  .generation = context->generation,
                                  .parent_event_id = context->header.creator_event_id});
}

void NativeArtifactCaptureSink::TransferCompleted(
    const std::uint64_t artifact_id,
    const NativeArtifactReceiveStatus status) noexcept {
  Get().OnTransferCompleted(artifact_id, status);
}

void NativeArtifactCaptureSink::OnTransferCompleted(
    const std::uint64_t artifact_id,
    const NativeArtifactReceiveStatus status) noexcept {
  const auto found = pending_.find(artifact_id);
  if (found == pending_.end()) {
    return;
  }
  const PendingContext context = found->second;
  pending_.erase(found);
  if (!IsCurrentCapture(context.session_id, context.generation)) {
    return;
  }
  if (auto receipt = guest_receipts_.find(artifact_id); receipt != guest_receipts_.end()) {
    receipt->second = status == NativeArtifactReceiveStatus::kAccepted ? 1 : 2;
    DrainGuestDependencies();
  }
  if (!context.wasm_observations.empty()) {
    const bool accepted = status == NativeArtifactReceiveStatus::kAccepted;
    for (auto entry = wasm_dispatch_modules_.begin(); entry != wasm_dispatch_modules_.end();
         ++entry) {
      if (entry->second.first != artifact_id)
        continue;
      if (accepted)
        entry->second.second = true;
      else
        wasm_dispatch_modules_.erase(entry);
      break;
    }
    if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled())
      return;
    const auto emitter = emitter_.load(std::memory_order_acquire);
    for (const auto& [observation, is_current_document] : context.wasm_observations) {
      if (accepted && emitter && is_current_document && is_current_document())
        emitter(observation);
      else
        EmitRendererGap(observation, "native_wasm_dispatch_artifact_or_document_lost");
    }
  }
  EmitResult(status == NativeArtifactReceiveStatus::kAccepted
                 ? NativeProbeType::kArtifactCaptured
                 : NativeProbeType::kArtifactCaptureFailed,
             artifact_id, context.request_id, context.frame_id, StatusName(status),
             context.result_category, context.parent_event_id);
}

void NativeArtifactCaptureSink::EmitResult(const NativeProbeType type,
                                           const std::uint64_t artifact_id,
                                           const std::uint64_t request_id,
                                           const std::uint64_t frame_id,
                                           const std::string& detail,
                                           const NativeProbeCategory category,
                                           const std::uint64_t parent_event_id) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) {
    return;
  }
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (now >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }
  NativeProbeEvent event;
  event.header.category = category;
  event.header.type = type;
  event.header.sequence_number = NativeProbeSession::Get().NextBrowserSequence();
  event.header.monotonic_time_ns = now;
  event.header.session_id = session_id_.load(std::memory_order_relaxed);
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.frame_id = frame_id;
  event.header.artifact_id = artifact_id;
  event.header.request_id = request_id;
  event.header.parent_event_id = parent_event_id;
  const std::size_t size = std::min(detail.size(), event.inline_payload.size());
  std::transform(detail.begin(), detail.begin() + static_cast<std::ptrdiff_t>(size),
                 event.inline_payload.begin(), [](const char value) {
                   return static_cast<std::byte>(static_cast<unsigned char>(value));
                 });
  event.header.payload_size = static_cast<std::uint32_t>(size);
  if (size != detail.size()) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated);
  }
  emitter(event);
}

bool NativeArtifactCaptureSink::IsCurrentCapture(const std::uint64_t session_id,
                                                 const std::uint64_t generation) const noexcept {
  return generation == generation_.load(std::memory_order_acquire) &&
         session_id == session_id_.load(std::memory_order_relaxed);
}

bool NativeArtifactCaptureSink::Reserve(const std::size_t bytes) noexcept {
  std::size_t current = active_bytes_.load(std::memory_order_relaxed);
  while (current <= kMaxActiveCaptureBytes && bytes <= kMaxActiveCaptureBytes - current) {
    if (active_bytes_.compare_exchange_weak(current, current + bytes, std::memory_order_acq_rel,
                                            std::memory_order_relaxed)) {
      return true;
    }
  }
  return false;
}

void NativeArtifactCaptureSink::Release(const std::size_t bytes) noexcept {
  active_bytes_.fetch_sub(bytes, std::memory_order_acq_rel);
}

}  // namespace reb
