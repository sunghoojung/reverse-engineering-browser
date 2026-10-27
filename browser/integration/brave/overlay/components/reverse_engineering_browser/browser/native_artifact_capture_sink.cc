// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "base/functional/bind.h"
#include "base/process/process_handle.h"
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
  wasm_dispatch_count_ = 0;
  wasm_dispatch_budget_gap_emitted_ = false;
  runtime_typed_array_count_.store(0, std::memory_order_relaxed);
  allocating_scripts_.clear();
  emitter_.store(emitter, std::memory_order_release);
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
  if (wasm_dispatch_count_ >= 16) {
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
  const auto artifact_id = CaptureGeneratedArtifactInternal(
      NativeArtifactKind::kWasm, NativeArtifactCaptureOrigin::kUnknown, 0,
      observation.execution_context_id, observation.header.frame_id, observation.source_url,
      mojo_base::BigBuffer(bytes), 0, true);
  const auto found = pending_.find(artifact_id);
  if (!artifact_id || found == pending_.end()) {
    gap("native_wasm_dispatch_artifact_unavailable");
    return;
  }
  NativeProbeEvent event;
  event.header = observation.header;
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = NativeProbeType::kWasmDispatchObservation;
  event.header.artifact_id = artifact_id;
  event.header.parent_event_id = 0;
  event.header.payload_size = 128;
  const NativeWasmDispatchObservationPayload sample{
      .function_index = observation.function_index,
      .module_byte_offset = observation.module_byte_offset,
      .selector = observation.selector,
      .table_count = observation.table_count,
      .sample_index = observation.sample_index};
  event.inline_payload = EncodeNativeWasmDispatchObservationPayload(sample);
  found->second.wasm_observation = event;
  found->second.is_current_document = std::move(is_current_document);
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
      (native_wasm_runtime && kind == NativeArtifactKind::kWasm &&
       capture_origin == NativeArtifactCaptureOrigin::kUnknown) ||
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
  const std::string mime_type = kind == NativeArtifactKind::kJavaScript ? "text/javascript"
                                : kind == NativeArtifactKind::kWasm     ? "application/wasm"
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
  if (context.wasm_observation) {
    if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled())
      return;
    if (status == NativeArtifactReceiveStatus::kAccepted && context.is_current_document &&
        context.is_current_document()) {
      if (const auto emitter = emitter_.load(std::memory_order_acquire))
        emitter(*context.wasm_observation);
    } else {
      EmitResult(NativeProbeType::kGap, artifact_id, 0, context.frame_id,
                 "native_wasm_dispatch_artifact_or_document_lost", NativeProbeCategory::kVm);
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
