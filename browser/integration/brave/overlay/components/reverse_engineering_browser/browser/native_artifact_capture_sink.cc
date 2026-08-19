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

constexpr std::size_t kMaxArtifactBytes = 16U * 1024U * 1024U;
constexpr std::size_t kMaxActiveCaptureBytes = 32U * 1024U * 1024U;
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

std::string SanitizedUrl(const GURL& url) {
  GURL::Replacements replacements;
  replacements.ClearUsername();
  replacements.ClearPassword();
  replacements.ClearQuery();
  replacements.ClearRef();
  return url.ReplaceComponents(replacements).spec();
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
  if (emitter_.load(std::memory_order_acquire) == nullptr ||
      !NativeArtifactSocketClient::Get().IsConnected() ||
      (category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kArtifact)) == 0) {
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
  session_id_.store(emitter ? session_id : 0, std::memory_order_relaxed);
  category_mask_.store(emitter ? category_mask : 0, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(emitter ? expires_at_monotonic_ns : 0, std::memory_order_relaxed);
  if (!emitter) {
    pending_.clear();
  }
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
  context->url = SanitizedUrl(request.url);
  context->mime_type = response_head.mime_type;
  context->reservation_bytes = reservation;
  context->request_id = request_id;
  context->frame_id = frame_id;
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

void NativeArtifactCaptureSink::OnBodyComplete(std::unique_ptr<CaptureContext> context,
                                               const bool complete,
                                               std::vector<std::uint8_t> content) {
  Release(context->reservation_bytes);
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
                   PendingContext{context->request_id, context->frame_id});
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
  EmitResult(status == NativeArtifactReceiveStatus::kAccepted
                 ? NativeProbeType::kArtifactCaptured
                 : NativeProbeType::kArtifactCaptureFailed,
             artifact_id, context.request_id, context.frame_id, StatusName(status));
}

void NativeArtifactCaptureSink::EmitResult(const NativeProbeType type,
                                           const std::uint64_t artifact_id,
                                           const std::uint64_t request_id,
                                           const std::uint64_t frame_id,
                                           const std::string& detail) noexcept {
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
  event.header.category = NativeProbeCategory::kArtifact;
  event.header.type = type;
  event.header.sequence_number = NativeProbeSession::Get().NextBrowserSequence();
  event.header.monotonic_time_ns = now;
  event.header.session_id = session_id_.load(std::memory_order_relaxed);
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.frame_id = frame_id;
  event.header.artifact_id = artifact_id;
  event.header.request_id = request_id;
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
