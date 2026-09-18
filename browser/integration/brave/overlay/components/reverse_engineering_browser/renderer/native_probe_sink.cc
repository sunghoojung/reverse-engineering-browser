// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"

#include <algorithm>
#include <string_view>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"

namespace reb {

namespace {

std::uint64_t MonotonicTimeNs() noexcept {
  return static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
}

bool IsFingerprintSurfaceCategory(const NativeProbeCategory category) noexcept {
  switch (category) {
    case NativeProbeCategory::kCanvas:
    case NativeProbeCategory::kWebGl:
    case NativeProbeCategory::kWebAudio:
    case NativeProbeCategory::kNavigator:
    case NativeProbeCategory::kPermissions:
    case NativeProbeCategory::kStorage:
    case NativeProbeCategory::kWebRtc:
    case NativeProbeCategory::kRuntime:
      return true;
    case NativeProbeCategory::kUnknown:
    case NativeProbeCategory::kWasm:
    case NativeProbeCategory::kNetwork:
    case NativeProbeCategory::kVm:
    case NativeProbeCategory::kArtifact:
      return false;
  }
  return false;
}

// Origin Trace reads artifact content through a bounded 2 MiB local response.
// Keep Canvas data URLs within that exact limit so an accepted image is always
// complete enough to validate and display instead of becoming a partial base64
// preview. Other generated artifact kinds retain their 16 MiB transport cap.
constexpr std::size_t kCanvasDataUrlMaxBytes = 2U * 1024U * 1024U;

void SetPayload(NativeProbeEvent& event,
                const std::string_view first,
                const std::string_view second = {}) noexcept {
  std::size_t written = 0;
  const auto append = [&event, &written](const std::string_view value) {
    const std::size_t available = event.inline_payload.size() - written;
    const std::size_t size = std::min(value.size(), available);
    std::transform(value.begin(), value.begin() + static_cast<std::ptrdiff_t>(size),
                   event.inline_payload.begin() + static_cast<std::ptrdiff_t>(written),
                   [](const char character) {
                     return static_cast<std::byte>(static_cast<unsigned char>(character));
                   });
    written += size;
    return size == value.size();
  };

  const bool complete = append(first) && append(second);
  event.header.payload_size = static_cast<std::uint32_t>(written);
  if (!complete) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated);
  }
}

}  // namespace

NativeProbeSink& NativeProbeSink::Get() {
  static NativeProbeSink sink;
  return sink;
}

void NativeProbeSink::SetEmitters(const NativeProbeEmitter emitter,
                                  const NativeGeneratedArtifactEmitter artifact_emitter,
                                  const std::uint64_t session_id,
                                  const std::uint64_t category_mask,
                                  const std::uint64_t expires_at_monotonic_ns,
                                  const bool capture_canvas_images,
                                  const NativeProbeFrameIdProvider frame_id_provider) noexcept {
  // SetEmitters is serialized by NativeProbeTransport's bound sequence. Stop
  // new readers before marking the independently atomic configuration fields
  // unstable. The completed even generation release-publishes the relaxed
  // policy fields and emitter together. Active readers acquire an even
  // generation, snapshot those fields, and accept only an unchanged final
  // generation.
  emitter_.store(nullptr, std::memory_order_release);
  artifact_emitter_.store(nullptr, std::memory_order_release);
  config_generation_.fetch_add(1, std::memory_order_acq_rel);
  const bool active = emitter && artifact_emitter;
  session_id_.store(active ? session_id : 0, std::memory_order_relaxed);
  category_mask_.store(active ? category_mask : 0, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(active ? expires_at_monotonic_ns : 0, std::memory_order_relaxed);
  capture_canvas_images_.store(active && capture_canvas_images, std::memory_order_relaxed);
  frame_id_provider_.store(active ? frame_id_provider : nullptr, std::memory_order_relaxed);
  emitter_.store(emitter, std::memory_order_relaxed);
  artifact_emitter_.store(artifact_emitter, std::memory_order_relaxed);
  config_generation_.fetch_add(1, std::memory_order_release);
}

bool NativeProbeSink::IsCanvasImageCaptureEnabled() const noexcept {
  return capture_canvas_images_.load(std::memory_order_acquire) && IsArtifactCaptureEnabled();
}

bool NativeProbeSink::IsArtifactCaptureEnabled() const noexcept {
  if (!artifact_emitter_.load(std::memory_order_acquire)) [[likely]] {
    return false;
  }
  const std::uint64_t generation = config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return false;
  }
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at = expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const NativeGeneratedArtifactEmitter artifact_emitter =
      artifact_emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  return config_generation_.load(std::memory_order_acquire) == generation && artifact_emitter &&
         (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kArtifact)) != 0 &&
         MonotonicTimeNs() < expires_at;
}

void NativeProbeSink::CaptureGeneratedArtifact(
    const NativeArtifactKind kind,
    const NativeArtifactCaptureOrigin capture_origin,
    const std::uint64_t creator_event_id,
    const std::uint64_t execution_context_id,
    const std::uint64_t frame_id,
    const std::string_view source_url,
    const std::span<const std::uint8_t> content) noexcept {
  if (!artifact_emitter_.load(std::memory_order_acquire) || source_url.empty() ||
      source_url.size() > kNativeArtifactMaxUrlBytes || content.empty() ||
      content.size() > kNativeArtifactMaxContentBytes) [[likely]] {
    return;
  }
  const bool valid_kind_and_origin =
      (kind == NativeArtifactKind::kJavaScript &&
       capture_origin == NativeArtifactCaptureOrigin::kDynamicJavaScript) ||
      (kind == NativeArtifactKind::kWasm &&
       (capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyCompile ||
        capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyModule ||
        capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyInstantiate)) ||
      (kind == NativeArtifactKind::kCanvasDataUrl &&
       capture_origin == NativeArtifactCaptureOrigin::kCanvasToDataUrl && creator_event_id != 0 &&
       execution_context_id == 0);
  if (!valid_kind_and_origin ||
      (kind != NativeArtifactKind::kCanvasDataUrl && execution_context_id == 0)) {
    return;
  }
  const std::uint64_t generation = config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0) {
    return;
  }
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at = expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const NativeGeneratedArtifactEmitter artifact_emitter =
      artifact_emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != generation || !artifact_emitter ||
      (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kArtifact)) == 0 ||
      MonotonicTimeNs() >= expires_at) {
    return;
  }
  artifact_emitter(kind, capture_origin, creator_event_id, execution_context_id, frame_id,
                   source_url, content);
}

void NativeProbeSink::RecordApiCall(const NativeProbeCategory category,
                                    const std::string_view operation) noexcept {
  static_cast<void>(RecordSurfaceOperation(category, NativeProbeType::kApiCall, operation));
}

void NativeProbeSink::RecordPropertyRead(const NativeProbeCategory category,
                                         const std::string_view operation) noexcept {
  static_cast<void>(RecordSurfaceOperation(category, NativeProbeType::kPropertyRead, operation));
}

void NativeProbeSink::RecordApiCallOnce(const NativeProbeCategory category,
                                        const std::string_view operation,
                                        std::atomic<std::uint64_t>& observed_session_id) noexcept {
  static_cast<void>(
      RecordSurfaceOperation(category, NativeProbeType::kApiCall, operation, &observed_session_id));
}

void NativeProbeSink::RecordPropertyReadOnce(
    const NativeProbeCategory category,
    const std::string_view operation,
    std::atomic<std::uint64_t>& observed_session_id) noexcept {
  static_cast<void>(RecordSurfaceOperation(category, NativeProbeType::kPropertyRead, operation,
                                           &observed_session_id));
}

std::uint64_t NativeProbeSink::RecordSurfaceOperation(
    const NativeProbeCategory category,
    const NativeProbeType type,
    const std::string_view operation,
    std::atomic<std::uint64_t>* const observed_session_id) noexcept {
  if (!emitter_.load(std::memory_order_acquire)) [[likely]] {
    return 0;
  }
  if (!IsFingerprintSurfaceCategory(category) ||
      (type != NativeProbeType::kApiCall && type != NativeProbeType::kPropertyRead) ||
      operation.empty()) {
    return 0;
  }
  const std::uint64_t config_generation = config_generation_.load(std::memory_order_acquire);
  if ((config_generation & 1U) != 0) {
    return 0;
  }
  const std::uint64_t monotonic_time_ns = MonotonicTimeNs();
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at_monotonic_ns =
      expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const std::uint64_t session_id = session_id_.load(std::memory_order_relaxed);
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != config_generation || !emitter ||
      (category_mask & NativeProbeCategoryMask(category)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns) {
    return 0;
  }

  if (observed_session_id) {
    std::uint64_t observed = observed_session_id->load(std::memory_order_acquire);
    while (observed != session_id) {
      if (observed_session_id->compare_exchange_weak(
              observed, session_id, std::memory_order_acq_rel, std::memory_order_acquire)) {
        break;
      }
    }
    if (observed == session_id) {
      return 0;
    }
  }

  NativeProbeEvent event;
  event.header.category = category;
  event.header.type = type;
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.session_id = session_id;
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  const NativeProbeFrameIdProvider frame_id_provider =
      frame_id_provider_.load(std::memory_order_relaxed);
  event.header.frame_id = frame_id_provider ? frame_id_provider() : 0;
  SetPayload(event, operation);
  emitter(event);
  return event.header.sequence_number;
}

void NativeProbeSink::RecordCanvasToDataUrl() noexcept {
  RecordApiCall(NativeProbeCategory::kCanvas, "canvas.toDataURL");
}

void NativeProbeSink::RecordCanvasToDataUrl(const std::string_view data_url) noexcept {
  constexpr std::string_view kImageDataUrlPrefix = "data:image/";
  if (!IsCanvasImageCaptureEnabled() || !data_url.starts_with(kImageDataUrlPrefix) ||
      data_url.find(";base64,") == std::string_view::npos ||
      data_url.size() > kCanvasDataUrlMaxBytes) {
    RecordCanvasToDataUrl();
    return;
  }
  const std::uint64_t creator_event_id = RecordSurfaceOperation(
      NativeProbeCategory::kCanvas, NativeProbeType::kApiCall, "canvas.toDataURL");
  if (creator_event_id == 0) {
    return;
  }
  CaptureGeneratedArtifact(
      NativeArtifactKind::kCanvasDataUrl, NativeArtifactCaptureOrigin::kCanvasToDataUrl,
      creator_event_id, 0, 0, "canvas://readback",
      std::span(reinterpret_cast<const std::uint8_t*>(data_url.data()), data_url.size()));
}

void NativeProbeSink::RecordWebAudioCall(const std::string_view operation) noexcept {
  RecordApiCall(NativeProbeCategory::kWebAudio, operation);
}

void NativeProbeSink::RecordRequestInitiated(const std::int32_t request_id,
                                             const std::string_view method,
                                             const std::string_view url) noexcept {
  if (!emitter_.load(std::memory_order_acquire)) [[likely]] {
    return;
  }
  const std::uint64_t config_generation = config_generation_.load(std::memory_order_acquire);
  if ((config_generation & 1U) != 0) {
    return;
  }
  const std::uint64_t monotonic_time_ns = MonotonicTimeNs();
  const std::uint64_t category_mask = category_mask_.load(std::memory_order_relaxed);
  const std::uint64_t expires_at_monotonic_ns =
      expires_at_monotonic_ns_.load(std::memory_order_relaxed);
  const std::uint64_t session_id = session_id_.load(std::memory_order_relaxed);
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_relaxed);
  std::atomic_thread_fence(std::memory_order_acquire);
  if (config_generation_.load(std::memory_order_acquire) != config_generation || !emitter ||
      (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns) {
    return;
  }

  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kRequestInitiated;
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.session_id = session_id;
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.request_id = static_cast<std::uint64_t>(static_cast<std::uint32_t>(request_id));
  SetPayload(event, method, " ");
  const std::size_t method_size = event.header.payload_size;
  if ((event.header.flags & static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated)) == 0) {
    const std::size_t available = event.inline_payload.size() - method_size;
    const std::size_t url_size = std::min(url.size(), available);
    std::transform(url.begin(), url.begin() + static_cast<std::ptrdiff_t>(url_size),
                   event.inline_payload.begin() + static_cast<std::ptrdiff_t>(method_size),
                   [](const char character) {
                     return static_cast<std::byte>(static_cast<unsigned char>(character));
                   });
    event.header.payload_size += static_cast<std::uint32_t>(url_size);
    if (url_size != url.size()) {
      event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated);
    }
  }
  emitter(event);
}

}  // namespace reb
