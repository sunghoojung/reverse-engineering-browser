// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"

#include <algorithm>
#include <array>
#include <string_view>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/url_response_head.mojom.h"

namespace reb {

namespace {

void SetPayload(NativeProbeEvent& event,
                const std::string_view first,
                const std::string_view second = {},
                const std::string_view third = {}) noexcept {
  std::size_t written = 0;
  bool complete = true;
  for (const std::string_view value : std::array<std::string_view, 3>{first, second, third}) {
    const std::size_t available = event.inline_payload.size() - written;
    const std::size_t size = std::min(value.size(), available);
    std::transform(value.begin(), value.begin() + static_cast<std::ptrdiff_t>(size),
                   event.inline_payload.begin() + static_cast<std::ptrdiff_t>(written),
                   [](const char character) {
                     return static_cast<std::byte>(static_cast<unsigned char>(character));
                   });
    written += size;
    complete = complete && size == value.size();
  }
  event.header.payload_size = static_cast<std::uint32_t>(written);
  if (!complete) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated);
  }
}

NativeProbeEvent MakeNetworkEvent(const NativeProbeType type,
                                  const std::uint64_t sequence_number,
                                  const std::uint64_t monotonic_time_ns,
                                  const std::uint64_t session_id,
                                  const std::uint64_t request_id,
                                  const std::int32_t initiator_request_id,
                                  const std::uint32_t initiator_process_id,
                                  const std::uint64_t frame_id,
                                  const std::uint64_t browser_context_id_high,
                                  const std::uint64_t browser_context_id_low) noexcept {
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = type;
  event.header.sequence_number = sequence_number;
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.session_id = session_id;
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.request_id = request_id;
  event.header.initiator_request_id = static_cast<std::uint32_t>(initiator_request_id);
  event.header.initiator_process_id = initiator_process_id;
  event.header.frame_id = frame_id;
  event.header.browser_context_id_high = browser_context_id_high;
  event.header.browser_context_id_low = browser_context_id_low;
  return event;
}

}  // namespace

NativeNetworkCaptureSink& NativeNetworkCaptureSink::Get() {
  static NativeNetworkCaptureSink sink;
  return sink;
}

bool NativeNetworkCaptureSink::IsEnabled() const noexcept {
  if (emitter_.load(std::memory_order_acquire) == nullptr ||
      (category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0) {
    return false;
  }
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  return now < expires_at_monotonic_ns_.load(std::memory_order_relaxed);
}

void NativeNetworkCaptureSink::SetEmitter(const NativeProbeEmitter emitter,
                                          const std::uint64_t session_id,
                                          const std::uint64_t category_mask,
                                          const std::uint64_t expires_at_monotonic_ns) noexcept {
  emitter_.store(nullptr, std::memory_order_release);
  session_id_.store(emitter ? session_id : 0, std::memory_order_relaxed);
  category_mask_.store(emitter ? category_mask : 0, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(emitter ? expires_at_monotonic_ns : 0, std::memory_order_relaxed);
  emitter_.store(emitter, std::memory_order_release);
}

void NativeNetworkCaptureSink::RecordRequestStarted(
    const std::uint64_t request_id,
    const std::int32_t initiator_request_id,
    const std::uint32_t initiator_process_id,
    const std::uint64_t frame_id,
    const std::uint64_t browser_context_id_high,
    const std::uint64_t browser_context_id_low,
    const network::ResourceRequest& request) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }

  NativeProbeEvent event = MakeNetworkEvent(
      NativeProbeType::kRequestStarted, NativeProbeSession::Get().NextBrowserSequence(),
      monotonic_time_ns, session_id_.load(std::memory_order_relaxed), request_id,
      initiator_request_id, initiator_process_id, frame_id, browser_context_id_high,
      browser_context_id_low);
  event.header.resource_type =
      static_cast<std::uint16_t>(std::clamp(request.resource_type, 0, 65535));
  if (request.originated_from_service_worker) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kFromServiceWorker);
  }
  SetPayload(event, request.method, " ", request.url.host());
  emitter(event);
}

void NativeNetworkCaptureSink::RecordRequestRedirected(
    const std::uint64_t request_id,
    const std::int32_t initiator_request_id,
    const std::uint32_t initiator_process_id,
    const std::uint64_t frame_id,
    const std::uint64_t browser_context_id_high,
    const std::uint64_t browser_context_id_low,
    const net::RedirectInfo& redirect_info,
    const network::mojom::URLResponseHead& response_head) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }

  NativeProbeEvent event = MakeNetworkEvent(
      NativeProbeType::kRequestRedirected, NativeProbeSession::Get().NextBrowserSequence(),
      monotonic_time_ns, session_id_.load(std::memory_order_relaxed), request_id,
      initiator_request_id, initiator_process_id, frame_id, browser_context_id_high,
      browser_context_id_low);
  event.header.status_code = response_head.headers ? response_head.headers->response_code() : 0;
  event.header.encoded_data_length = response_head.encoded_data_length;
  SetPayload(event, redirect_info.new_method, " ", redirect_info.new_url.host());
  emitter(event);
}

std::uint64_t NativeNetworkCaptureSink::RecordResponseStarted(
    const std::uint64_t request_id,
    const std::int32_t initiator_request_id,
    const std::uint32_t initiator_process_id,
    const std::uint64_t frame_id,
    const std::uint64_t browser_context_id_high,
    const std::uint64_t browser_context_id_low,
    const network::mojom::URLResponseHead& response_head) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return 0;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return 0;
  }

  const std::uint64_t sequence_number = NativeProbeSession::Get().NextBrowserSequence();
  NativeProbeEvent event = MakeNetworkEvent(
      NativeProbeType::kResponseStarted, sequence_number, monotonic_time_ns,
      session_id_.load(std::memory_order_relaxed), request_id, initiator_request_id,
      initiator_process_id, frame_id, browser_context_id_high, browser_context_id_low);
  event.header.status_code = response_head.headers ? response_head.headers->response_code() : 0;
  event.header.encoded_data_length = response_head.encoded_data_length;
  if (response_head.was_fetched_via_cache) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kFromCache);
  }
  if (response_head.was_fetched_via_service_worker) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kFromServiceWorker);
  }
  SetPayload(event, response_head.mime_type, "; protocol=", response_head.alpn_negotiated_protocol);
  emitter(event);
  return sequence_number;
}

void NativeNetworkCaptureSink::RecordRequestCompleted(
    const std::uint64_t request_id,
    const std::int32_t initiator_request_id,
    const std::uint32_t initiator_process_id,
    const std::uint64_t frame_id,
    const std::uint64_t browser_context_id_high,
    const std::uint64_t browser_context_id_low,
    const network::URLLoaderCompletionStatus& status) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }

  NativeProbeEvent event = MakeNetworkEvent(
      status.error_code == 0 ? NativeProbeType::kRequestCompleted : NativeProbeType::kRequestFailed,
      NativeProbeSession::Get().NextBrowserSequence(), monotonic_time_ns,
      session_id_.load(std::memory_order_relaxed), request_id, initiator_request_id,
      initiator_process_id, frame_id, browser_context_id_high, browser_context_id_low);
  event.header.error_code = status.error_code;
  event.header.encoded_data_length = status.encoded_data_length;
  event.header.decoded_body_length = status.decoded_body_length;
  SetPayload(event, status.error_code == 0 ? "completed" : "failed");
  emitter(event);
}

}  // namespace reb
