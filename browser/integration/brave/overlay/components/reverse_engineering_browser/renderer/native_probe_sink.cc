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

constexpr std::string_view kCanvasToDataUrlPayload = "canvas.toDataURL";

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

void NativeProbeSink::SetEmitter(const NativeProbeEmitter emitter,
                                 const std::uint64_t session_id) noexcept {
  emitter_.store(nullptr, std::memory_order_release);
  session_id_.store(emitter ? session_id : 0, std::memory_order_relaxed);
  emitter_.store(emitter, std::memory_order_release);
}

void NativeProbeSink::RecordCanvasToDataUrl() noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return;
  }

  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kCanvas;
  event.header.type = NativeProbeType::kApiCall;
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.session_id = session_id_.load(std::memory_order_relaxed);
  event.header.monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  SetPayload(event, kCanvasToDataUrlPayload);
  emitter(event);
}

void NativeProbeSink::RecordRequestInitiated(const std::int32_t request_id,
                                             const std::string_view method,
                                             const std::string_view url) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return;
  }

  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kRequestInitiated;
  event.header.sequence_number = next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  event.header.session_id = session_id_.load(std::memory_order_relaxed);
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
