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

}  // namespace

NativeProbeSink& NativeProbeSink::Get() {
  static NativeProbeSink sink;
  return sink;
}

void NativeProbeSink::SetEmitter(const NativeProbeEmitter emitter) noexcept {
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
  event.header.monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.payload_size = static_cast<std::uint32_t>(kCanvasToDataUrlPayload.size());
  std::transform(
      kCanvasToDataUrlPayload.begin(), kCanvasToDataUrlPayload.end(), event.inline_payload.begin(),
      [](const char value) { return static_cast<std::byte>(static_cast<unsigned char>(value)); });
  emitter(event);
}

}  // namespace reb
