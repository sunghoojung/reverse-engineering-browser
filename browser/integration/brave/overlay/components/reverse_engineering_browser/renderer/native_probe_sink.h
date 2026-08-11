// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_

#include <atomic>
#include <cstdint>
#include <string_view>

#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"

namespace reb {

class NativeProbeSink final {
 public:
  static NativeProbeSink& Get();

  NativeProbeSink(const NativeProbeSink&) = delete;
  NativeProbeSink& operator=(const NativeProbeSink&) = delete;

  void SetEmitter(NativeProbeEmitter emitter, std::uint64_t session_id) noexcept;
  void RecordCanvasToDataUrl() noexcept;
  void RecordRequestInitiated(std::int32_t request_id,
                              std::string_view method,
                              std::string_view url) noexcept;

 private:
  NativeProbeSink() = default;

  std::atomic<NativeProbeEmitter> emitter_{nullptr};
  std::atomic<std::uint64_t> next_sequence_{1};
  std::atomic<std::uint64_t> session_id_{0};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
