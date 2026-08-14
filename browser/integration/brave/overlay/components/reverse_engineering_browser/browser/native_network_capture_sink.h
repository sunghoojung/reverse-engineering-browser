// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_NETWORK_CAPTURE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_NETWORK_CAPTURE_SINK_H_

#include <atomic>
#include <cstdint>

#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"

namespace net {
struct RedirectInfo;
}

namespace network {
struct ResourceRequest;
struct URLLoaderCompletionStatus;
namespace mojom {
class URLResponseHead;
}
}  // namespace network

namespace reb {

// Browser-process observation boundary for Brave's existing URL loader factory
// and client proxies. Registering an emitter explicitly enables capture for one
// authorized session. The inactive path is one atomic load per lifecycle event.
class NativeNetworkCaptureSink final {
 public:
  static NativeNetworkCaptureSink& Get();

  NativeNetworkCaptureSink(const NativeNetworkCaptureSink&) = delete;
  NativeNetworkCaptureSink& operator=(const NativeNetworkCaptureSink&) = delete;

  [[nodiscard]] bool IsEnabled() const noexcept;
  void SetEmitter(NativeProbeEmitter emitter,
                  std::uint64_t session_id,
                  std::uint64_t category_mask,
                  std::uint64_t expires_at_monotonic_ns) noexcept;

  void RecordRequestStarted(std::uint64_t request_id,
                            std::int32_t initiator_request_id,
                            std::uint32_t initiator_process_id,
                            std::uint64_t frame_id,
                            std::uint64_t browser_context_id_high,
                            std::uint64_t browser_context_id_low,
                            const network::ResourceRequest& request) noexcept;
  void RecordRequestRedirected(std::uint64_t request_id,
                               std::int32_t initiator_request_id,
                               std::uint32_t initiator_process_id,
                               std::uint64_t frame_id,
                               std::uint64_t browser_context_id_high,
                               std::uint64_t browser_context_id_low,
                               const net::RedirectInfo& redirect_info,
                               const network::mojom::URLResponseHead& response_head) noexcept;
  void RecordResponseStarted(std::uint64_t request_id,
                             std::int32_t initiator_request_id,
                             std::uint32_t initiator_process_id,
                             std::uint64_t frame_id,
                             std::uint64_t browser_context_id_high,
                             std::uint64_t browser_context_id_low,
                             const network::mojom::URLResponseHead& response_head) noexcept;
  void RecordRequestCompleted(std::uint64_t request_id,
                              std::int32_t initiator_request_id,
                              std::uint32_t initiator_process_id,
                              std::uint64_t frame_id,
                              std::uint64_t browser_context_id_high,
                              std::uint64_t browser_context_id_low,
                              const network::URLLoaderCompletionStatus& status) noexcept;

 private:
  NativeNetworkCaptureSink() = default;

  std::atomic<NativeProbeEmitter> emitter_{nullptr};
  std::atomic<std::uint64_t> next_sequence_{1};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_NETWORK_CAPTURE_SINK_H_
