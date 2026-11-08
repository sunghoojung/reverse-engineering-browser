// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_NETWORK_CAPTURE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_NETWORK_CAPTURE_SINK_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "base/files/file_path.h"
#include "base/no_destructor.h"
#include "base/synchronization/lock.h"

#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_network_cookies.h"
#include "brave/components/reverse_engineering_browser/common/native_network_headers.h"
#include "brave/components/reverse_engineering_browser/common/native_network_headers_hook.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"

class GURL;

namespace content {
class BrowserContext;
}

namespace net {
class HttpResponseHeaders;
struct RedirectInfo;
}  // namespace net

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
  // UI sequence only. Set once from the explicit disposable user-data directory,
  // before activation; never admit OTR/system/other profile contexts.
  void SetOwnedProfilePath(base::FilePath path);
  [[nodiscard]] bool IsOwnedContext(content::BrowserContext* context) const;
  [[nodiscard]] std::uint64_t generation() const noexcept;
  // capture_content admits raw request targets, body bytes and header blocks
  // for this configuration (--reb-capture-request-content). Metadata-only
  // sessions keep host-only targets and record body length, type and digest
  // without bytes, and no headers.
  void SetEmitter(NativeProbeEmitter emitter,
                  std::uint64_t session_id,
                  std::uint64_t category_mask,
                  std::uint64_t expires_at_monotonic_ns,
                  bool capture_content = false) noexcept;

  void RecordRequestStarted(std::uint64_t request_id,
                            std::int32_t initiator_request_id,
                            std::uint32_t initiator_process_id,
                            std::uint32_t tab_id,
                            std::uint64_t frame_id,
                            std::uint64_t browser_context_id_high,
                            std::uint64_t browser_context_id_low,
                            const network::ResourceRequest& request) noexcept;
  // Content sessions only, after RecordRequestStarted: a request without a
  // DevTools ID gets `reb-<request_id>`, so the network service reports the
  // headers it sends (protocol/native-network-v3.md). No request byte changes.
  void AssignNetworkHeadersId(std::uint64_t request_id, network::ResourceRequest& request) noexcept;
  void RecordRequestRedirected(std::uint64_t request_id,
                               std::int32_t initiator_request_id,
                               std::uint32_t initiator_process_id,
                               std::uint32_t tab_id,
                               std::uint64_t frame_id,
                               std::uint64_t browser_context_id_high,
                               std::uint64_t browser_context_id_low,
                               const net::RedirectInfo& redirect_info,
                               const network::mojom::URLResponseHead& response_head) noexcept;
  [[nodiscard]] std::uint64_t RecordResponseStarted(
      std::uint64_t request_id,
      std::int32_t initiator_request_id,
      std::uint32_t initiator_process_id,
      std::uint32_t tab_id,
      std::uint64_t frame_id,
      std::uint64_t browser_context_id_high,
      std::uint64_t browser_context_id_low,
      const network::mojom::URLResponseHead& response_head,
      bool synthetic = false,
      const net::HttpResponseHeaders* network_headers = nullptr) noexcept;
  void RecordRequestCompleted(std::uint64_t request_id,
                              std::int32_t initiator_request_id,
                              std::uint32_t initiator_process_id,
                              std::uint32_t tab_id,
                              std::uint64_t frame_id,
                              std::uint64_t browser_context_id_high,
                              std::uint64_t browser_context_id_low,
                              const network::URLLoaderCompletionStatus& status,
                              std::string_view disposition = {}) noexcept;
  // The network_headers_hook observer while a content session is active:
  // header blocks and the sent and received cookie lists of each hop.
  void RecordNetworkHeaders(NativeNetworkHeadersKind kind,
                            std::string_view devtools_request_id,
                            const std::vector<network::mojom::HttpRawHeaderPairPtr>& headers,
                            NativeNetworkCookies cookies = {}) noexcept;

 private:
  friend class base::NoDestructor<NativeNetworkCaptureSink>;
  NativeNetworkCaptureSink();

  void EmitRequestTarget(NativeProbeEmitter emitter,
                         const NativeProbeHeader& parent,
                         const GURL& url) noexcept;
  void EmitRequestBody(NativeProbeEmitter emitter,
                       const NativeProbeHeader& parent,
                       const network::ResourceRequest& request,
                       bool capture_content) noexcept;

  // One hop of a tracked request: its start record and URL.
  struct HeaderHop final {
    NativeProbeHeader parent;
    std::uint32_t hop = 0;
    std::string url;
  };
  // The DevTools pipe is not ordered with the loader pipe, so finished hops
  // whose heads say a raw request was emitted wait for it, oldest first.
  struct TrackedHeaders final {
    HeaderHop open;
    bool open_received = false;
    std::vector<HeaderHop> awaiting;
    std::string devtools_id;
    // The hop of the latest raw request; its raw response follows on one pipe.
    std::optional<HeaderHop> raw_hop;
  };
  void EndHeaderHop(TrackedHeaders& tracked, bool emitted_extra_info);
  // Measures, then serializes into an exactly reserved buffer, hashes, shares
  // or retains, and emits one header record. Requires header_lock_.
  template <class ForEach>
  void EmitHeaderBlock(NativeProbeEmitter emitter,
                       NativeProbeType type,
                       const NativeProbeHeader& parent,
                       NativeHeaderBlockSummary summary,
                       std::string_view url,
                       ForEach for_each);
  template <class ForEach>
  void EmitCookieList(NativeProbeEmitter emitter,
                      const NativeProbeHeader& parent,
                      NativeCookieListSummary summary,
                      std::string_view url,
                      ForEach for_each);
  // Shares an identical block or retains this one as an artifact the event
  // creates, within the header budget. Requires header_lock_.
  [[nodiscard]] NativeHeaderState RetainBlock(NativeArtifactKind kind,
                                              std::uint8_t share_kind,
                                              const NativeProbeHeader& parent,
                                              std::string_view url,
                                              std::vector<std::uint8_t> block,
                                              const std::array<std::uint8_t, 32>& sha256,
                                              NativeProbeEvent& event);

  base::FilePath owned_profile_path_;
  std::atomic<std::uint64_t> generation_{0};
  std::atomic<NativeProbeEmitter> emitter_{nullptr};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<bool> capture_content_{false};
  // Request-body artifacts admitted in this configuration (UI sequence).
  std::atomic<std::size_t> request_body_count_{0};
  std::atomic<std::size_t> request_body_bytes_{0};
  // Header blocks of this configuration; content sessions only.
  base::Lock header_lock_;
  std::unordered_map<std::uint64_t, TrackedHeaders> tracked_headers_;
  std::map<std::array<std::uint8_t, 37>, std::uint64_t> shared_header_blocks_;
  std::size_t header_bytes_ = 0;
  std::uint32_t unattributed_header_blocks_ = 0;
  std::uint32_t unattributed_cookie_lists_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_NETWORK_CAPTURE_SINK_H_
