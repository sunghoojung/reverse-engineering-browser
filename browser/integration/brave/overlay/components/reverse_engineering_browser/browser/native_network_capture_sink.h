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
#include "brave/components/reverse_engineering_browser/common/native_navigation_initiator_hook.h"
#include "brave/components/reverse_engineering_browser/common/native_network_cookies.h"
#include "brave/components/reverse_engineering_browser/common/native_network_headers.h"
#include "brave/components/reverse_engineering_browser/common/native_network_headers_hook.h"
#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_tab_link.h"

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

struct NativeRequestBodyReadOutcome;

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
                            const network::ResourceRequest& request,
                            NativeLoaderKind loader_kind = NativeLoaderKind::kNotRecorded,
                            const NativeBrowserRequestOwner& owner = {}) noexcept;
  // Content sessions only, after RecordRequestStarted: a request without a
  // DevTools ID gets `reb-<request_id>`, so the network service reports the
  // headers it sends (protocol/native-network-v3.md). No request byte changes.
  // A failed header or cookie artifact may no longer be shared by later requests.
  void ForgetSharedBlock(std::uint64_t artifact_id) noexcept;
  // Records every deferred body while the session can still record them.
  void FlushDeferredBodies() noexcept;
  void AssignNetworkHeadersId(std::uint64_t request_id, network::ResourceRequest& request) noexcept;
  // Content sessions only, right after AssignNetworkHeadersId: reads a body
  // with file, blob or stream parts, whose request_body record then follows
  // when the read ends (protocol/native-network-v3.md). Only a stream part's
  // getter changes, to one that forwards every byte unchanged.
  void TeeRequestBody(std::uint64_t request_id, network::ResourceRequest& request) noexcept;
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
  // Keeps a navigation's renderer stack by DevTools ID until its request starts.
  bool NoteNavigationInitiator(std::string_view devtools_request_id,
                               std::uint32_t renderer_process_id,
                               std::uint64_t renderer_sequence) noexcept;

 private:
  friend class base::NoDestructor<NativeNetworkCaptureSink>;
  NativeNetworkCaptureSink();

  void EmitRequestTarget(NativeProbeEmitter emitter,
                         const NativeProbeHeader& parent,
                         const GURL& url) noexcept;
  void EmitRequestBody(NativeProbeEmitter emitter,
                       const NativeProbeHeader& parent,
                       const network::ResourceRequest& request,
                       bool capture_content,
                       const NativeBrowserRequestOwner& owner) noexcept;
  void EmitNavigationLink(NativeProbeEmitter emitter,
                          const NativeProbeHeader& parent,
                          std::string_view devtools_request_id) noexcept;

  // A body record waiting for its read.
  struct DeferredBody final {
    NativeProbeHeader parent{};
    NativeRequestBodySummary summary;
    std::string url;
    std::string mime_type;
  };
  void EmitDeferredBody(NativeProbeEmitter emitter,
                        const DeferredBody& body,
                        NativeRequestBodyState state) noexcept;
  // The read's recorder: emits the body record and returns its sequence.
  std::uint64_t RecordBodyRead(std::uint64_t generation,
                               std::uint64_t read_id,
                               const NativeRequestBodyReadOutcome& outcome) noexcept;

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
  // Header blocks of this configuration; content sessions only.
  base::Lock header_lock_;
  std::unordered_map<std::uint64_t, TrackedHeaders> tracked_headers_;
  std::map<std::array<std::uint8_t, 37>, std::uint64_t> shared_header_blocks_;
  std::size_t header_bytes_ = 0;
  std::uint32_t unattributed_header_blocks_ = 0;
  std::uint32_t unattributed_cookie_lists_ = 0;
  // Hashed DevTools IDs of the newest finished requests, so a late block for one is counted.
  std::array<std::size_t, 256> finished_devtools_ids_{};
  std::size_t finished_devtools_next_ = 0;
  // Pending navigation links, newest kept.
  struct NavigationInitiator final {
    std::string devtools_id;
    std::uint32_t process_id = 0;
    std::uint64_t sequence = 0;
  };
  base::Lock navigation_lock_;
  std::array<NavigationInitiator, 64> navigation_initiators_;
  std::size_t navigation_initiator_next_ = 0;
  // UI sequence. The latest start's unread body, until TeeRequestBody takes it,
  // and the bodies being read.
  std::optional<DeferredBody> unread_body_;
  std::map<std::uint64_t, DeferredBody> reading_bodies_;
  std::uint64_t next_read_id_ = 1;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_NETWORK_CAPTURE_SINK_H_
