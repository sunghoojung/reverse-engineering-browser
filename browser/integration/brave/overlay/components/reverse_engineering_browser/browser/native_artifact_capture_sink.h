// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "base/no_destructor.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "mojo/public/cpp/system/data_pipe.h"

namespace network {
struct ResourceRequest;
namespace mojom {
class URLResponseHead;
}
}  // namespace network

namespace reb {

// Browser-process capture boundary for immutable JavaScript and WebAssembly
// response bodies plus renderer-submitted generated source. It is enabled only
// for an authorized artifact category and keeps every item explicitly bounded.
class NativeArtifactCaptureSink final {
 public:
  static NativeArtifactCaptureSink& Get();

  NativeArtifactCaptureSink(const NativeArtifactCaptureSink&) = delete;
  NativeArtifactCaptureSink& operator=(const NativeArtifactCaptureSink&) = delete;

  [[nodiscard]] bool IsEnabled() const noexcept;
  void SetEmitter(NativeProbeEmitter emitter,
                  std::uint64_t session_id,
                  std::uint64_t category_mask,
                  std::uint64_t expires_at_monotonic_ns) noexcept;

  [[nodiscard]] mojo::ScopedDataPipeConsumerHandle MaybeCaptureResponse(
      std::uint64_t request_id,
      std::uint64_t frame_id,
      std::uint64_t creator_event_id,
      const network::ResourceRequest& request,
      const network::mojom::URLResponseHead& response_head,
      mojo::ScopedDataPipeConsumerHandle body);

  void CaptureGeneratedArtifact(NativeArtifactKind kind,
                                NativeArtifactCaptureOrigin capture_origin,
                                std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                mojo_base::BigBuffer content);

  static void TransferCompleted(std::uint64_t artifact_id,
                                NativeArtifactReceiveStatus status) noexcept;

 private:
  friend class base::NoDestructor<NativeArtifactCaptureSink>;

  struct CaptureContext final {
    NativeArtifactHeader header;
    std::string url;
    std::string mime_type;
    std::size_t reservation_bytes = 0;
    std::uint64_t request_id = 0;
    std::uint64_t frame_id = 0;
  };

  struct PendingContext final {
    std::uint64_t request_id = 0;
    std::uint64_t frame_id = 0;
  };

  NativeArtifactCaptureSink();
  ~NativeArtifactCaptureSink();

  void OnBodyComplete(std::unique_ptr<CaptureContext> context,
                      bool complete,
                      std::vector<std::uint8_t> content);
  void OnTransferCompleted(std::uint64_t artifact_id, NativeArtifactReceiveStatus status) noexcept;
  void EmitResult(NativeProbeType type,
                  std::uint64_t artifact_id,
                  std::uint64_t request_id,
                  std::uint64_t frame_id,
                  const std::string& detail) noexcept;
  [[nodiscard]] bool Reserve(std::size_t bytes) noexcept;
  void Release(std::size_t bytes) noexcept;

  std::atomic<NativeProbeEmitter> emitter_{nullptr};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<std::uint64_t> next_artifact_id_{1};
  std::atomic<std::size_t> active_bytes_{0};
  std::map<std::uint64_t, PendingContext> pending_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_
