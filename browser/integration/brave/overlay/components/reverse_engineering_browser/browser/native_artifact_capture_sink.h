// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include "brave/components/reverse_engineering_browser/common/native_wasm_dispatch.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest.h"

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

  void CaptureWasmDispatch(const NativeWasmDispatchObservation& observation,
                           mojo_base::BigBuffer content,
                           std::function<bool()> is_current_document);
  void CaptureNativeGuest(const NativeGuestCapture& capture,
                          std::uint64_t epoch,
                          std::function<bool()> is_current_document);
  void CaptureNativeGuestHost(const NativeProbeEvent& event, std::uint64_t epoch);
  void CaptureRuntimeTypedArray(int renderer_process_id,
                                std::uint64_t capture_session_id,
                                std::uint64_t script_id,
                                bool is_eval,
                                std::uint64_t creator_event_id,
                                std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                mojo_base::BigBuffer script_source,
                                mojo_base::BigBuffer content);
  std::uint64_t CaptureGeneratedArtifact(NativeArtifactKind kind,
                                         NativeArtifactCaptureOrigin capture_origin,
                                         std::uint64_t creator_event_id,
                                         std::uint64_t execution_context_id,
                                         std::uint64_t frame_id,
                                         std::string_view source_url,
                                         mojo_base::BigBuffer content,
                                         std::uint64_t parent_artifact_id = 0);

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
    std::uint64_t generation = 0;
  };

  struct PendingContext final {
    std::uint64_t request_id = 0;
    std::uint64_t frame_id = 0;
    std::uint64_t session_id = 0;
    std::uint64_t generation = 0;
    // Only network creators share the browser event's sequence namespace.
    std::uint64_t parent_event_id = 0;
    NativeProbeCategory result_category = NativeProbeCategory::kArtifact;
    std::optional<NativeProbeEvent> wasm_observation = std::nullopt;
    std::function<bool()> is_current_document = {};
  };

  using GuestEventKey = std::pair<std::uint32_t, std::uint64_t>;
  struct GuestGroup final {
    std::uint64_t epoch = 0, document_high = 0, document_low = 0, module_id = 0, adapter_id = 0;
    std::uint64_t context_id = 0, frame_id = 0;
    std::uint32_t process_id = 0;
    std::array<std::uint8_t, 32> module_digest{}, recipe_digest{};
    // IPC admission is not artifact admission. Failure poisons this binding
    // until reconfiguration; empty-module messages never silently retry it.
    bool failed = false;
  };
  struct GuestInvocation final {
    NativeProbeEvent event{};
    std::uint64_t module_id = 0, adapter_id = 0;
    std::function<bool()> current_document;
    bool published = false;
  };
  struct GuestDispatch final {
    NativeProbeEvent event{};
    GuestEventKey invocation{};
    std::uint64_t epoch = 0, module_id = 0, adapter_id = 0, bytecode_id = 0;
    std::function<bool()> current_document;
    std::vector<NativeProbeEvent> hosts;
    bool published = false, failed = false;
  };
  void DrainGuestDependencies();
  std::vector<GuestGroup> guest_groups_;
  std::map<GuestEventKey, GuestInvocation> guest_invocations_;
  std::map<GuestEventKey, GuestDispatch> guest_dispatches_;
  // 0 pending, 1 accepted, 2 rejected; bounded by three artifacts per sample.
  std::map<std::uint64_t, std::uint8_t> guest_receipts_;
  std::size_t guest_host_count_ = 0, guest_capture_count_ = 0;
  bool guest_host_gap_emitted_ = false, guest_budget_gap_emitted_ = false;

  NativeArtifactCaptureSink();
  ~NativeArtifactCaptureSink();

  std::uint64_t CaptureGeneratedArtifactInternal(NativeArtifactKind kind,
                                                 NativeArtifactCaptureOrigin capture_origin,
                                                 std::uint64_t creator_event_id,
                                                 std::uint64_t execution_context_id,
                                                 std::uint64_t frame_id,
                                                 std::string_view source_url,
                                                 mojo_base::BigBuffer content,
                                                 std::uint64_t parent_artifact_id,
                                                 bool native_wasm_runtime);

  void OnBodyComplete(std::unique_ptr<CaptureContext> context,
                      bool complete,
                      std::vector<std::uint8_t> content);
  void OnTransferCompleted(std::uint64_t artifact_id, NativeArtifactReceiveStatus status) noexcept;
  void EmitResult(NativeProbeType type,
                  std::uint64_t artifact_id,
                  std::uint64_t request_id,
                  std::uint64_t frame_id,
                  const std::string& detail,
                  NativeProbeCategory category = NativeProbeCategory::kArtifact,
                  std::uint64_t parent_event_id = 0) noexcept;
  [[nodiscard]] bool IsEnabledFor(NativeProbeCategory category) const noexcept;
  [[nodiscard]] bool IsCurrentCapture(std::uint64_t session_id,
                                      std::uint64_t generation) const noexcept;
  [[nodiscard]] bool Reserve(std::size_t bytes) noexcept;
  void Release(std::size_t bytes) noexcept;

  // Configuration, body completions and posted transfer ACKs run on the browser
  // sequence. A new generation retires admitted work even if session ID is reused.
  std::atomic<std::uint64_t> generation_{0};
  std::atomic<NativeProbeEmitter> emitter_{nullptr};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<std::uint64_t> next_artifact_id_{1};
  std::atomic<std::size_t> active_bytes_{0};
  std::atomic<std::size_t> runtime_typed_array_count_{0};
  std::map<std::uint64_t, PendingContext> pending_;
  std::size_t wasm_dispatch_count_ = 0;
  bool wasm_dispatch_budget_gap_emitted_ = false;
  // Only the browser assigns artifact IDs. Never key this relation by URL.
  using ScriptKey = std::tuple<int, std::uint64_t, std::uint64_t, std::uint64_t>;
  std::map<ScriptKey, std::uint64_t> allocating_scripts_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_
