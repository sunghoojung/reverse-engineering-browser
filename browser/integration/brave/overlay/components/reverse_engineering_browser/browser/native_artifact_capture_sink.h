// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include "brave/components/reverse_engineering_browser/common/native_wasm_dispatch.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_sample_budget.h"

#include "base/functional/callback.h"
#include "base/memory/scoped_refptr.h"
#include "base/no_destructor.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_stream.h"
#include "brave/components/reverse_engineering_browser/browser/native_request_body_reader.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_memory_pool.h"
#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#include "brave/components/reverse_engineering_browser/common/native_network_response_body.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "mojo/public/cpp/system/data_pipe.h"

namespace network {
class ResourceRequestBody;
struct ResourceRequest;
namespace mojom {
class URLResponseHead;
}
}  // namespace network

namespace reb {

// The first `size` bytes of `body`'s in-memory elements, or of `text`.
struct NativeRequestContent final {
  NativeArtifactKind kind = NativeArtifactKind::kUnknown;
  std::uint64_t request_id = 0;
  std::uint64_t frame_id = 0;
  std::uint64_t creator_event_id = 0;
  std::string url;
  std::string mime_type;
  std::size_t size = 0;
  scoped_refptr<network::ResourceRequestBody> body;
  std::string text;
};

enum class NativeRequestContentAdmission : std::uint8_t {
  kQueued,
  kUnavailable,
  kSessionBudget,
  kRefused,
};

// What a request body read retained, for the record that names it.
struct NativeRequestBodyReadOutcome final {
  NativeRequestBodyState state = NativeRequestBodyState::kNotCapturedReadIncomplete;
  std::uint64_t artifact_id = 0;
  std::uint64_t body_length = 0;
  std::uint64_t captured_length = 0;
  std::array<std::uint8_t, 32> sha256{};
};
// Emits the body record and returns its sequence, the artifact's creator; zero
// when the session no longer records it.
using NativeRequestBodyRecorder =
    base::OnceCallback<std::uint64_t(const NativeRequestBodyReadOutcome&)>;

// Browser-process capture boundary for immutable JavaScript and WebAssembly
// response bodies plus renderer-submitted generated source. Other response
// bodies go to NativeResponseBodyCapture in content sessions. It is enabled
// only for an authorized artifact category and keeps every item bounded.
class NativeArtifactCaptureSink final {
 public:
  static NativeArtifactCaptureSink& Get();

  NativeArtifactCaptureSink(const NativeArtifactCaptureSink&) = delete;
  NativeArtifactCaptureSink& operator=(const NativeArtifactCaptureSink&) = delete;

  [[nodiscard]] bool IsEnabled() const noexcept;
  void SetEmitter(NativeProbeEmitter emitter,
                  std::uint64_t session_id,
                  std::uint64_t category_mask,
                  std::uint64_t expires_at_monotonic_ns,
                  std::uint64_t request_content_budget = kNativeRequestContentDefaultBudgetBytes,
                  const NativeResponseBodyPolicy& response_bodies = {}) noexcept;

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
  // Same module transfer and ACK ordering as CaptureWasmDispatch.
  void CaptureWasmIndirect(const NativeWasmIndirectObservation& observation,
                           mojo_base::BigBuffer content,
                           std::function<bool()> is_current_document);
  // Replaces the filters used by later observations. A new SetEmitter restores
  // the unrestricted policy. Invalid policies are ignored.
  void SetWasmSampleBudgetPolicy(const NativeWasmSampleBudgetPolicy& policy) noexcept;
  // Zeros both stream counters without dropping pending module transfers or
  // changing the session. The next observation of each stream is index 0.
  void ResetWasmSampleBudgets() noexcept;
  // Empty content binds the single module artifact already stored for this
  // document. Zero or several matches are explicit gaps, never a guess.
  void CaptureWasmExecution(const NativeWasmExecutionObservation& observation,
                            mojo_base::BigBuffer content,
                            std::function<bool()> is_current_document);
  // module_status receives the browser verdict for module bytes this capture
  // carried (accepted once module and adapter artifacts are both accepted).
  void CaptureNativeGuest(const NativeGuestCapture& capture,
                          std::uint64_t epoch,
                          std::function<bool()> is_current_document,
                          std::function<void(bool)> module_status = {});
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

  // UI sequence. Copies off it; every loss, from stream open on, is one event
  // parented to the creator.
  [[nodiscard]] NativeRequestContentAdmission CaptureRequestContent(NativeRequestContent content,
                                                                    std::uint64_t& artifact_id);
  // UI sequence. Reads a body with file, blob or stream parts through
  // NativeRequestBodyReader and streams it as a request_body artifact. A
  // stream part is forwarded through an observational tee, so `request` is
  // changed only by that interposed getter. `record` runs once, here.
  [[nodiscard]] NativeRequestContentAdmission ReadRequestBody(network::ResourceRequest& request,
                                                              std::uint64_t request_id,
                                                              std::uint64_t frame_id,
                                                              std::string url,
                                                              std::string mime_type,
                                                              NativeRequestBodyRecorder record);
  // Queues one header block (text/plain) or cookie list
  // (application/x-reb-cookie-list) as a sensitive artifact within the
  // in-flight pool. Returns its ID, or zero when nothing was queued; the caller
  // records that outcome (protocol/native-network-v3.md).
  [[nodiscard]] std::uint64_t CaptureHeaderBlock(NativeArtifactKind kind,
                                                 std::uint64_t request_id,
                                                 std::uint64_t frame_id,
                                                 std::uint64_t creator_event_id,
                                                 std::string url,
                                                 std::vector<std::uint8_t> content);

  static void TransferCompleted(std::uint64_t artifact_id,
                                NativeArtifactReceiveStatus status) noexcept;
  [[nodiscard]] std::size_t in_flight_bytes() const noexcept { return memory_pool_.used(); }
  // Response bodies share the pool, the artifact IDs and the ACK path.
  [[nodiscard]] NativeArtifactMemoryPool& memory_pool() noexcept { return memory_pool_; }
  [[nodiscard]] std::uint64_t NextArtifactId() noexcept {
    return next_artifact_id_.fetch_add(1, std::memory_order_relaxed);
  }
  // A response body stream opened by NativeResponseBodyCapture. Its end ACK,
  // or first refusal, becomes artifact_captured or artifact_capture_failed
  // parented to the creator record and is passed back to that capture.
  void TrackResponseBody(std::uint64_t artifact_id,
                         std::uint64_t request_id,
                         std::uint64_t frame_id,
                         std::uint64_t creator_event_id) noexcept;

 private:
  friend class base::NoDestructor<NativeArtifactCaptureSink>;

  struct CaptureContext final {
    NativeArtifactHeader header;
    std::uint64_t request_id = 0;
    std::uint64_t frame_id = 0;
    std::uint64_t generation = 0;
  };

  struct CopiedContent final {
    NativeArtifactStream stream;
    std::size_t size = 0;
  };
  // A script or Wasm response streaming through the tee.
  struct ResponseStream final {
    std::uint64_t request_id = 0;
    std::uint64_t frame_id = 0;
    NativeArtifactStream stream;
  };

  struct PendingContext final {
    std::uint64_t request_id = 0;
    std::uint64_t frame_id = 0;
    std::uint64_t session_id = 0;
    std::uint64_t generation = 0;
    // Only network creators share the browser event's sequence namespace.
    std::uint64_t parent_event_id = 0;
    NativeProbeCategory result_category = NativeProbeCategory::kArtifact;
    bool response_body = false;
    // A request body still being read: no record exists yet to parent a loss
    // to, so a report sets read_lost and OnRequestBodyRead records it.
    bool read_open = false;
    bool read_lost = false;
    // Physical dispatch observations that share this module artifact.
    std::vector<std::pair<NativeProbeEvent, std::function<bool()>>> wasm_observations = {};
  };

  using GuestEventKey = std::pair<std::uint32_t, std::uint64_t>;
  // The receiver's verdict on one guest artifact. An ID with no entry was
  // never queued or was cleared at expiry, and reads as rejected.
  enum class GuestReceipt : std::uint8_t { kPending, kAccepted, kRejected };
  // A document's module binding. IPC admission is not artifact admission:
  // only kPending and kAccepted bind empty-module samples. Fresh module bytes
  // move kUnbound or kRejected to kPending, at most
  // kNativeGuestModuleAttemptLimit times; the module and adapter receipts
  // then settle it as kAccepted or kRejected.
  enum class GuestBinding : std::uint8_t { kUnbound, kPending, kAccepted, kRejected };
  struct GuestGroup final {
    std::uint64_t epoch = 0, document_high = 0, document_low = 0, module_id = 0, adapter_id = 0;
    std::uint64_t context_id = 0, frame_id = 0;
    std::uint32_t process_id = 0;
    std::array<std::uint8_t, 32> module_digest{}, recipe_digest{};
    GuestBinding binding = GuestBinding::kUnbound;
    std::uint8_t attempts = 0;
    // The bound document. Once it is gone (navigation, frame or renderer
    // exit, retired epoch) no sample can name this group again.
    std::function<bool()> current_document;
    std::vector<std::function<void(bool)>> status_waiters;
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
  // Frees the groups whose document is gone, so the group bound counts live
  // documents only. Their outstanding module verdicts are reported rejected.
  void ReclaimGuestGroups();
  // Holds a physical Wasm observation until its document's module artifact is
  // accepted, transferring the module once per document.
  void PublishAfterWasmModule(NativeProbeEvent event,
                              const std::vector<std::uint8_t>& bytes,
                              std::uint64_t execution_context_id,
                              std::uint64_t document_token_high,
                              std::uint64_t document_token_low,
                              std::string_view source_url,
                              std::function<bool()> is_current_document);
  // Fills the renderer sequence slot of an unpublished record with a gap. A
  // record without a slot gets a browser-sequence gap, so every refusal stays
  // visible.
  void EmitRendererGap(const NativeProbeEvent& source, std::string_view reason) noexcept;
  // Publishes a host record without its guest parent; one marker per reason.
  void PublishUnparentedHost(NativeProbeEvent host, bool& gap_emitted, std::string_view reason);
  // Runs shortly before session expiry, after which the session drops every
  // record: unresolved guest work becomes explicit gaps, held hosts survive.
  void FlushBeforeExpiry(std::uint64_t generation);
  // Retains open response bodies, then turns every unresolved guest dispatch
  // and held Wasm observation into a gap in its own slot, publishing held
  // hosts unparented.
  void FlushPendingWork(std::string_view guest_reason, std::string_view wasm_reason);
  std::vector<GuestGroup> guest_groups_;
  std::map<GuestEventKey, GuestInvocation> guest_invocations_;
  std::map<GuestEventKey, GuestDispatch> guest_dispatches_;
  // Bounded by three artifacts per sample.
  std::map<std::uint64_t, GuestReceipt> guest_receipts_;
  std::size_t guest_routed_host_count_ = 0, guest_held_host_count_ = 0, guest_capture_count_ = 0;
  std::set<GuestEventKey> guest_host_identities_;
  // One marker per reason for losses with no renderer slot to fill: a host
  // published without its parent, or a host record without a sequence.
  bool guest_host_malformed_gap_emitted_ = false, guest_host_parent_lost_gap_emitted_ = false,
       guest_host_parent_omitted_gap_emitted_ = false;

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

  void OnBodyData(std::uint64_t artifact_id, std::span<const std::uint8_t> chunk);
  void OnBodyComplete(std::uint64_t artifact_id, NativeArtifactBodyEnd end);
  // Ends a response stream that failed, with the reason it carries.
  void FailResponseStream(std::uint64_t artifact_id, const char* reason);
  static CopiedContent CopyRequestContent(scoped_refptr<network::ResourceRequestBody> body,
                                          std::string text,
                                          std::size_t size,
                                          NativeArtifactStream stream);
  void OnRequestContentCopied(std::unique_ptr<CaptureContext> context, CopiedContent copied);
  void OnRequestBodyRead(std::uint64_t generation,
                         std::uint64_t request_id,
                         std::uint64_t frame_id,
                         std::size_t allowance,
                         NativeRequestBodyRecorder record,
                         NativeRequestBodyReadResult result);
  void RefundRequestContent(std::size_t bytes) noexcept;
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

  // Configuration, body completions and posted transfer ACKs run on the browser
  // sequence. A new generation retires admitted work even if session ID is reused.
  std::atomic<std::uint64_t> generation_{0};
  std::atomic<NativeProbeEmitter> emitter_{nullptr};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<std::uint64_t> next_artifact_id_{1};
  NativeArtifactMemoryPool memory_pool_{kNativeArtifactInFlightBytes};
  std::uint64_t request_content_budget_ = 0;
  std::uint64_t request_content_used_ = 0;
  std::set<std::array<std::uint8_t, 32>> request_content_digests_;
  std::atomic<std::size_t> runtime_typed_array_count_{0};
  std::map<std::uint64_t, PendingContext> pending_;
  std::map<std::uint64_t, ResponseStream> response_streams_;
  std::size_t wasm_dispatch_count_ = 0;
  // One artifact per exact module and document for physical observations.
  // Value is the artifact ID and whether its transfer was already accepted.
  using WasmModuleKey = std::tuple<std::uint32_t,
                                   std::uint64_t,
                                   std::uint64_t,
                                   std::uint64_t,
                                   std::uint64_t,
                                   std::array<std::uint8_t, 32>>;
  std::map<WasmModuleKey, std::pair<std::uint64_t, bool>> wasm_dispatch_modules_;
  std::size_t wasm_indirect_count_ = 0;
  std::uint64_t wasm_budget_epoch_ = 2;
  NativeWasmSampleBudgetPolicy wasm_sample_budget_{};
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots> wasm_dispatch_function_keys_{};
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots> wasm_indirect_function_keys_{};
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots> wasm_indirect_site_keys_{};
  std::size_t wasm_execution_count_ = 0;
  // Only the browser assigns artifact IDs. Never key this relation by URL.
  using ScriptKey = std::tuple<int, std::uint64_t, std::uint64_t, std::uint64_t>;
  std::map<ScriptKey, std::uint64_t> allocating_scripts_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_CAPTURE_SINK_H_
