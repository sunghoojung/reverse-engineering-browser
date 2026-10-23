// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_

#include <atomic>
#include <cstdint>
#include <span>
#include <string_view>

#include "base/component_export.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_vm_dispatch_emit.h"

namespace reb {

// True means admitted to the renderer ring, not delivered to the browser,
// broker, or evidence store. The generation identifies the captured policy.
// Emitters must remain non-blocking and non-throwing.
using NativeRendererProbeEmitter = bool (*)(const NativeProbeEvent& event,
                                            std::uint64_t config_generation) noexcept;

using NativeProbeFrameIdProvider = std::uint64_t (*)() noexcept;

// Trusted native detector output only. Registration is not exposed to page JS.
enum class NativeRuntimeScriptObservation : std::uint8_t {
  kCapturedVmCandidate,
  kCapturedLikelyVm,
  kStaticDispatchLoop,
};

class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeProbeSink final {
 public:
  static NativeProbeSink& Get();

  NativeProbeSink(const NativeProbeSink&) = delete;
  NativeProbeSink& operator=(const NativeProbeSink&) = delete;

  // Must be called from one serialized control sequence.
  void SetEmitters(NativeRendererProbeEmitter emitter,
                   NativeGeneratedArtifactEmitter artifact_emitter,
                   std::uint64_t session_id,
                   std::uint64_t category_mask,
                   std::uint64_t expires_at_monotonic_ns,
                   bool capture_canvas_images = false,
                   NativeProbeFrameIdProvider frame_id_provider = nullptr) noexcept;
  // Called after acquiring the transport queue pointer. A successful check
  // authorizes an in-flight insertion into that retained mapping; Disable does
  // not wait for producers already past this admission check.
  [[nodiscard]] bool CanAdmitEvent(const NativeProbeEvent& event,
                                   std::uint64_t config_generation) const noexcept;
  [[nodiscard]] bool IsArtifactCaptureEnabled() const noexcept;
  [[nodiscard]] bool IsVmCaptureEnabled() const noexcept;
  [[nodiscard]] bool IsCanvasImageCaptureEnabled() const noexcept;
  [[nodiscard]] bool RuntimeScriptSourceNeeded(std::uint64_t execution_context_id,
                                               std::uint64_t script_id) const noexcept;
  [[nodiscard]] std::uint64_t RuntimeCaptureGeneration() const noexcept;
  // Caller must preserve the generation at observation time. No URL matching,
  // cross-thread transfer, or inference of VM classification occurs here.
  [[nodiscard]] bool RegisterRuntimeScriptObservation(
      std::uint64_t generation,
      std::uint64_t execution_context_id,
      std::uint64_t script_id,
      NativeRuntimeScriptObservation observation) noexcept;
  [[nodiscard]] bool RuntimeBufferHasSignal(std::uint64_t generation,
                                            std::uint64_t execution_context_id,
                                            std::uint64_t frame_id,
                                            std::size_t bytes,
                                            std::uint64_t script_id,
                                            bool is_eval) noexcept;
  void RecordRuntimeBufferOmission(std::uint64_t generation,
                                   std::uint64_t frame_id,
                                   std::string_view reason) noexcept;
  void CaptureRuntimeTypedArray(std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::span<const std::uint8_t> content,
                                const NativeRuntimeScript& script) noexcept;
  void CaptureGeneratedArtifact(NativeArtifactKind kind,
                                NativeArtifactCaptureOrigin capture_origin,
                                std::uint64_t creator_event_id,
                                std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::span<const std::uint8_t> content) noexcept;
  void CaptureGeneratedArtifact(NativeArtifactKind kind,
                                NativeArtifactCaptureOrigin capture_origin,
                                std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::span<const std::uint8_t> content) noexcept {
    CaptureGeneratedArtifact(kind, capture_origin, 0, execution_context_id, frame_id, source_url,
                             content);
  }
  void RecordApiCall(NativeProbeCategory category, std::string_view operation) noexcept;
  void RecordPropertyRead(NativeProbeCategory category, std::string_view operation) noexcept;
  // Call-site state is an opaque, monotonically ordered configuration claim,
  // not a session ID. Zero initializes an unobserved site. Failed admission
  // leaves generation - 1 so stale callers cannot reclaim a newer generation.
  void RecordApiCallOnce(NativeProbeCategory category,
                         std::string_view operation,
                         std::atomic<std::uint64_t>& observed_generation) noexcept;
  void RecordPropertyReadOnce(NativeProbeCategory category,
                              std::string_view operation,
                              std::atomic<std::uint64_t>& observed_generation) noexcept;
  void RecordCanvasToDataUrl() noexcept;
  void RecordCanvasToDataUrl(std::string_view data_url) noexcept;
  void RecordWebAudioCall(std::string_view operation) noexcept;
  void RecordRequestInitiated(std::int32_t request_id,
                              std::string_view method,
                              std::string_view url) noexcept;
  // Copies one guest step the caller already observed. The instruction
  // pointer, opcode, and handler index are not read from V8, Wasm, canvas,
  // or a static handler table. At most kNativeVmDispatchSampleBudget samples
  // are admitted for one capture configuration. Overflow and rejected emits
  // stay on a generation-scoped counter until PublishVmDispatchBudgetGap
  // writes one vm gap whose decimal payload is the exact unreported count.
  void RecordVmDispatchSample(const NativeVmDispatchSamplePayload& sample) noexcept;
  // Emits one coalesced vm gap for dispatch observations that were not
  // retained. A full probe queue already counts its own drops, so this gap
  // covers budget overflow and emits rejected before the queue. Safe to call
  // when capture is inactive or the counter is caught up.
  void PublishVmDispatchBudgetGap() noexcept;

 private:
  NativeProbeSink() noexcept;

  std::uint64_t RecordRuntimeBufferEvent(NativeProbeType type,
                                         std::uint64_t frame_id,
                                         std::string_view reason,
                                         std::uint64_t generation) noexcept;

  [[nodiscard]] std::uint64_t RecordSurfaceOperation(
      NativeProbeCategory category,
      NativeProbeType type,
      std::string_view operation,
      std::atomic<std::uint64_t>* observed_generation = nullptr) noexcept;

  void NoteVmDispatchLoss(std::uint64_t generation,
                          std::uint64_t session_id,
                          std::uint64_t monotonic_time_ns,
                          std::uint64_t frame_id,
                          std::uint32_t process_id,
                          std::uint32_t thread_id,
                          std::uint64_t interpreter_artifact_id) noexcept;

  std::atomic<NativeRendererProbeEmitter> emitter_{nullptr};
  std::atomic<NativeProbeFrameIdProvider> frame_id_provider_{nullptr};
  std::atomic<NativeGeneratedArtifactEmitter> artifact_emitter_{nullptr};
  std::atomic<std::uint64_t> next_sequence_{1};
  // Even generations are stable. SetEmitters transitions through the next odd
  // generation while replacing the independently atomic policy fields.
  std::atomic<std::uint64_t> config_generation_{0};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<bool> capture_canvas_images_{false};
  std::atomic<std::size_t> runtime_typed_array_count_{0};
  NativeVmDispatchBudget dispatch_sample_budget_;
  // Cumulative dispatch losses for the active capture. reported_ trails
  // dropped_ until a vm gap is admitted. Identity fields describe the losses
  // still waiting to be published. The counters are not reset: a generation
  // bump publishes the remainder first, then new losses append.
  std::atomic<std::uint64_t> dispatch_loss_generation_{0};
  std::atomic<std::uint64_t> dispatch_loss_dropped_{0};
  std::atomic<std::uint64_t> dispatch_loss_reported_{0};
  std::atomic<std::uint64_t> dispatch_loss_artifact_id_{0};
  std::atomic<std::uint64_t> dispatch_loss_session_id_{0};
  std::atomic<std::uint64_t> dispatch_loss_time_ns_{0};
  std::atomic<std::uint64_t> dispatch_loss_frame_id_{0};
  std::atomic<std::uint32_t> dispatch_loss_process_id_{0};
  std::atomic<std::uint32_t> dispatch_loss_thread_id_{0};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
