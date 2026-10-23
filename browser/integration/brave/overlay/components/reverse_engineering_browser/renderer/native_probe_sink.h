// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "base/component_export.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_vm_dispatch_emit.h"

namespace reb {

// Maximum allocating-script source prefix scanned to admit a runtime buffer.
// The same bound is the renderer classifier's window.
inline constexpr std::size_t kRuntimeScriptNoteBytes = 256U * 1024U;
inline constexpr std::size_t kRuntimeTypedArrayMaxSnapshots = 16;

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
  // True while this script's source attempt is remembered in this generation,
  // including a negative classification or an unavailable conversion.
  [[nodiscard]] bool RuntimeScriptSourceNoted(std::uint64_t generation,
                                              std::uint64_t execution_context_id,
                                              std::uint64_t script_id) const noexcept;
  // Check before UTF-8 conversion. Positive observations stay pinned; negative
  // entries rotate within 64 slots. At most 256 attempts (including conversion
  // misses and scan allocation failures) run per generation and thread.
  [[nodiscard]] bool RuntimeScriptNoteAccepts(std::uint64_t generation,
                                              std::uint64_t execution_context_id,
                                              std::uint64_t script_id) const noexcept;
  // Records a bounded structural classification, returning whether it found a
  // signal. Cached entries are not rescanned. Evicted negatives can be retried
  // only within the total attempt budget. Allocation failure is retryable within
  // that budget; a full positive table or exhausted budget refuses the scan.
  // source_truncated is true when source is a prefix of a longer script.
  [[nodiscard]] bool NoteRuntimeScriptSource(std::uint64_t generation,
                                             std::uint64_t execution_context_id,
                                             std::uint64_t script_id,
                                             std::span<const std::uint8_t> source,
                                             bool source_truncated = false) noexcept;
  // Remembers a conversion that produced no bytes, so the caller does not
  // allocate the prefix again. Returns false.
  [[nodiscard]] bool RememberRuntimeScriptMiss(std::uint64_t generation,
                                               std::uint64_t execution_context_id,
                                               std::uint64_t script_id) noexcept;
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
  // are admitted for one capture configuration.
  void RecordVmDispatchSample(const NativeVmDispatchSamplePayload& sample) noexcept;

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
  // Monotonic generation claims are never reset: an old capture cannot spend
  // or release a replacement configuration's snapshot quota.
  std::array<std::atomic<std::uint64_t>, kRuntimeTypedArrayMaxSnapshots>
      runtime_snapshot_generations_{};
  NativeVmDispatchBudget dispatch_sample_budget_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
