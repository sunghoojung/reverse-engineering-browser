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

namespace reb {

using NativeProbeFrameIdProvider = std::uint64_t (*)() noexcept;

class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeProbeSink final {
 public:
  static NativeProbeSink& Get();

  NativeProbeSink(const NativeProbeSink&) = delete;
  NativeProbeSink& operator=(const NativeProbeSink&) = delete;

  // Must be called from one serialized control sequence.
  void SetEmitters(NativeProbeEmitter emitter,
                   NativeGeneratedArtifactEmitter artifact_emitter,
                   std::uint64_t session_id,
                   std::uint64_t category_mask,
                   std::uint64_t expires_at_monotonic_ns,
                   bool capture_canvas_images = false,
                   NativeProbeFrameIdProvider frame_id_provider = nullptr) noexcept;
  [[nodiscard]] bool IsArtifactCaptureEnabled() const noexcept;
  [[nodiscard]] bool IsCanvasImageCaptureEnabled() const noexcept;
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
  void RecordApiCallOnce(NativeProbeCategory category,
                         std::string_view operation,
                         std::atomic<std::uint64_t>& observed_session_id) noexcept;
  void RecordPropertyReadOnce(NativeProbeCategory category,
                              std::string_view operation,
                              std::atomic<std::uint64_t>& observed_session_id) noexcept;
  void RecordCanvasToDataUrl() noexcept;
  void RecordCanvasToDataUrl(std::string_view data_url) noexcept;
  void RecordWebAudioCall(std::string_view operation) noexcept;
  void RecordRequestInitiated(std::int32_t request_id,
                              std::string_view method,
                              std::string_view url) noexcept;

 private:
  NativeProbeSink() = default;

  [[nodiscard]] std::uint64_t RecordSurfaceOperation(
      NativeProbeCategory category,
      NativeProbeType type,
      std::string_view operation,
      std::atomic<std::uint64_t>* observed_session_id = nullptr) noexcept;

  std::atomic<NativeProbeEmitter> emitter_{nullptr};
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
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
