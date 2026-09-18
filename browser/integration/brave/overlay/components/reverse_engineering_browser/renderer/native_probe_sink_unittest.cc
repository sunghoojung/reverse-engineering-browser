// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/test/test_timeouts.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace reb {
namespace {

std::vector<NativeProbeEvent>* g_events = nullptr;
struct CapturedArtifact final {
  NativeArtifactKind kind = NativeArtifactKind::kUnknown;
  NativeArtifactCaptureOrigin capture_origin = NativeArtifactCaptureOrigin::kUnknown;
  std::uint64_t creator_event_id = 0;
  std::uint64_t execution_context_id = 0;
  std::uint64_t frame_id = 0;
  std::string source_url;
  std::vector<std::uint8_t> content;
};
std::vector<CapturedArtifact>* g_artifacts = nullptr;
std::atomic<std::uint64_t> g_concurrent_event_count{0};
std::atomic<std::uint64_t> g_mixed_configuration_count{0};

std::uint64_t TestFrameId() noexcept {
  return 42;
}

void CaptureEvent(const NativeProbeEvent& event) noexcept {
  if (g_events) {
    g_events->push_back(event);
  }
}

void CaptureArtifact(const NativeArtifactKind kind,
                     const NativeArtifactCaptureOrigin capture_origin,
                     const std::uint64_t creator_event_id,
                     const std::uint64_t execution_context_id,
                     const std::uint64_t frame_id,
                     const std::string_view source_url,
                     const std::span<const std::uint8_t> content) noexcept {
  if (g_artifacts) {
    g_artifacts->push_back({kind, capture_origin, creator_event_id, execution_context_id, frame_id,
                            std::string(source_url),
                            std::vector<std::uint8_t>(content.begin(), content.end())});
  }
}

void ValidateConcurrentEvent(const NativeProbeEvent& event,
                             const std::uint64_t expected_session_id) noexcept {
  g_concurrent_event_count.fetch_add(1, std::memory_order_relaxed);
  if (event.header.category != NativeProbeCategory::kWebAudio ||
      event.header.session_id != expected_session_id) {
    g_mixed_configuration_count.fetch_add(1, std::memory_order_relaxed);
  }
}

void ValidateConcurrentEventA(const NativeProbeEvent& event) noexcept {
  ValidateConcurrentEvent(event, 71);
}

void ValidateConcurrentEventB(const NativeProbeEvent& event) noexcept {
  ValidateConcurrentEvent(event, 72);
}

std::string Payload(const NativeProbeEvent& event) {
  const std::size_t size =
      std::min<std::size_t>(event.header.payload_size, event.inline_payload.size());
  std::string payload(size, '\0');
  std::transform(event.inline_payload.begin(),
                 event.inline_payload.begin() + static_cast<std::ptrdiff_t>(size), payload.begin(),
                 [](const std::byte value) {
                   return static_cast<char>(std::to_integer<unsigned char>(value));
                 });
  return payload;
}

class NativeProbeSinkTest : public testing::Test {
 protected:
  void SetUp() override {
    g_events = &events_;
    g_artifacts = &artifacts_;
    g_concurrent_event_count.store(0, std::memory_order_relaxed);
    g_mixed_configuration_count.store(0, std::memory_order_relaxed);
    NativeProbeSink::Get().SetEmitters(nullptr, nullptr, 0, 0, 0);
  }

  void TearDown() override {
    NativeProbeSink::Get().SetEmitters(nullptr, nullptr, 0, 0, 0);
    g_events = nullptr;
    g_artifacts = nullptr;
  }

  std::vector<NativeProbeEvent> events_;
  std::vector<CapturedArtifact> artifacts_;
};

TEST_F(NativeProbeSinkTest, RecordsAuthorizedWebAudioFunctionCalls) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kWebAudio),
                                     std::numeric_limits<std::uint64_t>::max());

  NativeProbeSink::Get().RecordWebAudioCall("OfflineAudioContext.startRendering");

  ASSERT_EQ(events_.size(), 1u);
  const NativeProbeEvent& event = events_.front();
  EXPECT_EQ(event.header.category, NativeProbeCategory::kWebAudio);
  EXPECT_EQ(event.header.type, NativeProbeType::kApiCall);
  EXPECT_EQ(event.header.session_id, 71u);
  EXPECT_NE(event.header.sequence_number, 0u);
  EXPECT_NE(event.header.process_id, 0u);
  EXPECT_EQ(Payload(event), "OfflineAudioContext.startRendering");
  EXPECT_EQ(event.header.flags, 0u);
}

TEST_F(NativeProbeSinkTest, RecordsAuthorizedSurfaceCallsAndPropertyReads) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kCanvas) |
                                         NativeProbeCategoryMask(NativeProbeCategory::kWebGl) |
                                         NativeProbeCategoryMask(NativeProbeCategory::kNavigator),
                                     std::numeric_limits<std::uint64_t>::max());

  NativeProbeSink::Get().RecordApiCall(NativeProbeCategory::kCanvas, "canvas.fillRect");
  NativeProbeSink::Get().RecordApiCall(NativeProbeCategory::kWebGl, "WebGL.getParameter");
  NativeProbeSink::Get().RecordPropertyRead(NativeProbeCategory::kNavigator,
                                            "navigator.hardwareConcurrency");

  ASSERT_EQ(events_.size(), 3u);
  EXPECT_EQ(events_[0].header.category, NativeProbeCategory::kCanvas);
  EXPECT_EQ(events_[0].header.type, NativeProbeType::kApiCall);
  EXPECT_EQ(Payload(events_[0]), "canvas.fillRect");
  EXPECT_EQ(events_[1].header.category, NativeProbeCategory::kWebGl);
  EXPECT_EQ(events_[1].header.type, NativeProbeType::kApiCall);
  EXPECT_EQ(Payload(events_[1]), "WebGL.getParameter");
  EXPECT_EQ(events_[2].header.category, NativeProbeCategory::kNavigator);
  EXPECT_EQ(events_[2].header.type, NativeProbeType::kPropertyRead);
  EXPECT_EQ(Payload(events_[2]), "navigator.hardwareConcurrency");
}

TEST_F(NativeProbeSinkTest, AttributesActiveSurfaceEventsToCurrentFrame) {
  NativeProbeSink::Get().SetEmitters(
      &CaptureEvent, &CaptureArtifact, 71, NativeProbeCategoryMask(NativeProbeCategory::kCanvas),
      std::numeric_limits<std::uint64_t>::max(), false, &TestFrameId);

  NativeProbeSink::Get().RecordApiCall(NativeProbeCategory::kCanvas, "canvas.toDataURL");

  ASSERT_EQ(events_.size(), 1u);
  EXPECT_EQ(events_[0].header.frame_id, 42u);
}

TEST_F(NativeProbeSinkTest, RecordsAuthorizedRuntimeFingerprintCalls) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kRuntime),
                                     std::numeric_limits<std::uint64_t>::max());

  NativeProbeSink::Get().RecordApiCall(NativeProbeCategory::kRuntime, "Math.acos");

  ASSERT_EQ(events_.size(), 1u);
  EXPECT_EQ(events_[0].header.category, NativeProbeCategory::kRuntime);
  EXPECT_EQ(events_[0].header.type, NativeProbeType::kApiCall);
  EXPECT_EQ(Payload(events_[0]), "Math.acos");
}

TEST_F(NativeProbeSinkTest, RetainsOneGeneratedObservationPerCaptureSession) {
  std::atomic<std::uint64_t> api_observed_session{0};
  std::atomic<std::uint64_t> property_observed_session{0};
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kRuntime) |
                                         NativeProbeCategoryMask(NativeProbeCategory::kNavigator),
                                     std::numeric_limits<std::uint64_t>::max());

  NativeProbeSink::Get().RecordApiCallOnce(NativeProbeCategory::kRuntime, "Math.acos",
                                           api_observed_session);
  NativeProbeSink::Get().RecordApiCallOnce(NativeProbeCategory::kRuntime, "Math.acos",
                                           api_observed_session);
  NativeProbeSink::Get().RecordPropertyReadOnce(NativeProbeCategory::kNavigator, "Screen.width",
                                                property_observed_session);
  NativeProbeSink::Get().RecordPropertyReadOnce(NativeProbeCategory::kNavigator, "Screen.width",
                                                property_observed_session);

  ASSERT_EQ(events_.size(), 2u);
  EXPECT_EQ(Payload(events_[0]), "Math.acos");
  EXPECT_EQ(Payload(events_[1]), "Screen.width");

  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 72,
                                     NativeProbeCategoryMask(NativeProbeCategory::kRuntime),
                                     std::numeric_limits<std::uint64_t>::max());
  NativeProbeSink::Get().RecordApiCallOnce(NativeProbeCategory::kRuntime, "Math.acos",
                                           api_observed_session);

  ASSERT_EQ(events_.size(), 3u);
  EXPECT_EQ(events_.back().header.session_id, 72u);
}

TEST_F(NativeProbeSinkTest, DisabledGeneratedObservationDoesNotConsumeSessionMarker) {
  std::atomic<std::uint64_t> observed_session{0};
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kCanvas),
                                     std::numeric_limits<std::uint64_t>::max());

  NativeProbeSink::Get().RecordApiCallOnce(NativeProbeCategory::kRuntime, "Math.acos",
                                           observed_session);
  EXPECT_EQ(observed_session.load(std::memory_order_acquire), 0u);

  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kRuntime),
                                     std::numeric_limits<std::uint64_t>::max());
  NativeProbeSink::Get().RecordApiCallOnce(NativeProbeCategory::kRuntime, "Math.acos",
                                           observed_session);

  ASSERT_EQ(events_.size(), 1u);
  EXPECT_EQ(observed_session.load(std::memory_order_acquire), 71u);
}

TEST_F(NativeProbeSinkTest, RejectsInvalidSurfaceOperations) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     kAllNativeProbeCategoryMask,
                                     std::numeric_limits<std::uint64_t>::max());

  NativeProbeSink::Get().RecordApiCall(NativeProbeCategory::kUnknown, "unknown.call");
  NativeProbeSink::Get().RecordApiCall(NativeProbeCategory::kNetwork, "network.call");
  NativeProbeSink::Get().RecordApiCall(NativeProbeCategory::kCanvas, "");

  EXPECT_TRUE(events_.empty());
}

TEST_F(NativeProbeSinkTest, RejectsWebAudioOutsideCategoryPolicy) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kCanvas),
                                     std::numeric_limits<std::uint64_t>::max());

  NativeProbeSink::Get().RecordWebAudioCall("AudioBuffer.getChannelData");

  EXPECT_TRUE(events_.empty());
}

TEST_F(NativeProbeSinkTest, DisabledWebAudioDoesNotEmitOrConsumeSequence) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kWebAudio),
                                     std::numeric_limits<std::uint64_t>::max());
  NativeProbeSink::Get().RecordWebAudioCall("BaseAudioContext.createAnalyser");
  ASSERT_EQ(events_.size(), 1u);
  const std::uint64_t first_sequence = events_.front().header.sequence_number;

  NativeProbeSink::Get().SetEmitters(nullptr, nullptr, 0, 0, 0);
  NativeProbeSink::Get().RecordWebAudioCall("AnalyserNode.getFloatFrequencyData");
  EXPECT_EQ(events_.size(), 1u);

  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kWebAudio),
                                     std::numeric_limits<std::uint64_t>::max());
  NativeProbeSink::Get().RecordWebAudioCall("BaseAudioContext.createOscillator");

  ASSERT_EQ(events_.size(), 2u);
  EXPECT_EQ(events_.back().header.sequence_number, first_sequence + 1);
}

TEST_F(NativeProbeSinkTest, DoesNotMixConcurrentConfigurations) {
  constexpr std::uint64_t kWebAudioMask = NativeProbeCategoryMask(NativeProbeCategory::kWebAudio);
  constexpr int kConfigurationIterations = 50000;
  constexpr int kRecordIterations = 200000;
  std::atomic<bool> start{false};

  std::thread recorder([&start] {
    while (!start.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    for (int iteration = 0; iteration < kRecordIterations; ++iteration) {
      NativeProbeSink::Get().RecordWebAudioCall("AnalyserNode.getFloatFrequencyData");
    }
  });
  std::thread configurer([&start] {
    start.store(true, std::memory_order_release);
    for (int iteration = 0; iteration < kConfigurationIterations; ++iteration) {
      NativeProbeSink::Get().SetEmitters(&ValidateConcurrentEventA, &CaptureArtifact, 71,
                                         kWebAudioMask, std::numeric_limits<std::uint64_t>::max());
      std::this_thread::yield();
      NativeProbeSink::Get().SetEmitters(&ValidateConcurrentEventB, &CaptureArtifact, 72,
                                         kWebAudioMask, std::numeric_limits<std::uint64_t>::max());
    }
    NativeProbeSink::Get().SetEmitters(&ValidateConcurrentEventA, &CaptureArtifact, 71,
                                       kWebAudioMask, std::numeric_limits<std::uint64_t>::max());
  });

  recorder.join();
  configurer.join();
  NativeProbeSink::Get().RecordWebAudioCall("AnalyserNode.getFloatFrequencyData");

  EXPECT_GT(g_concurrent_event_count.load(std::memory_order_relaxed), 0u);
  EXPECT_EQ(g_mixed_configuration_count.load(std::memory_order_relaxed), 0u);
}

TEST_F(NativeProbeSinkTest, RejectsWebAudioAfterExpiration) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kWebAudio), 1);

  NativeProbeSink::Get().RecordWebAudioCall("AnalyserNode.getFloatFrequencyData");

  EXPECT_TRUE(events_.empty());
}

TEST_F(NativeProbeSinkTest, MarksOversizedOperationNamesTruncated) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kWebAudio),
                                     std::numeric_limits<std::uint64_t>::max());
  const std::string oversized(kNativeProbeInlinePayloadSize + 1, 'a');

  NativeProbeSink::Get().RecordWebAudioCall(oversized);

  ASSERT_EQ(events_.size(), 1u);
  EXPECT_EQ(events_.front().header.payload_size, kNativeProbeInlinePayloadSize);
  EXPECT_NE(
      events_.front().header.flags & static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated),
      0);
}

TEST_F(NativeProbeSinkTest, CapturesAuthorizedRuntimeGeneratedSource) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kArtifact),
                                     std::numeric_limits<std::uint64_t>::max());
  const std::array<std::uint8_t, 4> source = {'t', 'e', 's', 't'};

  ASSERT_TRUE(NativeProbeSink::Get().IsArtifactCaptureEnabled());
  NativeProbeSink::Get().CaptureGeneratedArtifact(
      NativeArtifactKind::kJavaScript, NativeArtifactCaptureOrigin::kDynamicJavaScript, 91, 92,
      "https://authorized.test/runtime", source);

  ASSERT_EQ(artifacts_.size(), 1u);
  EXPECT_EQ(artifacts_.front().kind, NativeArtifactKind::kJavaScript);
  EXPECT_EQ(artifacts_.front().capture_origin, NativeArtifactCaptureOrigin::kDynamicJavaScript);
  EXPECT_EQ(artifacts_.front().execution_context_id, 91u);
  EXPECT_EQ(artifacts_.front().frame_id, 92u);
  EXPECT_EQ(artifacts_.front().source_url, "https://authorized.test/runtime");
  EXPECT_EQ(artifacts_.front().content, std::vector<std::uint8_t>(source.begin(), source.end()));
}

TEST_F(NativeProbeSinkTest, CanvasOutputRequiresExplicitSensitiveCapture) {
  const std::string data_url = "data:image/png;base64,iVBORw0KGgo=";
  const std::uint64_t mask = NativeProbeCategoryMask(NativeProbeCategory::kCanvas) |
                             NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71, mask,
                                     std::numeric_limits<std::uint64_t>::max());

  NativeProbeSink::Get().RecordCanvasToDataUrl(data_url);
  EXPECT_EQ(events_.size(), 1u);
  EXPECT_TRUE(artifacts_.empty());

  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71, mask,
                                     std::numeric_limits<std::uint64_t>::max(), true);
  NativeProbeSink::Get().RecordCanvasToDataUrl(data_url);

  ASSERT_EQ(events_.size(), 2u);
  ASSERT_EQ(artifacts_.size(), 1u);
  EXPECT_EQ(artifacts_.front().kind, NativeArtifactKind::kCanvasDataUrl);
  EXPECT_EQ(artifacts_.front().capture_origin, NativeArtifactCaptureOrigin::kCanvasToDataUrl);
  EXPECT_EQ(artifacts_.front().creator_event_id, events_.back().header.sequence_number);
  EXPECT_EQ(artifacts_.front().content,
            std::vector<std::uint8_t>(data_url.begin(), data_url.end()));
}

TEST_F(NativeProbeSinkTest, RejectsCanvasOutputThatCannotBeDisplayedWhole) {
  constexpr std::size_t kViewerContentLimit = 2U * 1024U * 1024U;
  std::string data_url = "data:image/png;base64,";
  data_url.append(kViewerContentLimit, 'A');
  const std::uint64_t mask = NativeProbeCategoryMask(NativeProbeCategory::kCanvas) |
                             NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71, mask,
                                     std::numeric_limits<std::uint64_t>::max(), true);

  NativeProbeSink::Get().RecordCanvasToDataUrl(data_url);

  ASSERT_EQ(events_.size(), 1u);
  EXPECT_EQ(Payload(events_.front()), "canvas.toDataURL");
  EXPECT_TRUE(artifacts_.empty());
}

TEST_F(NativeProbeSinkTest, RejectsGeneratedSourceOutsidePolicyAndLimits) {
  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kCanvas),
                                     std::numeric_limits<std::uint64_t>::max());
  const std::array<std::uint8_t, 1> source = {'x'};

  EXPECT_FALSE(NativeProbeSink::Get().IsArtifactCaptureEnabled());
  NativeProbeSink::Get().CaptureGeneratedArtifact(
      NativeArtifactKind::kJavaScript, NativeArtifactCaptureOrigin::kDynamicJavaScript, 91, 92,
      "https://authorized.test/runtime", source);

  NativeProbeSink::Get().SetEmitters(&CaptureEvent, &CaptureArtifact, 71,
                                     NativeProbeCategoryMask(NativeProbeCategory::kArtifact),
                                     std::numeric_limits<std::uint64_t>::max());
  NativeProbeSink::Get().CaptureGeneratedArtifact(
      NativeArtifactKind::kWasm, NativeArtifactCaptureOrigin::kDynamicJavaScript, 91, 92,
      "https://authorized.test/runtime", source);
  NativeProbeSink::Get().CaptureGeneratedArtifact(NativeArtifactKind::kJavaScript,
                                                  NativeArtifactCaptureOrigin::kDynamicJavaScript,
                                                  0, 92, "https://authorized.test/runtime", source);
  NativeProbeSink::Get().CaptureGeneratedArtifact(NativeArtifactKind::kJavaScript,
                                                  NativeArtifactCaptureOrigin::kDynamicJavaScript,
                                                  91, 92, "https://authorized.test/runtime", {});

  EXPECT_TRUE(artifacts_.empty());
}

}  // namespace
}  // namespace reb

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::CommandLine::Init(argc, argv);
  TestTimeouts::Initialize();
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
