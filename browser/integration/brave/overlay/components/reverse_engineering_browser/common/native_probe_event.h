// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_EVENT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_EVENT_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace reb {

inline constexpr std::uint16_t kNativeProbeProtocolVersion = 2;
inline constexpr std::size_t kNativeProbeInlinePayloadSize = 128;
inline constexpr std::size_t kNativeProbeRecordReservedSize = 48;

enum class NativeProbeCategory : std::uint16_t {
  kUnknown = 0,
  kCanvas = 1,
  kWebGl = 2,
  kWebAudio = 3,
  kNavigator = 4,
  kPermissions = 5,
  kStorage = 6,
  kWebRtc = 7,
  kWasm = 8,
  kNetwork = 9,
  kVm = 10,
  kArtifact = 11,
};

inline constexpr std::uint64_t kAllNativeProbeCategoryMask =
    (std::uint64_t{1} << static_cast<std::uint16_t>(NativeProbeCategory::kArtifact)) - 1;

[[nodiscard]] constexpr std::uint64_t NativeProbeCategoryMask(
    const NativeProbeCategory category) noexcept {
  const auto value = static_cast<std::uint16_t>(category);
  return value == 0 || value > static_cast<std::uint16_t>(NativeProbeCategory::kArtifact)
             ? 0
             : std::uint64_t{1} << (value - 1U);
}

[[nodiscard]] constexpr bool IsValidNativeProbeCategoryMask(
    const std::uint64_t category_mask) noexcept {
  return category_mask != 0 && (category_mask & ~kAllNativeProbeCategoryMask) == 0;
}

enum class NativeProbeType : std::uint16_t {
  kUnknown = 0,
  kApiCall = 1,
  kPropertyRead = 2,
  kModuleCompiled = 3,
  kModuleInstantiated = 4,
  kRequestStarted = 5,
  kResponseCompleted = 6,
  kGap = 7,
  kRequestInitiated = 8,
  kRequestRedirected = 9,
  kResponseStarted = 10,
  kRequestCompleted = 11,
  kRequestFailed = 12,
  kVmFinding = 13,
  kArtifactCaptured = 14,
  kArtifactCaptureFailed = 15,
};

enum class NativeProbeFlag : std::uint16_t {
  kNone = 0,
  kPayloadTruncated = 1U << 0U,
  kFromCache = 1U << 1U,
  kFromServiceWorker = 1U << 2U,
};

struct NativeProbeHeader final {
  std::uint16_t protocol_version = kNativeProbeProtocolVersion;
  std::uint16_t header_size = sizeof(NativeProbeHeader);
  NativeProbeCategory category = NativeProbeCategory::kUnknown;
  NativeProbeType type = NativeProbeType::kUnknown;
  std::uint32_t payload_size = 0;
  std::uint32_t reserved0 = 0;
  std::uint64_t sequence_number = 0;
  std::uint64_t monotonic_time_ns = 0;
  std::uint64_t session_id = 0;
  std::uint32_t process_id = 0;
  std::uint32_t thread_id = 0;
  std::uint64_t navigation_id = 0;
  std::uint64_t frame_id = 0;
  std::uint64_t artifact_id = 0;
  std::uint64_t parent_event_id = 0;
  std::uint64_t request_id = 0;
  std::uint64_t browser_context_id_high = 0;
  std::uint64_t browser_context_id_low = 0;
  std::int64_t encoded_data_length = 0;
  std::int64_t decoded_body_length = 0;
  std::int32_t status_code = 0;
  std::int32_t error_code = 0;
  std::uint16_t resource_type = 0;
  std::uint16_t flags = 0;
  std::uint32_t initiator_request_id = 0;
  std::uint32_t initiator_process_id = 0;
  std::uint32_t reserved1 = 0;
};

struct alignas(64) NativeProbeEvent final {
  NativeProbeHeader header{};
  std::array<std::byte, kNativeProbeInlinePayloadSize> inline_payload{};
  std::array<std::byte, kNativeProbeRecordReservedSize> reserved{};
};

static_assert(std::is_standard_layout_v<NativeProbeHeader>);
static_assert(std::is_trivially_copyable_v<NativeProbeHeader>);
static_assert(std::is_standard_layout_v<NativeProbeEvent>);
static_assert(std::is_trivially_copyable_v<NativeProbeEvent>);
static_assert(std::has_unique_object_representations_v<NativeProbeHeader>);
static_assert(std::has_unique_object_representations_v<NativeProbeEvent>);
#define REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(member, expected) \
  static_assert(offsetof(NativeProbeHeader, member) == expected)
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(protocol_version, 0);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(header_size, 2);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(category, 4);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(type, 6);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(payload_size, 8);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(reserved0, 12);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(sequence_number, 16);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(monotonic_time_ns, 24);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(session_id, 32);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(process_id, 40);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(thread_id, 44);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(navigation_id, 48);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(frame_id, 56);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(artifact_id, 64);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(parent_event_id, 72);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(request_id, 80);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(browser_context_id_high, 88);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(browser_context_id_low, 96);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(encoded_data_length, 104);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(decoded_body_length, 112);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(status_code, 120);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(error_code, 124);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(resource_type, 128);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(flags, 130);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(initiator_request_id, 132);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(initiator_process_id, 136);
REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET(reserved1, 140);
#undef REB_ASSERT_NATIVE_PROBE_HEADER_OFFSET
static_assert(sizeof(NativeProbeHeader) == 144);
static_assert(sizeof(NativeProbeEvent) == 320);
static_assert(alignof(NativeProbeEvent) == 64);
static_assert(offsetof(NativeProbeEvent, inline_payload) == 144);
static_assert(offsetof(NativeProbeEvent, reserved) == 272);

// Emitters must be non-blocking and non-throwing. Their owner provides bounded
// buffering and explicit dropped-event accounting.
using NativeProbeEmitter = void (*)(const NativeProbeEvent& event) noexcept;

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_EVENT_H_
