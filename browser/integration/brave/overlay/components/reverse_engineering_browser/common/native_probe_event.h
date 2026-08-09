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

inline constexpr std::uint16_t kNativeProbeProtocolVersion = 1;
inline constexpr std::size_t kNativeProbeInlinePayloadSize = 48;

enum class NativeProbeCategory : std::uint16_t {
  kUnknown = 0,
  kCanvas,
  kWebGl,
  kWebAudio,
  kNavigator,
  kPermissions,
  kStorage,
  kWebRtc,
  kWasm,
  kNetwork,
};

enum class NativeProbeType : std::uint16_t {
  kUnknown = 0,
  kApiCall,
  kPropertyRead,
  kModuleCompiled,
  kModuleInstantiated,
  kRequestStarted,
  kResponseCompleted,
  kGap,
};

struct NativeProbeHeader final {
  std::uint16_t protocol_version = kNativeProbeProtocolVersion;
  std::uint16_t header_size = sizeof(NativeProbeHeader);
  NativeProbeCategory category = NativeProbeCategory::kUnknown;
  NativeProbeType type = NativeProbeType::kUnknown;
  std::uint32_t payload_size = 0;
  std::uint64_t sequence_number = 0;
  std::uint64_t monotonic_time_ns = 0;
  std::uint64_t session_id = 0;
  std::uint32_t process_id = 0;
  std::uint32_t thread_id = 0;
  std::uint64_t navigation_id = 0;
  std::uint64_t frame_id = 0;
  std::uint64_t artifact_id = 0;
  std::uint64_t parent_event_id = 0;
};

struct alignas(64) NativeProbeEvent final {
  NativeProbeHeader header{};
  std::array<std::byte, kNativeProbeInlinePayloadSize> inline_payload{};
};

static_assert(std::is_trivially_copyable_v<NativeProbeEvent>);
static_assert(sizeof(NativeProbeHeader) == 80);
static_assert(sizeof(NativeProbeEvent) == 128);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_EVENT_H_
