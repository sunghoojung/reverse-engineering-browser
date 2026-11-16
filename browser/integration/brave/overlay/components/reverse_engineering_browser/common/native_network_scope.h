// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_SCOPE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_SCOPE_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#if __has_include("brave/components/reverse_engineering_browser/common/native_probe_event.h")
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#else
#include "native_probe_event.h"
#endif

namespace reb {
// Producer half of protocol/native-network-v3.md; the core mirror is
// include/reb/network_scope.hpp.
enum class NativeSchemeClass : std::uint8_t {
  kNotRecorded = 0,
  kHttp = 1,
  kHttps = 2,
  kWs = 3,
  kWss = 4,
  kData = 5,
  kBlob = 6,
  kFile = 7,
  kExtension = 8,
  kOther = 15,
  kChrome = 16,
  kChromeUntrusted = 17,
  kBrave = 18,
  kDevTools = 19,
  kChromeSearch = 20,
};

inline constexpr std::uint8_t kNativeWebUiRendererExclusion = 64;
inline constexpr std::uint8_t kNativeWebUiRequestExclusion = 67;
// Classes 68 and 69 belong to another part of the contract.
inline constexpr std::uint8_t kNativeMemoryCacheReuseExclusion = 70;
// Reuses in a page that is not ordinary (an SVG image's own document or a
// page popup), which no tab owns; counted apart from the budget's overflow.
inline constexpr std::uint8_t kNativeNonOrdinaryPageReuseExclusion = 71;
inline constexpr std::uint16_t kNativeCaptureExclusionPayloadVersion = 1;
inline constexpr std::uint32_t kNativeCaptureExclusionPayloadSize = 16;
// One counter per browser-internal scheme class, 16 to 20.
inline constexpr std::size_t kNativeSchemeExclusionSlots = 5;
// The renderer's probe queue counters: the scheme classes, then classes 70 and 71.
inline constexpr std::size_t kNativeRendererExclusionSlots = kNativeSchemeExclusionSlots + 2;

// The queue slot of a class the renderer counts, or kNativeRendererExclusionSlots.
[[nodiscard]] constexpr std::size_t NativeRendererExclusionSlot(
    const std::uint8_t exclusion_class) noexcept {
  if (exclusion_class >= 16 && exclusion_class < 16 + kNativeSchemeExclusionSlots)
    return exclusion_class - 16U;
  if (exclusion_class == kNativeMemoryCacheReuseExclusion)
    return kNativeSchemeExclusionSlots;
  return exclusion_class == kNativeNonOrdinaryPageReuseExclusion ? kNativeSchemeExclusionSlots + 1
                                                                 : kNativeRendererExclusionSlots;
}

[[nodiscard]] constexpr std::uint8_t NativeRendererExclusionClass(const std::size_t slot) noexcept {
  if (slot < kNativeSchemeExclusionSlots)
    return static_cast<std::uint8_t>(16 + slot);
  return slot == kNativeSchemeExclusionSlots ? kNativeMemoryCacheReuseExclusion
                                             : kNativeNonOrdinaryPageReuseExclusion;
}

// memory_cache_reuse (type 52), "Memory-cache reuse" in
// protocol/native-network-v3.md.
inline constexpr std::uint16_t kNativeMemoryCacheReusePayloadVersion = 2;
inline constexpr std::uint32_t kNativeMemoryCacheReusePayloadSize = 128;
inline constexpr std::size_t kNativeMemoryCacheReuseHostSize = 120;
inline constexpr std::uint8_t kNativeMemoryCacheReuseStaticData = 1U << 0U;
inline constexpr std::uint8_t kNativeMemoryCacheReuseHostTruncated = 1U << 1U;
// Version 2: the envelope's initiator_process_id and initiator_request_id name
// the renderer request whose response Blink reused, as a request_tab_link
// names a renderer record.
inline constexpr std::uint8_t kNativeMemoryCacheReuseSourceNamed = 1U << 2U;
// Records one renderer configuration admits; later reuses count as class 70.
inline constexpr std::uint32_t kNativeMemoryCacheReuseBudget = 4096;

// resource_type is Blink's ResourceType, 1 to 15 at the pin.
[[nodiscard]] inline std::array<std::byte, kNativeProbeInlinePayloadSize>
EncodeNativeMemoryCacheReusePayload(const std::uint8_t resource_type,
                                    const bool static_data,
                                    const std::string_view host,
                                    const bool source_named) noexcept {
  std::array<std::byte, kNativeProbeInlinePayloadSize> payload{};
  const std::size_t length = std::min(host.size(), kNativeMemoryCacheReuseHostSize);
  payload[0] = static_cast<std::byte>(kNativeMemoryCacheReusePayloadVersion);
  payload[2] = static_cast<std::byte>(kNativeMemoryCacheReusePayloadSize);
  payload[4] = static_cast<std::byte>(resource_type);
  payload[5] =
      static_cast<std::byte>((static_data ? kNativeMemoryCacheReuseStaticData : 0U) |
                             (length != host.size() ? kNativeMemoryCacheReuseHostTruncated : 0U) |
                             (source_named ? kNativeMemoryCacheReuseSourceNamed : 0U));
  payload[6] = static_cast<std::byte>(length);
  for (std::size_t index = 0; index < length; ++index)
    payload[8 + index] = static_cast<std::byte>(static_cast<unsigned char>(host[index]));
  return payload;
}

// Schemes arrive canonical and lower case from GURL and KURL.
[[nodiscard]] constexpr NativeSchemeClass ClassifyNativeScheme(
    const std::string_view scheme) noexcept {
  if (scheme == "https")
    return NativeSchemeClass::kHttps;
  if (scheme == "http")
    return NativeSchemeClass::kHttp;
  if (scheme == "wss")
    return NativeSchemeClass::kWss;
  if (scheme == "ws")
    return NativeSchemeClass::kWs;
  if (scheme == "data")
    return NativeSchemeClass::kData;
  if (scheme == "blob")
    return NativeSchemeClass::kBlob;
  if (scheme == "file")
    return NativeSchemeClass::kFile;
  if (scheme == "chrome-extension")
    return NativeSchemeClass::kExtension;
  if (scheme == "chrome")
    return NativeSchemeClass::kChrome;
  if (scheme == "chrome-untrusted")
    return NativeSchemeClass::kChromeUntrusted;
  if (scheme == "brave")
    return NativeSchemeClass::kBrave;
  if (scheme == "devtools")
    return NativeSchemeClass::kDevTools;
  if (scheme == "chrome-search")
    return NativeSchemeClass::kChromeSearch;
  return NativeSchemeClass::kOther;
}

[[nodiscard]] constexpr bool IsBrowserInternalSchemeClass(const NativeSchemeClass value) noexcept {
  const auto code = static_cast<std::uint8_t>(value);
  return code >= 16 && code < 16 + kNativeSchemeExclusionSlots;
}

// Schemes the browser network proxy observes; anything else is answered
// without it.
[[nodiscard]] constexpr bool IsProxiedSchemeClass(const NativeSchemeClass value) noexcept {
  return value == NativeSchemeClass::kHttp || value == NativeSchemeClass::kHttps ||
         value == NativeSchemeClass::kWs || value == NativeSchemeClass::kWss;
}

[[nodiscard]] inline NativeProbeEvent MakeNativeCaptureExclusionEvent(
    const std::uint64_t session_id,
    const std::uint64_t sequence_number,
    const std::uint64_t monotonic_time_ns,
    const std::uint32_t process_id,
    const std::uint32_t thread_id,
    const std::uint32_t excluded_process_id,
    const std::uint8_t exclusion_class,
    const std::uint64_t count) noexcept {
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kCaptureExclusion;
  event.header.session_id = session_id;
  event.header.sequence_number = sequence_number;
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.process_id = process_id;
  event.header.thread_id = thread_id;
  event.header.initiator_process_id = excluded_process_id;
  event.header.payload_size = kNativeCaptureExclusionPayloadSize;
  event.inline_payload[0] = static_cast<std::byte>(kNativeCaptureExclusionPayloadVersion);
  event.inline_payload[2] = static_cast<std::byte>(kNativeCaptureExclusionPayloadSize);
  event.inline_payload[4] = static_cast<std::byte>(exclusion_class);
  for (std::size_t index = 0; index < 8; ++index)
    event.inline_payload[8 + index] = static_cast<std::byte>((count >> (8U * index)) & 0xffU);
  return event;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_SCOPE_H_
