// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_TAB_LINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_TAB_LINK_H_

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>

#if __has_include("brave/components/reverse_engineering_browser/common/native_probe_event.h")
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#else
#include "native_probe_event.h"
#endif

namespace reb {

// Producer half of protocol/native-network-v3.md "Request owners and tabs";
// include/reb/tab_link.hpp is the consumer half.
enum class NativeLoaderKind : std::uint8_t {
  kNotRecorded = 0,
  kNavigation = 1,
  kDownload = 2,
  kDocumentSubresource = 3,
  kWorkerMainResource = 4,
  kWorkerSubresource = 5,
  kServiceWorkerScript = 6,
  kServiceWorkerSubresource = 7,
  kPrefetch = 8,
  kDevTools = 9,
  kEarlyHints = 10,
  kDocument = 16,
  kDedicatedWorker = 17,
  kSharedWorker = 18,
  kServiceWorker = 19,
  kOtherContext = 20,
  kScriptContext = 21,
};

enum class NativeTabLinkKind : std::uint8_t {
  kDedicatedWorker = 1,
  kSharedWorkerClients = 2,
  kServiceWorkerClients = 3,
  kServiceWorkerLastClients = 4,
};

inline constexpr std::uint8_t kNativeExtensionWorkerExclusion = 65;
inline constexpr std::uint8_t kNativeDevToolsLoadExclusion = 66;
inline constexpr std::uint16_t kNativeTabSetPayloadVersion = 1;
inline constexpr std::uint32_t kNativeTabSetPayloadSize = 128;
inline constexpr std::size_t kNativeTabSetPartTabs = 26;
inline constexpr std::uint8_t kNativeTabSetLastClients = 1;
inline constexpr std::uint16_t kNativeRequestTabLinkPayloadVersion = 1;
inline constexpr std::uint32_t kNativeRequestTabLinkPayloadSize = 24;

// Frame ids and worker context ids share this fold of a 128-bit token.
[[nodiscard]] constexpr std::uint64_t NativeContextFold(const std::uint64_t high,
                                                        const std::uint64_t low) noexcept {
  return std::rotl(high, 17) ^ low;
}

// URLLoaderFactoryType ordinal (common/native_request_namespace.h) + 1.
[[nodiscard]] constexpr NativeLoaderKind NativeBrowserLoaderKind(const int factory_type) noexcept {
  return factory_type >= 0 && factory_type <= 9 ? static_cast<NativeLoaderKind>(factory_type + 1)
                                                : NativeLoaderKind::kNotRecorded;
}

[[nodiscard]] constexpr bool IsNativeWorkerOwner(const NativeLoaderKind kind) noexcept {
  return kind == NativeLoaderKind::kDedicatedWorker || kind == NativeLoaderKind::kSharedWorker ||
         kind == NativeLoaderKind::kServiceWorker;
}

namespace native_tab_link_detail {
inline void Put(NativeProbeEvent& event,
                const std::size_t offset,
                const std::uint64_t value,
                const std::size_t size) noexcept {
  for (std::size_t index = 0; index < size; ++index)
    event.inline_payload[offset + index] = static_cast<std::byte>((value >> (8U * index)) & 0xffU);
}
}  // namespace native_tab_link_detail

[[nodiscard]] constexpr std::size_t NativeTabSetParts(const std::size_t tab_count) noexcept {
  return (tab_count + kNativeTabSetPartTabs - 1) / kNativeTabSetPartTabs;
}

// One part of a complete, ascending, distinct tab list. The caller assigns the
// browser sequence and passes the previous part's sequence for parts after 0.
[[nodiscard]] inline NativeProbeEvent MakeNativeTabSetPart(
    const NativeProbeHeader& identity,
    const NativeLoaderKind owner_kind,
    const std::uint64_t owner_fold,
    const bool last_clients,
    const std::uint64_t set_id,
    const std::span<const std::uint32_t> tabs,
    const std::size_t part_index,
    const std::uint64_t previous_sequence) noexcept {
  using native_tab_link_detail::Put;
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kTabSet;
  event.header.session_id = identity.session_id;
  event.header.sequence_number = identity.sequence_number;
  event.header.monotonic_time_ns = identity.monotonic_time_ns;
  event.header.process_id = identity.process_id;
  event.header.thread_id = identity.thread_id;
  event.header.frame_id = owner_fold;
  event.header.parent_event_id = part_index == 0 ? 0 : previous_sequence;
  event.header.payload_size = kNativeTabSetPayloadSize;
  const std::size_t first = part_index * kNativeTabSetPartTabs;
  const std::size_t count =
      std::min(kNativeTabSetPartTabs, tabs.size() - std::min(first, tabs.size()));
  Put(event, 0, kNativeTabSetPayloadVersion, 2);
  Put(event, 2, kNativeTabSetPayloadSize, 2);
  Put(event, 4, static_cast<std::uint8_t>(owner_kind), 1);
  Put(event, 5, last_clients ? kNativeTabSetLastClients : 0, 1);
  Put(event, 6, part_index, 2);
  Put(event, 8, set_id, 8);
  Put(event, 16, tabs.size(), 4);
  Put(event, 20, count, 2);
  for (std::size_t index = 0; index < count; ++index)
    Put(event, 24 + 4 * index, tabs[first + index], 4);
  event.header.tab_id = count != 0 ? tabs[first] : 0;
  return event;
}

// Names one renderer request_initiated; see protocol/native-network-v3.md.
[[nodiscard]] inline NativeProbeEvent MakeNativeRequestTabLink(
    const NativeProbeHeader& linked,
    const NativeProbeHeader& identity,
    const NativeTabLinkKind kind,
    const std::uint64_t set_id,
    const std::span<const std::uint32_t> tabs) noexcept {
  using native_tab_link_detail::Put;
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kRequestTabLink;
  event.header.session_id = identity.session_id;
  event.header.sequence_number = identity.sequence_number;
  event.header.monotonic_time_ns = linked.monotonic_time_ns;
  event.header.process_id = identity.process_id;
  event.header.thread_id = identity.thread_id;
  event.header.tab_id = tabs.size() == 1 ? tabs[0] : 0;
  event.header.frame_id = linked.frame_id;
  event.header.parent_event_id = linked.sequence_number;
  event.header.initiator_process_id = linked.process_id;
  event.header.initiator_request_id = static_cast<std::uint32_t>(linked.request_id);
  event.header.payload_size = kNativeRequestTabLinkPayloadSize;
  Put(event, 0, kNativeRequestTabLinkPayloadVersion, 2);
  Put(event, 2, kNativeRequestTabLinkPayloadSize, 2);
  Put(event, 4, static_cast<std::uint8_t>(kind), 1);
  Put(event, 8, set_id, 8);
  Put(event, 16, tabs.size(), 4);
  return event;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_TAB_LINK_H_
