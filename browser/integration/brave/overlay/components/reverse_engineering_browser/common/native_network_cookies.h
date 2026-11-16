// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_COOKIES_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_COOKIES_H_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "native_network_headers.h"
#include "native_network_request.h"

namespace reb {
// Producer half of "Cookies" in protocol/native-network-v3.md. The core mirror
// in include/reb/network_cookies.hpp decodes and validates the same bytes.
inline constexpr std::uint16_t kNativeCookiePayloadVersion = 1;
// script_cookie version 2 names the isolate of its frame and stack (byte 6);
// version 3 records each cookie name a document.cookie read returned.
inline constexpr std::uint16_t kNativeScriptCookiePayloadVersion = 3;
// 180 cookies per domain of 4 KiB name and value plus two 1 KiB attributes is
// about 1.1 MiB; the rest leaves room for excluded and partitioned cookies.
inline constexpr std::size_t kNativeCookieListLimitBytes = 2U * 1024U * 1024U;
inline constexpr std::size_t kNativeCookieListHeaderBytes = 16;
inline constexpr std::size_t kNativeCookieEntryBytes = 64;
inline constexpr std::size_t kNativeScriptCookieNamePrefixBytes = 24;

enum class NativeCookieDirection : std::uint8_t {
  kSent = 1,
  kReceived = 2,
};

enum class NativeScriptCookieApi : std::uint8_t {
  kDocumentCookieSet = 1,
  kDocumentCookieGet = 2,
  kCookieStoreSet = 3,
  kCookieStoreGet = 4,
  kCookieStoreGetAll = 5,
  kCookieStoreDelete = 6,
};

inline constexpr std::uint8_t kNativeScriptCookieNameTruncated = 1U << 0U;
inline constexpr std::uint8_t kNativeScriptCookieFrameRecorded = 1U << 1U;
inline constexpr std::uint8_t kNativeScriptCookieStackRecorded = 1U << 2U;
inline constexpr std::uint8_t kNativeScriptCookieTableFull = 1U << 3U;
// Version 3: the record of a document.cookie read itself, with no name. Every
// other version 3 document.cookie read record names one cookie it returned.
inline constexpr std::uint8_t kNativeScriptCookieReadRecord = 1U << 4U;

inline constexpr std::uint8_t kNativeCookieParsed = 1U << 0U;
inline constexpr std::uint8_t kNativeCookieHttpOnly = 1U << 1U;
inline constexpr std::uint8_t kNativeCookieSecure = 1U << 2U;
inline constexpr std::uint8_t kNativeCookiePartitioned = 1U << 3U;
inline constexpr std::uint8_t kNativeCookieCrossSiteAncestor = 1U << 4U;
inline constexpr std::uint8_t kNativeCookieDomain = 1U << 5U;

struct NativeCookieListSummary final {
  NativeCookieDirection direction = NativeCookieDirection::kSent;
  NativeHeaderState state = NativeHeaderState::kEmpty;
  std::uint32_t cookie_count = 0;
  std::uint32_t blocked_count = 0;
  std::uint32_t list_length = 0;
  std::uint32_t hop = 0;
  std::uint32_t unattributed_lists = 0;
  std::array<std::uint8_t, 32> sha256{};
};

// The request_initiator_stack frame layout.
struct NativeScriptFrame final {
  std::uint8_t kind = 0;
  std::uint8_t flags = 0;
  std::uint16_t combinator = 0;
  std::uint32_t script_id = 0;
  std::uint32_t position = 0;
  std::uint32_t function_start = 0;
  friend bool operator==(const NativeScriptFrame&, const NativeScriptFrame&) = default;
};

struct NativeScriptCookieSummary final {
  NativeScriptCookieApi api = NativeScriptCookieApi::kDocumentCookieSet;
  std::uint8_t flags = 0;
  std::uint32_t count = 1;
  std::uint32_t name_length = 0;
  std::uint32_t value_length = 0;
  std::uint32_t string_length = 0;
  // A document.cookie read record's names that no name record counts: past
  // the per-read name bound or refused by a full table. Written at offset 16
  // in place of the value length, which a read does not have.
  std::uint32_t unrecorded_names = 0;
  NativeScriptFrame frame;
  std::array<std::uint8_t, 32> stack_digest{};
  std::array<std::uint8_t, 32> value_sha256{};
  std::array<std::uint8_t, kNativeScriptCookieNamePrefixBytes> name_prefix{};
  // NativeStackThread of the calling isolate; 0 when the thread was never
  // attached, and then no frame or stack is recorded. A worker's record
  // names the worker's context ID as its frame_id, the stack scope's key.
  std::uint8_t thread = 0;
};

// One cookie of a list; the strings are borrowed for the call.
struct NativeCookieEntry final {
  std::uint64_t exclusion_reasons = 0;
  std::uint64_t warning_reasons = 0;
  std::int64_t expiry_ms = 0;
  std::uint8_t flags = 0;
  std::uint8_t same_site = 0;
  std::uint8_t priority = 0;
  std::uint8_t effective_same_site = 0;
  std::uint8_t source_scheme = 0;
  std::int32_t source_port = 0;
  std::string_view name;
  std::string_view value;
  std::string_view domain;
  std::string_view path;
  std::string_view partition_site;
  std::string_view line;
};

namespace native_cookie_detail {
template <class Out>
void PutLe(Out& out, const std::size_t offset, const std::uint64_t value, const std::size_t width) {
  for (std::size_t i = 0; i < width; ++i) {
    out[offset + i] = static_cast<typename Out::value_type>((value >> (8U * i)) & 0xffU);
  }
}
}  // namespace native_cookie_detail

[[nodiscard]] inline std::uint64_t NativeCookieEntrySize(const NativeCookieEntry& entry) noexcept {
  return kNativeCookieEntryBytes + entry.name.size() + entry.value.size() + entry.domain.size() +
         entry.path.size() + entry.partition_site.size() + entry.line.size();
}

inline void AppendNativeCookieListHeader(std::vector<std::uint8_t>& out,
                                         const NativeCookieDirection direction,
                                         const std::uint32_t count) {
  std::array<std::uint8_t, kNativeCookieListHeaderBytes> fields = {'R', 'B', 'C', 'K'};
  native_cookie_detail::PutLe(fields, 4, kNativeCookiePayloadVersion, 2);
  fields[6] = static_cast<std::uint8_t>(direction);
  native_cookie_detail::PutLe(fields, 8, count, 4);
  out.insert(out.end(), fields.begin(), fields.end());
}

inline void AppendNativeCookieEntry(std::vector<std::uint8_t>& out,
                                    const NativeCookieEntry& entry) {
  using native_cookie_detail::PutLe;
  std::array<std::uint8_t, kNativeCookieEntryBytes> fixed{};
  PutLe(fixed, 0, entry.exclusion_reasons, 8);
  PutLe(fixed, 8, entry.warning_reasons, 8);
  PutLe(fixed, 16, static_cast<std::uint64_t>(entry.expiry_ms), 8);
  fixed[24] = entry.flags;
  fixed[25] = entry.same_site;
  fixed[26] = entry.priority;
  fixed[27] = entry.effective_same_site;
  fixed[28] = entry.source_scheme;
  PutLe(fixed, 32, static_cast<std::uint32_t>(entry.source_port), 4);
  const std::array<std::string_view, 6> strings = {entry.name, entry.value,          entry.domain,
                                                   entry.path, entry.partition_site, entry.line};
  for (std::size_t i = 0; i < strings.size(); ++i) {
    PutLe(fixed, 36 + 4 * i, strings[i].size(), 4);
  }
  out.insert(out.end(), fixed.begin(), fixed.end());
  for (const std::string_view text : strings) {
    out.insert(out.end(), text.begin(), text.end());
  }
}

[[nodiscard]] inline std::array<std::byte, kNativeRequestPayloadSize> EncodeNativeCookieListPayload(
    const NativeCookieListSummary& value) noexcept {
  using native_request_detail::Put;
  std::array<std::byte, kNativeRequestPayloadSize> out{};
  Put(out, 0, kNativeCookiePayloadVersion, 2);
  Put(out, 2, kNativeRequestPayloadSize, 2);
  Put(out, 4, static_cast<std::uint8_t>(value.direction), 1);
  Put(out, 5, static_cast<std::uint8_t>(value.state), 1);
  Put(out, 8, value.cookie_count, 4);
  Put(out, 12, value.blocked_count, 4);
  Put(out, 16, value.list_length, 4);
  Put(out, 20, value.hop, 4);
  Put(out, 24, value.unattributed_lists, 4);
  std::transform(value.sha256.begin(), value.sha256.end(), out.begin() + 32,
                 [](const std::uint8_t byte) { return static_cast<std::byte>(byte); });
  return out;
}

[[nodiscard]] inline std::array<std::byte, kNativeRequestPayloadSize>
EncodeNativeScriptCookiePayload(const NativeScriptCookieSummary& value) noexcept {
  using native_request_detail::Put;
  std::array<std::byte, kNativeRequestPayloadSize> out{};
  const auto bytes = [&out](const std::size_t offset, const auto& in) {
    std::transform(in.begin(), in.end(), out.begin() + static_cast<std::ptrdiff_t>(offset),
                   [](const std::uint8_t byte) { return static_cast<std::byte>(byte); });
  };
  Put(out, 0, kNativeScriptCookiePayloadVersion, 2);
  Put(out, 2, kNativeRequestPayloadSize, 2);
  Put(out, 4, static_cast<std::uint8_t>(value.api), 1);
  Put(out, 5, value.flags, 1);
  Put(out, 6, value.thread, 1);
  Put(out, 8, value.count, 4);
  Put(out, 12, value.name_length, 4);
  Put(out, 16,
      (value.flags & kNativeScriptCookieReadRecord) != 0 ? value.unrecorded_names
                                                         : value.value_length,
      4);
  Put(out, 20, value.string_length, 4);
  Put(out, 24, value.frame.kind, 1);
  Put(out, 25, value.frame.flags, 1);
  Put(out, 26, value.frame.combinator, 2);
  Put(out, 28, value.frame.script_id, 4);
  Put(out, 32, value.frame.position, 4);
  Put(out, 36, value.frame.function_start, 4);
  bytes(40, value.stack_digest);
  bytes(72, value.value_sha256);
  bytes(104, value.name_prefix);
  return out;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_COOKIES_H_
