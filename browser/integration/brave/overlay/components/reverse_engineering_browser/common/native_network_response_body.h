// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_RESPONSE_BODY_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_RESPONSE_BODY_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#if __has_include("brave/components/reverse_engineering_browser/common/native_network_request.h")
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#else
#include "native_artifact_header.h"
#include "native_network_request.h"
#endif

namespace reb {

// Producer half of the response_body record in protocol/native-network-v3.md.
// include/reb/network_response_body.hpp decodes and validates the same bytes.
// Version 2 adds flag bit 7, kNativeResponseBodySnapshotsWithheld.
inline constexpr std::uint16_t kNativeResponseBodyPayloadVersion = 2;
inline constexpr std::size_t kNativeResponseBodyCodingSlots = 4;
inline constexpr std::uint64_t kNativeResponseBodyCaptureBytes = kNativeArtifactMaxContentBytes;
// Partial snapshots of an open body ("Partial bodies" in native-network-v3.md).
// Each copies every byte kept so far, so they are spaced by the body's age and
// paid from a byte allowance rather than counted: the first after a second,
// each later one at least a 32nd of the body's age after the one before.
inline constexpr std::uint64_t kNativeResponseBodySnapshotFirstNs = 1'000'000'000;
inline constexpr std::uint64_t kNativeResponseBodySnapshotAgeDivisor = 32;
// One body's snapshots copy at most an eighth of the session budget, and all of a
// session's snapshots at most a quarter, so whole bodies keep three quarters.
inline constexpr std::uint64_t kNativeResponseBodySnapshotBodyDivisor = 8;
inline constexpr std::uint64_t kNativeResponseBodySnapshotSessionDivisor = 4;
// Unique response bytes per session (--reb-response-body-budget-bytes).
inline constexpr std::uint64_t kNativeResponseBodyDefaultBudgetBytes = 512ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kNativeResponseBodyMinBudgetBytes = 1ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kNativeResponseBodyMaxBudgetBytes =
    16ULL * 1024ULL * 1024ULL * 1024ULL;

enum class NativeResponseBodyState : std::uint8_t {
  kCaptured = 1,
  kCapturedTruncated = 2,
  kPartial = 3,
  kAborted = 4,
  kCancelled = 5,
  kEmpty = 6,
  kNotModified = 7,
  kRedirected = 8,
  kNotCapturedType = 9,
  kNotCapturedArtifactUnavailable = 10,
  kNotCapturedTransferRefused = 11,
  kNotCapturedSessionBudget = 12,
};

enum class NativeResponseCoding : std::uint8_t {
  kNone = 0,
  kGzip = 1,
  kDeflate = 2,
  kBrotli = 3,
  kZstd = 4,
  kDcb = 5,
  kDcz = 6,
  kCompress = 7,
  kOther = 15,
};

inline constexpr std::uint8_t kNativeResponseBodyShared = 1U << 0U;
inline constexpr std::uint8_t kNativeResponseBodyFromCache = 1U << 1U;
inline constexpr std::uint8_t kNativeResponseBodyServiceWorker = 1U << 2U;
inline constexpr std::uint8_t kNativeResponseBodyStillEncoded = 1U << 3U;
inline constexpr std::uint8_t kNativeResponseBodyCodingsOmitted = 1U << 4U;
inline constexpr std::uint8_t kNativeResponseBodyCompletionUnobserved = 1U << 5U;
inline constexpr std::uint8_t kNativeResponseBodyContentTypePresent = 1U << 6U;
// A snapshot the spacing allowed was withheld by a byte bound; every later
// record of the body carries it ("Partial bodies" in native-network-v3.md).
inline constexpr std::uint8_t kNativeResponseBodySnapshotsWithheld = 1U << 7U;

struct NativeResponseBodyPolicy final {
  // Content sessions only (--reb-capture-request-content).
  bool enabled = false;
  // Element-loaded images, audio, video and fonts (--reb-capture-response-media).
  bool media = false;
  std::uint64_t budget = kNativeResponseBodyDefaultBudgetBytes;
};

struct NativeResponseBodySummary final {
  NativeResponseBodyState state = NativeResponseBodyState::kEmpty;
  std::uint8_t flags = 0;
  std::uint8_t content_type_length = 0;
  std::uint8_t coding_count = 0;
  std::uint64_t body_length = 0;
  std::uint64_t captured_length = 0;
  std::array<NativeResponseCoding, kNativeResponseBodyCodingSlots> codings{};
  std::uint16_t partial_index = 0;
  std::array<std::uint8_t, 32> sha256{};
  std::array<char, kNativeRequestContentTypeBytes> content_type{};
};

namespace native_response_detail {
constexpr char Lower(const char c) noexcept {
  return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}
constexpr bool Is(std::string_view value, const std::string_view expected) noexcept {
  if (value.size() != expected.size()) {
    return false;
  }
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (Lower(value[i]) != expected[i]) {
      return false;
    }
  }
  return true;
}
constexpr NativeResponseCoding CodingOf(const std::string_view token) noexcept {
  return Is(token, "gzip") || Is(token, "x-gzip")           ? NativeResponseCoding::kGzip
         : Is(token, "deflate")                             ? NativeResponseCoding::kDeflate
         : Is(token, "br")                                  ? NativeResponseCoding::kBrotli
         : Is(token, "zstd")                                ? NativeResponseCoding::kZstd
         : Is(token, "dcb")                                 ? NativeResponseCoding::kDcb
         : Is(token, "dcz")                                 ? NativeResponseCoding::kDcz
         : Is(token, "compress") || Is(token, "x-compress") ? NativeResponseCoding::kCompress
                                                            : NativeResponseCoding::kOther;
}
}  // namespace native_response_detail

// Content-Encoding codings in the order the server applied them. "identity"
// and empty list members are not codings.
constexpr void SetNativeResponseCodings(std::string_view header,
                                        NativeResponseBodySummary& summary) noexcept {
  summary.coding_count = 0;
  summary.codings.fill(NativeResponseCoding::kNone);
  while (!header.empty()) {
    const std::size_t comma = header.find(',');
    std::string_view token = header.substr(0, comma);
    header = comma == std::string_view::npos ? std::string_view() : header.substr(comma + 1);
    const auto first = token.find_first_not_of(" \t");
    if (first == std::string_view::npos) {
      continue;
    }
    token = token.substr(first, token.find_last_not_of(" \t") - first + 1);
    if (native_response_detail::Is(token, "identity")) {
      continue;
    }
    if (summary.coding_count == kNativeResponseBodyCodingSlots) {
      summary.flags |= kNativeResponseBodyCodingsOmitted;
      return;
    }
    summary.codings[summary.coding_count++] = native_response_detail::CodingOf(token);
  }
}

constexpr void SetNativeResponseContentType(const std::string_view mime_type,
                                            NativeResponseBodySummary& summary) noexcept {
  if (NormalizeNativeContentType(mime_type, summary.content_type, summary.content_type_length)) {
    summary.flags |= kNativeResponseBodyContentTypePresent;
  }
}

// Images, audio, video and fonts that page elements load are kept only when
// the session asks for media; every other response body is kept. A fetch or
// XHR image is a deliberate script read, so it is kept by default.
[[nodiscard]] constexpr bool IsNativeResponseMedia(const int resource_type,
                                                   const std::string_view mime_type) noexcept {
  using native_response_detail::Is;
  // blink.mojom.ResourceType at the pin.
  constexpr int kImage = 4, kFont = 5, kMedia = 8, kFavicon = 12, kXhr = 13;
  const auto major = mime_type.substr(0, mime_type.find('/'));
  if (resource_type == kFont || resource_type == kMedia || Is(major, "audio") ||
      Is(major, "video") || Is(major, "font") || Is(mime_type, "application/font-woff") ||
      Is(mime_type, "application/font-woff2") || Is(mime_type, "application/font-sfnt") ||
      Is(mime_type, "application/x-font-ttf") || Is(mime_type, "application/x-font-otf") ||
      Is(mime_type, "application/x-font-woff") || Is(mime_type, "application/vnd.ms-fontobject")) {
    return true;
  }
  const bool image = resource_type == kImage || resource_type == kFavicon || Is(major, "image");
  return image && resource_type != kXhr && !Is(mime_type, "image/svg+xml");
}

// Fixed little-endian layout; see the field table in native-network-v3.md.
[[nodiscard]] inline std::array<std::byte, kNativeRequestPayloadSize>
EncodeNativeResponseBodyPayload(const NativeResponseBodySummary& value) noexcept {
  using native_request_detail::Put;
  std::array<std::byte, kNativeRequestPayloadSize> out{};
  Put(out, 0, kNativeResponseBodyPayloadVersion, 2);
  Put(out, 2, kNativeRequestPayloadSize, 2);
  Put(out, 4, static_cast<std::uint8_t>(value.state), 1);
  Put(out, 5, value.flags, 1);
  Put(out, 6, value.content_type_length, 1);
  Put(out, 7, value.coding_count, 1);
  Put(out, 8, value.body_length, 8);
  Put(out, 16, value.captured_length, 8);
  for (std::size_t i = 0; i < value.codings.size(); ++i) {
    Put(out, 24 + i, static_cast<std::uint8_t>(value.codings[i]), 1);
  }
  Put(out, 28, value.partial_index, 2);
  std::transform(value.sha256.begin(), value.sha256.end(), out.begin() + 32,
                 [](const std::uint8_t byte) { return static_cast<std::byte>(byte); });
  std::transform(
      value.content_type.begin(), value.content_type.end(), out.begin() + 64,
      [](const char c) { return static_cast<std::byte>(static_cast<unsigned char>(c)); });
  return out;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_RESPONSE_BODY_H_
