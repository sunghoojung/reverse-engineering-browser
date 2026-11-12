// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_REQUEST_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_REQUEST_H_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace reb {
// Browser-side producer half of protocol/native-network-v2.md. The core mirror
// in include/reb/network_request.hpp decodes and validates the same bytes.
inline constexpr std::uint16_t kNativeRequestPayloadVersion = 1;
// Version 2 adds the full-target retention byte; see native-network-v2.md.
inline constexpr std::uint16_t kNativeRequestTargetPayloadVersion = 2;
inline constexpr std::size_t kNativeRequestPayloadSize = 128;
inline constexpr std::size_t kNativeRequestTargetPrefixBytes = 116;

// The path and query of a parsed URL without its fragment, as
// GURL::PathForRequestPiece, inside a spec of spec_length. Components are
// url::Component begin and len, len -1 when absent. An absent path is an empty
// target at the spec's end, and the range never leaves the spec.
struct NativeTargetRange final {
  std::size_t begin = 0;
  std::size_t length = 0;
};

[[nodiscard]] constexpr NativeTargetRange NativeRequestTargetRange(const std::size_t spec_length,
                                                                   const int path_begin,
                                                                   const int path_len,
                                                                   const int query_begin,
                                                                   const int query_len,
                                                                   const int ref_begin,
                                                                   const int ref_len) noexcept {
  if (path_len < 0 || path_begin < 0 || static_cast<std::size_t>(path_begin) > spec_length) {
    return {spec_length, 0};
  }
  const std::int64_t begin = path_begin;
  const std::int64_t end = ref_len >= 0     ? std::int64_t{ref_begin} - 1
                           : query_len >= 0 ? std::int64_t{query_begin} + query_len
                                            : begin + path_len;
  const std::int64_t bounded = std::clamp(end, begin, static_cast<std::int64_t>(spec_length));
  return {static_cast<std::size_t>(begin), static_cast<std::size_t>(bounded - begin)};
}
// url::kMaxURLChars at the pin.
inline constexpr std::size_t kNativeRequestTargetMaxBytes = 2U * 1024U * 1024U;
inline constexpr std::size_t kNativeRequestContentTypeBytes = 64;
// The artifact cap. Larger bodies keep this prefix and their original length.
inline constexpr std::size_t kNativeRequestBodyCaptureBytes = 16U * 1024U * 1024U;
// Bounds the synchronous UI-thread digest. Larger in-memory bodies are marked
// instead of hashed; their artifact digest is computed off the UI thread.
inline constexpr std::size_t kNativeRequestBodyDigestBytes = 4U * 1024U * 1024U;
// Unique body and full-target bytes per session (--reb-request-content-budget-bytes).
inline constexpr std::uint64_t kNativeRequestContentDefaultBudgetBytes = 256ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kNativeRequestContentMinBudgetBytes = 1ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kNativeRequestContentMaxBudgetBytes =
    4ULL * 1024ULL * 1024ULL * 1024ULL;

enum class NativeRequestBodyKind : std::uint8_t {
  kNone = 0,
  kBytes = 1,
  kFile = 2,
  kDataPipe = 3,
  kChunkedDataPipe = 4,
  kMixed = 5,
  kUnknown = 6,
};

enum class NativeRequestBodyState : std::uint8_t {
  kNoBody = 1,
  kEmpty = 2,
  kMetadataOnly = 3,
  kCaptured = 4,
  kCapturedTruncated = 5,
  kNotCapturedBodyKind = 6,
  kNotCapturedArtifactUnavailable = 7,
  kNotCapturedTransferRefused = 8,
  kNotCapturedUrl = 9,
  kNotCapturedSessionBudget = 10,
  kNotCapturedCredentialForm = 11,
  // native-network-v3.md: a file, blob or stream part could not be read whole.
  kNotCapturedReadIncomplete = 12,
};

inline constexpr std::uint8_t kNativeRequestBodyContentCapture = 1U << 0U;
inline constexpr std::uint8_t kNativeRequestBodyDigestPresent = 1U << 1U;
inline constexpr std::uint8_t kNativeRequestBodyDigestSizeLimit = 1U << 2U;
inline constexpr std::uint8_t kNativeRequestBodyLengthPartial = 1U << 3U;
inline constexpr std::uint8_t kNativeRequestBodyContentTypePresent = 1U << 4U;
inline constexpr std::uint8_t kNativeRequestBodyContentTypeOmitted = 1U << 5U;
// The browser read the file, blob or stream parts (native-network-v3.md).
inline constexpr std::uint8_t kNativeRequestBodyRead = 1U << 6U;

enum class NativeRequestScheme : std::uint8_t {
  kOther = 0,
  kHttp = 1,
  kHttps = 2,
  kWs = 3,
  kWss = 4,
};

struct NativeRequestBodySummary final {
  NativeRequestBodyKind kind = NativeRequestBodyKind::kNone;
  NativeRequestBodyState state = NativeRequestBodyState::kNoBody;
  std::uint8_t flags = 0;
  std::uint8_t content_type_length = 0;
  std::uint64_t body_length = 0;
  std::uint64_t captured_length = 0;
  std::uint32_t element_count = 0;
  std::array<std::uint8_t, 32> sha256{};
  std::array<char, kNativeRequestContentTypeBytes> content_type{};
};

// Where the bytes past the inline prefix went.
enum class NativeRequestTargetRetention : std::uint8_t {
  kComplete = 0,
  kRetained = 1,
  kNotRetainedArtifactUnavailable = 2,
  kNotRetainedTransferRefused = 3,
  kNotRetainedSessionBudget = 4,
  kNotRetainedUrl = 5,
};

struct NativeRequestTarget final {
  std::uint32_t target_length = 0;
  NativeRequestScheme scheme = NativeRequestScheme::kOther;
  NativeRequestTargetRetention retention = NativeRequestTargetRetention::kComplete;
  std::uint16_t port = 0;
  std::array<char, kNativeRequestTargetPrefixBytes> prefix{};
};

namespace native_request_detail {
inline void Put(std::array<std::byte, kNativeRequestPayloadSize>& out,
                const std::size_t offset,
                const std::uint64_t value,
                const std::size_t width) noexcept {
  for (std::size_t i = 0; i < width; ++i) {
    out[offset + i] = static_cast<std::byte>((value >> (8U * i)) & 0xffU);
  }
}
// RFC 9110 token characters, the only bytes a normalized media type keeps.
constexpr bool IsTokenCharacter(const char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
         std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
}
}  // namespace native_request_detail

// Lower-cased `type/subtype` before any parameter. Parameters such as charset
// or a multipart boundary are dropped. Returns false, leaving `length` zero,
// when the header is not a bounded media type.
[[nodiscard]] constexpr bool NormalizeNativeContentType(
    std::string_view header,
    std::array<char, kNativeRequestContentTypeBytes>& out,
    std::uint8_t& length) noexcept {
  out.fill('\0');
  length = 0;
  header = header.substr(0, header.find(';'));
  const auto first = header.find_first_not_of(" \t");
  if (first == std::string_view::npos) {
    return false;
  }
  header = header.substr(first, header.find_last_not_of(" \t") - first + 1);
  if (header.size() > out.size()) {
    return false;
  }
  std::size_t slashes = 0;
  for (std::size_t i = 0; i < header.size(); ++i) {
    char c = header[i];
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
    if (c == '/') {
      if (++slashes > 1 || i == 0 || i + 1 == header.size()) {
        out.fill('\0');
        return false;
      }
    } else if (!native_request_detail::IsTokenCharacter(c)) {
      out.fill('\0');
      return false;
    }
    out[i] = c;
  }
  if (slashes != 1) {
    out.fill('\0');
    return false;
  }
  length = static_cast<std::uint8_t>(header.size());
  return true;
}

// Fixed little-endian layout; see the field table in native-network-v2.md.
[[nodiscard]] inline std::array<std::byte, kNativeRequestPayloadSize>
EncodeNativeRequestBodyPayload(const NativeRequestBodySummary& value) noexcept {
  using native_request_detail::Put;
  std::array<std::byte, kNativeRequestPayloadSize> out{};
  Put(out, 0, kNativeRequestPayloadVersion, 2);
  Put(out, 2, kNativeRequestPayloadSize, 2);
  Put(out, 4, static_cast<std::uint8_t>(value.kind), 1);
  Put(out, 5, static_cast<std::uint8_t>(value.state), 1);
  Put(out, 6, value.flags, 1);
  Put(out, 7, value.content_type_length, 1);
  Put(out, 8, value.body_length, 8);
  Put(out, 16, value.captured_length, 8);
  Put(out, 24, value.element_count, 4);
  std::transform(value.sha256.begin(), value.sha256.end(), out.begin() + 32,
                 [](const std::uint8_t byte) { return static_cast<std::byte>(byte); });
  std::transform(
      value.content_type.begin(), value.content_type.end(), out.begin() + 64,
      [](const char c) { return static_cast<std::byte>(static_cast<unsigned char>(c)); });
  return out;
}

[[nodiscard]] inline std::array<std::byte, kNativeRequestPayloadSize>
EncodeNativeRequestTargetPayload(const NativeRequestTarget& value) noexcept {
  using native_request_detail::Put;
  std::array<std::byte, kNativeRequestPayloadSize> out{};
  Put(out, 0, kNativeRequestTargetPayloadVersion, 2);
  Put(out, 2, kNativeRequestPayloadSize, 2);
  Put(out, 4, value.target_length, 4);
  Put(out, 8, static_cast<std::uint8_t>(value.scheme), 1);
  Put(out, 9, static_cast<std::uint8_t>(value.retention), 1);
  Put(out, 10, value.port, 2);
  std::transform(value.prefix.begin(), value.prefix.end(), out.begin() + 12, [](const char c) {
    return static_cast<std::byte>(static_cast<unsigned char>(c));
  });
  return out;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_REQUEST_H_
