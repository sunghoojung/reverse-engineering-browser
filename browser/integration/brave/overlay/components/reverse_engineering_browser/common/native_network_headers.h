// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_HEADERS_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_HEADERS_H_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "native_network_request.h"

namespace reb {
// Browser-side producer half of protocol/native-network-v3.md. The core mirror
// in include/reb/network_headers.hpp decodes and validates the same bytes.
inline constexpr std::uint16_t kNativeHeaderPayloadVersion = 1;
// Chromium's 256 KiB header bound plus what `: ` normalization can add.
inline constexpr std::size_t kNativeHeaderBlockLimitBytes = 320U * 1024U;
inline constexpr std::size_t kNativeHeaderSessionBytes = 64U * 1024U * 1024U;
inline constexpr std::size_t kNativeHeaderShareEntries = 4096;
inline constexpr std::size_t kNativeHeaderTrackedRequests = 4096;

enum class NativeHeaderSource : std::uint8_t {
  kBrowser = 1,
  kNetwork = 2,
  kEarlyHints = 3,
};

enum class NativeHeaderState : std::uint8_t {
  kCaptured = 1,
  kCapturedShared = 2,
  kEmpty = 3,
  kNotCapturedBlockLimit = 4,
  kNotCapturedArtifactUnavailable = 5,
  kNotCapturedTransferRefused = 6,
  kNotCapturedSessionBudget = 7,
  kNotCapturedUrl = 8,
};

struct NativeHeaderBlockSummary final {
  NativeHeaderSource source = NativeHeaderSource::kBrowser;
  NativeHeaderState state = NativeHeaderState::kEmpty;
  std::uint8_t referrer_policy = 0;
  std::uint8_t address_family = 0;
  std::uint32_t header_count = 0;
  std::uint32_t block_length = 0;
  std::uint32_t hop = 0;
  std::uint16_t status_code = 0;
  std::uint16_t remote_port = 0;
  std::array<std::uint8_t, 16> remote_address{};
  std::uint32_t unattributed_blocks = 0;
  std::array<std::uint8_t, 32> sha256{};
};

// Fixed little-endian layout; see the field table in native-network-v3.md.
[[nodiscard]] inline std::array<std::byte, kNativeRequestPayloadSize>
EncodeNativeHeaderBlockPayload(const NativeHeaderBlockSummary& value) noexcept {
  using native_request_detail::Put;
  std::array<std::byte, kNativeRequestPayloadSize> out{};
  const auto bytes = [&out](const std::size_t offset, const auto& in) {
    std::transform(in.begin(), in.end(), out.begin() + static_cast<std::ptrdiff_t>(offset),
                   [](const std::uint8_t byte) { return static_cast<std::byte>(byte); });
  };
  Put(out, 0, kNativeHeaderPayloadVersion, 2);
  Put(out, 2, kNativeRequestPayloadSize, 2);
  Put(out, 4, static_cast<std::uint8_t>(value.source), 1);
  Put(out, 5, static_cast<std::uint8_t>(value.state), 1);
  Put(out, 6, value.referrer_policy, 1);
  Put(out, 7, value.address_family, 1);
  Put(out, 8, value.header_count, 4);
  Put(out, 12, value.block_length, 4);
  Put(out, 16, value.hop, 4);
  Put(out, 20, value.status_code, 2);
  Put(out, 22, value.remote_port, 2);
  bytes(24, value.remote_address);
  Put(out, 40, value.unattributed_blocks, 4);
  bytes(48, value.sha256);
  return out;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_HEADERS_H_
