// Copyright 2026 The Reverse Engineering Browser Authors
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
// Version 2 retains a block of any length. Version 1 retained one of at most
// 320 KiB and recorded a longer one as kNotCapturedBlockLimit.
inline constexpr std::uint16_t kNativeHeaderPayloadVersion = 2;
// The 32-bit length field's ceiling: a block this long or longer is recorded
// as kNotCapturedBlockLimit with this length, the only block not retained for
// its size.
inline constexpr std::uint64_t kNativeHeaderLengthUnrepresentable = 0xffff'ffffU;
// Accepted blocks a later identical block can name instead of being sent
// again. Past it a repeat is sent and stored once more by digest, so the
// bound costs only dedupe, never a block.
inline constexpr std::size_t kNativeHeaderShareEntries = 65'536;
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
  // Version 2: longer than the length field holds. Version 1: longer than
  // its 320 KiB block limit.
  kNotCapturedBlockLimit = 4,
  kNotCapturedArtifactUnavailable = 5,
  kNotCapturedTransferRefused = 6,
  // Retired: older sessions' 64 MiB header budget. Never emitted.
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
