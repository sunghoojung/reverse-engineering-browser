// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_IPC_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_IPC_H_

#include <array>
#include <cstddef>
#include <cstdint>

namespace reb {

inline constexpr std::uint32_t kNativeProbeLocalIpcMagic = 0x52454249;
inline constexpr std::uint16_t kNativeProbeLocalIpcVersion = 1;
inline constexpr std::size_t kNativeProbeLocalIpcTokenSize = 32;

using NativeProbeLocalIpcToken =
    std::array<std::byte, kNativeProbeLocalIpcTokenSize>;

struct NativeProbeLocalIpcHello final {
  std::uint32_t magic = kNativeProbeLocalIpcMagic;
  std::uint16_t version = kNativeProbeLocalIpcVersion;
  std::uint16_t size =
      static_cast<std::uint16_t>(sizeof(NativeProbeLocalIpcHello));
  std::uint64_t session_id = 0;
  NativeProbeLocalIpcToken token{};
  std::array<std::byte, 16> reserved{};
};

static_assert(sizeof(NativeProbeLocalIpcHello) == 64);
static_assert(alignof(NativeProbeLocalIpcHello) == 8);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_PROBE_IPC_H_
