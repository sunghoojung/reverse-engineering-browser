// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_IO_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_IO_H_

#include <chrono>
#include <cstddef>
#include <span>

namespace reb {

using NativeConsoleDeadline = std::chrono::steady_clock::time_point;
[[nodiscard]] bool NativeConsoleRead(int socket,
                                     std::span<std::byte> bytes,
                                     NativeConsoleDeadline deadline) noexcept;
[[nodiscard]] bool NativeConsoleWrite(int socket,
                                      std::span<const std::byte> bytes,
                                      NativeConsoleDeadline deadline) noexcept;
// A record that keeps moving never times out, however large; one that makes no
// progress for `stall` does. For payloads, whose size their header bounded.
[[nodiscard]] bool NativeConsoleRead(int socket,
                                     std::span<std::byte> bytes,
                                     std::chrono::milliseconds stall) noexcept;
[[nodiscard]] bool NativeConsoleWrite(int socket,
                                      std::span<const std::byte> bytes,
                                      std::chrono::milliseconds stall) noexcept;

template <typename T>
[[nodiscard]] auto NativeConsoleBytes(T& value) noexcept {
  return std::as_writable_bytes(std::span(&value, 1));
}
template <typename T>
[[nodiscard]] auto NativeConsoleBytes(const T& value) noexcept {
  return std::as_bytes(std::span(&value, 1));
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_IO_H_
