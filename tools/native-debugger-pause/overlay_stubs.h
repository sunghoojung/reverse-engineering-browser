// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// The sibling overlay declarations the pausing debugger uses, stood in for
// here because their real headers reach into Chromium. Each signature is
// copied from the overlay header named in the comment; the harness is
// checking the debugger's own files, not these.
#ifndef REB_TOOLS_NATIVE_DEBUGGER_PAUSE_OVERLAY_STUBS_H_
#define REB_TOOLS_NATIVE_DEBUGGER_PAUSE_OVERLAY_STUBS_H_

#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

#include "chromium_stubs.h"

namespace reb {

// common/native_probe_event.h, the four this contract owns and one from
// phase 1 so a wrong name cannot pass as a right one.
enum class NativeProbeType : std::uint16_t {
  kRequestWatchMatch = 40,
  kDebuggerAttached = 66,
  kDebuggerPaused = 67,
  kDebuggerResumed = 68,
  kDebuggerBreakpoint = 69,
};

// common/native_console_io.h
using NativeConsoleDeadline = std::chrono::steady_clock::time_point;
[[nodiscard]] bool NativeConsoleRead(int socket,
                                     std::span<std::byte> bytes,
                                     NativeConsoleDeadline deadline) noexcept;
[[nodiscard]] bool NativeConsoleWrite(int socket,
                                      std::span<const std::byte> bytes,
                                      NativeConsoleDeadline deadline) noexcept;
template <typename T>
[[nodiscard]] auto NativeConsoleBytes(T& value) noexcept {
  return std::as_writable_bytes(std::span(&value, 1));
}
template <typename T>
[[nodiscard]] auto NativeConsoleBytes(const T& value) noexcept {
  return std::as_bytes(std::span(&value, 1));
}

// renderer/native_script_cookie_sink.h
[[nodiscard]] constexpr std::uint64_t NativeFrameIdOf(const std::uint64_t token_high,
                                                      const std::uint64_t token_low) noexcept {
  return std::rotl(token_high, 17) ^ token_low;
}

// renderer/native_request_stack.h
class NativeRequestStackWalk {
 public:
  static void RecordObservation(NativeProbeType type,
                                std::int32_t request_id,
                                std::uint64_t parent_sequence,
                                std::uint64_t frame_id,
                                const std::array<std::uint8_t, 48>& tail) noexcept;
};

// browser/native_console_session.h
[[nodiscard]] std::uint64_t NativeConsoleDocumentIdIfAssigned(content::RenderFrameHost* frame);

}  // namespace reb

#endif  // REB_TOOLS_NATIVE_DEBUGGER_PAUSE_OVERLAY_STUBS_H_
