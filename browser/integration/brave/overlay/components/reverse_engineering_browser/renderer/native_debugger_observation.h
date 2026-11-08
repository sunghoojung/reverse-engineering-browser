// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_OBSERVATION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_OBSERVATION_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "base/component_export.h"
#include "brave/components/reverse_engineering_browser/common/native_request_stack.h"

namespace reb {

// protocol/native-debugger-observation-v1.md.
inline constexpr std::uint32_t kNativeWatchRequests = 1U << 0U;
inline constexpr std::uint32_t kNativeWatchListeners = 1U << 1U;
inline constexpr std::uint32_t kNativeWatchTimers = 1U << 2U;
inline constexpr std::uint32_t kNativeWatchCsp = 1U << 3U;
inline constexpr std::uint32_t kNativeWatchUncaught = 1U << 4U;
inline constexpr std::uint32_t kNativeWatchCaught = 1U << 5U;
inline constexpr std::uint32_t kNativeWatchDom = 1U << 6U;
inline constexpr std::size_t kNativeWatchRequestRules = 8;
inline constexpr std::size_t kNativeWatchEventRules = 16;
inline constexpr std::size_t kNativeWatchDomNodes = 4;
inline constexpr std::size_t kNativeWatchUrlBytes = 256;
inline constexpr std::size_t kNativeWatchEventBytes = 27;
inline constexpr std::uint32_t kNativeWatchBudget = 1024;

struct NativeWatchRequestRule final {
  std::array<char, kNativeWatchUrlBytes> url{};
  std::size_t url_length = 0;
  std::array<char, 16> method{};
  std::size_t method_length = 0;
};

struct NativeWatchDomNode final {
  // Identity only, never dereferenced; the Console holds the element alive.
  const void* node = nullptr;
  bool attributes = false;
  bool subtree = false;
  bool removal = false;
};

struct NativeWatchRules final {
  std::array<NativeWatchRequestRule, kNativeWatchRequestRules> requests{};
  std::size_t request_count = 0;
  std::array<std::array<char, kNativeWatchEventBytes>, kNativeWatchEventRules> events{};
  std::array<std::size_t, kNativeWatchEventRules> event_lengths{};
  std::size_t event_count = 0;
  bool timers = false;
  bool csp = false;
  bool uncaught = false;
  bool caught = false;
  std::array<NativeWatchDomNode, kNativeWatchDomNodes> dom{};
  std::size_t dom_count = 0;
};

// Main thread only, except Armed(). Hooks call Armed() first: one relaxed load.
class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeDebuggerWatch final {
 public:
  [[nodiscard]] static bool Armed(const std::uint32_t kinds) noexcept {
    return (mask_.load(std::memory_order_relaxed) & kinds) != 0;
  }
  // False, arming nothing, without an active capture configuration.
  [[nodiscard]] static bool Arm(std::uint64_t frame_id, const NativeWatchRules& rules) noexcept;
  static void Disarm(std::uint64_t frame_id) noexcept;

  // frame_id 0 means the frame of the current script context.
  static void Request(std::int32_t request_id,
                      std::uint64_t initiated_sequence,
                      std::string_view method,
                      std::string_view url) noexcept;
  static void Listener(std::uint64_t frame_id,
                       std::string_view event_type,
                       std::uint8_t target_kind,
                       std::uint16_t node_type,
                       const NativeStackFrame& listener) noexcept;
  static void Timer(bool fired,
                    bool interval,
                    bool string_callback,
                    std::uint32_t timer_id,
                    std::uint32_t delay_ms,
                    const NativeStackFrame& callback) noexcept;
  static void Csp(std::uint8_t directive, bool report_only, std::string_view host) noexcept;
  static void Exception(std::uint8_t kind) noexcept;
  // The slot of a watched node, or -1.
  [[nodiscard]] static int DomSlot(const void* node) noexcept;
  static void Mutation(std::uint64_t frame_id,
                       std::uint8_t kind,
                       int slot,
                       std::uint16_t node_type,
                       std::string_view attribute) noexcept;

  // A kind 1 frame at a function's start, or a zero frame for a native one.
  [[nodiscard]] static NativeStackFrame FunctionFrame(int script_id, int start_position) noexcept;

 private:
  // Charges the per-configuration budget; leaves one gap on first refusal.
  [[nodiscard]] static bool Charge() noexcept;
  static std::atomic<std::uint32_t> mask_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_OBSERVATION_H_
