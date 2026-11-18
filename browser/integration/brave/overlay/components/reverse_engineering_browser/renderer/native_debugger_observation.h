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
#include <optional>
#include <string>
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
// Rule tables, not record counts: a set the tables cannot hold is refused at
// arming. Each slot index fits the record's u8 slot field.
inline constexpr std::size_t kNativeWatchRequestRules = 32;
inline constexpr std::size_t kNativeWatchEventRules = 64;
inline constexpr std::size_t kNativeWatchDomNodes = 32;
inline constexpr std::size_t kNativeWatchUrlBytes = 256;
inline constexpr std::size_t kNativeWatchEventBytes = 27;
inline constexpr std::size_t kNativeWatchHostBytes = 45;
inline constexpr std::size_t kNativeWatchAttributeBytes = 32;
inline constexpr std::size_t kNativeWatchAncestorLimit = 1024;
inline constexpr std::uint8_t kNativeWatchAttribute = 1;
inline constexpr std::uint8_t kNativeWatchSubtree = 2;
inline constexpr std::uint8_t kNativeWatchRemoval = 3;

struct NativeWatchRequestRule final {
  std::array<char, kNativeWatchUrlBytes> url{};
  std::size_t url_length = 0;
  std::array<char, 16> method{};
  std::size_t method_length = 0;
};

struct NativeWatchDomNode final {
  // Blink's DOMNodeId: never reused, so a collected node matches nothing.
  std::int32_t node_id = 0;
  bool attributes = false;
  bool subtree = false;
  bool removal = false;
};

// Exported: the Console runtime, outside this component, builds the rules.
struct COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeWatchRules final {
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

  // Each refuses, adding nothing, a rule the renderer could not hold exactly.
  [[nodiscard]] bool AddRequest(std::string_view url_contains, std::string_view method) noexcept;
  [[nodiscard]] bool AddEvent(std::string_view type) noexcept;
  [[nodiscard]] bool AddDom(std::int32_t node_id,
                            bool attributes,
                            bool subtree,
                            bool removal) noexcept;
};

// The Console's armed rules, kept for every later document of one exact
// origin and frame kind (protocol/native-debugger-observation-v1.md). The
// browser derives the origin and kind from the document they were armed on
// and assigns `serial`; DOM rules name one document's nodes, so a scope never
// holds any.
struct COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeWatchScope final {
  std::uint64_t serial = 0;
  std::string origin;
  bool top_frame = false;
  NativeWatchRules rules;
};

// Main thread only, except Armed() and Request(). Hooks call Armed() first: one relaxed load.
// Each armed document matches only its own frame's records; frame id 0 never does. A renderer
// holds the Console's own arm of one document and every document the kept scope armed.
class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeDebuggerWatch final {
 public:
  [[nodiscard]] static bool Armed(const std::uint32_t kinds) noexcept {
    return (mask_.load(std::memory_order_relaxed) & kinds) != 0;
  }
  // The Console's arm of one document, replacing its previous arm in this
  // renderer. False, arming nothing, without an active capture configuration.
  [[nodiscard]] static bool Arm(std::uint64_t frame_id, const NativeWatchRules& rules) noexcept;
  // Disarms the frame's document, whichever arm it holds.
  static void Disarm(std::uint64_t frame_id) noexcept;
  // Whether a record of kinds from frame_id would be admitted now.
  [[nodiscard]] static bool Wants(std::uint64_t frame_id, std::uint32_t kinds) noexcept;

  // Replaces the kept scope, or clears it. Documents the previous scope armed
  // take the new rules when the origin and frame kind stay the same, and are
  // disarmed otherwise; a new scope arms only documents that start after it.
  static void SetScope(std::optional<NativeWatchScope> scope);
  // One bool load: whether a document's start needs its origin at all.
  [[nodiscard]] static bool HasScope() noexcept;
  // At a document's start, before its own scripts: arms the kept scope's rules
  // when the scope names this exact origin and frame kind.
  [[nodiscard]] static bool ArmScope(std::uint64_t frame_id,
                                     std::string_view origin,
                                     bool top_frame);
  // Called after the armed kinds change, so the Console runtime can install or
  // remove V8's throw observer. Null until the runtime registers it.
  static void SetKindsChanged(void (*changed)()) noexcept;

  // Matches only the armed document's own main-thread requests.
  static void Request(std::int32_t request_id,
                      std::uint64_t initiated_sequence,
                      std::string_view method,
                      std::string_view url) noexcept;
  static void Listener(std::uint64_t frame_id,
                       std::string_view event_type,
                       std::uint8_t target_kind,
                       std::uint16_t node_type,
                       const NativeStackFrame& listener) noexcept;
  static void Timer(std::uint64_t frame_id,
                    bool fired,
                    bool interval,
                    bool string_callback,
                    std::uint32_t timer_id,
                    std::uint32_t delay_ms,
                    const NativeStackFrame& callback) noexcept;
  static void Csp(std::uint64_t frame_id,
                  std::uint8_t directive,
                  bool report_only,
                  std::string_view host) noexcept;
  // kind 1 uncaught, 2 caught by JavaScript, 3 rejected with no handler.
  static void Exception(std::uint64_t frame_id,
                        std::uint8_t kind,
                        const NativeStackFrame& site) noexcept;
  // The slot of a node watched for kind (kNativeWatchAttribute and so on), or -1.
  [[nodiscard]] static int DomSlot(std::int32_t node_id, std::uint8_t kind) noexcept;
  static void Mutation(std::uint64_t frame_id,
                       std::uint8_t kind,
                       int slot,
                       std::uint16_t node_type,
                       std::string_view attribute) noexcept;

  // A kind 1 frame: a function's start, or a throw site inside it.
  [[nodiscard]] static NativeStackFrame FunctionFrame(int script_id,
                                                      int start_position,
                                                      int position = -1) noexcept;

 private:
  // Whether the configuration a document was armed under is still the
  // published one. Every record it admits is recorded; a full queue counts its
  // drops.
  [[nodiscard]] static bool Charge(std::uint64_t armed_generation) noexcept;
  // The published configuration's generation when a capture can record, else 0.
  [[nodiscard]] static std::uint64_t ArmableGeneration() noexcept;
  // The rules a record of kinds from frame_id is admitted under now, and the
  // generation they were armed in, or null.
  [[nodiscard]] static const NativeWatchRules* Admitted(std::uint64_t frame_id,
                                                        std::uint32_t kinds,
                                                        std::uint64_t& generation) noexcept;
  // Republishes the union of every armed document's kinds.
  static void Publish() noexcept;
  static std::atomic<std::uint32_t> mask_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_OBSERVATION_H_
