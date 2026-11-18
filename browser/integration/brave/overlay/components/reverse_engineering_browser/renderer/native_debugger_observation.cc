// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_debugger_observation.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/no_destructor.h"
#include "base/threading/platform_thread.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"

// Chromium builds this directory with -Wunsafe-buffer-usage as an error. The
// records here are fixed layouts written at offsets their sizes bound, so
// each raw offset and memcpy is marked UNSAFE_BUFFERS.
namespace reb {

namespace {

// One armed document. Its configuration generation guards it, so a new
// capture configuration ends it without touching the table.
struct ArmedFrame final {
  std::uint64_t frame_id = 0;
  std::uint64_t generation = 0;
  // The kept scope's serial for a document that scope armed; 0 for the
  // Console's own arm.
  std::uint64_t scope = 0;
  std::uint32_t mask = 0;
  NativeWatchRules rules;
};

// Sorted by frame id, so a hook finds its document in O(log n) of the
// renderer's armed documents. Main thread only: arming, disarming and every
// lookup run there, and the thread check comes before any read.
std::vector<ArmedFrame>& Frames() {
  static base::NoDestructor<std::vector<ArmedFrame>> frames;
  return *frames;
}
std::optional<NativeWatchScope>& KeptScope() {
  static base::NoDestructor<std::optional<NativeWatchScope>> scope;
  return *scope;
}
bool g_has_scope = false;
// The frame the Console's own arm holds, or 0. Its entry has scope 0.
std::uint64_t g_console_frame = 0;
void (*g_kinds_changed)() = nullptr;
// Arm's thread, the main thread; no other thread reads the table.
std::atomic<decltype(base::PlatformThread::CurrentId().raw())> g_watch_thread{0};

std::uint32_t MaskOf(const NativeWatchRules& rules) noexcept {
  std::uint32_t mask = 0;
  mask |= rules.request_count != 0 ? kNativeWatchRequests : 0;
  mask |= rules.event_count != 0 ? kNativeWatchListeners : 0;
  mask |= rules.timers ? kNativeWatchTimers : 0;
  mask |= rules.csp ? kNativeWatchCsp : 0;
  mask |= rules.uncaught ? kNativeWatchUncaught : 0;
  mask |= rules.caught ? kNativeWatchCaught : 0;
  mask |= rules.dom_count != 0 ? kNativeWatchDom : 0;
  return mask;
}

bool OnWatchThread() noexcept {
  return base::PlatformThread::CurrentId().raw() == g_watch_thread.load(std::memory_order_relaxed);
}

std::vector<ArmedFrame>::iterator Position(const std::uint64_t frame_id) {
  return std::lower_bound(
      Frames().begin(), Frames().end(), frame_id,
      [](const ArmedFrame& armed, const std::uint64_t id) { return armed.frame_id < id; });
}

ArmedFrame* Find(const std::uint64_t frame_id) {
  const auto at = Position(frame_id);
  return at != Frames().end() && at->frame_id == frame_id ? &*at : nullptr;
}

void Put(const std::uint64_t frame_id,
         const std::uint64_t generation,
         const std::uint64_t scope,
         const NativeWatchRules& rules) {
  g_watch_thread.store(base::PlatformThread::CurrentId().raw(), std::memory_order_relaxed);
  auto at = Position(frame_id);
  if (at == Frames().end() || at->frame_id != frame_id) {
    at = Frames().insert(at, ArmedFrame{});
  }
  at->frame_id = frame_id;
  at->generation = generation;
  at->scope = scope;
  at->mask = MaskOf(rules);
  at->rules = rules;
  if (scope != 0 && g_console_frame == frame_id) {
    g_console_frame = 0;
  }
}

std::array<std::uint8_t, 48> Tail() noexcept {
  return {};
}

void PutFrame(std::array<std::uint8_t, 48>& tail,
              const std::size_t at,
              const NativeStackFrame& frame) noexcept {
  UNSAFE_BUFFERS(std::memcpy(tail.data() + at, &frame, sizeof(frame)));
}

void PutName(std::array<std::uint8_t, 48>& tail,
             const std::size_t length_at,
             const std::size_t text_at,
             const std::string_view text,
             const std::size_t limit) noexcept {
  const std::size_t n = std::min(text.size(), limit);
  tail[length_at] = static_cast<std::uint8_t>(n);
  UNSAFE_BUFFERS(std::memcpy(tail.data() + text_at, text.data(), n));
}

}  // namespace

std::atomic<std::uint32_t> NativeDebuggerWatch::mask_{0};

bool NativeDebuggerWatch::Charge(const std::uint64_t armed_generation) noexcept {
  const std::uint64_t generation =
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire);
  return (generation & 1U) == 0 && generation == armed_generation;
}

std::uint64_t NativeDebuggerWatch::ArmableGeneration() noexcept {
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  return (generation & 1U) == 0 && sink.emitter_.load(std::memory_order_acquire) ? generation : 0;
}

const NativeWatchRules* NativeDebuggerWatch::Admitted(const std::uint64_t frame_id,
                                                      const std::uint32_t kinds,
                                                      std::uint64_t& generation) noexcept {
  if (!Armed(kinds) || frame_id == 0 || !OnWatchThread()) {
    return nullptr;
  }
  const ArmedFrame* const armed = Find(frame_id);
  if (!armed || (armed->mask & kinds) == 0 ||
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire) !=
          armed->generation) {
    return nullptr;
  }
  generation = armed->generation;
  return &armed->rules;
}

void NativeDebuggerWatch::Publish() noexcept {
  std::uint32_t mask = 0;
  for (const ArmedFrame& armed : Frames()) {
    mask |= armed.mask;
  }
  mask_.store(mask, std::memory_order_relaxed);
  if (g_kinds_changed) {
    g_kinds_changed();
  }
}

bool NativeWatchRules::AddRequest(const std::string_view url_contains,
                                  const std::string_view method) noexcept {
  const bool upper =
      std::all_of(method.begin(), method.end(), [](const char c) { return c >= 'A' && c <= 'Z'; });
  if (request_count == requests.size() || url_contains.empty() ||
      url_contains.size() > kNativeWatchUrlBytes ||
      url_contains.find('\0') != std::string_view::npos ||
      method.size() > requests[0].method.size() || !upper) {
    return false;
  }
  NativeWatchRequestRule& rule = requests[request_count++];
  UNSAFE_BUFFERS(std::memcpy(rule.url.data(), url_contains.data(), url_contains.size()));
  rule.url_length = url_contains.size();
  UNSAFE_BUFFERS(std::memcpy(rule.method.data(), method.data(), method.size()));
  rule.method_length = method.size();
  return true;
}

bool NativeWatchRules::AddEvent(const std::string_view type) noexcept {
  const bool printable =
      std::all_of(type.begin(), type.end(), [](const char c) { return c > 0x20 && c < 0x7f; });
  if (event_count == events.size() || type.empty() || type.size() > kNativeWatchEventBytes ||
      !printable) {
    return false;
  }
  for (std::size_t i = 0; i < event_count; ++i) {
    if (std::string_view(events[i].data(), event_lengths[i]) == type) {
      return false;
    }
  }
  UNSAFE_BUFFERS(std::memcpy(events[event_count].data(), type.data(), type.size()));
  event_lengths[event_count++] = type.size();
  return true;
}

bool NativeWatchRules::AddDom(const std::int32_t node_id,
                              const bool attributes,
                              const bool subtree,
                              const bool removal) noexcept {
  if (dom_count == dom.size() || node_id <= 0 || !(attributes || subtree || removal)) {
    return false;
  }
  for (std::size_t i = 0; i < dom_count; ++i) {
    if (dom[i].node_id == node_id) {
      return false;
    }
  }
  dom[dom_count++] = {node_id, attributes, subtree, removal};
  return true;
}

bool NativeDebuggerWatch::Arm(const std::uint64_t frame_id,
                              const NativeWatchRules& rules) noexcept {
  const std::uint64_t generation = ArmableGeneration();
  if (frame_id == 0 || generation == 0) {
    return false;
  }
  if (g_console_frame != 0 && g_console_frame != frame_id) {
    Disarm(g_console_frame);
  }
  Put(frame_id, generation, 0, rules);
  g_console_frame = frame_id;
  Publish();
  return true;
}

void NativeDebuggerWatch::Disarm(const std::uint64_t frame_id) noexcept {
  const auto at = Position(frame_id);
  if (frame_id == 0 || at == Frames().end() || at->frame_id != frame_id) {
    return;
  }
  Frames().erase(at);
  if (g_console_frame == frame_id) {
    g_console_frame = 0;
  }
  Publish();
}

bool NativeDebuggerWatch::Wants(const std::uint64_t frame_id, const std::uint32_t kinds) noexcept {
  std::uint64_t generation = 0;
  return Admitted(frame_id, kinds, generation) != nullptr;
}

void NativeDebuggerWatch::SetScope(std::optional<NativeWatchScope> scope) {
  if (scope && (scope->serial == 0 || scope->rules.dom_count != 0 || MaskOf(scope->rules) == 0)) {
    scope.reset();
  }
  std::optional<NativeWatchScope>& kept = KeptScope();
  const bool same =
      kept && scope && kept->origin == scope->origin && kept->top_frame == scope->top_frame;
  if (same) {
    for (ArmedFrame& armed : Frames()) {
      if (armed.scope != 0) {
        armed.scope = scope->serial;
        armed.mask = MaskOf(scope->rules);
        armed.rules = scope->rules;
      }
    }
  } else {
    std::erase_if(Frames(), [](const ArmedFrame& armed) { return armed.scope != 0; });
  }
  kept = std::move(scope);
  g_has_scope = kept.has_value();
  Publish();
}

bool NativeDebuggerWatch::HasScope() noexcept {
  return g_has_scope;
}

bool NativeDebuggerWatch::ArmScope(const std::uint64_t frame_id,
                                   const std::string_view origin,
                                   const bool top_frame) {
  const std::optional<NativeWatchScope>& kept = KeptScope();
  if (!kept || frame_id == 0 || kept->top_frame != top_frame || kept->origin != origin) {
    return false;
  }
  const std::uint64_t generation = ArmableGeneration();
  if (generation == 0) {
    return false;
  }
  Put(frame_id, generation, kept->serial, kept->rules);
  Publish();
  return true;
}

void NativeDebuggerWatch::SetKindsChanged(void (*changed)()) noexcept {
  g_kinds_changed = changed;
}

void NativeDebuggerWatch::Request(const std::int32_t request_id,
                                  const std::uint64_t initiated_sequence,
                                  const std::string_view method,
                                  const std::string_view url) noexcept {
  const std::uint64_t frame_id =
      Armed(kNativeWatchRequests) ? NativeRequestStackWalk::RequestFrameId() : 0;
  std::uint64_t generation = 0;
  const NativeWatchRules* const rules = Admitted(frame_id, kNativeWatchRequests, generation);
  if (!rules) {
    return;
  }
  for (std::size_t slot = 0; slot < rules->request_count; ++slot) {
    const NativeWatchRequestRule& rule = rules->requests[slot];
    const std::string_view want(rule.url.data(), rule.url_length);
    if (url.find(want) == std::string_view::npos) {
      continue;
    }
    const std::string_view want_method(rule.method.data(), rule.method_length);
    if (rule.method_length != 0 && method != want_method) {
      continue;
    }
    if (!Charge(generation)) {
      return;
    }
    std::array<std::uint8_t, 48> tail = Tail();
    tail[0] = static_cast<std::uint8_t>(slot);
    tail[1] = rule.method_length != 0 ? 1 : 0;
    NativeRequestStackWalk::RecordObservation(NativeProbeType::kRequestWatchMatch, request_id,
                                              initiated_sequence, frame_id, tail);
    return;
  }
}

void NativeDebuggerWatch::Listener(const std::uint64_t frame_id,
                                   const std::string_view event_type,
                                   const std::uint8_t target_kind,
                                   const std::uint16_t node_type,
                                   const NativeStackFrame& listener) noexcept {
  std::uint64_t generation = 0;
  const NativeWatchRules* const armed = Admitted(frame_id, kNativeWatchListeners, generation);
  if (!armed) {
    return;
  }
  const NativeWatchRules& rules = *armed;
  std::size_t slot = rules.event_count;
  for (std::size_t i = 0; i < rules.event_count; ++i) {
    if (std::string_view(rules.events[i].data(), rules.event_lengths[i]) == event_type) {
      slot = i;
      break;
    }
  }
  if (slot == rules.event_count || target_kind < 1 || target_kind > 5 || !Charge(generation)) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = static_cast<std::uint8_t>(slot);
  tail[1] = target_kind;
  UNSAFE_BUFFERS(std::memcpy(tail.data() + 2, &node_type, sizeof(node_type)));
  PutFrame(tail, 4, listener);
  PutName(tail, 20, 21, event_type, kNativeWatchEventBytes);
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kListenerDispatch, 0, 0, frame_id,
                                            tail);
}

void NativeDebuggerWatch::Timer(const std::uint64_t frame_id,
                                const bool fired,
                                const bool interval,
                                const bool string_callback,
                                const std::uint32_t timer_id,
                                const std::uint32_t delay_ms,
                                const NativeStackFrame& callback) noexcept {
  std::uint64_t generation = 0;
  if (!Admitted(frame_id, kNativeWatchTimers, generation) || !Charge(generation)) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = fired ? 2 : 1;
  tail[1] = interval ? 2 : 1;
  const std::uint16_t flags = string_callback ? 1 : 0;
  UNSAFE_BUFFERS(std::memcpy(tail.data() + 2, &flags, sizeof(flags)));
  UNSAFE_BUFFERS(std::memcpy(tail.data() + 4, &timer_id, sizeof(timer_id)));
  UNSAFE_BUFFERS(std::memcpy(tail.data() + 8, &delay_ms, sizeof(delay_ms)));
  PutFrame(tail, 12, callback);
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kTimerObservation, 0, 0, frame_id,
                                            tail);
}

void NativeDebuggerWatch::Csp(const std::uint64_t frame_id,
                              const std::uint8_t directive,
                              const bool report_only,
                              const std::string_view host) noexcept {
  const bool ascii =
      std::all_of(host.begin(), host.end(), [](const char c) { return c > 0x20 && c < 0x7f; });
  std::uint64_t generation = 0;
  if (!Admitted(frame_id, kNativeWatchCsp, generation) || !Charge(generation)) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = directive;
  tail[1] = report_only ? 2 : 1;
  // A longer or non-ASCII host is left out rather than cut.
  if (ascii && host.size() <= kNativeWatchHostBytes) {
    PutName(tail, 2, 3, host, kNativeWatchHostBytes);
  }
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kCspViolation, 0, 0, frame_id, tail);
}

void NativeDebuggerWatch::Exception(const std::uint64_t frame_id,
                                    const std::uint8_t kind,
                                    const NativeStackFrame& site) noexcept {
  if (kind < 1 || kind > 3) {
    return;
  }
  std::uint64_t generation = 0;
  if (!Admitted(frame_id, kind == 2 ? kNativeWatchCaught : kNativeWatchUncaught, generation) ||
      !Charge(generation)) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = kind;
  PutFrame(tail, 4, site);
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kExceptionObservation, 0, 0, frame_id,
                                            tail);
}

int NativeDebuggerWatch::DomSlot(const std::int32_t node_id, const std::uint8_t kind) noexcept {
  // Only the Console's own arm holds DOM rules: a node id names one document.
  if (!Armed(kNativeWatchDom) || node_id <= 0 || !OnWatchThread() || g_console_frame == 0) {
    return -1;
  }
  const ArmedFrame* const console = Find(g_console_frame);
  for (std::size_t i = 0; console && i < console->rules.dom_count; ++i) {
    const NativeWatchDomNode& node = console->rules.dom[i];
    const bool wanted = (kind == kNativeWatchAttribute && node.attributes) ||
                        (kind == kNativeWatchSubtree && node.subtree) ||
                        (kind == kNativeWatchRemoval && node.removal);
    if (node.node_id == node_id && wanted) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

void NativeDebuggerWatch::Mutation(const std::uint64_t frame_id,
                                   const std::uint8_t kind,
                                   const int slot,
                                   const std::uint16_t node_type,
                                   const std::string_view attribute) noexcept {
  std::uint64_t generation = 0;
  const NativeWatchRules* const rules = Admitted(frame_id, kNativeWatchDom, generation);
  if (!rules || slot < 0 || static_cast<std::size_t>(slot) >= rules->dom_count ||
      DomSlot(rules->dom[static_cast<std::size_t>(slot)].node_id, kind) != slot) {
    return;
  }
  const bool ascii = std::all_of(attribute.begin(), attribute.end(),
                                 [](const char c) { return c > 0x20 && c < 0x7f; });
  if ((kind == kNativeWatchAttribute && (attribute.empty() || !ascii)) || !Charge(generation)) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = kind;
  tail[1] = static_cast<std::uint8_t>(slot);
  UNSAFE_BUFFERS(std::memcpy(tail.data() + 2, &node_type, sizeof(node_type)));
  if (kind == kNativeWatchAttribute) {
    PutName(tail, 4, 5, attribute, kNativeWatchAttributeBytes);
  }
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kDomMutation, 0, 0, frame_id, tail);
}

NativeStackFrame NativeDebuggerWatch::FunctionFrame(const int script_id,
                                                    const int start_position,
                                                    const int position) noexcept {
  NativeStackFrame frame;
  if (script_id <= 0 || start_position < 0) {
    return frame;
  }
  frame.kind = static_cast<std::uint8_t>(NativeStackFrameKind::kJavaScript);
  frame.script_id = static_cast<std::uint32_t>(script_id);
  frame.position = static_cast<std::uint32_t>(position < 0 ? start_position : position);
  frame.detail = static_cast<std::uint32_t>(start_position);
  return frame;
}

}  // namespace reb
