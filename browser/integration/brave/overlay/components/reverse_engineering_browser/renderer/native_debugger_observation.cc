// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_debugger_observation.h"

#include <algorithm>
#include <atomic>
#include <cstring>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"

namespace reb {

namespace {

// One armed rule set per renderer. The current live Console binds one
// document; a second Arm replaces the first. Published generation guards it.
struct ArmedWatch final {
  std::uint64_t generation = 0;
  std::uint64_t frame_id = 0;
  NativeWatchRules rules;
  std::uint32_t budget = 0;
  bool budget_gap = false;
};
ArmedWatch g_watch;
// Arm's thread, the main thread; no other thread reads g_watch.
std::atomic<decltype(base::PlatformThread::CurrentId().raw())> g_watch_thread{0};

std::array<std::uint8_t, 48> Tail() noexcept {
  return {};
}

void PutFrame(std::array<std::uint8_t, 48>& tail,
              const std::size_t at,
              const NativeStackFrame& frame) noexcept {
  std::memcpy(tail.data() + at, &frame, sizeof(frame));
}

void PutName(std::array<std::uint8_t, 48>& tail,
             const std::size_t length_at,
             const std::size_t text_at,
             const std::string_view text,
             const std::size_t limit) noexcept {
  const std::size_t n = std::min(text.size(), limit);
  tail[length_at] = static_cast<std::uint8_t>(n);
  std::memcpy(tail.data() + text_at, text.data(), n);
}

}  // namespace

std::atomic<std::uint32_t> NativeDebuggerWatch::mask_{0};

bool NativeDebuggerWatch::Charge() noexcept {
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  if ((generation & 1U) != 0 || generation != g_watch.generation) {
    return false;
  }
  if (g_watch.budget >= kNativeWatchBudget) {
    if (!g_watch.budget_gap) {
      g_watch.budget_gap = true;
      NativeProbeEvent gap;
      gap.header.category = NativeProbeCategory::kRuntime;
      gap.header.type = NativeProbeType::kGap;
      gap.header.session_id = sink.session_id_.load(std::memory_order_relaxed);
      gap.header.monotonic_time_ns =
          static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
      gap.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
      gap.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
      gap.header.frame_id = g_watch.frame_id;
      constexpr std::string_view kReason = "debugger_observation_budget";
      gap.header.payload_size = static_cast<std::uint32_t>(kReason.size());
      std::transform(kReason.begin(), kReason.end(), gap.inline_payload.begin(),
                     [](const char c) { return static_cast<std::byte>(c); });
      gap.header.sequence_number = sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
      static_cast<void>(sink.EmitStatus(gap, generation));
    }
    return false;
  }
  ++g_watch.budget;
  return true;
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
  std::memcpy(rule.url.data(), url_contains.data(), url_contains.size());
  rule.url_length = url_contains.size();
  std::memcpy(rule.method.data(), method.data(), method.size());
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
  std::memcpy(events[event_count].data(), type.data(), type.size());
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
  NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  if (frame_id == 0 || (generation & 1U) != 0 || !sink.emitter_.load(std::memory_order_acquire)) {
    mask_.store(0, std::memory_order_relaxed);
    g_watch = ArmedWatch{};
    return false;
  }
  g_watch.generation = generation;
  g_watch.frame_id = frame_id;
  g_watch.rules = rules;
  g_watch.budget = 0;
  g_watch.budget_gap = false;
  g_watch_thread.store(base::PlatformThread::CurrentId().raw(), std::memory_order_relaxed);
  std::uint32_t mask = 0;
  mask |= rules.request_count != 0 ? kNativeWatchRequests : 0;
  mask |= rules.event_count != 0 ? kNativeWatchListeners : 0;
  mask |= rules.timers ? kNativeWatchTimers : 0;
  mask |= rules.csp ? kNativeWatchCsp : 0;
  mask |= rules.uncaught ? kNativeWatchUncaught : 0;
  mask |= rules.caught ? kNativeWatchCaught : 0;
  mask |= rules.dom_count != 0 ? kNativeWatchDom : 0;
  mask_.store(mask, std::memory_order_relaxed);
  return true;
}

void NativeDebuggerWatch::Disarm(const std::uint64_t frame_id) noexcept {
  if (g_watch.frame_id == frame_id) {
    mask_.store(0, std::memory_order_relaxed);
    g_watch = ArmedWatch{};
  }
}

bool NativeDebuggerWatch::Wants(const std::uint64_t frame_id, const std::uint32_t kinds) noexcept {
  if (!Armed(kinds) || frame_id == 0 ||
      base::PlatformThread::CurrentId().raw() != g_watch_thread.load(std::memory_order_relaxed) ||
      frame_id != g_watch.frame_id) {
    return false;
  }
  const std::uint64_t generation =
      NativeProbeSink::Get().config_generation_.load(std::memory_order_acquire);
  return generation == g_watch.generation &&
         (g_watch.budget < kNativeWatchBudget || !g_watch.budget_gap);
}

void NativeDebuggerWatch::Request(const std::int32_t request_id,
                                  const std::uint64_t initiated_sequence,
                                  const std::string_view method,
                                  const std::string_view url) noexcept {
  const std::uint64_t frame_id =
      Armed(kNativeWatchRequests) ? NativeRequestStackWalk::RequestFrameId() : 0;
  if (!Wants(frame_id, kNativeWatchRequests)) {
    return;
  }
  for (std::size_t slot = 0; slot < g_watch.rules.request_count; ++slot) {
    const NativeWatchRequestRule& rule = g_watch.rules.requests[slot];
    const std::string_view want(rule.url.data(), rule.url_length);
    if (url.find(want) == std::string_view::npos) {
      continue;
    }
    const std::string_view want_method(rule.method.data(), rule.method_length);
    if (rule.method_length != 0 && method != want_method) {
      continue;
    }
    if (!Charge()) {
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
  if (!Wants(frame_id, kNativeWatchListeners)) {
    return;
  }
  std::size_t slot = g_watch.rules.event_count;
  for (std::size_t i = 0; i < g_watch.rules.event_count; ++i) {
    if (std::string_view(g_watch.rules.events[i].data(), g_watch.rules.event_lengths[i]) ==
        event_type) {
      slot = i;
      break;
    }
  }
  if (slot == g_watch.rules.event_count || target_kind < 1 || target_kind > 5 || !Charge()) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = static_cast<std::uint8_t>(slot);
  tail[1] = target_kind;
  std::memcpy(tail.data() + 2, &node_type, sizeof(node_type));
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
  if (!Wants(frame_id, kNativeWatchTimers) || !Charge()) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = fired ? 2 : 1;
  tail[1] = interval ? 2 : 1;
  const std::uint16_t flags = string_callback ? 1 : 0;
  std::memcpy(tail.data() + 2, &flags, sizeof(flags));
  std::memcpy(tail.data() + 4, &timer_id, sizeof(timer_id));
  std::memcpy(tail.data() + 8, &delay_ms, sizeof(delay_ms));
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
  if (!Wants(frame_id, kNativeWatchCsp) || !Charge()) {
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
  if (kind < 1 || kind > 3 ||
      !Wants(frame_id, kind == 2 ? kNativeWatchCaught : kNativeWatchUncaught) || !Charge()) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = kind;
  PutFrame(tail, 4, site);
  NativeRequestStackWalk::RecordObservation(NativeProbeType::kExceptionObservation, 0, 0, frame_id,
                                            tail);
}

int NativeDebuggerWatch::DomSlot(const std::int32_t node_id, const std::uint8_t kind) noexcept {
  if (!Armed(kNativeWatchDom) || node_id <= 0 ||
      base::PlatformThread::CurrentId().raw() != g_watch_thread.load(std::memory_order_relaxed)) {
    return -1;
  }
  for (std::size_t i = 0; i < g_watch.rules.dom_count; ++i) {
    const NativeWatchDomNode& node = g_watch.rules.dom[i];
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
  if (!Wants(frame_id, kNativeWatchDom) || slot < 0 ||
      static_cast<std::size_t>(slot) >= g_watch.rules.dom_count ||
      DomSlot(g_watch.rules.dom[static_cast<std::size_t>(slot)].node_id, kind) != slot) {
    return;
  }
  const bool ascii = std::all_of(attribute.begin(), attribute.end(),
                                 [](const char c) { return c > 0x20 && c < 0x7f; });
  if ((kind == kNativeWatchAttribute && (attribute.empty() || !ascii)) || !Charge()) {
    return;
  }
  std::array<std::uint8_t, 48> tail = Tail();
  tail[0] = kind;
  tail[1] = static_cast<std::uint8_t>(slot);
  std::memcpy(tail.data() + 2, &node_type, sizeof(node_type));
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
