#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iostream>
#include <span>
#include <string>
#include <type_traits>

#include "components/reverse_engineering_browser/common/native_js_dispatch.h"
#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "reb/event.hpp"
#include "reb/js_dispatch.hpp"

namespace {

int failures = 0;

void Check(const bool condition, const char* const message) {
  if (!condition) {
    std::cerr << "FAIL " << message << '\n';
    ++failures;
  }
}

// The renderer encoder (overlay) and the core decoder each own a copy of the
// version-1 layout. Set one field at a time to a distinct value and require
// identical bytes and identical cross-decoding, so the copies cannot drift.
template <class OverlayField, class CoreField, class Value>
void CheckField(OverlayField reb::NativeJsDispatchObservationPayload::*overlay_field,
                CoreField reb::JsDispatchObservationPayload::*core_field,
                Value value,
                const char* name) {
  reb::NativeJsDispatchObservationPayload overlay;
  reb::JsDispatchObservationPayload core;
  overlay.*overlay_field = static_cast<OverlayField>(value);
  core.*core_field = static_cast<CoreField>(value);
  const auto overlay_bytes = reb::EncodeNativeJsDispatchObservationPayload(overlay);
  const auto core_bytes = reb::EncodeJsDispatchObservationPayload(core);
  reb::JsDispatchObservationPayload decoded_core;
  reb::NativeJsDispatchObservationPayload decoded_overlay;
  Check(reb::DecodeJsDispatchObservationPayload(overlay_bytes, decoded_core), name);
  Check(reb::DecodeNativeJsDispatchObservationPayload(core_bytes, decoded_overlay), name);
  Check(decoded_core.*core_field == static_cast<CoreField>(value) &&
            decoded_overlay.*overlay_field == static_cast<OverlayField>(value),
        name);
  Check(std::equal(
            overlay_bytes.begin(), overlay_bytes.end(), core_bytes.begin(), core_bytes.end(),
            [](auto a, auto b) { return static_cast<unsigned>(a) == static_cast<unsigned>(b); }),
        name);
}

void CheckWireParity() {
  using O = reb::NativeJsDispatchObservationPayload;
  using C = reb::JsDispatchObservationPayload;
  static_assert(static_cast<std::uint16_t>(reb::EventType::kJsDispatchObservation) ==
                static_cast<std::uint16_t>(reb::NativeProbeType::kJsDispatchObservation));
  static_assert(sizeof(O) == sizeof(C));
  CheckField(&O::protocol_version, &C::protocol_version, 0x0102, "protocol_version");
  CheckField(&O::payload_size, &C::payload_size, 0x0304, "payload_size");
  CheckField(&O::shape, &C::shape, 0x05, "shape");
  CheckField(&O::selector_kind, &C::selector_kind, 0x06, "selector_kind");
  CheckField(&O::site_slot, &C::site_slot, 0x07, "site_slot");
  CheckField(&O::flags, &C::flags, 0x08, "flags");
  CheckField(&O::script_id, &C::script_id, 0x090a0b0cU, "script_id");
  CheckField(&O::anchor_offset, &C::anchor_offset, 0x0d0e0f10U, "anchor_offset");
  CheckField(&O::source_length, &C::source_length, 0x11121314U, "source_length");
  CheckField(&O::selector_low32, &C::selector_low32, 0xfffffffeU, "selector_low32");
  CheckField(&O::handler_script_id, &C::handler_script_id, 0x15161718U, "handler_script_id");
  CheckField(&O::handler_start, &C::handler_start, 0x191a1b1cU, "handler_start");
  CheckField(&O::handler_end, &C::handler_end, 0x1d1e1f20U, "handler_end");
  CheckField(&O::activation_id, &C::activation_id, 0x21222324U, "activation_id");
  CheckField(&O::parent_activation_id, &C::parent_activation_id, 0x25262728U,
             "parent_activation_id");
  CheckField(&O::site_sample_index, &C::site_sample_index, 0x292a, "site_sample_index");
  CheckField(&O::sample_index, &C::sample_index, 0x2b2c, "sample_index");
  for (std::size_t i = 0; i < 32; ++i) {
    O overlay;
    C core;
    overlay.source_sha256[i] =
        static_cast<std::remove_cvref_t<decltype(overlay.source_sha256[i])>>(0xa0 + i);
    core.source_sha256[i] = static_cast<std::byte>(0xa0 + i);
    const auto a = reb::EncodeNativeJsDispatchObservationPayload(overlay);
    const auto b = reb::EncodeJsDispatchObservationPayload(core);
    Check(static_cast<unsigned>(a[48 + i]) == 0xa0 + i &&
              static_cast<unsigned>(b[48 + i]) == 0xa0 + i,
          "source_sha256 offset");
  }
}

reb::EventRecord Valid() {
  reb::EventRecord event{};
  event.header.category = reb::EventCategory::kVm;
  event.header.type = reb::EventType::kJsDispatchObservation;
  event.header.payload_size = 128;
  event.header.session_id = 1;
  event.header.sequence_number = 2;
  event.header.monotonic_time_ns = 3;
  event.header.process_id = 4;
  event.header.thread_id = 5;
  event.header.frame_id = 6;
  event.header.tab_id = 7;
  reb::JsDispatchObservationPayload p;
  p.shape = static_cast<std::uint8_t>(reb::JsDispatchShape::kIndexedCall);
  p.selector_kind = static_cast<std::uint8_t>(reb::JsDispatchSelectorKind::kInteger);
  p.site_slot = 7;
  p.flags = reb::kJsDispatchNewActivation | reb::kJsDispatchHandlerSpan;
  p.script_id = 9;
  p.anchor_offset = 99;
  p.source_length = 100;
  p.selector_low32 = 0xffffffffU;
  p.handler_script_id = 9;
  p.handler_start = 10;
  p.handler_end = 11;
  p.activation_id = 5;
  p.parent_activation_id = 4;
  p.site_sample_index = 63;
  p.sample_index = 255;
  p.source_sha256.fill(std::byte{0x5a});
  event.inline_payload = reb::EncodeJsDispatchObservationPayload(p);
  return event;
}

reb::JsDispatchObservationPayload Payload(const reb::EventRecord& event) {
  reb::JsDispatchObservationPayload p;
  static_cast<void>(reb::DecodeJsDispatchObservationPayload(event.inline_payload, p));
  return p;
}

void Expect(const char* name, const std::function<void(reb::EventRecord&)>& mutate, bool valid) {
  auto event = Valid();
  mutate(event);
  Check(reb::IsValidJsDispatchObservation(event) == valid, name);
  Check(reb::IsValidEvent(event) == valid, name);
}

void ExpectPayload(const char* name,
                   const std::function<void(reb::JsDispatchObservationPayload&)>& mutate,
                   bool valid) {
  Expect(
      name,
      [&](reb::EventRecord& event) {
        auto p = Payload(event);
        mutate(p);
        event.inline_payload = reb::EncodeJsDispatchObservationPayload(p);
      },
      valid);
}

void CheckValidation() {
  using P = reb::JsDispatchObservationPayload;
  using K = reb::JsDispatchSelectorKind;
  Expect("baseline", [](reb::EventRecord&) {}, true);
  // Envelope rules.
  Expect("envelope version", [](auto& e) { e.header.protocol_version = 2; }, false);
  Expect("category", [](auto& e) { e.header.category = reb::EventCategory::kWasm; }, false);
  Expect("truncated", [](auto& e) { e.header.payload_size = 127; }, false);
  Expect("envelope flags", [](auto& e) { e.header.flags = 1; }, false);
  Expect("session", [](auto& e) { e.header.session_id = 0; }, false);
  Expect("sequence", [](auto& e) { e.header.sequence_number = 0; }, false);
  Expect("time", [](auto& e) { e.header.monotonic_time_ns = 0; }, false);
  Expect("process", [](auto& e) { e.header.process_id = 0; }, false);
  Expect("thread", [](auto& e) { e.header.thread_id = 0; }, false);
  Expect("frame", [](auto& e) { e.header.frame_id = 0; }, false);
  Expect("artifact", [](auto& e) { e.header.artifact_id = 1; }, false);
  Expect("parent event", [](auto& e) { e.header.parent_event_id = 1; }, false);
  Expect("navigation", [](auto& e) { e.header.navigation_id = 1; }, false);
  Expect("request", [](auto& e) { e.header.request_id = 1; }, false);
  Expect("tab zero", [](auto& e) { e.header.tab_id = 0; }, true);
  // Payload rules.
  ExpectPayload("reserved", [](P& p) { p.reserved[47] = std::byte{1}; }, false);
  ExpectPayload("version", [](P& p) { p.protocol_version = 2; }, false);
  ExpectPayload("size", [](P& p) { p.payload_size = 127; }, false);
  ExpectPayload("shape zero", [](P& p) { p.shape = 0; }, false);
  ExpectPayload("shape", [](P& p) { p.shape = 3; }, false);
  ExpectPayload("kind zero", [](P& p) { p.selector_kind = 0; }, false);
  ExpectPayload("kind", [](P& p) { p.selector_kind = 10; }, false);
  ExpectPayload("slot", [](P& p) { p.site_slot = 8; }, false);
  for (unsigned bit = 4; bit < 8; ++bit)
    ExpectPayload("flags", [bit](P& p) { p.flags |= static_cast<std::uint8_t>(1U << bit); }, false);
  ExpectPayload("script", [](P& p) { p.script_id = 0; }, false);
  ExpectPayload("source length", [](P& p) { p.source_length = 0; }, false);
  ExpectPayload("anchor", [](P& p) { p.anchor_offset = p.source_length; }, false);
  ExpectPayload("activation", [](P& p) { p.activation_id = 0; }, false);
  ExpectPayload("parent order", [](P& p) { p.parent_activation_id = p.activation_id; }, false);
  ExpectPayload("parent none", [](P& p) { p.parent_activation_id = 0; }, true);
  ExpectPayload(
      "parent with unknown", [](P& p) { p.flags |= reb::kJsDispatchParentUnknown; }, false);
  ExpectPayload(
      "parent with truncated", [](P& p) { p.flags |= reb::kJsDispatchParentSearchTruncated; },
      false);
  ExpectPayload(
      "unknown without parent",
      [](P& p) {
        p.parent_activation_id = 0;
        p.flags |= reb::kJsDispatchParentUnknown;
      },
      true);
  ExpectPayload(
      "truncated without parent",
      [](P& p) {
        p.parent_activation_id = 0;
        p.flags |= reb::kJsDispatchParentSearchTruncated;
      },
      true);
  ExpectPayload("site sample", [](P& p) { p.site_sample_index = 64; }, false);
  ExpectPayload("sample", [](P& p) { p.sample_index = 256; }, false);
  // Handler span consistency.
  ExpectPayload(
      "handler without flag",
      [](P& p) { p.flags = static_cast<std::uint8_t>(p.flags & ~reb::kJsDispatchHandlerSpan); },
      false);
  ExpectPayload(
      "no handler",
      [](P& p) {
        p.flags = static_cast<std::uint8_t>(p.flags & ~reb::kJsDispatchHandlerSpan);
        p.handler_script_id = p.handler_start = p.handler_end = 0;
      },
      true);
  ExpectPayload(
      "handler end only",
      [](P& p) {
        p.flags = static_cast<std::uint8_t>(p.flags & ~reb::kJsDispatchHandlerSpan);
        p.handler_script_id = p.handler_start = 0;
      },
      false);
  ExpectPayload("handler script", [](P& p) { p.handler_script_id = 0; }, false);
  ExpectPayload("handler order", [](P& p) { p.handler_end = p.handler_start; }, false);
  ExpectPayload(
      "switch handler",
      [](P& p) { p.shape = static_cast<std::uint8_t>(reb::JsDispatchShape::kSwitch); }, false);
  ExpectPayload(
      "switch without handler",
      [](P& p) {
        p.shape = static_cast<std::uint8_t>(reb::JsDispatchShape::kSwitch);
        p.flags = static_cast<std::uint8_t>(p.flags & ~reb::kJsDispatchHandlerSpan);
        p.handler_script_id = p.handler_start = p.handler_end = 0;
      },
      true);
  // Selector bits copy only what the kind permits.
  for (std::uint8_t kind = 2; kind <= 9; ++kind) {
    if (kind == static_cast<std::uint8_t>(K::kBoolean))
      continue;
    ExpectPayload(
        "non-integer bits",
        [kind](P& p) {
          p.selector_kind = kind;
          p.selector_low32 = 1;
        },
        false);
    ExpectPayload(
        "non-integer zero",
        [kind](P& p) {
          p.selector_kind = kind;
          p.selector_low32 = 0;
        },
        true);
  }
  ExpectPayload(
      "boolean one",
      [](P& p) {
        p.selector_kind = static_cast<std::uint8_t>(K::kBoolean);
        p.selector_low32 = 1;
      },
      true);
  ExpectPayload(
      "boolean two",
      [](P& p) {
        p.selector_kind = static_cast<std::uint8_t>(K::kBoolean);
        p.selector_low32 = 2;
      },
      false);
  // Decoding requires the exact size; the encoding is explicitly little-endian.
  const auto event = Valid();
  reb::JsDispatchObservationPayload decoded;
  for (std::size_t size : {std::size_t{0}, std::size_t{48}, std::size_t{127}})
    Check(!reb::DecodeJsDispatchObservationPayload(std::span(event.inline_payload).first(size),
                                                   decoded),
          "truncated decode");
  Check(event.inline_payload[0] == std::byte{1} && event.inline_payload[1] == std::byte{0} &&
            event.inline_payload[2] == std::byte{128} && event.inline_payload[3] == std::byte{0} &&
            event.inline_payload[20] == std::byte{0xff} &&
            event.inline_payload[46] == std::byte{0xff} && event.inline_payload[47] == std::byte{0},
        "little-endian layout");
  Check(reb::EventTypeName(reb::EventType::kJsDispatchObservation) == "js_dispatch_observation",
        "event type name");
  const auto json = reb::EventToJson(event);
  Check(json.find("\"type\":\"js_dispatch_observation\"") != std::string::npos &&
            json.find("\"category\":\"vm\"") != std::string::npos,
        "core JSON names the type");
}

}  // namespace

int main() {
  CheckWireParity();
  CheckValidation();
  if (failures != 0)
    return 1;
  std::puts("PASS native JavaScript dispatch wire: overlay/core parity and every validation rule");
  return 0;
}
