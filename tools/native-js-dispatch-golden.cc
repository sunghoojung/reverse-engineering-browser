// Emits native JavaScript dispatch observations through the renderer (overlay)
// encoder and the production core JSON writer, for cross-language checks.
// Authored test observations, not evidence of a running Brave/V8 build.
//
// Every valid case names the owned fixture
// tools/fixtures/native-js-dispatch/two-level-vm.js as V8 compiles it:
//   source_sha256 (UTF-16LE) 9c282690be91c5c360c60bf9f43d7992bdf29f2cef7f1d1debff2a54fa75d8e1
//   source_length 1392 UTF-16 code units (1395 UTF-8 bytes)
//   slot 0: outer `switch` keyword, anchor 1047 (UTF-8 byte 1050)
//   slot 1: inner `ops[` bracket, anchor 698 (UTF-8 byte 701)
//   slot 2: extended `ext[` bracket, anchor 1236 (UTF-8 byte 1239)
// Handler spans are V8 SharedFunctionInfo positions: the parameter `(` to
// just after the closing `}`: ops[1] 516..537, ops[3] 588..612, ext[3] 961..990.
#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <type_traits>

#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_js_dispatch.h"
#include "reb/event.hpp"
#include "reb/js_dispatch.hpp"

namespace {

constexpr std::array<std::uint8_t, 32> kFixtureSourceSha256{
    0x9c, 0x28, 0x26, 0x90, 0xbe, 0x91, 0xc5, 0xc3, 0x60, 0xc6, 0x0b, 0xf9, 0xf4, 0x3d, 0x79, 0x92,
    0xbd, 0xf2, 0x9f, 0x2c, 0xef, 0x7f, 0x1d, 0x1d, 0xeb, 0xff, 0x2a, 0x54, 0xfa, 0x75, 0xd8, 0xe1};
constexpr std::uint32_t kFixtureSourceLength = 1392;
constexpr std::uint32_t kSwitchAnchor = 1047;
constexpr std::uint32_t kInnerAnchor = 698;
constexpr std::uint32_t kExtendedAnchor = 1236;
constexpr std::uint32_t kScriptId = 9;

using Shape = reb::JsDispatchShape;
using Kind = reb::JsDispatchSelectorKind;

// Every core field, so the overlay copy is checked field by field below.
reb::NativeJsDispatchObservationPayload ToOverlay(const reb::JsDispatchObservationPayload& v) {
  reb::NativeJsDispatchObservationPayload o;
  o.protocol_version = v.protocol_version;
  o.payload_size = v.payload_size;
  o.shape = v.shape;
  o.selector_kind = v.selector_kind;
  o.site_slot = v.site_slot;
  o.flags = v.flags;
  o.script_id = v.script_id;
  o.anchor_offset = v.anchor_offset;
  o.source_length = v.source_length;
  o.selector_low32 = v.selector_low32;
  o.handler_script_id = v.handler_script_id;
  o.handler_start = v.handler_start;
  o.handler_end = v.handler_end;
  o.activation_id = v.activation_id;
  o.parent_activation_id = v.parent_activation_id;
  o.site_sample_index = v.site_sample_index;
  o.sample_index = v.sample_index;
  for (std::size_t i = 0; i < 32; ++i)
    o.source_sha256[i] =
        static_cast<std::remove_cvref_t<decltype(o.source_sha256[i])>>(v.source_sha256[i]);
  for (std::size_t i = 0; i < 48; ++i)
    o.reserved[i] = static_cast<std::remove_cvref_t<decltype(o.reserved[i])>>(v.reserved[i]);
  return o;
}

reb::JsDispatchObservationPayload Switch(std::uint32_t selector) {
  reb::JsDispatchObservationPayload p;
  p.shape = static_cast<std::uint8_t>(Shape::kSwitch);
  p.selector_kind = static_cast<std::uint8_t>(Kind::kInteger);
  p.site_slot = 0;
  p.script_id = kScriptId;
  p.anchor_offset = kSwitchAnchor;
  p.source_length = kFixtureSourceLength;
  p.selector_low32 = selector;
  p.activation_id = 1;
  for (std::size_t i = 0; i < 32; ++i)
    p.source_sha256[i] = static_cast<std::byte>(kFixtureSourceSha256[i]);
  return p;
}

reb::JsDispatchObservationPayload Indexed(std::uint8_t slot,
                                          std::uint32_t anchor,
                                          std::uint32_t selector,
                                          std::uint32_t handler_start,
                                          std::uint32_t handler_end) {
  auto p = Switch(selector);
  p.shape = static_cast<std::uint8_t>(Shape::kIndexedCall);
  p.site_slot = slot;
  p.anchor_offset = anchor;
  p.flags = reb::kJsDispatchHandlerSpan;
  p.handler_script_id = kScriptId;
  p.handler_start = handler_start;
  p.handler_end = handler_end;
  return p;
}

}  // namespace

int main(int argc, char** argv) {
  std::string_view mode = "default";
  if (argc == 3 && std::string_view(argv[1]) == "--case")
    mode = argv[2];
  else if (argc != 1)
    return 2;
  reb::NativeProbeEvent native;
  native.header.category = reb::NativeProbeCategory::kVm;
  native.header.type = reb::NativeProbeType::kJsDispatchObservation;
  native.header.payload_size = 128;
  native.header.session_id = 101;
  native.header.frame_id = 103;
  native.header.process_id = 3;
  native.header.thread_id = 4;
  native.header.sequence_number = 201;
  native.header.monotonic_time_ns = 55;

  auto payload = Switch(7);
  payload.flags = reb::kJsDispatchNewActivation;
  const auto indexed = [] {
    auto p = Indexed(2, kExtendedAnchor, 3, 961, 990);
    p.site_sample_index = 1;
    p.sample_index = 1;
    return p;
  };
  const auto nested = [] {
    auto p = Indexed(1, kInnerAnchor, 1, 516, 537);
    p.flags |= reb::kJsDispatchNewActivation;
    p.activation_id = 2;
    p.parent_activation_id = 1;
    p.sample_index = 2;
    return p;
  };
  const auto string_selector = [] {
    auto p = Switch(0);
    p.selector_kind = static_cast<std::uint8_t>(Kind::kString);
    p.site_sample_index = 1;
    p.sample_index = 3;
    return p;
  };
  bool valid = true;
  if (mode == "default") {
  } else if (mode == "indexed") {
    payload = indexed();
    native.header.sequence_number = 202;
    native.header.monotonic_time_ns = 56;
  } else if (mode == "nested") {
    payload = nested();
    native.header.sequence_number = 203;
    native.header.monotonic_time_ns = 57;
  } else if (mode == "string-selector") {
    payload = string_selector();
    native.header.sequence_number = 204;
    native.header.monotonic_time_ns = 58;
  } else if (mode == "parent-unknown") {
    payload = Indexed(1, kInnerAnchor, 3, 588, 612);
    payload.flags |= reb::kJsDispatchNewActivation | reb::kJsDispatchParentUnknown;
    payload.activation_id = 3;
    payload.site_sample_index = 1;
    payload.sample_index = 4;
    native.header.sequence_number = 205;
    native.header.monotonic_time_ns = 59;
  } else if (mode == "wide-identities") {
    native.header.session_id = native.header.sequence_number = native.header.monotonic_time_ns =
        native.header.frame_id = std::numeric_limits<std::uint64_t>::max();
    native.header.process_id = native.header.thread_id = native.header.tab_id =
        std::numeric_limits<std::uint32_t>::max();
  } else {
    valid = false;
    if (mode == "reserved")
      payload.reserved[0] = std::byte{1};
    else if (mode == "version")
      payload.protocol_version = 2;
    else if (mode == "size")
      payload.payload_size = 127;
    else if (mode == "truncated")
      native.header.payload_size = 127;
    else if (mode == "shape")
      payload.shape = 3;
    else if (mode == "kind")
      payload.selector_kind = 10;
    else if (mode == "slot")
      payload.site_slot = reb::kJsDispatchSiteLimit;
    else if (mode == "flags")
      payload.flags |= 1U << 4U;
    else if (mode == "parent-order") {
      payload = nested();
      payload.parent_activation_id = payload.activation_id;
    } else if (mode == "handler-without-flag") {
      payload = indexed();
      payload.flags = 0;
    } else if (mode == "switch-handler") {
      payload.flags |= reb::kJsDispatchHandlerSpan;
      payload.handler_script_id = kScriptId;
      payload.handler_start = 961;
      payload.handler_end = 990;
    } else if (mode == "non-integer-bits") {
      payload = string_selector();
      payload.selector_low32 = 1;
    } else if (mode == "sample-index")
      payload.sample_index = reb::kJsDispatchSampleBudget;
    else if (mode == "site-sample-index")
      payload.site_sample_index = reb::kJsDispatchSiteSampleBudget;
    else if (mode == "anchor")
      payload.anchor_offset = payload.source_length;
    // Further rules beyond the shared case list.
    else if (mode == "boolean-bits") {
      payload.selector_kind = static_cast<std::uint8_t>(Kind::kBoolean);
      payload.selector_low32 = 2;
    } else if (mode == "activation")
      payload.activation_id = 0;
    else if (mode == "script")
      payload.script_id = 0;
    else if (mode == "source-length")
      payload.source_length = 0;
    else if (mode == "parent-flags") {
      payload = nested();
      payload.flags |= reb::kJsDispatchParentSearchTruncated;
    } else if (mode == "handler-order") {
      payload = indexed();
      payload.handler_end = payload.handler_start;
    } else if (mode == "handler-script") {
      payload = indexed();
      payload.handler_script_id = 0;
    } else if (mode == "envelope-version")
      native.header.protocol_version = 2;
    else if (mode == "envelope-flags")
      native.header.flags = 1;
    else if (mode == "identity")
      native.header.frame_id = 0;
    else if (mode == "artifact")
      native.header.artifact_id = 9;
    else if (mode == "parent-event")
      native.header.parent_event_id = 9;
    else if (mode == "navigation")
      native.header.navigation_id = 9;
    else if (mode == "request")
      native.header.request_id = 9;
    else if (mode == "big-endian") {
    } else
      return 2;
  }
  native.inline_payload = reb::EncodeNativeJsDispatchObservationPayload(ToOverlay(payload));
  // The overlay renderer encoder and the core encoder must agree byte for byte.
  assert(native.inline_payload == reb::EncodeJsDispatchObservationPayload(payload));
  if (mode == "big-endian") {
    native.inline_payload[0] = std::byte{0};
    native.inline_payload[1] = std::byte{1};
  }
  static_assert(sizeof(reb::NativeProbeEvent) == sizeof(reb::EventRecord));
  static_assert(static_cast<std::uint16_t>(reb::NativeProbeType::kJsDispatchObservation) ==
                static_cast<std::uint16_t>(reb::EventType::kJsDispatchObservation));
  const auto event = std::bit_cast<reb::EventRecord>(native);
  assert(reb::IsValidEvent(event) == valid);
  reb::JsDispatchObservationPayload decoded;
  if (event.header.payload_size == 128) {
    assert(reb::DecodeJsDispatchObservationPayload(event.inline_payload, decoded));
    assert(reb::EncodeJsDispatchObservationPayload(decoded) == native.inline_payload);
  }
  std::cout << reb::EventToJson(event) << '\n';
}
