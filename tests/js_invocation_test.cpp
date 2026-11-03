#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string_view>

#include "components/reverse_engineering_browser/common/native_js_invocation.h"
#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "components/reverse_engineering_browser/common/native_wasm_dispatch.h"
#include "reb/event.hpp"
#include "reb/js_invocation.hpp"
#include "reb/wasm_dispatch.hpp"

namespace {

int failures = 0;

void Check(const bool condition, const char* const message) {
  if (!condition) {
    std::cerr << "FAIL " << message << '\n';
    ++failures;
  }
}

template <std::size_t N>
bool SameBytes(const std::array<std::byte, N>& a, const std::array<std::byte, N>& b) {
  return std::equal(a.begin(), a.end(), b.begin());
}

// The renderer encoder (overlay) and the core decoder each own a copy of every
// layout. Set one field at a time to a distinct value and require identical
// bytes, so the copies cannot drift.
template <class Overlay, class Core, class OverlayField, class CoreField, class Encode, class
          CoreEncode>
void CheckField(OverlayField Overlay::*overlay_field,
                CoreField Core::*core_field,
                std::uint64_t value,
                Encode encode,
                CoreEncode core_encode,
                const char* name) {
  Overlay overlay;
  Core core;
  overlay.*overlay_field = static_cast<OverlayField>(value);
  core.*core_field = static_cast<CoreField>(value);
  Check(SameBytes(encode(overlay), core_encode(core)), name);
}

void CheckWireParity() {
  static_assert(static_cast<std::uint16_t>(reb::EventType::kJsInvocationStart) ==
                static_cast<std::uint16_t>(reb::NativeProbeType::kJsInvocationStart));
  static_assert(static_cast<std::uint16_t>(reb::EventType::kJsInvocationSettle) ==
                static_cast<std::uint16_t>(reb::NativeProbeType::kJsInvocationSettle));
  static_assert(static_cast<std::uint16_t>(reb::EventType::kJsInvocationRequest) ==
                static_cast<std::uint16_t>(reb::NativeProbeType::kJsInvocationRequest));
  using OS = reb::NativeJsInvocationStartPayload;
  using CS = reb::JsInvocationStartPayload;
  const auto os = [](const OS& v) { return reb::EncodeNativeJsInvocationStartPayload(v); };
  const auto cs = [](const CS& v) { return reb::EncodeJsInvocationStartPayload(v); };
  CheckField(&OS::protocol_version, &CS::protocol_version, 0x0102, os, cs, "start version");
  CheckField(&OS::payload_size, &CS::payload_size, 0x0304, os, cs, "start size");
  CheckField(&OS::site_slot, &CS::site_slot, 0x05, os, cs, "start slot");
  CheckField(&OS::flags, &CS::flags, 0x06, os, cs, "start flags");
  CheckField(&OS::argument_count, &CS::argument_count, 0x0708, os, cs, "argument_count");
  CheckField(&OS::script_id, &CS::script_id, 0x090a0b0c, os, cs, "script_id");
  CheckField(&OS::anchor_offset, &CS::anchor_offset, 0x0d0e0f10, os, cs, "anchor_offset");
  CheckField(&OS::source_length, &CS::source_length, 0x11121314, os, cs, "source_length");
  CheckField(&OS::invocation_id, &CS::invocation_id, 0x15161718, os, cs, "invocation_id");
  CheckField(&OS::parent_invocation_id, &CS::parent_invocation_id, 0x191a1b1c, os, cs, "parent");
  CheckField(&OS::site_sample_index, &CS::site_sample_index, 0x1d1e, os, cs, "site sample");
  CheckField(&OS::sample_index, &CS::sample_index, 0x1f20, os, cs, "sample");
  CheckField(&OS::document_id, &CS::document_id, 0x2122232425262728, os, cs, "document_id");
  for (std::size_t i = 0; i < reb::kJsInvocationArgumentLimit; ++i) {
    OS overlay;
    CS core;
    overlay.argument_kinds[i] = core.argument_kinds[i] = static_cast<std::uint8_t>(0x30 + i);
    overlay.argument_low32[i] = core.argument_low32[i] = 0x40414243U + static_cast<unsigned>(i);
    const auto bytes = reb::EncodeJsInvocationStartPayload(core);
    Check(SameBytes(reb::EncodeNativeJsInvocationStartPayload(overlay), bytes), "argument parity");
    Check(bytes[32 + i] == static_cast<std::byte>(0x30 + i) &&
              bytes[40 + 4 * i] == static_cast<std::byte>(0x43 + i),
          "argument offsets");
  }
  for (std::size_t i = 0; i < 32; ++i) {
    OS overlay;
    CS core;
    overlay.source_sha256[i] = static_cast<std::uint8_t>(0xa0 + i);
    core.source_sha256[i] = static_cast<std::byte>(0xa0 + i);
    Check(SameBytes(reb::EncodeNativeJsInvocationStartPayload(overlay),
                    reb::EncodeJsInvocationStartPayload(core)) &&
              reb::EncodeJsInvocationStartPayload(core)[72 + i] == static_cast<std::byte>(0xa0 + i),
          "source_sha256 offset");
  }

  using OT = reb::NativeJsInvocationSettlePayload;
  using CT = reb::JsInvocationSettlePayload;
  const auto ot = [](const OT& v) { return reb::EncodeNativeJsInvocationSettlePayload(v); };
  const auto ct = [](const CT& v) { return reb::EncodeJsInvocationSettlePayload(v); };
  CheckField(&OT::site_slot, &CT::site_slot, 0x05, ot, ct, "settle slot");
  CheckField(&OT::outcome, &CT::outcome, 0x06, ot, ct, "outcome");
  CheckField(&OT::via, &CT::via, 0x07, ot, ct, "via");
  CheckField(&OT::value_kind, &CT::value_kind, 0x08, ot, ct, "value_kind");
  CheckField(&OT::invocation_id, &CT::invocation_id, 0x090a0b0c, ot, ct, "settle invocation");
  CheckField(&OT::value_length, &CT::value_length, 0x0d0e0f10, ot, ct, "value_length");
  CheckField(&OT::digest_state, &CT::digest_state, 0x11, ot, ct, "digest_state");
  CheckField(&OT::digest_encoding, &CT::digest_encoding, 0x12, ot, ct, "digest_encoding");
  CheckField(&OT::flags, &CT::flags, 0x13, ot, ct, "settle flags");
  CheckField(&OT::reserved0, &CT::reserved0, 0x14, ot, ct, "settle reserved0");
  CheckField(&OT::digest_byte_length, &CT::digest_byte_length, 0x15161718, ot, ct, "bytes");
  CheckField(&OT::rolling_hash, &CT::rolling_hash, 0x191a1b1c1d1e1f20, ot, ct, "rolling");
  CheckField(&OT::document_id, &CT::document_id, 0x2122232425262728, ot, ct, "settle document");
  for (std::size_t i = 0; i < 32; ++i) {
    OT overlay;
    CT core;
    overlay.value_sha256[i] = static_cast<std::uint8_t>(0xb0 + i);
    core.value_sha256[i] = static_cast<std::byte>(0xb0 + i);
    Check(SameBytes(reb::EncodeNativeJsInvocationSettlePayload(overlay),
                    reb::EncodeJsInvocationSettlePayload(core)) &&
              reb::EncodeJsInvocationSettlePayload(core)[32 + i] == static_cast<std::byte>(0xb0 + i),
          "value_sha256 offset");
  }

  using OR = reb::NativeJsInvocationRequestPayload;
  using CR = reb::JsInvocationRequestPayload;
  const auto orq = [](const OR& v) { return reb::EncodeNativeJsInvocationRequestPayload(v); };
  const auto crq = [](const CR& v) { return reb::EncodeJsInvocationRequestPayload(v); };
  CheckField(&OR::state, &CR::state, 0x05, orq, crq, "request state");
  CheckField(&OR::invocation_id, &CR::invocation_id, 0x090a0b0c, orq, crq, "request invocation");
  CheckField(&OR::sample_index, &CR::sample_index, 0x0d0e, orq, crq, "request sample");
  CheckField(&OR::reserved1, &CR::reserved1, 0x0f10, orq, crq, "request reserved1");

  // Wasm consumers: the overlay and core version-2 layouts agree too.
  using OW = reb::NativeWasmDispatchObservationPayload;
  using CW = reb::WasmDispatchObservationPayload;
  const auto ow = [](const OW& v) { return reb::EncodeNativeWasmDispatchObservationPayload(v); };
  const auto cw = [](const CW& v) { return reb::EncodeWasmDispatchObservationPayload(v); };
  CheckField(&OW::js_invocation_state, &CW::js_invocation_state, 0x31, ow, cw, "br_table state");
  CheckField(&OW::js_invocation_id, &CW::js_invocation_id, 0x32333435, ow, cw, "br_table id");
  using OI = reb::NativeWasmIndirectObservationPayload;
  using CI = reb::WasmIndirectObservationPayload;
  const auto oi = [](const OI& v) { return reb::EncodeNativeWasmIndirectObservationPayload(v); };
  const auto ci = [](const CI& v) { return reb::EncodeWasmIndirectObservationPayload(v); };
  CheckField(&OI::js_invocation_state, &CI::js_invocation_state, 0x41, oi, ci, "indirect state");
  CheckField(&OI::js_invocation_id, &CI::js_invocation_id, 0x42434445, oi, ci, "indirect id");
}

reb::EventRecord Envelope(reb::EventType type) {
  reb::EventRecord event{};
  event.header.category = reb::EventCategory::kVm;
  event.header.type = type;
  event.header.payload_size = 128;
  event.header.session_id = 1;
  event.header.sequence_number = 2;
  event.header.monotonic_time_ns = 3;
  event.header.process_id = 4;
  event.header.thread_id = 5;
  event.header.frame_id = 6;
  event.header.tab_id = 7;
  return event;
}

reb::JsInvocationStartPayload StartPayload() {
  reb::JsInvocationStartPayload p;
  p.site_slot = 1;
  p.argument_count = 2;
  p.script_id = 17;
  p.anchor_offset = 41;
  p.source_length = 900;
  p.invocation_id = 5;
  p.argument_kinds[0] = static_cast<std::uint8_t>(reb::JsInvocationValueKind::kString);
  p.argument_kinds[1] = static_cast<std::uint8_t>(reb::JsInvocationValueKind::kObject);
  p.source_sha256[0] = std::byte{0x5a};
  p.document_id = 0x0102030405060708;
  return p;
}

reb::EventRecord Start(const reb::JsInvocationStartPayload& p) {
  auto event = Envelope(reb::EventType::kJsInvocationStart);
  event.inline_payload = reb::EncodeJsInvocationStartPayload(p);
  return event;
}

reb::JsInvocationSettlePayload SettlePayload() {
  reb::JsInvocationSettlePayload p;
  p.site_slot = 1;
  p.outcome = static_cast<std::uint8_t>(reb::JsInvocationOutcome::kFulfilled);
  p.via = static_cast<std::uint8_t>(reb::JsInvocationSettleVia::kPromise);
  p.value_kind = static_cast<std::uint8_t>(reb::JsInvocationValueKind::kString);
  p.invocation_id = 5;
  p.value_length = 5;
  p.digest_state = static_cast<std::uint8_t>(reb::JsInvocationDigestState::kPresent);
  p.digest_encoding = static_cast<std::uint8_t>(reb::JsInvocationDigestEncoding::kUtf8);
  p.digest_byte_length = 5;
  const std::array<std::byte, 5> token{std::byte{'t'}, std::byte{'o'}, std::byte{'k'},
                                       std::byte{'e'}, std::byte{'n'}};
  p.rolling_hash = reb::JsInvocationRollingHash(token);
  p.value_sha256[0] = std::byte{0x77};
  p.document_id = 0x0102030405060708;
  return p;
}

reb::EventRecord Settle(const reb::JsInvocationSettlePayload& p) {
  auto event = Envelope(reb::EventType::kJsInvocationSettle);
  event.inline_payload = reb::EncodeJsInvocationSettlePayload(p);
  return event;
}

reb::EventRecord Request(std::uint8_t state, std::uint32_t id) {
  auto event = Envelope(reb::EventType::kJsInvocationRequest);
  event.header.request_id = 31;
  reb::JsInvocationRequestPayload p;
  p.state = state;
  p.invocation_id = id;
  event.inline_payload = reb::EncodeJsInvocationRequestPayload(p);
  return event;
}

void CheckStartRules() {
  Check(reb::IsValidEvent(Start(StartPayload())), "valid start");
  Check(reb::EventTypeName(reb::EventType::kJsInvocationStart) == "js_invocation_start",
        "start name");
  const auto rejects = [](auto mutate, const char* name) {
    auto p = StartPayload();
    mutate(p);
    Check(!reb::IsValidEvent(Start(p)), name);
  };
  rejects([](auto& p) { p.protocol_version = 2; }, "unknown start version");
  rejects([](auto& p) { p.site_slot = 8; }, "slot beyond the site limit");
  rejects([](auto& p) { p.flags = 0x04; }, "unknown start flag");
  rejects([](auto& p) { p.script_id = 0; }, "zero script");
  rejects([](auto& p) { p.anchor_offset = p.source_length; }, "anchor past the source");
  rejects([](auto& p) { p.invocation_id = 0; }, "zero invocation");
  rejects([](auto& p) { p.parent_invocation_id = 5; }, "parent not earlier");
  rejects(
      [](auto& p) {
        p.parent_invocation_id = 2;
        p.flags = reb::kJsInvocationParentUnknown;
      },
      "known parent with the unknown flag");
  rejects([](auto& p) { p.argument_kinds[2] = 3; }, "a kind past the argument count");
  rejects([](auto& p) { p.argument_kinds[1] = 15; }, "unknown argument kind");
  rejects([](auto& p) { p.argument_low32[0] = 1; }, "low bits on a string");
  rejects([](auto& p) { p.argument_count = 9; }, "truncation without its flag");
  rejects([](auto& p) { p.flags = reb::kJsInvocationArgumentsTruncated; }, "flag without truncation");
  rejects([](auto& p) { p.document_id = 0; }, "zero document");
  rejects([](auto& p) { p.reserved[3] = std::byte{1}; }, "nonzero start reserved");
  rejects([](auto& p) { p.site_sample_index = 64; }, "site sample index past its budget");
  auto integer = StartPayload();
  integer.argument_count = 9;
  integer.flags = reb::kJsInvocationArgumentsTruncated;
  integer.argument_kinds[0] = static_cast<std::uint8_t>(reb::JsInvocationValueKind::kInteger);
  integer.argument_low32[0] = 0xffffffffU;
  for (std::size_t i = 1; i < reb::kJsInvocationArgumentLimit; ++i)
    integer.argument_kinds[i] = static_cast<std::uint8_t>(reb::JsInvocationValueKind::kUndefined);
  integer.parent_invocation_id = 4;
  Check(reb::IsValidEvent(Start(integer)), "integer low bits, truncation and a parent");
  auto envelope = Start(StartPayload());
  envelope.header.frame_id = 0;
  Check(!reb::IsValidEvent(envelope), "start without a frame");
  envelope = Start(StartPayload());
  envelope.header.navigation_id = 9;
  Check(!reb::IsValidEvent(envelope), "start never invents a navigation ID");
  envelope = Start(StartPayload());
  envelope.header.category = reb::EventCategory::kNetwork;
  Check(!reb::IsValidEvent(envelope), "start outside the vm category");
}

void CheckSettleRules() {
  Check(reb::IsValidEvent(Settle(SettlePayload())), "valid settle");
  const auto rejects = [](auto mutate, const char* name) {
    auto p = SettlePayload();
    mutate(p);
    Check(!reb::IsValidEvent(Settle(p)), name);
  };
  rejects([](auto& p) { p.outcome = 3; }, "unknown outcome");
  rejects([](auto& p) { p.via = 2; }, "fulfilled by a throw");
  rejects([](auto& p) { p.via = 4; }, "unknown via");
  rejects([](auto& p) { p.value_kind = 0; }, "unknown value kind");
  rejects([](auto& p) { p.digest_encoding = 2; }, "string digested as raw bytes");
  rejects([](auto& p) { p.digest_byte_length = 4; }, "UTF-8 shorter than the UTF-16 length");
  rejects([](auto& p) { p.digest_byte_length = (1U << 20U) + 1; }, "digest over its limit");
  rejects([](auto& p) { p.flags = 2; }, "unknown settle flag");
  rejects([](auto& p) { p.document_id = 0; }, "settle without a document");
  rejects([](auto& p) { p.reserved[0] = std::byte{1}; }, "nonzero settle reserved");
  rejects(
      [](auto& p) {
        p.digest_state = static_cast<std::uint8_t>(reb::JsInvocationDigestState::kNotRequested);
      },
      "digest bytes kept when none was requested");
  rejects(
      [](auto& p) {
        p.outcome = static_cast<std::uint8_t>(reb::JsInvocationOutcome::kRejected);
        p.via = static_cast<std::uint8_t>(reb::JsInvocationSettleVia::kSyncThrow);
      },
      "a rejection is never digested");
  // Without sensitive capture nothing content-derived remains.
  reb::JsInvocationSettlePayload plain = SettlePayload();
  plain.digest_state = 0;
  plain.digest_encoding = 0;
  plain.digest_byte_length = 0;
  plain.rolling_hash = 0;
  plain.value_sha256 = {};
  Check(reb::IsValidEvent(Settle(plain)), "settle without digests");
  auto thrown = plain;
  thrown.outcome = static_cast<std::uint8_t>(reb::JsInvocationOutcome::kRejected);
  thrown.via = static_cast<std::uint8_t>(reb::JsInvocationSettleVia::kSyncThrow);
  thrown.value_kind = static_cast<std::uint8_t>(reb::JsInvocationValueKind::kObject);
  thrown.value_length = 0;
  Check(reb::IsValidEvent(Settle(thrown)), "synchronous throw");
  thrown.digest_state = static_cast<std::uint8_t>(reb::JsInvocationDigestState::kNotDigestible);
  Check(reb::IsValidEvent(Settle(thrown)), "a rejection under digests is not digestible");
  auto bytes = SettlePayload();
  bytes.value_kind = static_cast<std::uint8_t>(reb::JsInvocationValueKind::kArrayBufferView);
  bytes.digest_encoding = static_cast<std::uint8_t>(reb::JsInvocationDigestEncoding::kBytes);
  Check(reb::IsValidEvent(Settle(bytes)), "typed array bytes");
  bytes.flags = reb::kJsInvocationLossyUtf8;
  Check(!reb::IsValidEvent(Settle(bytes)), "lossy flag on raw bytes");
  auto large = plain;
  large.digest_state = static_cast<std::uint8_t>(reb::JsInvocationDigestState::kTooLarge);
  Check(reb::IsValidEvent(Settle(large)), "string too large to digest");
  large.digest_state = static_cast<std::uint8_t>(reb::JsInvocationDigestState::kUnavailable);
  Check(!reb::IsValidEvent(Settle(large)), "a string is never unavailable");
  auto number = plain;
  number.value_kind = static_cast<std::uint8_t>(reb::JsInvocationValueKind::kNumber);
  Check(!reb::IsValidEvent(Settle(number)), "a number has no length");
  number.value_length = 0;
  number.digest_state = static_cast<std::uint8_t>(reb::JsInvocationDigestState::kNotDigestible);
  Check(reb::IsValidEvent(Settle(number)), "a number is not digestible");
}

void CheckRequestRules() {
  using State = reb::JsInvocationContextState;
  Check(reb::IsValidEvent(Request(static_cast<std::uint8_t>(State::kInside), 5)), "inside");
  Check(reb::IsValidEvent(Request(static_cast<std::uint8_t>(State::kUnknown), 0)), "unknown");
  Check(!reb::IsValidEvent(Request(static_cast<std::uint8_t>(State::kInside), 0)),
        "inside without an ID");
  Check(!reb::IsValidEvent(Request(static_cast<std::uint8_t>(State::kUnknown), 5)),
        "unknown with an ID");
  Check(!reb::IsValidEvent(Request(static_cast<std::uint8_t>(State::kNone), 0)),
        "a request outside any invocation is never recorded");
  auto event = Request(static_cast<std::uint8_t>(State::kInside), 5);
  event.header.request_id = 0;
  Check(!reb::IsValidEvent(event), "request without a renderer request ID");
  event = Request(static_cast<std::uint8_t>(State::kInside), 5);
  event.header.request_id = 0x100000000ULL;
  Check(!reb::IsValidEvent(event), "renderer request IDs are 32-bit");
  event = Request(static_cast<std::uint8_t>(State::kInside), 5);
  event.header.frame_id = 0;
  Check(reb::IsValidEvent(event), "a loader may not know its frame");
}

void CheckWasmVersions() {
  reb::EventRecord event{};
  event.header.category = reb::EventCategory::kVm;
  event.header.type = reb::EventType::kWasmDispatchObservation;
  event.header.payload_size = 128;
  event.header.session_id = 1;
  event.header.sequence_number = 2;
  event.header.monotonic_time_ns = 3;
  event.header.process_id = 4;
  event.header.thread_id = 5;
  event.header.frame_id = 6;
  event.header.artifact_id = 8;
  reb::WasmDispatchObservationPayload p;
  p.module_byte_offset = 12;
  p.protocol_version = 1;
  event.inline_payload = reb::EncodeWasmDispatchObservationPayload(p);
  Check(reb::IsValidEvent(event), "version 1 br_table stays readable");
  p.js_invocation_state = static_cast<std::uint8_t>(reb::JsInvocationContextState::kInside);
  p.js_invocation_id = 3;
  event.inline_payload = reb::EncodeWasmDispatchObservationPayload(p);
  Check(!reb::IsValidEvent(event), "version 1 reserved the context bytes");
  p.protocol_version = 2;
  event.inline_payload = reb::EncodeWasmDispatchObservationPayload(p);
  Check(reb::IsValidEvent(event), "version 2 inside an invocation");
  Check(event.inline_payload[24] == std::byte{2} && event.inline_payload[28] == std::byte{3},
        "br_table context offsets");
  p.js_invocation_id = 0;
  event.inline_payload = reb::EncodeWasmDispatchObservationPayload(p);
  Check(!reb::IsValidEvent(event), "inside without an ID");
  p.js_invocation_state = 4;
  event.inline_payload = reb::EncodeWasmDispatchObservationPayload(p);
  Check(!reb::IsValidEvent(event), "unknown context state");
  p.js_invocation_state = 0;
  p.js_invocation_reserved[1] = std::byte{1};
  event.inline_payload = reb::EncodeWasmDispatchObservationPayload(p);
  Check(!reb::IsValidEvent(event), "nonzero context padding");
}

void CheckRollingHash() {
  // Reference values shared with the Python, Rust and JavaScript joins.
  constexpr std::string_view kText = "abc";
  std::array<std::byte, 3> text{};
  std::memcpy(text.data(), kText.data(), text.size());
  const std::uint64_t expected =
      ((std::uint64_t{'a'} * reb::kJsInvocationRollingBase + 'b') * reb::kJsInvocationRollingBase) +
      'c';
  Check(reb::JsInvocationRollingHash(text) == expected, "rolling hash definition");
  Check(reb::JsInvocationRollingHash(text) == 0x014a08000118b972ULL, "rolling hash reference");
  const std::array<std::uint8_t, 3> overlay{'a', 'b', 'c'};
  Check(reb::NativeJsInvocationRollingHash(overlay) == expected, "overlay rolling hash");
  Check(reb::JsInvocationRollingHash({}) == 0, "empty rolling hash");
}

}  // namespace

int main() {
  CheckWireParity();
  CheckStartRules();
  CheckSettleRules();
  CheckRequestRules();
  CheckWasmVersions();
  CheckRollingHash();
  if (failures != 0)
    return 1;
  std::cout << "PASS native JavaScript invocation records: overlay and core agree on every field, "
               "every validation rule, Wasm context versions and the rolling hash\n";
  return 0;
}
