// Native JavaScript dispatch: real sink, transport and ring with the same
// narrow boundaries as main.cc. The sink retains one site list for the process
// lifetime, so every case below uses kJsSites and the changed-list refusal runs
// last.
#pragma once

#include "brave/components/reverse_engineering_browser/common/native_js_dispatch.h"

namespace {
using reb::NativeJsDispatchObservationPayload;
using reb::NativeJsDispatchShape;
using reb::NativeJsDispatchSite;

NativeJsDispatchSite JsSite(std::uint8_t seed, std::uint32_t anchor, NativeJsDispatchShape shape) {
  NativeJsDispatchSite site;
  for (std::size_t i = 0; i < site.source_sha256.size(); ++i)
    site.source_sha256[i] = static_cast<std::uint8_t>(seed + i);
  site.source_length = 1000;
  site.anchor_offset = anchor;
  site.shape = shape;
  return site;
}
const std::array<NativeJsDispatchSite, 8> kJsSites{
    JsSite(1, 10, NativeJsDispatchShape::kSwitch),
    JsSite(1, 20, NativeJsDispatchShape::kIndexedCall),
    JsSite(2, 10, NativeJsDispatchShape::kSwitch),
    JsSite(3, 30, NativeJsDispatchShape::kIndexedCall),
    JsSite(4, 40, NativeJsDispatchShape::kSwitch),
    JsSite(5, 50, NativeJsDispatchShape::kSwitch),
    JsSite(6, 60, NativeJsDispatchShape::kIndexedCall),
    JsSite(7, 70, NativeJsDispatchShape::kSwitch),
};
std::vector<std::uint8_t> JsSiteRecords(std::span<const NativeJsDispatchSite> sites) {
  std::vector<std::uint8_t> records;
  for (const auto& site : sites) {
    const auto record = reb::EncodeNativeJsDispatchSite(site);
    records.insert(records.end(), record.begin(), record.end());
  }
  return records;
}
NativeJsDispatchObservationPayload JsPayload(std::size_t slot, std::uint32_t activation = 1) {
  const auto& site = kJsSites[slot];
  NativeJsDispatchObservationPayload payload;
  payload.shape = static_cast<std::uint8_t>(site.shape);
  payload.selector_kind = static_cast<std::uint8_t>(reb::NativeJsDispatchSelectorKind::kInteger);
  payload.site_slot = static_cast<std::uint8_t>(slot);
  payload.script_id = 12;
  payload.anchor_offset = site.anchor_offset;
  payload.source_length = site.source_length;
  payload.selector_low32 = 0xFFFFFFFEU;
  payload.activation_id = activation;
  payload.source_sha256 = site.source_sha256;
  if (site.shape == NativeJsDispatchShape::kIndexedCall) {
    payload.flags = reb::kNativeJsDispatchHandlerSpan;
    payload.handler_script_id = 12;
    payload.handler_start = 100;
    payload.handler_end = 140;
  }
  return payload;
}
std::string_view JsGapReason(const NativeProbeEvent& event) {
  assert(event.header.type == reb::NativeProbeType::kGap &&
         event.header.category == reb::NativeProbeCategory::kVm);
  return {reinterpret_cast<const char*>(event.inline_payload.data()), event.header.payload_size};
}
NativeJsDispatchObservationPayload JsDecoded(const NativeProbeEvent& event) {
  assert(reb::IsValidNativeJsDispatchHeader(event.header));
  NativeJsDispatchObservationPayload payload;
  assert(reb::DecodeNativeJsDispatchObservationPayload(event.inline_payload, payload));
  assert(reb::IsValidNativeJsDispatchObservationPayload(payload));
  return payload;
}
void ConfigureJs(NativeProbeQueue& queue,
                 std::uint64_t session = 42,
                 std::uint64_t expires = kForever,
                 std::uint64_t mask = reb::kAllNativeProbeCategoryMask,
                 std::span<const NativeJsDispatchSite> sites = kJsSites) {
  transport.Configure(session, mask, expires, false, {&queue, sizeof(queue)}, 0, {},
                      JsSiteRecords(sites));
}

// Not inlined: main's frame must not also hold this test's 2.6 MB ring.
[[gnu::noinline]] void NativeJsDispatchWire() {
  NativeJsDispatchObservationPayload value;
  value.shape = 2;
  value.selector_kind = 1;
  value.site_slot = 7;
  value.flags = reb::kNativeJsDispatchNewActivation | reb::kNativeJsDispatchHandlerSpan;
  value.script_id = 0x01020304U;
  value.anchor_offset = 0x05060708U;
  value.source_length = 0x090A0B0CU;
  value.selector_low32 = 0x0D0E0F10U;
  value.handler_script_id = 0x11121314U;
  value.handler_start = 0x15161718U;
  value.handler_end = 0x191A1B1CU;
  value.activation_id = 0x21222324U;
  value.parent_activation_id = 0x1D1E1F20U;
  value.site_sample_index = 63;
  value.sample_index = 255;
  for (std::size_t i = 0; i < 32; ++i)
    value.source_sha256[i] = static_cast<std::uint8_t>(0xA0U + i);
  assert(reb::IsValidNativeJsDispatchObservationPayload(value));
  const auto bytes = reb::EncodeNativeJsDispatchObservationPayload(value);
  constexpr std::array<std::uint8_t, 48> head{
      1,    0,    128,  0,    2,    1,    7,    9,    4,    3,    2,    1,
      8,    7,    6,    5,    0x0C, 0x0B, 0x0A, 9,    0x10, 0x0F, 0x0E, 0x0D,
      0x14, 0x13, 0x12, 0x11, 0x18, 0x17, 0x16, 0x15, 0x1C, 0x1B, 0x1A, 0x19,
      0x24, 0x23, 0x22, 0x21, 0x20, 0x1F, 0x1E, 0x1D, 63,   0,    255,  0};
  for (std::size_t i = 0; i < head.size(); ++i)
    assert(std::to_integer<std::uint8_t>(bytes[i]) == head[i]);
  for (std::size_t i = 0; i < 32; ++i)
    assert(std::to_integer<std::uint8_t>(bytes[48 + i]) == 0xA0U + i);
  for (std::size_t i = 80; i < 128; ++i)
    assert(bytes[i] == std::byte{0});
  NativeJsDispatchObservationPayload decoded;
  assert(reb::DecodeNativeJsDispatchObservationPayload(bytes, decoded));
  assert(std::memcmp(&decoded, &value, sizeof(value)) == 0);
  assert(!reb::DecodeNativeJsDispatchObservationPayload(std::span(bytes).first(127), decoded));

  const auto rejected = [&](auto mutate) {
    auto copy = value;
    mutate(copy);
    return !reb::IsValidNativeJsDispatchObservationPayload(copy);
  };
  using P = NativeJsDispatchObservationPayload;
  assert(rejected([](P& p) { p.protocol_version = 2; }));
  assert(rejected([](P& p) { p.payload_size = 127; }));
  assert(rejected([](P& p) { p.shape = 0; }));
  assert(rejected([](P& p) { p.shape = 3; }));
  assert(rejected([](P& p) { p.selector_kind = 0; }));
  assert(rejected([](P& p) { p.selector_kind = 10; }));
  assert(rejected([](P& p) { p.site_slot = 8; }));
  assert(rejected([](P& p) { p.flags |= 16; }));
  assert(rejected([](P& p) { p.script_id = 0; }));
  assert(rejected([](P& p) { p.source_length = 0; }));
  assert(rejected([](P& p) { p.anchor_offset = p.source_length; }));
  assert(rejected([](P& p) { p.activation_id = 0; }));
  assert(rejected([](P& p) { p.site_sample_index = 64; }));
  assert(rejected([](P& p) { p.sample_index = 256; }));
  assert(rejected([](P& p) { p.selector_kind = 7, p.selector_low32 = 2; }));
  assert(!rejected([](P& p) { p.selector_kind = 7, p.selector_low32 = 1; }));
  assert(rejected([](P& p) { p.selector_kind = 3, p.selector_low32 = 1; }));
  assert(!rejected([](P& p) { p.selector_kind = 3, p.selector_low32 = 0; }));
  assert(rejected([](P& p) { p.shape = 1; }));  // switch with a handler span
  assert(rejected([](P& p) { p.handler_script_id = 0; }));
  assert(rejected([](P& p) { p.handler_end = p.handler_start; }));
  assert(rejected([](P& p) { p.flags = 0; }));  // handler fields without the flag
  assert(!rejected(
      [](P& p) { p.flags = 0, p.handler_script_id = p.handler_start = p.handler_end = 0; }));
  assert(rejected([](P& p) { p.parent_activation_id = p.activation_id; }));
  assert(rejected([](P& p) { p.flags |= reb::kNativeJsDispatchParentUnknown; }));
  assert(rejected([](P& p) { p.flags |= reb::kNativeJsDispatchParentSearchTruncated; }));
  assert(!rejected(
      [](P& p) { p.parent_activation_id = 0, p.flags |= reb::kNativeJsDispatchParentUnknown; }));
  assert(rejected([](P& p) {
    p.parent_activation_id = 0;
    p.flags |= reb::kNativeJsDispatchParentUnknown | reb::kNativeJsDispatchParentSearchTruncated;
  }));
  assert(rejected([](P& p) { p.reserved[47] = std::byte{1}; }));

  reb::NativeProbeHeader header;
  header.category = reb::NativeProbeCategory::kVm;
  header.type = reb::NativeProbeType::kJsDispatchObservation;
  header.payload_size = 128;
  header.session_id = header.sequence_number = header.monotonic_time_ns = header.frame_id = 1;
  header.process_id = header.thread_id = 1;
  header.tab_id = 9;  // The browser bridge may attribute a tab.
  assert(reb::IsValidNativeJsDispatchHeader(header));
  header.artifact_id = 1;
  assert(!reb::IsValidNativeJsDispatchHeader(header));
  header.artifact_id = 0;
  header.frame_id = 0;
  assert(!reb::IsValidNativeJsDispatchHeader(header));
  header.frame_id = 1;
  header.flags = 1;
  assert(!reb::IsValidNativeJsDispatchHeader(header));

  std::array<NativeJsDispatchSite, 8> out{};
  const auto records = JsSiteRecords(kJsSites);
  assert(records.size() == 8 * 44);
  const auto record = reb::EncodeNativeJsDispatchSite(kJsSites[1]);
  assert(record[32] == 0xE8 && record[33] == 3 && record[36] == 20 && record[40] == 2 &&
         record[41] == 0 && record[42] == 0 && record[43] == 0);
  assert(reb::DecodeNativeJsDispatchSites(records, out) == 8 &&
         std::equal(out.begin(), out.end(), kJsSites.begin()));
  assert(reb::DecodeNativeJsDispatchSites({}, out) == 0);
  assert(reb::DecodeNativeJsDispatchSites(std::span(records).first(43), out) == 0);
  auto nine = records;
  nine.insert(nine.end(), record.begin(), record.end());
  assert(reb::DecodeNativeJsDispatchSites(nine, out) == 0);
  const auto mutated = [&](std::size_t offset, std::uint8_t value_byte) {
    auto copy = std::vector<std::uint8_t>(record.begin(), record.end());
    copy[offset] = value_byte;
    return reb::DecodeNativeJsDispatchSites(copy, out);
  };
  assert(mutated(40, 3) == 0 && mutated(40, 0) == 0 && mutated(41, 1) == 0 && mutated(43, 1) == 0);
  auto anchor_at_end = std::vector<std::uint8_t>(record.begin(), record.end());
  anchor_at_end[32] = 20, anchor_at_end[33] = 0;  // source length 20 == anchor 20
  assert(reb::DecodeNativeJsDispatchSites(anchor_at_end, out) == 0);
  auto zero_length = std::vector<std::uint8_t>(record.begin(), record.end());
  zero_length[32] = zero_length[33] = 0;
  assert(reb::DecodeNativeJsDispatchSites(zero_length, out) == 0);
  auto duplicate = std::vector<std::uint8_t>(record.begin(), record.end());
  duplicate.insert(duplicate.end(), record.begin(), record.end());
  assert(reb::DecodeNativeJsDispatchSites(duplicate, out) == 0);
  // Same anchor in different text is a different site.
  assert(reb::DecodeNativeJsDispatchSites(std::span(records).first(3 * 44), out) == 3);
  std::cout << "PASS native JS dispatch wire: byte-exact payload, every validation rule, "
               "envelope and 44-byte site records\n";
}

struct JsEmitter {
  inline static bool reject_dispatch = false;
  inline static std::vector<NativeProbeEvent> events;
  inline static unsigned frame_lookups = 0;
};
reb::NativeProbeEmitStatus CaptureJsEvent(const NativeProbeEvent& event, std::uint64_t) noexcept {
  if (JsEmitter::reject_dispatch &&
      event.header.type == reb::NativeProbeType::kJsDispatchObservation)
    return reb::NativeProbeEmitStatus::kRejected;
  JsEmitter::events.push_back(event);
  return reb::NativeProbeEmitStatus::kAdmitted;
}
std::uint64_t CountJsFrameLookup() noexcept {
  ++JsEmitter::frame_lookups;
  return 5;
}

[[gnu::noinline]] void NativeJsDispatchAdmission() {
  NativeProbeQueue queue;
  const auto record = [&](std::size_t slot, std::uint64_t epoch, std::uint64_t frame = 8) {
    sink.RecordNativeJsDispatch(epoch, frame, JsPayload(slot));
  };
  transport.Disable();
  const auto before = allocations.load();
  assert(sink.NativeJsDispatchEpoch() == 0 && !sink.IsNativeJsDispatchEnabled(2, 0));
  record(0, 2);
  sink.NoteNativeJsDispatchStatus(2, 0, reb::NativeJsDispatchSiteStatus::kCompiledBeforeArming);
  sink.NoteNativeJsDispatchInputUnavailable(2, 8);
  assert(allocations.load() == before && Drain(queue) == 0);  // inactive: no allocation, no record

  // Without sites, without the VM category, or expired, nothing is armed.
  Configure(queue);
  assert(sink.NativeJsDispatchEpoch() == 0);
  ConfigureJs(queue, 42, kForever, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas));
  assert(sink.NativeJsDispatchEpoch() == 0);
  assert(Drain(queue) == 0);
  ConfigureJs(queue, 42, 1000);
  assert(sink.NativeJsDispatchEpoch() != 0);
  base::test_now_ns = 1000;
  assert(sink.NativeJsDispatchEpoch() == 0);
  base::test_now_ns = 100;

  ConfigureJs(queue);
  const auto epoch = sink.NativeJsDispatchEpoch();
  assert(epoch != 0 && (epoch & 1U) == 0);
  std::array<NativeJsDispatchSite, 8> copied{};
  assert(sink.CopyNativeJsDispatchSites(epoch, copied) == 8 &&
         std::equal(copied.begin(), copied.end(), kJsSites.begin()));
  assert(sink.CopyNativeJsDispatchSites(epoch - 2, copied) == 0);  // stale epoch
  assert(sink.IsNativeJsDispatchEnabled(epoch, 7) && !sink.IsNativeJsDispatchEnabled(epoch, 8));

  // 64 per site, then one coalesced site-budget gap; other sites continue.
  for (std::size_t n = 0; n < 64; ++n) {
    record(0, epoch);
    const auto payload = JsDecoded(One(queue));
    assert(payload.site_sample_index == n && payload.sample_index == n && payload.site_slot == 0);
  }
  record(0, epoch);
  assert(JsGapReason(One(queue)) == "native_js_dispatch_site_budget_incomplete");
  assert(!sink.IsNativeJsDispatchEnabled(epoch, 0) && sink.IsNativeJsDispatchEnabled(epoch, 1));
  record(1, epoch);
  auto payload = JsDecoded(One(queue));
  assert(payload.site_sample_index == 0 && payload.sample_index == 64 &&
         payload.handler_end == 140);
  for (std::size_t n = 1; n < 64; ++n)
    record(1, epoch);
  record(1, epoch);  // the second capped site reuses the coalesced gap
  assert(Drain(queue) == 63 && !sink.IsNativeJsDispatchEnabled(epoch, 1));
  // 256 per configuration, then one budget gap and every site is refused.
  for (std::size_t slot = 2; slot < 4; ++slot)
    for (std::size_t n = 0; n < 64; ++n)
      record(slot, epoch);
  assert(Drain(queue) == 128);
  record(4, epoch);
  assert(JsGapReason(One(queue)) == "native_js_dispatch_budget_incomplete");
  for (std::uint32_t slot = 0; slot < 8; ++slot)
    assert(!sink.IsNativeJsDispatchEnabled(epoch, slot));
  record(5, epoch);
  assert(Drain(queue) == 0);

  // A replacement configuration, even for the same session, has fresh budgets
  // and refuses every record of the previous epoch.
  ConfigureJs(queue);
  const auto second = sink.NativeJsDispatchEpoch();
  assert(second > epoch && sink.IsNativeJsDispatchEnabled(second, 0));
  record(0, epoch);
  sink.NoteNativeJsDispatchStatus(epoch, 0, reb::NativeJsDispatchSiteStatus::kCompiledBeforeArming);
  assert(Drain(queue) == 0);
  record(0, second);
  payload = JsDecoded(One(queue));
  assert(payload.sample_index == 0 && payload.site_sample_index == 0);

  // A full ring counts its own drop and returns both claims.
  Fill(queue);
  const auto dropped = queue.DroppedCount();
  record(2, second);
  assert(queue.DroppedCount() == dropped + 1);
  assert(Drain(queue) == reb::kNativeProbeQueueCapacity);
  record(2, second);
  payload = JsDecoded(One(queue));
  assert(payload.sample_index == 1 && payload.site_sample_index == 0);

  // Invalid records and non-document contexts are one coalesced input gap.
  auto wrong_key = JsPayload(3);
  wrong_key.source_sha256[0] ^= 1;
  sink.RecordNativeJsDispatch(second, 8, wrong_key);
  assert(JsGapReason(One(queue)) == "native_js_dispatch_input_unavailable");
  auto invalid = JsPayload(3);
  invalid.selector_kind = 10;
  sink.RecordNativeJsDispatch(second, 8, invalid);
  record(3, second, 0);
  sink.NoteNativeJsDispatchInputUnavailable(second, 0);
  assert(Drain(queue) == 0);
  record(3, second);
  payload = JsDecoded(One(queue));
  assert(payload.sample_index == 2);  // refused records consumed no budget

  // Compiled before arming: one gap per configuration and slot.
  sink.NoteNativeJsDispatchStatus(second, 3,
                                  reb::NativeJsDispatchSiteStatus::kCompiledBeforeArming);
  assert(JsGapReason(One(queue)) == "native_js_dispatch_site_3_compiled_before_arming");
  sink.NoteNativeJsDispatchStatus(second, 3,
                                  reb::NativeJsDispatchSiteStatus::kCompiledBeforeArming);
  assert(Drain(queue) == 0);
  sink.NoteNativeJsDispatchStatus(second, 5,
                                  reb::NativeJsDispatchSiteStatus::kCompiledBeforeArming);
  const auto status_gap = One(queue);
  assert(JsGapReason(status_gap) == "native_js_dispatch_site_5_compiled_before_arming" &&
         status_gap.header.frame_id == 0);
  sink.NoteNativeJsDispatchStatus(second, 8,
                                  reb::NativeJsDispatchSiteStatus::kCompiledBeforeArming);
  assert(Drain(queue) == 0);

  // An emitter refusal returns both claims and is one coalesced transport gap.
  // V8-facing calls never invoke the frame-id provider, which re-enters V8.
  JsEmitter::events.clear();
  sink.SetEmitters(&CaptureJsEvent, &CaptureRuntimeMetadata, 42, reb::kAllNativeProbeCategoryMask,
                   kForever, false, &CountJsFrameLookup);
  assert(sink.NativeJsDispatchEpoch() == 0);  // SetEmitters disarms until configured
  sink.ConfigureNativeJsDispatch(kJsSites);
  const auto third = sink.NativeJsDispatchEpoch();
  assert(third > second && sink.IsNativeJsDispatchEnabled(third, 6));
  JsEmitter::reject_dispatch = true;
  record(6, third);
  record(6, third);
  assert(JsEmitter::events.size() == 1 &&
         JsGapReason(JsEmitter::events[0]) == "native_js_dispatch_transport_unavailable");
  JsEmitter::reject_dispatch = false;
  record(6, third);
  assert(JsEmitter::events.size() == 2);
  payload = JsDecoded(JsEmitter::events[1]);
  assert(payload.sample_index == 0 && payload.site_sample_index == 0 &&
         JsEmitter::events[1].header.frame_id == 8);
  assert(JsEmitter::frame_lookups == 0);

  // The browser keeps the list fixed; a different list arms nothing.
  JsEmitter::events.clear();
  sink.SetEmitters(&CaptureJsEvent, &CaptureRuntimeMetadata, 42, reb::kAllNativeProbeCategoryMask,
                   kForever, false, nullptr);
  sink.ConfigureNativeJsDispatch(std::span(kJsSites).first(2));
  assert(sink.NativeJsDispatchEpoch() == 0 && JsEmitter::events.size() == 1 &&
         JsGapReason(JsEmitter::events[0]) == "native_js_dispatch_input_unavailable");
  // A malformed record list from Mojo is refused the same way.
  transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, false,
                      {&queue, sizeof(queue)}, 0, {}, std::vector<std::uint8_t>(43, 1));
  assert(sink.NativeJsDispatchEpoch() == 0);
  assert(JsGapReason(One(queue)) == "native_js_dispatch_input_unavailable");
  transport.Disable();
  std::cout << "PASS native JS dispatch admission: disabled, expiry and category refusal, 64 per "
               "site and 256 per configuration with coalesced gaps, ring-full release, transport "
               "and input gaps, compiled-before-arming per slot, fixed site list\n";
}
}  // namespace
