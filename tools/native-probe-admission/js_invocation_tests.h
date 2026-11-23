// Native JavaScript invocation identity: the real sink, transport and ring
// with the same narrow boundaries as main.cc. The sink keeps each slot's site
// for the process lifetime, so the revision case runs first, while its slots
// are still empty, and every later case uses kInvocationSites.
#pragma once

#include "brave/components/reverse_engineering_browser/common/native_js_invocation.h"

namespace {
using reb::NativeJsInvocationContext;
using reb::NativeJsInvocationSettlePayload;
using reb::NativeJsInvocationSite;
using reb::NativeJsInvocationStartPayload;

NativeJsInvocationSite InvocationSite(std::uint8_t seed, std::uint32_t anchor) {
  NativeJsInvocationSite site;
  for (std::size_t i = 0; i < site.source_sha256.size(); ++i)
    site.source_sha256[i] = static_cast<std::uint8_t>(seed + i);
  site.source_length = 900;
  site.anchor_offset = anchor;
  return site;
}
// More slots than one byte names, reaching into the sink's third segment.
constexpr std::size_t kInvocationSiteCount = 1000;
using InvocationSiteTable = std::vector<NativeJsInvocationSite>;
InvocationSiteTable MakeInvocationSites() {
  InvocationSiteTable sites(kInvocationSiteCount);
  sites[0] = InvocationSite(9, 41);
  sites[1] = InvocationSite(9, 300);
  for (std::size_t slot = 2; slot < sites.size(); ++slot)
    sites[slot] = InvocationSite(static_cast<std::uint8_t>(10 + slot / 64),
                                 static_cast<std::uint32_t>(400 + slot % 64));
  return sites;
}
const InvocationSiteTable kInvocationSites = MakeInvocationSites();
std::vector<std::uint8_t> InvocationRecords(std::span<const NativeJsInvocationSite> sites) {
  std::vector<std::uint8_t> records;
  for (const auto& site : sites) {
    const auto record = reb::EncodeNativeJsInvocationSite(site);
    records.insert(records.end(), record.begin(), record.end());
  }
  return records;
}
NativeJsInvocationStartPayload StartFor(std::size_t slot, std::uint32_t id) {
  const auto& site = kInvocationSites[slot];
  NativeJsInvocationStartPayload payload;
  payload.site_slot = static_cast<std::uint32_t>(slot);
  payload.argument_count = 2;
  payload.argument_kinds[0] = 1;
  payload.argument_low32[0] = 2;
  payload.argument_kinds[1] = 3;
  payload.script_id = 12;
  payload.anchor_offset = site.anchor_offset;
  payload.source_length = site.source_length;
  payload.invocation_id = id;
  payload.source_sha256 = site.source_sha256;
  payload.document_id = 99;
  return payload;
}
NativeJsInvocationSettlePayload SettleFor(std::uint32_t id, bool digest, std::uint32_t slot = 0) {
  NativeJsInvocationSettlePayload payload;
  payload.site_slot = slot;
  payload.outcome = 1;
  payload.via = 3;
  payload.value_kind = 3;
  payload.invocation_id = id;
  payload.value_length = 3;
  payload.document_id = 99;
  if (digest) {
    payload.digest_state = 1;
    payload.digest_encoding = 1;
    payload.digest_byte_length = 3;
    const std::array<std::uint8_t, 3> token{'t', 'o', 'k'};
    payload.rolling_hash = reb::NativeJsInvocationRollingHash(token);
    payload.value_sha256.fill(0x44);
  }
  return payload;
}
std::string_view InvocationGap(const NativeProbeEvent& event) {
  assert(event.header.type == reb::NativeProbeType::kGap &&
         event.header.category == reb::NativeProbeCategory::kVm);
  return {reinterpret_cast<const char*>(event.inline_payload.data()), event.header.payload_size};
}
std::uint32_t InvocationU32(const NativeProbeEvent& event, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i)
    value |= std::to_integer<std::uint32_t>(event.inline_payload[offset + i]) << (8 * i);
  return value;
}
// The site ordinal of a version 2 start, at payload bytes 28-31.
std::uint32_t StartOrdinal(const NativeProbeEvent& event) {
  assert(reb::IsValidNativeJsInvocationStartHeader(event.header) &&
         std::to_integer<std::uint8_t>(event.inline_payload[0]) == 2 &&
         std::to_integer<std::uint8_t>(event.inline_payload[1]) == 0);
  return InvocationU32(event, 28);
}
// The request ordinal, at payload bytes 12-15.
std::uint32_t RequestOrdinal(const NativeProbeEvent& event) {
  assert(reb::IsValidNativeJsInvocationRequestHeader(event.header));
  return InvocationU32(event, 12);
}
void ConfigureInvocation(NativeProbeQueue& queue,
                         bool digests = false,
                         std::uint64_t mask = reb::kAllNativeProbeCategoryMask,
                         std::uint64_t expires = kForever) {
  transport.Configure(42, mask, expires, false, {&queue, sizeof(queue)}, 0, {}, {},
                      InvocationRecords(kInvocationSites), digests);
}
struct InvocationProvider {
  inline static NativeJsInvocationContext context{};
  inline static unsigned reads = 0;
};
NativeJsInvocationContext ReadInvocation() noexcept {
  ++InvocationProvider::reads;
  return InvocationProvider::context;
}
unsigned invocation_frame_lookups = 0;
void CountInvocationFrameLookup() {
  ++invocation_frame_lookups;
}
struct InvocationEmitter {
  inline static bool reject_starts = false;
  inline static std::vector<NativeProbeEvent> events;
};
reb::NativeProbeEmitStatus CaptureInvocationEvent(const NativeProbeEvent& event,
                                                  std::uint64_t) noexcept {
  if (InvocationEmitter::reject_starts &&
      event.header.type == reb::NativeProbeType::kJsInvocationStart)
    return reb::NativeProbeEmitStatus::kRejected;
  InvocationEmitter::events.push_back(event);
  return reb::NativeProbeEmitStatus::kAdmitted;
}

[[gnu::noinline]] void NativeJsInvocationAdmission() {
  NativeProbeQueue queue;
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(&ReadInvocation);
  InvocationProvider::context = {2, 7, true};
  const auto before = allocations.load();
  // Disabled: nothing is armed, nothing allocates, nothing is recorded, and
  // consumers see not_observed without even reading V8.
  assert(sink.NativeJsInvocationEpoch() == 0 && !sink.IsNativeJsInvocationEnabled(2, 0));
  assert(!sink.RecordNativeJsInvocationStart(2, 8, StartFor(0, 1)));
  sink.RecordNativeJsInvocationRequest(31);
  assert(sink.CurrentNativeJsInvocation().state == 0 && InvocationProvider::reads == 0);
  assert(allocations.load() == before && Drain(queue) == 0);

  // Without the VM category nothing is armed; a configuration without sites
  // arms nothing either.
  ConfigureInvocation(queue, false,
                      reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork));
  assert(sink.NativeJsInvocationEpoch() == 0 && sink.CurrentNativeJsInvocation().state == 0);
  Configure(queue);
  assert(sink.NativeJsInvocationEpoch() == 0);

  // Armed but not called: an epoch and every site, and no record.
  ConfigureInvocation(queue);
  const auto epoch = sink.NativeJsInvocationEpoch();
  assert(epoch != 0 && (epoch & 1U) == 0 && !sink.NativeJsInvocationDigests(epoch));
  InvocationSiteTable copied(kInvocationSiteCount);
  assert(sink.CopyNativeJsInvocationSites(epoch, 0, copied) == kInvocationSiteCount &&
         copied == kInvocationSites);
  assert(sink.CopyNativeJsInvocationSites(epoch - 2, 0, copied) == 0);
  // A copy from any first slot, and one past the end, report the whole count.
  std::array<NativeJsInvocationSite, 3> window{};
  assert(sink.CopyNativeJsInvocationSites(epoch, 998, window) == kInvocationSiteCount &&
         window[0] == kInvocationSites[998] && window[1] == kInvocationSites[999] &&
         window[2] == NativeJsInvocationSite{});
  assert(sink.CopyNativeJsInvocationSites(epoch, 5000, window) == kInvocationSiteCount);
  assert(sink.IsNativeJsInvocationEnabled(epoch, kInvocationSiteCount - 1) &&
         !sink.IsNativeJsInvocationEnabled(epoch, kInvocationSiteCount));
  assert(Drain(queue) == 0);

  // A consumer reads the provider while active; an inconsistent read is not
  // observed rather than guessed.
  assert(sink.CurrentNativeJsInvocation().state == 2 &&
         sink.CurrentNativeJsInvocation().invocation_id == 7);
  InvocationProvider::context = {2, 0, true};
  assert(sink.CurrentNativeJsInvocation().state == 0);
  InvocationProvider::context = {1, 3, true};
  assert(sink.CurrentNativeJsInvocation().state == 0);

  // Every call is recorded: 6000 starts of one site take ordinals 0-5999,
  // and each site counts its own.
  for (std::uint32_t n = 0; n < 6000; ++n) {
    assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, n + 1)));
    assert(StartOrdinal(One(queue)) == n);
  }
  assert(sink.IsNativeJsInvocationEnabled(epoch, 0));
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(kInvocationSiteCount - 1, 6001)));
  const auto last = One(queue);
  assert(StartOrdinal(last) == 0 && InvocationU32(last, 112) == kInvocationSiteCount - 1 &&
         std::to_integer<std::uint8_t>(last.inline_payload[4]) == 0);
  // A start that does not name its configured site is an input gap, is not
  // recorded and takes no ordinal; V8 then neither wraps nor settles it.
  auto wrong = StartFor(1, 6002);
  wrong.anchor_offset = 42;
  assert(!sink.RecordNativeJsInvocationStart(epoch, 8, wrong));
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  assert(!sink.RecordNativeJsInvocationStart(epoch, 0, StartFor(1, 6003)));
  assert(Drain(queue) == 0);  // no frame: the same coalesced input gap
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 6004)));
  assert(StartOrdinal(One(queue)) == 0);

  // A settle without the digest opt-in may not carry a digest.
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(1, true));
  assert(Drain(queue) == 0);  // refused; its input gap was already emitted
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(2, false));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationSettle);

  // Requests: inside an invocation, recorded; script outside any invocation,
  // not recorded; a loader start outside script while a recorded start has
  // not settled, unknown. Each takes the next request ordinal.
  InvocationProvider::context = {2, 9, true};
  sink.RecordNativeJsInvocationRequest(31);
  auto request = One(queue);
  assert(request.header.request_id == 31 && RequestOrdinal(request) == 0 &&
         std::to_integer<std::uint8_t>(request.inline_payload[4]) == 2 &&
         std::to_integer<std::uint8_t>(request.inline_payload[8]) == 9);
  InvocationProvider::context = {1, 0, true};
  sink.RecordNativeJsInvocationRequest(32);
  assert(Drain(queue) == 0);
  InvocationProvider::context = {1, 0, false};
  sink.RecordNativeJsInvocationRequest(33);
  request = One(queue);
  assert(RequestOrdinal(request) == 1 &&
         std::to_integer<std::uint8_t>(request.inline_payload[4]) == 3 &&
         std::to_integer<std::uint8_t>(request.inline_payload[8]) == 0);
  // A worker reads as not observed and is never made unknown.
  InvocationProvider::context = {0, 0, false};
  sink.RecordNativeJsInvocationRequest(36);
  assert(Drain(queue) == 0);
  // Every request inside an invocation is recorded, each with one context
  // read and one frame lookup.
  InvocationProvider::context = {2, 4, true};
  const auto reads = InvocationProvider::reads;
  invocation_frame_lookups = 0;
  blink::test_frame_hook = &CountInvocationFrameLookup;
  for (std::int32_t n = 0; n < 6000; ++n) {
    sink.RecordNativeJsInvocationRequest(100 + n);
    assert(RequestOrdinal(One(queue)) == static_cast<std::uint32_t>(n) + 2);
  }
  blink::test_frame_hook = nullptr;
  assert(InvocationProvider::reads == reads + 6000 && invocation_frame_lookups == 6000);

  // Status gaps per configuration and slot, and one when V8 runs out of
  // invocation IDs.
  sink.NoteNativeJsInvocationStatus(epoch, 1,
                                    reb::NativeJsInvocationSiteStatus::kUnsupportedFunction);
  assert(InvocationGap(One(queue)) == "native_js_invocation_site_1_unsupported_function");
  sink.NoteNativeJsInvocationStatus(epoch, 1,
                                    reb::NativeJsInvocationSiteStatus::kUnsupportedFunction);
  sink.NoteNativeJsInvocationStatus(epoch, kInvocationSiteCount,
                                    reb::NativeJsInvocationSiteStatus::kCompiledBeforeArming);
  assert(Drain(queue) == 0);
  sink.NoteNativeJsInvocationStatus(epoch, kInvocationSiteCount - 1,
                                    reb::NativeJsInvocationSiteStatus::kCompiledBeforeArming);
  assert(InvocationGap(One(queue)) == "native_js_invocation_site_999_compiled_before_arming");
  sink.NoteNativeJsInvocationStatus(epoch, kInvocationSiteCount - 1,
                                    reb::NativeJsInvocationSiteStatus::kUnsupportedFunction);
  assert(InvocationGap(One(queue)) == "native_js_invocation_site_999_unsupported_function");
  sink.NoteNativeJsInvocationStatus(epoch, 3, reb::NativeJsInvocationSiteStatus::kIdsExhausted);
  assert(InvocationGap(One(queue)) == "native_js_invocation_ids_exhausted");
  sink.NoteNativeJsInvocationStatus(epoch, 4, reb::NativeJsInvocationSiteStatus::kIdsExhausted);
  assert(Drain(queue) == 0);
  sink.NoteNativeJsInvocationSettleUnavailable(epoch, 8, 3);
  assert(InvocationGap(One(queue)) == "native_js_invocation_settle_unavailable");

  // A replacement configuration with the digest opt-in: ordinals restart,
  // nothing is open, and digests are accepted.
  ConfigureInvocation(queue, true);
  const auto second = sink.NativeJsInvocationEpoch();
  assert(second > epoch && sink.NativeJsInvocationDigests(second));
  assert(!sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 1)));  // stale epoch
  InvocationProvider::context = {1, 0, false};
  sink.RecordNativeJsInvocationRequest(34);  // nothing open in this configuration
  assert(Drain(queue) == 0);
  assert(sink.RecordNativeJsInvocationStart(second, 8, StartFor(0, 80)));
  assert(StartOrdinal(One(queue)) == 0);
  sink.RecordNativeJsInvocationSettle(second, 8, SettleFor(80, true));
  auto settle = One(queue);
  assert(reb::IsValidNativeJsInvocationSettleHeader(settle.header) &&
         std::to_integer<std::uint8_t>(settle.inline_payload[16]) == 1);
  InvocationProvider::context = {2, 80, true};
  sink.RecordNativeJsInvocationRequest(37);
  assert(RequestOrdinal(One(queue)) == 0);
  // Without the Network category no request record is made.
  ConfigureInvocation(queue, false, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm));
  assert(sink.NativeJsInvocationEpoch() != 0);
  sink.RecordNativeJsInvocationRequest(35);
  assert(Drain(queue) == 0);
  // Expiry disarms.
  ConfigureInvocation(queue, false, reb::kAllNativeProbeCategoryMask, 1000);
  assert(sink.NativeJsInvocationEpoch() != 0);
  base::test_now_ns = 1000;
  assert(sink.NativeJsInvocationEpoch() == 0 && sink.CurrentNativeJsInvocation().state == 0);
  base::test_now_ns = 100;

  // Slots keep their sites: a shorter list disarms the slots it omits...
  transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, false,
                      {&queue, sizeof(queue)}, 0, {}, {},
                      InvocationRecords(std::span(kInvocationSites).first(1)), false);
  const auto shorter = sink.NativeJsInvocationEpoch();
  assert(shorter != 0 && sink.IsNativeJsInvocationEnabled(shorter, 0) &&
         !sink.IsNativeJsInvocationEnabled(shorter, 1));
  assert(sink.CopyNativeJsInvocationSites(shorter, 0, copied) == kInvocationSiteCount &&
         copied[0] == kInvocationSites[0] && !copied[1].armed && copied[1].source_length == 0);
  assert(Drain(queue) == 0);
  // ...and a list that names another site at a kept slot, or is malformed,
  // arms nothing.
  auto moved = kInvocationSites;
  std::swap(moved[0], moved[1]);
  transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, false,
                      {&queue, sizeof(queue)}, 0, {}, {}, InvocationRecords(moved), false);
  assert(sink.NativeJsInvocationEpoch() == 0);
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, false,
                      {&queue, sizeof(queue)}, 0, {}, {}, std::vector<std::uint8_t>(43, 1), false);
  assert(sink.NativeJsInvocationEpoch() == 0);
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(nullptr);
  std::cout << "PASS native JS invocation admission: disabled and allocation-free, category and "
               "expiry refusal, 1000 sites armed but not called, 6000 starts of one site and "
               "6000 requests with no count refusal, per-site and request ordinals that restart "
               "per configuration, exact site match, digest opt-in, inside/none/unknown "
               "requests, status and ID-exhaustion gaps, and slots that keep their sites\n";
}

// A revision of the running configuration arms, disarms and appends slots.
// Ordinals, open starts and digests stay; a revision that renumbers a slot,
// is malformed, or arrives without an invocation configuration changes
// nothing.
[[gnu::noinline]] void NativeJsInvocationRevisions() {
  NativeProbeQueue queue;
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(&ReadInvocation);
  // Tracking functions before any is armed: no epoch, so V8 stays inactive.
  transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, false,
                      {&queue, sizeof(queue)}, 0, {}, {}, std::vector<std::uint8_t>{}, true);
  assert(sink.NativeJsInvocationEpoch() == 0 && Drain(queue) == 0);
  transport.UpdateJsInvocationSites(InvocationRecords(std::span(kInvocationSites).first(2)));
  const auto epoch = sink.NativeJsInvocationEpoch();
  const auto first = sink.NativeJsInvocationRevision(epoch);
  assert(epoch != 0 && first != 0 && sink.NativeJsInvocationDigests(epoch));
  assert(sink.IsNativeJsInvocationEnabled(epoch, 1) && !sink.IsNativeJsInvocationEnabled(epoch, 2));
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 1)));
  assert(StartOrdinal(One(queue)) == 0);

  // Slot 0 disarmed while its call is open, and a third slot appended.
  auto table =
      std::vector<NativeJsInvocationSite>(kInvocationSites.begin(), kInvocationSites.begin() + 3);
  table[0].armed = false;
  transport.UpdateJsInvocationSites(InvocationRecords(table));
  const auto second = sink.NativeJsInvocationRevision(epoch);
  assert(sink.NativeJsInvocationEpoch() == epoch && second > first);
  assert(!sink.IsNativeJsInvocationEnabled(epoch, 0) && sink.IsNativeJsInvocationEnabled(epoch, 2));
  InvocationSiteTable copied(kInvocationSiteCount);
  assert(sink.CopyNativeJsInvocationSites(epoch, 0, copied) == 3 && !copied[0].armed &&
         copied[0].source_length == 0 && copied[2] == kInvocationSites[2]);
  // A start V8 still reports for the disarmed slot is not recorded and is no
  // input fault.
  assert(!sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 2)));
  assert(Drain(queue) == 0);
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(2, 3)));
  assert(StartOrdinal(One(queue)) == 0);
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(3, true, 2));
  assert(Drain(queue) == 1);
  // The call opened before the revision is still open, and settles.
  InvocationProvider::context = {1, 0, false};
  sink.RecordNativeJsInvocationRequest(60);
  assert(RequestOrdinal(One(queue)) == 0);
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(1, true, 0));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationSettle);
  sink.RecordNativeJsInvocationRequest(61);
  assert(Drain(queue) == 0);

  // Re-arming slot 0 continues its ordinals.
  table[0].armed = true;
  transport.UpdateJsInvocationSites(InvocationRecords(table));
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 4)));
  assert(StartOrdinal(One(queue)) == 1);
  // Renumbering a slot or a malformed revision changes nothing: one input
  // gap for the configuration.
  const auto armed = sink.NativeJsInvocationRevision(epoch);
  std::swap(table[1], table[2]);
  transport.UpdateJsInvocationSites(InvocationRecords(table));
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  transport.UpdateJsInvocationSites(std::vector<std::uint8_t>(43, 1));
  assert(Drain(queue) == 0 && sink.NativeJsInvocationRevision(epoch) == armed);
  assert(sink.IsNativeJsInvocationEnabled(epoch, 1) && sink.IsNativeJsInvocationEnabled(epoch, 2));
  // A configuration that tracks no functions takes no revision.
  Configure(queue);
  transport.UpdateJsInvocationSites(InvocationRecords(std::span(kInvocationSites).first(3)));
  assert(sink.NativeJsInvocationEpoch() == 0 && Drain(queue) == 0);
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(nullptr);
  // The admission test that follows starts from an unread provider.
  InvocationProvider::context = {};
  InvocationProvider::reads = 0;
  std::cout << "PASS native JS invocation revisions: an empty list tracks later sites, a "
               "revision arms, disarms and appends slots of the running configuration, an open "
               "call settles across it, ordinals continue, and a renumbering or malformed "
               "revision changes nothing\n";
}

// The open count behind an unknown request follows recorded starts exactly:
// V8 settles only a start the sink recorded, and that settle closes it
// whether or not its own record is retained.
[[gnu::noinline]] void NativeJsInvocationOpenStarts() {
  NativeProbeQueue queue;
  sink.SetNativeJsInvocationContextProvider(&ReadInvocation);
  ConfigureInvocation(queue);
  const auto epoch = sink.NativeJsInvocationEpoch();
  const auto unknown_requests = [&](std::int32_t request_id) {
    InvocationProvider::context = {1, 0, false};
    sink.RecordNativeJsInvocationRequest(request_id);
    return Drain(queue);
  };
  // A stays pending on site 1 while site 0 starts and settles 64 times.
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 1)));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  for (std::uint32_t n = 0; n < 64; ++n) {
    assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, n + 2)));
    sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(n + 2, false));
    assert(Drain(queue) == 2);
  }
  assert(unknown_requests(40) == 1);
  // B finds the ring full: the ring counts the drop and B is not open. Its
  // ordinal stays missing beside that count.
  Fill(queue);
  auto dropped = queue.DroppedCount();
  assert(!sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 66)));
  assert(queue.DroppedCount() == dropped + 1);
  Drain(queue);
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 67)));
  assert(StartOrdinal(One(queue)) == 65);
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(67, false));
  assert(Drain(queue) == 1 && unknown_requests(41) == 1);
  // The full ring drops A's settle, which the ring counts; A closes anyway.
  Fill(queue);
  dropped = queue.DroppedCount();
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(1, false, 1));
  assert(queue.DroppedCount() == dropped + 1);
  Drain(queue);
  assert(unknown_requests(42) == 0);
  // C's settle is malformed: refused as input, and C closes.
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 68)));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  auto malformed = SettleFor(68, false, 1);
  malformed.outcome = 9;
  sink.RecordNativeJsInvocationSettle(epoch, 8, malformed);
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  assert(unknown_requests(43) == 0);
  // D's settle job ran after its document went away: a gap, and D closes.
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 69)));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  assert(unknown_requests(44) == 1);
  sink.NoteNativeJsInvocationSettleUnavailable(epoch, 8, 69);
  assert(InvocationGap(One(queue)) == "native_js_invocation_settle_unavailable");
  assert(unknown_requests(45) == 0);
  // Blink's refusal of a start from a detached document opens nothing.
  sink.NoteNativeJsInvocationInputUnavailable(epoch, 0);
  assert(Drain(queue) == 0 && unknown_requests(46) == 0);

  // An emitter refusal is one coalesced transport gap; the refused start is
  // not open and its ordinal stays missing.
  InvocationEmitter::events.clear();
  sink.SetEmitters(&CaptureInvocationEvent, &CaptureRuntimeMetadata, 42,
                   reb::kAllNativeProbeCategoryMask, kForever, false, nullptr);
  sink.ConfigureNativeJsInvocation(kInvocationSites, false);
  const auto third = sink.NativeJsInvocationEpoch();
  assert(third > epoch);
  InvocationEmitter::reject_starts = true;
  assert(!sink.RecordNativeJsInvocationStart(third, 8, StartFor(2, 1)));
  assert(!sink.RecordNativeJsInvocationStart(third, 8, StartFor(2, 2)));
  assert(InvocationEmitter::events.size() == 1 && InvocationGap(InvocationEmitter::events[0]) ==
                                                      "native_js_invocation_transport_unavailable");
  InvocationEmitter::reject_starts = false;
  assert(sink.RecordNativeJsInvocationStart(third, 8, StartFor(2, 3)));
  assert(InvocationEmitter::events.size() == 2 && StartOrdinal(InvocationEmitter::events[1]) == 2);
  InvocationProvider::context = {1, 0, false};
  sink.RecordNativeJsInvocationRequest(47);
  assert(InvocationEmitter::events.size() == 3 &&
         std::to_integer<std::uint8_t>(InvocationEmitter::events[2].inline_payload[4]) == 3);
  sink.RecordNativeJsInvocationSettle(third, 8, SettleFor(3, false, 2));
  sink.RecordNativeJsInvocationRequest(48);
  assert(InvocationEmitter::events.size() == 4);  // the settle; no unknown request
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(nullptr);
  std::cout << "PASS native JS invocation open starts: only recorded starts are open, a settle "
               "closes its start when its record is dropped, refused or unavailable, and a "
               "start refused by a full ring or the emitter is neither open nor given its "
               "ordinal again\n";
}

// A gap the full ring cannot take is held and written once, before the next
// invocation record when the ring has room, or when the configuration ends.
[[gnu::noinline]] void NativeJsInvocationHeldGaps() {
  NativeProbeQueue queue;
  sink.SetNativeJsInvocationContextProvider(&ReadInvocation);
  const auto next = [&]() {
    NativeProbeEvent event;
    assert(queue.TryPop(event));
    return event;
  };
  ConfigureInvocation(queue);
  const auto epoch = sink.NativeJsInvocationEpoch();
  // A refused start while the ring is full: the ring counts the gap it could
  // not take, and the site stays armed.
  Fill(queue);
  const auto dropped = queue.DroppedCount();
  auto wrong = StartFor(1, 1);
  wrong.anchor_offset = 42;
  assert(!sink.RecordNativeJsInvocationStart(epoch, 8, wrong));
  assert(queue.DroppedCount() == dropped + 1 && sink.IsNativeJsInvocationEnabled(epoch, 1));
  Drain(queue);
  // The held gap precedes the next start, and is written only once.
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 2)));
  assert(InvocationGap(next()) == "native_js_invocation_input_unavailable");
  assert(StartOrdinal(One(queue)) == 0);
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 3)));
  assert(StartOrdinal(One(queue)) == 1);

  // A held settle gap never splits a request from its request_initiated
  // record: it waits for the next start.
  Fill(queue);
  sink.NoteNativeJsInvocationSettleUnavailable(epoch, 8, 2);
  Drain(queue);
  InvocationProvider::context = {2, 3, true};
  sink.RecordNativeJsInvocationRequest(50);
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationRequest);
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 4)));
  assert(InvocationGap(next()) == "native_js_invocation_settle_unavailable");
  assert(StartOrdinal(One(queue)) == 0);

  // Per-slot gaps of high slots the full ring refuses are held together with
  // a fixed one, and each is written once before the next start.
  Fill(queue);
  sink.NoteNativeJsInvocationStatus(epoch, 998,
                                    reb::NativeJsInvocationSiteStatus::kCompiledBeforeArming);
  sink.NoteNativeJsInvocationStatus(epoch, 999,
                                    reb::NativeJsInvocationSiteStatus::kUnsupportedFunction);
  sink.NoteNativeJsInvocationStatus(epoch, 999,
                                    reb::NativeJsInvocationSiteStatus::kCompiledBeforeArming);
  sink.NoteNativeJsInvocationStatus(epoch, 3, reb::NativeJsInvocationSiteStatus::kIdsExhausted);
  Drain(queue);
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 5)));
  std::vector<std::string> held;
  for (std::size_t n = 0; n < 4; ++n)
    held.emplace_back(InvocationGap(next()));
  std::sort(held.begin(), held.end());
  assert((held == std::vector<std::string>{"native_js_invocation_ids_exhausted",
                                           "native_js_invocation_site_998_compiled_before_arming",
                                           "native_js_invocation_site_999_compiled_before_arming",
                                           "native_js_invocation_site_999_unsupported_function"}));
  assert(StartOrdinal(One(queue)) == 1);
  assert(sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 6)));
  assert(StartOrdinal(One(queue)) == 2);

  // Blink's refusals of starts from a detached document stay coalesced, and
  // the configuration's end writes the gap the full ring held.
  ConfigureInvocation(queue);
  const auto second = sink.NativeJsInvocationEpoch();
  Fill(queue);
  for (std::uint32_t n = 0; n < 6000; ++n)
    sink.NoteNativeJsInvocationInputUnavailable(second, 0);
  assert(sink.IsNativeJsInvocationEnabled(second, 0));
  Drain(queue);
  ConfigureInvocation(queue);
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(nullptr);
  std::cout << "PASS native JS invocation held gaps: a fixed or per-slot gap the full ring "
               "refuses is written once before the next start or when the configuration ends, "
               "never between a request and its request_initiated record\n";
}
}  // namespace
