// Native JavaScript invocation identity: the real sink, transport and ring
// with the same narrow boundaries as main.cc. The sink retains one site list
// for the process lifetime, so every case uses kInvocationSites and the
// changed-list refusal runs last.
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
const std::array<NativeJsInvocationSite, 2> kInvocationSites{InvocationSite(9, 41),
                                                             InvocationSite(9, 300)};
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
  payload.site_slot = static_cast<std::uint8_t>(slot);
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
NativeJsInvocationSettlePayload SettleFor(std::uint32_t id, bool digest, std::uint8_t slot = 0) {
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

[[gnu::noinline]] void NativeJsInvocationAdmission() {
  NativeProbeQueue queue;
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(&ReadInvocation);
  InvocationProvider::context = {2, 7, true};
  const auto before = allocations.load();
  // Disabled: nothing is armed, nothing allocates, nothing is recorded, and
  // consumers see not_observed without even reading V8.
  assert(sink.NativeJsInvocationEpoch() == 0 && !sink.IsNativeJsInvocationEnabled(2, 0));
  sink.RecordNativeJsInvocationStart(2, 8, StartFor(0, 1));
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

  // Armed but not called: an epoch and sites, and no record.
  ConfigureInvocation(queue);
  const auto epoch = sink.NativeJsInvocationEpoch();
  assert(epoch != 0 && (epoch & 1U) == 0 && !sink.NativeJsInvocationDigests(epoch));
  std::array<NativeJsInvocationSite, 8> copied{};
  assert(sink.CopyNativeJsInvocationSites(epoch, copied) == 2 && copied[1] == kInvocationSites[1]);
  assert(sink.CopyNativeJsInvocationSites(epoch - 2, copied) == 0);
  assert(Drain(queue) == 0);

  // A consumer reads the provider while active; an inconsistent read is not
  // observed rather than guessed.
  assert(sink.CurrentNativeJsInvocation().state == 2 &&
         sink.CurrentNativeJsInvocation().invocation_id == 7);
  InvocationProvider::context = {2, 0, true};
  assert(sink.CurrentNativeJsInvocation().state == 0);
  InvocationProvider::context = {1, 3, true};
  assert(sink.CurrentNativeJsInvocation().state == 0);

  // 64 starts per site, then one coalesced gap; the other site continues.
  for (std::uint32_t n = 0; n < 64; ++n) {
    sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, n + 1));
    const auto event = One(queue);
    assert(reb::IsValidNativeJsInvocationStartHeader(event.header));
    assert(std::to_integer<std::uint8_t>(event.inline_payload[28]) == n);
  }
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 65));
  assert(InvocationGap(One(queue)) == "native_js_invocation_site_budget_incomplete");
  assert(!sink.IsNativeJsInvocationEnabled(epoch, 0) && sink.IsNativeJsInvocationEnabled(epoch, 1));
  // A start that does not name its configured site is an input gap.
  auto wrong = StartFor(1, 70);
  wrong.anchor_offset = 42;
  sink.RecordNativeJsInvocationStart(epoch, 8, wrong);
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  sink.RecordNativeJsInvocationStart(epoch, 0, StartFor(1, 71));
  assert(Drain(queue) == 0);  // no frame: the same coalesced input gap

  // A settle without the digest opt-in may not carry a digest. The refused
  // settle still closes its start, so a second settle of it is not recorded.
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(1, true));
  assert(Drain(queue) == 0);  // refused; its input gap was already emitted
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(1, false));
  assert(Drain(queue) == 0);
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(2, false));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationSettle);

  // Requests: inside an invocation, recorded; script outside any invocation,
  // not recorded; a loader start outside script while one may be open,
  // unknown. 62 starts remain open after two settles.
  InvocationProvider::context = {2, 9, true};
  sink.RecordNativeJsInvocationRequest(31);
  auto request = One(queue);
  assert(reb::IsValidNativeJsInvocationRequestHeader(request.header) &&
         request.header.request_id == 31 &&
         std::to_integer<std::uint8_t>(request.inline_payload[4]) == 2 &&
         std::to_integer<std::uint8_t>(request.inline_payload[8]) == 9);
  InvocationProvider::context = {1, 0, true};
  sink.RecordNativeJsInvocationRequest(32);
  assert(Drain(queue) == 0);
  InvocationProvider::context = {1, 0, false};
  sink.RecordNativeJsInvocationRequest(33);
  request = One(queue);
  assert(std::to_integer<std::uint8_t>(request.inline_payload[4]) == 3 &&
         std::to_integer<std::uint8_t>(request.inline_payload[8]) == 0);
  // A worker reads as not observed and is never made unknown.
  InvocationProvider::context = {0, 0, false};
  sink.RecordNativeJsInvocationRequest(36);
  assert(Drain(queue) == 0);

  // Status gaps per configuration and slot.
  sink.NoteNativeJsInvocationStatus(epoch, 1,
                                    reb::NativeJsInvocationSiteStatus::kUnsupportedFunction);
  assert(InvocationGap(One(queue)) == "native_js_invocation_site_1_unsupported_function");
  sink.NoteNativeJsInvocationStatus(epoch, 1,
                                    reb::NativeJsInvocationSiteStatus::kUnsupportedFunction);
  sink.NoteNativeJsInvocationStatus(epoch, 2,
                                    reb::NativeJsInvocationSiteStatus::kCompiledBeforeArming);
  assert(Drain(queue) == 0);
  sink.NoteNativeJsInvocationStatus(epoch, 0,
                                    reb::NativeJsInvocationSiteStatus::kCompiledBeforeArming);
  assert(InvocationGap(One(queue)) == "native_js_invocation_site_0_compiled_before_arming");
  sink.NoteNativeJsInvocationSettleUnavailable(epoch, 8, 3);
  assert(InvocationGap(One(queue)) == "native_js_invocation_settle_unavailable");

  // A replacement configuration with the digest opt-in: fresh budgets, no
  // open invocations, and digests accepted.
  ConfigureInvocation(queue, true);
  const auto second = sink.NativeJsInvocationEpoch();
  assert(second > epoch && sink.NativeJsInvocationDigests(second));
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 1));  // stale epoch
  InvocationProvider::context = {1, 0, false};
  sink.RecordNativeJsInvocationRequest(34);  // nothing open in this configuration
  // An ID admitted by the earlier configuration is not open in this one.
  sink.RecordNativeJsInvocationSettle(second, 8, SettleFor(4, false));
  assert(Drain(queue) == 0);
  sink.RecordNativeJsInvocationStart(second, 8, StartFor(0, 80));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  sink.RecordNativeJsInvocationSettle(second, 8, SettleFor(80, true));
  auto settle = One(queue);
  assert(reb::IsValidNativeJsInvocationSettleHeader(settle.header) &&
         std::to_integer<std::uint8_t>(settle.inline_payload[16]) == 1);
  // 256 requests per configuration, then one coalesced gap. After the cap a
  // loader start reads neither the invocation context nor the frame.
  InvocationProvider::context = {2, 4, true};
  for (std::int32_t n = 0; n < 256; ++n)
    sink.RecordNativeJsInvocationRequest(100 + n);
  assert(Drain(queue) == 256);
  auto reads = InvocationProvider::reads;
  invocation_frame_lookups = 0;
  blink::test_frame_hook = &CountInvocationFrameLookup;
  sink.RecordNativeJsInvocationRequest(1000);
  assert(InvocationGap(One(queue)) == "native_js_invocation_request_budget_incomplete");
  assert(InvocationProvider::reads == reads + 1 && invocation_frame_lookups == 1);
  reads = InvocationProvider::reads;
  sink.RecordNativeJsInvocationRequest(1001);
  blink::test_frame_hook = nullptr;
  assert(Drain(queue) == 0);
  assert(InvocationProvider::reads == reads && invocation_frame_lookups == 1);
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

  // The browser keeps the list fixed; a different list arms nothing.
  transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, false,
                      {&queue, sizeof(queue)}, 0, {}, {},
                      InvocationRecords(std::span(kInvocationSites).first(1)), false);
  assert(sink.NativeJsInvocationEpoch() == 0);
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  transport.Configure(42, reb::kAllNativeProbeCategoryMask, kForever, false,
                      {&queue, sizeof(queue)}, 0, {}, {}, std::vector<std::uint8_t>(43, 1), false);
  assert(sink.NativeJsInvocationEpoch() == 0);
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(nullptr);
  std::cout << "PASS native JS invocation admission: disabled and allocation-free, category and "
               "expiry refusal, armed-but-not-called, 64 per site with coalesced gaps, exact "
               "site match, digest opt-in, inside/none/unknown requests with a 256 budget, "
               "status gaps and a fixed site list\n";
}

// The open count behind an unknown request follows admitted starts exactly:
// a settle closes its own start whether or not its record is retained, and
// the settle of a start that was never admitted closes nothing.
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
  // A stays pending on site 1 while site 0 spends its 64 starts.
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 1));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  for (std::uint32_t n = 0; n < 64; ++n) {
    sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, n + 2));
    sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(n + 2, false));
    assert(Drain(queue) == 2);
  }
  // B is refused by the site budget, yet V8 settles it. That settle is not
  // recorded and leaves A open.
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 66));
  assert(InvocationGap(One(queue)) == "native_js_invocation_site_budget_incomplete");
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(66, false));
  assert(Drain(queue) == 0);
  assert(unknown_requests(40) == 1);
  // The full ring drops A's settle, which the ring counts; A closes anyway.
  Fill(queue);
  const auto dropped = queue.DroppedCount();
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(1, false, 1));
  assert(queue.DroppedCount() == dropped + 1);
  Drain(queue);
  assert(unknown_requests(41) == 0);
  // C's settle names another slot than its start: refused as input, closed.
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 67));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(67, false, 0));
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  assert(unknown_requests(42) == 0);
  // D's settle job ran after its document went away: a gap, and D closes
  // once. The same report for a start that is not open says nothing.
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 68));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  assert(unknown_requests(43) == 1);
  sink.NoteNativeJsInvocationSettleUnavailable(epoch, 8, 68);
  assert(InvocationGap(One(queue)) == "native_js_invocation_settle_unavailable");
  sink.NoteNativeJsInvocationSettleUnavailable(epoch, 8, 68);
  sink.NoteNativeJsInvocationSettleUnavailable(epoch, 8, 66);
  assert(Drain(queue) == 0);
  assert(unknown_requests(44) == 0);
  // E settles once; a repeated settle of the same ID is not recorded.
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 69));
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(69, false, 1));
  assert(Drain(queue) == 2);
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(69, false, 1));
  assert(Drain(queue) == 0);
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(nullptr);
  std::cout << "PASS native JS invocation open starts: a settle closes only its admitted start, "
               "including when its record is dropped, refused or unavailable, and never a "
               "refused start\n";
}

// Every start V8 reports spends budget, and a spent budget stops admission at
// once even while the ring cannot take its gap, so refused calls never keep V8
// wrapping. A held gap is written before the next invocation record once the
// ring has room, or when the configuration ends.
[[gnu::noinline]] void NativeJsInvocationBudgetCaps() {
  NativeProbeQueue queue;
  sink.SetNativeJsInvocationContextProvider(&ReadInvocation);
  const auto next = [&]() {
    NativeProbeEvent event;
    assert(queue.TryPop(event));
    return event;
  };
  ConfigureInvocation(queue);
  const auto epoch = sink.NativeJsInvocationEpoch();
  for (std::uint32_t n = 0; n < 64; ++n) {
    sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, n + 1));
    sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(n + 1, false));
    assert(Drain(queue) == 2);
  }
  // The 65th call finds site 0 spent while the ring is full. Admission stops
  // at once and the ring counts the gap it could not take.
  Fill(queue);
  const auto dropped = queue.DroppedCount();
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(0, 65));
  assert(queue.DroppedCount() == dropped + 1);
  assert(!sink.IsNativeJsInvocationEnabled(epoch, 0) && sink.IsNativeJsInvocationEnabled(epoch, 1));
  Drain(queue);
  // V8 still settles the call it wrapped. That settle is not recorded; the
  // held gap is written once there is room, and only once.
  sink.RecordNativeJsInvocationSettle(epoch, 8, SettleFor(65, false));
  assert(InvocationGap(One(queue)) == "native_js_invocation_site_budget_incomplete");
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 66));
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  // Starts refused as input spend site 1's remaining 63 like retained ones.
  auto wrong = StartFor(1, 67);
  wrong.anchor_offset = 42;
  for (std::uint32_t n = 0; n < 63; ++n) {
    wrong.invocation_id = 67 + n;
    sink.RecordNativeJsInvocationStart(epoch, 8, wrong);
  }
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  assert(sink.IsNativeJsInvocationEnabled(epoch, 1));
  sink.RecordNativeJsInvocationStart(epoch, 8, StartFor(1, 130));
  assert(Drain(queue) == 0);  // the site budget gap is per configuration
  assert(!sink.IsNativeJsInvocationEnabled(epoch, 1));

  // Blink's refusals of starts from a detached document spend the
  // configuration's 256. The cap holds while the ring is full, and the
  // configuration's end writes the held gap.
  ConfigureInvocation(queue);
  const auto second = sink.NativeJsInvocationEpoch();
  for (std::uint32_t n = 0; n < 256; ++n)
    sink.NoteNativeJsInvocationInputUnavailable(second, 0);
  assert(InvocationGap(One(queue)) == "native_js_invocation_input_unavailable");
  assert(sink.IsNativeJsInvocationEnabled(second, 0));
  Fill(queue);
  sink.NoteNativeJsInvocationInputUnavailable(second, 0);
  assert(!sink.IsNativeJsInvocationEnabled(second, 0) &&
         !sink.IsNativeJsInvocationEnabled(second, 1));
  Drain(queue);
  ConfigureInvocation(queue);
  assert(InvocationGap(One(queue)) == "native_js_invocation_budget_incomplete");

  // The request budget caps the same way; its held gap precedes the next
  // start rather than splitting a request from its request_initiated record.
  const auto third = sink.NativeJsInvocationEpoch();
  InvocationProvider::context = {2, 4, true};
  for (std::int32_t n = 0; n < 256; ++n)
    sink.RecordNativeJsInvocationRequest(100 + n);
  assert(Drain(queue) == 256);
  Fill(queue);
  sink.RecordNativeJsInvocationRequest(1000);
  Drain(queue);
  sink.RecordNativeJsInvocationRequest(1001);
  assert(Drain(queue) == 0);
  sink.RecordNativeJsInvocationStart(third, 8, StartFor(0, 140));
  assert(InvocationGap(next()) == "native_js_invocation_request_budget_incomplete");
  assert(One(queue).header.type == reb::NativeProbeType::kJsInvocationStart);
  transport.Disable();
  sink.SetNativeJsInvocationContextProvider(nullptr);
  std::cout << "PASS native JS invocation budget caps: refused starts spend budget, a spent "
               "budget stops admission with a full ring, and held gaps are written once the "
               "ring has room or the configuration ends\n";
}
}  // namespace
