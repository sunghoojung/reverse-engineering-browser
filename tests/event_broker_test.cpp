#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "reb/broker_refusal.hpp"
#include "reb/event.hpp"
#include "reb/event_broker.hpp"

namespace {

int failures = 0;

void Expect(const bool condition, const std::string_view message) {
  if (!condition) {
    std::cerr << message << '\n';
    ++failures;
  }
}

reb::EventRecord Make(const reb::EventCategory category,
                      const reb::EventType type,
                      const std::uint64_t sequence) {
  return reb::MakeEvent(category, type, sequence, sequence, 7);
}

bool Accept(reb::EventBroker& broker, const reb::EventRecord& event) {
  return broker.Ingest(event) == reb::IngestStatus::kAccepted;
}

reb::BrokerRefusalPayload RefusalOf(const reb::EventRecord& refusal) {
  reb::BrokerRefusalPayload payload;
  Expect(reb::DecodeBrokerRefusalPayload(reb::InlinePayload(refusal), payload),
         "refusal payload decodes");
  return payload;
}

// A canvas call in stream (7, process 11) that one mutation makes invalid.
reb::EventRecord Refusable(const std::uint64_t sequence) {
  reb::EventRecord event = Make(reb::EventCategory::kCanvas, reb::EventType::kApiCall, sequence);
  event.header.process_id = 11;
  event.header.thread_id = 12;
  event.header.tab_id = 13;
  event.header.navigation_id = 14;
  event.header.frame_id = 15;
  event.header.artifact_id = 16;
  event.header.parent_event_id = sequence - 1;
  event.header.request_id = 17;
  return event;
}

void CheckRefusals() {
  struct Case {
    reb::EventRefusal reason;
    void (*mutate)(reb::EventRecord&);
  };
  const Case cases[] = {
      {reb::EventRefusal::kProtocolVersion,
       [](reb::EventRecord& e) { e.header.protocol_version = 2; }},
      {reb::EventRefusal::kHeaderSize, [](reb::EventRecord& e) { e.header.header_size = 100; }},
      {reb::EventRefusal::kProcessId,
       [](reb::EventRecord& e) { e.header.process_id = reb::kBrokerProcessId; }},
      {reb::EventRefusal::kPayloadSize, [](reb::EventRecord& e) { e.header.payload_size = 129; }},
      {reb::EventRefusal::kReserved, [](reb::EventRecord& e) { e.reserved[47] = std::byte{1}; }},
      {reb::EventRefusal::kCategory,
       [](reb::EventRecord& e) { e.header.category = static_cast<reb::EventCategory>(999); }},
      {reb::EventRefusal::kType,
       [](reb::EventRecord& e) { e.header.type = static_cast<reb::EventType>(9999); }},
      // Only the broker writes a refusal, so one on the wire is refused.
      {reb::EventRefusal::kType,
       [](reb::EventRecord& e) { e.header.type = reb::EventType::kBrokerRefusal; }},
      {reb::EventRefusal::kFlags, [](reb::EventRecord& e) { e.header.flags = 0x8000; }},
      {reb::EventRefusal::kNetworkClass, [](reb::EventRecord& e) { e.header.scheme_class = 99; }},
      {reb::EventRefusal::kTypedPayload,
       [](reb::EventRecord& e) { e.header.type = reb::EventType::kWasmGuestDispatch; }},
  };
  for (const Case& test : cases) {
    const std::string name(reb::EventRefusalName(test.reason));
    reb::EventBroker broker(8);
    reb::EventRecord refused = Refusable(2);
    test.mutate(refused);
    Expect(reb::EventRefusalOf(refused) == test.reason, name + ": first failed check");
    Expect(!reb::IsValidEvent(refused), name + ": invalid");
    reb::EventRecord refusal;
    Expect(Accept(broker, Refusable(1)), name + ": stream start");
    Expect(broker.IngestAt(refused, 500, &refusal) == reb::IngestStatus::kRefused,
           name + ": refused with a record");
    Expect(Accept(broker, Refusable(3)), name + ": stream end");
    Expect(reb::IsValidBrokerRefusal(refusal), name + ": refusal is well formed");
    Expect(!reb::IsValidEvent(refusal), name + ": refusal is not a producer record");
    const reb::EventRefusal again =
        reb::IsEnvelopeRefusal(test.reason)           ? reb::EventRefusal::kProcessId
        : test.reason == reb::EventRefusal::kCategory ? reb::EventRefusal::kCategory
                                                      : reb::EventRefusal::kType;
    Expect(reb::EventRefusalOf(refusal) == again,
           name + ": a stored refusal sent back is refused again");
    const reb::BrokerRefusalPayload payload = RefusalOf(refusal);
    Expect(payload.reason == test.reason, name + ": reason");
    Expect(payload.received_monotonic_time_ns == 500, name + ": arrival time");
    Expect(payload.protocol_version == refused.header.protocol_version &&
               payload.header_size == refused.header.header_size &&
               payload.category == static_cast<std::uint16_t>(refused.header.category) &&
               payload.type == static_cast<std::uint16_t>(refused.header.type) &&
               payload.payload_size == refused.header.payload_size &&
               payload.flags == refused.header.flags &&
               payload.scheme_class == refused.header.scheme_class &&
               payload.sequence_number == 2 && payload.monotonic_time_ns == 2 &&
               payload.process_id == refused.header.process_id && payload.thread_id == 12,
           name + ": the fields as read");
    const reb::EventHeader& header = refusal.header;
    Expect(header.session_id == 7, name + ": session");
    Expect(header.category == (test.reason == reb::EventRefusal::kCategory
                                   ? reb::EventCategory::kUnknown
                                   : reb::EventCategory::kCanvas),
           name + ": category");
    const reb::BrokerStats stats = broker.Stats();
    Expect(stats.accepted == 2 && stats.invalid == 1 && stats.refusals_recorded == 1,
           name + ": counted");
    // A refusal takes the refused record's place, closing its hole, unless the
    // refused header cannot be trusted to name that place.
    Expect(stats.sequence_gaps == (reb::IsEnvelopeRefusal(test.reason) ? 1U : 0U),
           name + ": sequence gaps");
    if (reb::IsEnvelopeRefusal(test.reason)) {
      Expect(payload.identity == reb::BrokerRefusalIdentity::kBroker, name + ": broker identity");
      Expect(header.process_id == reb::kBrokerProcessId && header.thread_id == 0 &&
                 header.sequence_number == 1 && header.monotonic_time_ns == 500 &&
                 header.tab_id == 0 && header.frame_id == 0 && header.parent_event_id == 0 &&
                 header.request_id == 0,
             name + ": the broker's stream");
    } else {
      Expect(payload.identity == reb::BrokerRefusalIdentity::kRefused, name + ": refused identity");
      Expect(header.process_id == 11 && header.thread_id == 12 && header.sequence_number == 2 &&
                 header.monotonic_time_ns == 2 && header.tab_id == 13 &&
                 header.navigation_id == 14 && header.frame_id == 15 && header.artifact_id == 16 &&
                 header.parent_event_id == 1 && header.request_id == 17,
             name + ": the refused record's place");
    }
    const std::vector<reb::EventRecord> window = broker.Snapshot(8);
    Expect(window.size() == 3 && window[1].header.type == reb::EventType::kBrokerRefusal,
           name + ": retained in arrival order");
    // A reader rejects a refusal whose fields disagree with its reason.
    reb::EventRecord forged = refusal;
    reb::BrokerRefusalPayload wrong = payload;
    wrong.reason = test.reason == reb::EventRefusal::kCategory ? reb::EventRefusal::kTypedPayload
                                                               : reb::EventRefusal::kCategory;
    Expect(reb::SetInlinePayload(forged, reb::EncodeBrokerRefusalPayload(wrong)),
           name + ": forged payload");
    Expect(!reb::IsValidBrokerRefusal(forged), name + ": a disagreeing reason is rejected");
  }

  // The broker's own stream is contiguous across envelope refusals, whatever
  // the refused headers claimed.
  reb::EventBroker envelopes(8);
  reb::EventRecord first = Refusable(90);
  first.header.protocol_version = 9;
  reb::EventRecord second = Refusable(4);
  second.header.process_id = reb::kBrokerProcessId;
  second.header.sequence_number = 40;
  reb::EventRecord one;
  reb::EventRecord two;
  Expect(envelopes.IngestAt(first, 10, &one) == reb::IngestStatus::kRefused &&
             envelopes.IngestAt(second, 20, &two) == reb::IngestStatus::kRefused,
         "envelope refusals recorded");
  Expect(one.header.sequence_number == 1 && two.header.sequence_number == 2 &&
             one.header.process_id == reb::kBrokerProcessId &&
             two.header.process_id == reb::kBrokerProcessId,
         "the broker numbers its stream 1, 2");
  Expect(envelopes.Stats().sequence_gaps == 0, "the broker's stream has no hole");

  reb::EventRecord reserved = Refusable(2);
  reserved.header.reserved2 = 1;

  // Disabled: an excluded category or an expired session stores nothing, as
  // for a valid record, but the refusal is still counted invalid.
  reb::SessionPolicy webgl_only;
  webgl_only.category_mask = reb::EventCategoryMask(reb::EventCategory::kWebGl);
  webgl_only.expires_at_monotonic_ns = 1000;
  reb::EventBroker masked(8, webgl_only);
  reb::EventRecord dropped;
  Expect(masked.IngestAt(reserved, 10, &dropped) == reb::IngestStatus::kInvalid,
         "an excluded category leaves no refusal");
  Expect(dropped.header.type != reb::EventType::kBrokerRefusal, "no refusal is handed out");
  reb::EventRecord unknown = reserved;
  unknown.header.reserved2 = 0;
  unknown.header.category = static_cast<reb::EventCategory>(77);
  Expect(masked.IngestAt(unknown, 10) == reb::IngestStatus::kRefused,
         "an unknown category cannot be matched against the mask, so it is kept");
  reb::EventRecord webgl = reserved;
  webgl.header.category = reb::EventCategory::kWebGl;
  Expect(masked.IngestAt(webgl, 1000) == reb::IngestStatus::kInvalid,
         "an expired session leaves no refusal");
  const reb::BrokerStats masked_stats = masked.Stats();
  Expect(masked_stats.invalid == 3 && masked_stats.refusals_recorded == 1 &&
             masked_stats.category_rejected == 0 && masked_stats.expired == 0,
         "every refusal counts invalid; one is recorded");
  Expect(masked.Snapshot(8).size() == 1, "only the unknown-category refusal is retained");

  // A refusal is retained like any record, so a full ring evicts it.
  reb::EventBroker ring(2);
  Expect(ring.Ingest(reserved) == reb::IngestStatus::kRefused, "ring refusal");
  Expect(Accept(ring, Refusable(3)) && Accept(ring, Refusable(4)), "ring fills");
  Expect(ring.Stats().evicted == 1 && ring.Stats().refusals_recorded == 1,
         "eviction keeps the refusal count");

  reb::BrokerRefusalPayload round{};
  round.reason = reb::EventRefusal::kNetworkClass;
  round.protocol_version = 3;
  round.header_size = 144;
  round.category = 0xbeef;
  round.type = 0xcafe;
  round.payload_size = 0xdeadbeef;
  round.flags = 0xf00d;
  round.scheme_class = 0xab;
  round.loader_kind = 0xcd;
  round.received_monotonic_time_ns = 0x0102030405060708ULL;
  round.sequence_number = std::numeric_limits<std::uint64_t>::max();
  round.monotonic_time_ns = 0x1112131415161718ULL;
  round.process_id = 0x21222324;
  round.thread_id = 0x31323334;
  auto bytes = reb::EncodeBrokerRefusalPayload(round);
  reb::BrokerRefusalPayload decoded;
  Expect(reb::DecodeBrokerRefusalPayload(bytes, decoded) && decoded.reason == round.reason &&
             decoded.category == round.category && decoded.type == round.type &&
             decoded.payload_size == round.payload_size && decoded.flags == round.flags &&
             decoded.scheme_class == round.scheme_class &&
             decoded.loader_kind == round.loader_kind &&
             decoded.received_monotonic_time_ns == round.received_monotonic_time_ns &&
             decoded.sequence_number == round.sequence_number &&
             decoded.monotonic_time_ns == round.monotonic_time_ns &&
             decoded.process_id == round.process_id && decoded.thread_id == round.thread_id,
         "payload round trip");
  Expect(std::to_integer<int>(bytes[4]) == 9 && std::to_integer<int>(bytes[16]) == 0xef &&
             std::to_integer<int>(bytes[22]) == 0xab && std::to_integer<int>(bytes[55]) == 0x31,
         "little-endian offsets");
  bytes[56] = std::byte{1};
  Expect(!reb::DecodeBrokerRefusalPayload(bytes, decoded), "trailing bytes stay zero");
  Expect(!reb::DecodeBrokerRefusalPayload(std::span(bytes).first(127), decoded),
         "the payload is exactly 128 bytes");
}

}  // namespace

int main() {
  constexpr std::size_t kWindow = 5000;
  constexpr std::uint64_t kDrops = 280;
  reb::EventBroker broker(kWindow + 16);
  const reb::EventType kRequests[] = {
      reb::EventType::kRequestInitiated,
      reb::EventType::kRequestStarted,
      reb::EventType::kResponseStarted,
      reb::EventType::kRequestCompleted,
  };
  for (std::size_t index = 0; index < 4; ++index) {
    Expect(Accept(broker, Make(reb::EventCategory::kNetwork, kRequests[index], index + 1)),
           "request ingest");
  }
  reb::EventRecord gap = Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 285);
  Expect(reb::SetInlinePayload(gap, "280"), "gap payload");
  Expect(Accept(broker, gap), "gap ingest");
  for (std::uint64_t sequence = 286; sequence <= 5286; ++sequence) {
    Expect(Accept(broker, Make(reb::EventCategory::kCanvas, reb::EventType::kApiCall, sequence)),
           "canvas ingest");
  }

  const reb::BrokerStats stats = broker.Stats();
  Expect(stats.queue_drops == kDrops, "capture-wide queue drops stay 280");
  Expect(!stats.queue_drops_saturated, "queue drops are not saturated");
  Expect(stats.sequence_gaps == kDrops, "capture-wide sequence gaps stay 280");
  Expect(!stats.sequence_gaps_saturated, "sequence gaps are not saturated");

  const std::vector<reb::EventRecord> window = broker.Snapshot(kWindow);
  Expect(window.size() == kWindow, "snapshot keeps the 5000-event cap");
  Expect(window.front().header.sequence_number == 287,
         "low-level snapshots remain the newest general suffix");
  Expect(window.back().header.sequence_number == 5286, "newest record stays visible");
  Expect(std::ranges::none_of(window,
                              [](const reb::EventRecord& event) {
                                return event.header.category == reb::EventCategory::kNetwork;
                              }),
         "network retention belongs to the independent disk-backed API window");

  reb::EventBroker evicting(4);
  Expect(Accept(evicting, Make(reb::EventCategory::kWebGl, reb::EventType::kApiCall, 1)),
         "prefix ingest");
  reb::EventRecord evicted_gap = Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 282);
  Expect(reb::SetInlinePayload(evicted_gap, "280"), "evicted gap payload");
  Expect(Accept(evicting, evicted_gap), "evicted gap ingest");
  for (std::uint64_t sequence = 283; sequence < 283 + 8; ++sequence) {
    Expect(Accept(evicting, Make(reb::EventCategory::kWebGl, reb::EventType::kApiCall, sequence)),
           "webgl ingest");
  }
  const reb::BrokerStats retained = evicting.Stats();
  Expect(retained.queue_drops == kDrops, "queue drops survive ring eviction");
  Expect(retained.sequence_gaps == kDrops, "sequence gaps survive ring eviction");
  const std::vector<reb::EventRecord> retained_window = evicting.Snapshot(4);
  Expect(retained_window.size() == 4, "evicting ring stays at capacity");
  Expect(std::ranges::none_of(retained_window,
                              [](const reb::EventRecord& event) {
                                return event.header.type == reb::EventType::kGap;
                              }),
         "a full ring of non-canvas events can drop the gap record itself");

  for (const std::string_view payload :
       {"", "0", "01", "-1", "+1", " 2", "2 ", "18446744073709551616"}) {
    reb::EventBroker invalid_payload(1);
    reb::EventRecord event = Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 1);
    Expect(reb::SetInlinePayload(event, payload), "bounded malformed count payload");
    Expect(Accept(invalid_payload, event), "gap record envelope remains valid");
    Expect(invalid_payload.Stats().queue_drops == 1, "noncanonical drop count weighs one");
  }
  reb::EventBroker saturating(1);
  reb::EventRecord maximum = Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 1);
  Expect(reb::SetInlinePayload(maximum, "18446744073709551615"), "maximum count payload");
  Expect(Accept(saturating, maximum), "maximum count ingest");
  Expect(Accept(saturating, Make(reb::EventCategory::kWebGl, reb::EventType::kGap, 2)),
         "overflow ingest");
  Expect(saturating.Stats().queue_drops == std::numeric_limits<std::uint64_t>::max(),
         "drop count saturates");
  Expect(saturating.Stats().queue_drops_saturated, "saturation is explicit");

  const auto api = [&](std::uint64_t sequence) {
    return Make(reb::EventCategory::kRuntime, reb::EventType::kApiCall, sequence);
  };
  reb::EventBroker delayed(8);
  Expect(Accept(delayed, api(3)) && Accept(delayed, api(1)), "reverse arrival accepted");
  Expect(delayed.Stats().sequence_gaps == 1, "lower bound exposes one absent ID");
  Expect(Accept(delayed, api(2)) && Accept(delayed, api(2)), "late and duplicate accepted");
  Expect(delayed.Stats().sequence_gaps == 0, "late ID closes hole; duplicate neutral");
  Expect(Accept(delayed, api(8)), "forward gap accepted");
  Expect(delayed.Stats().sequence_gaps == 4, "four IDs missing");
  for (auto sequence : {6U, 4U, 7U, 5U})
    Expect(Accept(delayed, api(sequence)), "split hole fill");
  Expect(delayed.Stats().sequence_gaps == 0, "split holes close despite ring eviction");
  auto other = api(100);
  other.header.process_id = 99;
  Expect(Accept(delayed, other), "independent process accepted");
  Expect(delayed.Stats().sequence_gaps == 0, "unknown process prefix not counted");
  reb::EventBroker bounded(1);
  for (auto sequence : {1U, 3U, 5U})
    Expect(Accept(bounded, api(sequence)), "bounded holes");
  Expect(bounded.Stats().sequence_tracking_evictions == 1, "interval budget eviction explicit");
  Expect(bounded.Stats().sequence_gaps == 0, "evicted uncertainty not permanent loss");
  reb::EventBroker large(8);
  for (std::uint32_t process : {1U, 2U}) {
    auto first = api(1), last = api(std::numeric_limits<std::uint64_t>::max());
    first.header.process_id = last.header.process_id = process;
    Expect(Accept(large, first) && Accept(large, last), "wide bounds");
  }
  Expect(large.Stats().sequence_gaps_saturated, "distinct holes saturate safely");
  reb::EventBroker retract(8);
  Expect(Accept(retract, api(1)) && Accept(retract, api(std::numeric_limits<std::uint64_t>::max())),
         "large interval");
  auto small = api(1);
  small.header.process_id = 88;
  Expect(Accept(retract, small), "second stream");
  small.header.sequence_number = 6;
  Expect(Accept(retract, small), "second hole");
  Expect(retract.Stats().sequence_gaps_saturated, "combined saturation");
  for (auto sequence : {2U, 3U}) {
    small.header.sequence_number = sequence;
    Expect(Accept(retract, small), "late saturation retraction");
  }
  Expect(!retract.Stats().sequence_gaps_saturated &&
             retract.Stats().sequence_gaps == std::numeric_limits<std::uint64_t>::max(),
         "exact maximum unsaturates");
  // Independent set oracle for interleaved, duplicate and out-of-order arrivals.
  reb::EventBroker permutation(128);
  std::map<std::uint32_t, std::set<std::uint64_t>> observed;
  std::uint32_t random = 0x327U;
  for (std::size_t index = 0; index < 1000; ++index) {
    random = random * 1664525U + 1013904223U;
    const auto process = (random >> 16U) % 3U + 1U;
    const std::uint64_t sequence = (random >> 8U) % 64U + 1U;
    auto arrival = api(sequence);
    arrival.header.process_id = process;
    Expect(Accept(permutation, arrival), "interleaved arrival");
    observed[process].insert(sequence);
    std::uint64_t absent = 0;
    for (const auto& [unused, ids] : observed) {
      static_cast<void>(unused);
      absent += *ids.rbegin() - *ids.begin() - static_cast<std::uint64_t>(ids.size() - 1);
    }
    Expect(permutation.Stats().sequence_gaps == absent, "tracker matches independent ID set");
    Expect(permutation.Stats().sequence_tracking_evictions == 0, "property fixture fits budget");
  }

  CheckRefusals();

  if (failures != 0) {
    std::cerr << failures << " event broker window checks failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "PASS event broker preserves newest general snapshots, "
               "reports 280 capture-wide queue drops and records every refusal\n";
  return EXIT_SUCCESS;
}
