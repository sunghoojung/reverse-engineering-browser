// Browser-internal exclusion and renderer-answered requests,
// protocol/native-network-v3.md, through the real sink, transport and ring.
#pragma once

#include <memory>

#include "reb/event.hpp"
#include "reb/network_request.hpp"
#include "reb/network_scope.hpp"

namespace {

void ConfigureScope(NativeProbeQueue& queue, bool content, bool internal, std::uint64_t session) {
  transport.Configure(session, reb::kAllNativeProbeCategoryMask, kForever, false,
                      {&queue, sizeof(queue)}, 0, {}, {}, {}, false, content, internal);
}

reb::EventRecord Core(const NativeProbeEvent& event) {
  const auto record = std::bit_cast<reb::EventRecord>(event);
  assert(reb::IsValidEvent(record));
  return record;
}

void BrowserInternalExclusion() {
  NativeProbeQueue queue;
  ConfigureScope(queue, false, false, 51);
  const auto notified = reb::mojom::NativeProbeHost::notifications.load();
  const auto before = allocations.load();
  for (const std::string_view scheme :
       {"chrome", "chrome", "chrome-untrusted", "brave", "devtools", "chrome-search"}) {
    assert(!sink.RecordRequestInitiated(3, "GET", scheme, "resources").recorded());
  }
  assert(allocations == before && Drain(queue) == 0 && queue.DroppedCount() == 0);
  assert(queue.ExclusionCount(0) == 2 && queue.ExclusionCount(1) == 1 &&
         queue.ExclusionCount(2) == 1 && queue.ExclusionCount(3) == 1 &&
         queue.ExclusionCount(4) == 1 && queue.ExclusionCount(5) == 0);
  // One wake-up announces the counts until the browser clears it.
  assert(reb::mojom::NativeProbeHost::notifications == notified + 1);

  for (const auto& [scheme, expected] :
       std::array<std::pair<std::string_view, std::uint8_t>, 8>{{{"https", 2},
                                                                 {"http", 1},
                                                                 {"wss", 4},
                                                                 {"data", 5},
                                                                 {"blob", 6},
                                                                 {"file", 7},
                                                                 {"chrome-extension", 8},
                                                                 {"filesystem", 15}}}) {
    const auto request = sink.RecordRequestInitiated(4, "GET", scheme, "example.test");
    assert(request.recorded() && static_cast<std::uint8_t>(request.scheme_class) == expected);
    const auto event = One(queue);
    assert(event.header.scheme_class == expected && Core(event).header.scheme_class == expected);
  }

  auto opted_ring = std::make_unique<NativeProbeQueue>();
  auto& opted = *opted_ring;
  ConfigureScope(opted, false, true, 52);
  const auto internal = sink.RecordRequestInitiated(5, "GET", "chrome", "newtab");
  assert(internal.recorded() && One(opted).header.scheme_class == 16);
  assert(opted.ExclusionCount(0) == 0);

  auto network_off_ring = std::make_unique<NativeProbeQueue>();
  auto& network_off = *network_off_ring;
  transport.Configure(53, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas), kForever,
                      false, {&network_off, sizeof(network_off)});
  assert(!sink.RecordRequestInitiated(6, "GET", "chrome", "newtab").recorded());
  assert(network_off.ExclusionCount(0) == 0 && Drain(network_off) == 0);
  transport.Disable();
  assert(!sink.RecordRequestInitiated(6, "GET", "chrome", "newtab").recorded());
  assert(network_off.ExclusionCount(0) == 0);
  std::cout << "PASS browser-internal schemes are counted per class, never recorded, "
               "unless the configuration opts in\n";
}

reb::RequestTargetPayload TargetOf(const NativeProbeEvent& event) {
  const auto record = Core(event);
  assert(record.header.type == reb::EventType::kRequestTarget);
  reb::RequestTargetPayload value;
  assert(reb::DecodeRequestTargetPayload(record.inline_payload, value));
  return value;
}

void RendererAnsweredRequests() {
  NativeProbeQueue queue;
  ConfigureScope(queue, true, false, 61);
  blink::test_frame_present = true;
  auto proxied = sink.RecordRequestInitiated(10, "GET", "https", "example.test");
  const auto proxied_start = One(queue);
  blink::test_frame_present = false;
  proxied.NoteResponse(200, false, false);
  // The browser proxy finishes this one; the renderer adds nothing.
  sink.RecordRendererRequestComplete(proxied, "/app.js", 7, -1, 0, 10, 10);
  assert(Drain(queue) == 0);

  proxied.NoteResponse(200, true, false);
  sink.RecordRendererRequestComplete(proxied, "/sw?q=1", 7, 8443, 0, 0, 42);
  const auto target_event = Pop(queue);
  const auto completed = One(queue);
  const auto target = TargetOf(target_event);
  assert(target_event.header.parent_event_id == proxied_start.header.sequence_number &&
         target_event.header.process_id == proxied_start.header.process_id &&
         target_event.header.frame_id == proxied_start.header.frame_id &&
         target_event.header.frame_id != 0 && target_event.header.request_id == 10 &&
         target.target_length == 7 &&
         target.scheme == static_cast<std::uint8_t>(reb::RequestScheme::kHttps) &&
         target.port == 8443);
  const auto record = Core(completed);
  assert(record.header.type == reb::EventType::kRequestCompleted &&
         record.header.status_code == 200 && record.header.decoded_body_length == 42 &&
         record.header.request_id == 10 &&
         record.header.frame_id == proxied_start.header.frame_id &&
         record.header.scheme_class == 2 && record.header.parent_event_id == 0 &&
         (record.header.flags & static_cast<std::uint16_t>(reb::EventFlag::kFromServiceWorker)));

  auto data = sink.RecordRequestInitiated(11, "GET", "data", "");
  One(queue);
  data.NoteResponse(200, false, false);
  sink.RecordRendererRequestComplete(data, std::string(116, 'a'), 200, -1, 0, 200, 150);
  const auto long_target = TargetOf(Pop(queue));
  assert(long_target.target_length == 200 && long_target.scheme == 0);
  assert(Core(One(queue)).header.scheme_class == 5);

  auto blob = sink.RecordRequestInitiated(12, "GET", "blob", "");
  One(queue);
  sink.RecordRendererRequestComplete(blob, "https://example.test/uuid", 25, -1, -6, 0, 0);
  Pop(queue);
  const auto failed = Core(One(queue));
  assert(failed.header.type == reb::EventType::kRequestFailed && failed.header.error_code == -6 &&
         failed.header.status_code == 0 && failed.header.scheme_class == 6);

  // Metadata sessions finish the row without its path.
  auto metadata_ring = std::make_unique<NativeProbeQueue>();
  auto& metadata = *metadata_ring;
  ConfigureScope(metadata, false, false, 62);
  auto quiet = sink.RecordRequestInitiated(13, "GET", "data", "");
  One(metadata);
  quiet.NoteResponse(200, false, false);
  sink.RecordRendererRequestComplete(quiet, "text/plain,hi", 13, -1, 0, 13, 2);
  assert(Core(One(metadata)).header.type == reb::EventType::kRequestCompleted);

  // A start never finishes into a later configuration.
  auto stale = sink.RecordRequestInitiated(14, "GET", "data", "");
  One(metadata);
  ConfigureScope(metadata, true, false, 62);
  sink.RecordRendererRequestComplete(stale, "text/plain,hi", 13, -1, 0, 13, 2);
  assert(Drain(metadata) == 0);

  // A start the ring refused has nothing to finish.
  Fill(metadata);
  assert(!sink.RecordRequestInitiated(15, "GET", "data", "").recorded());
  assert(metadata.DroppedCount() == 1);
  Drain(metadata);

  transport.Disable();
  const auto before = allocations.load();
  for (int index = 0; index < 1000; ++index) {
    auto inactive = sink.RecordRequestInitiated(16, "GET", "data", "");
    inactive.NoteResponse(200, true, false);
    sink.RecordRendererRequestComplete(inactive, "x", 1, -1, 0, 1, 1);
    assert(!sink.IsCaptureArmed());
    assert(!inactive.recorded() && !inactive.AnsweredInRenderer());
  }
  assert(allocations == before && Drain(metadata) == 0);
  std::cout << "PASS renderer-answered requests finish with their own target and completion; "
               "proxied, stale, refused and inactive requests add nothing\n";
}

}  // namespace
