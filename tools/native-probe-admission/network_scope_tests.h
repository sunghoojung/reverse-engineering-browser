// Browser-internal exclusion and renderer-answered requests,
// protocol/native-network-v3.md, through the real sink, transport and ring.
#pragma once

#include <memory>
#include <thread>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#include "brave/components/reverse_engineering_browser/renderer/native_fetch_owner.h"
#include "brave/components/reverse_engineering_browser/renderer/native_service_worker_starts.h"
#include "reb/event.hpp"
#include "reb/network_request.hpp"
#include "reb/network_scope.hpp"
#include "reb/tab_link.hpp"

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

// protocol/native-network-v3.md "Request owners and tabs": the loader's fetch
// owner, not the running script, names a request's document or worker.
void RendererFetchOwners() {
  NativeProbeQueue queue;
  ConfigureScope(queue, false, false, 63);
  reb::EventRecord parser, worker, restored;
  {
    const reb::NativeFetchOwnerScope document({reb::NativeLoaderKind::kDocument, 0x1234});
    static_cast<void>(sink.RecordRequestInitiated(20, "GET", "https", "example.test"));
    parser = Core(One(queue));
    {
      const reb::NativeFetchOwnerScope nested({reb::NativeLoaderKind::kDedicatedWorker, 0x77});
      static_cast<void>(sink.RecordRequestInitiated(21, "GET", "https", "example.test"));
      worker = Core(One(queue));
    }
    static_cast<void>(sink.RecordRequestInitiated(22, "GET", "https", "example.test"));
    restored = Core(One(queue));
  }
  assert(parser.header.frame_id == 0x1234 && parser.header.loader_kind == 16);
  assert(worker.header.frame_id == 0x77 && worker.header.loader_kind == 17);
  assert(restored.header.frame_id == 0x1234 && restored.header.loader_kind == 16);
  // Without an owner the running script's frame is kept and labelled as such.
  static_cast<void>(sink.RecordRequestInitiated(23, "GET", "https", "example.test"));
  const auto script = Core(One(queue));
  assert(script.header.frame_id == 0 && script.header.loader_kind == 21);
  // A default owner is a no-op, so inactive loaders touch nothing.
  {
    const reb::NativeFetchOwnerScope none({});
    assert(reb::NativeFetchOwnerScope::Current().kind == reb::NativeLoaderKind::kNotRecorded);
  }
  auto mislabelled = parser;
  mislabelled.header.loader_kind = 3;
  assert(!reb::IsValidEvent(mislabelled));
  transport.Disable();
  std::cout << "PASS request_initiated names its fetch owner's document or worker, falls back "
               "to the script frame, and validates its loader kind\n";
}

std::string_view GapReason(const NativeProbeEvent& event) {
  assert(event.header.type == reb::NativeProbeType::kGap &&
         event.header.category == reb::NativeProbeCategory::kNetwork);
  return {reinterpret_cast<const char*>(event.inline_payload.data()), event.header.payload_size};
}

// protocol/native-network-v3.md "Service worker ends without a response".
void ServiceWorkerRequestEnds() {
  NativeProbeQueue queue;
  ConfigureScope(queue, true, false, 64);
  reb::EventRecord start;
  {
    const reb::NativeFetchOwnerScope document({reb::NativeLoaderKind::kDocument, 0x5151});
    static_cast<void>(sink.RecordRequestInitiated(5000, "GET", "https", "example.test"));
    start = Core(One(queue));
  }
  // The end runs on the loader's thread, which has no owner scope.
  sink.RecordServiceWorkerRequestEnd(5000, "/api?id=7", 9, 8443, -2);
  const auto target_event = Pop(queue);
  const auto failed = Core(One(queue));
  const auto target = TargetOf(target_event);
  assert(target_event.header.parent_event_id == start.header.sequence_number &&
         target_event.header.thread_id == start.header.thread_id &&
         target_event.header.frame_id == 0x5151 && target_event.header.request_id == 5000 &&
         target_event.header.monotonic_time_ns == start.header.monotonic_time_ns &&
         target.target_length == 9 && target.port == 8443 &&
         target.scheme == static_cast<std::uint8_t>(reb::RequestScheme::kHttps));
  assert(failed.header.type == reb::EventType::kRequestFailed && failed.header.error_code == -2 &&
         failed.header.status_code == 0 && failed.header.frame_id == 0x5151 &&
         failed.header.request_id == 5000 && failed.header.scheme_class == 2 &&
         failed.header.initiator_process_id == 0 &&
         failed.header.flags == static_cast<std::uint16_t>(reb::EventFlag::kFromServiceWorker));

  // A page that cancels a held request: ERR_ABORTED, here without request content.
  auto metadata_ring = std::make_unique<NativeProbeQueue>();
  auto& metadata = *metadata_ring;
  ConfigureScope(metadata, false, false, 65);
  static_cast<void>(sink.RecordRequestInitiated(5001, "POST", "http", "example.test"));
  const auto plain = Core(One(metadata));
  sink.RecordServiceWorkerRequestEnd(5001, "/upload", 7, -1, -3);
  const auto aborted = Core(One(metadata));
  assert(aborted.header.error_code == -3 && aborted.header.frame_id == plain.header.frame_id &&
         aborted.header.scheme_class == 1);

  // Only http(s) starts are kept; another scheme's ID finds an older start or nothing.
  static_cast<void>(sink.RecordRequestInitiated(5002 + 1024, "GET", "data", ""));
  One(metadata);
  sink.RecordServiceWorkerRequestEnd(5002 + 1024, "/x", 2, -1, -2);
  assert(Drain(metadata) == 0);

  // 1,024 later http(s) starts reuse the slot: the end is a named loss.
  static_cast<void>(sink.RecordRequestInitiated(5003, "GET", "https", "example.test"));
  static_cast<void>(sink.RecordRequestInitiated(5003 + 1024, "GET", "https", "example.test"));
  assert(Drain(metadata) == 2);
  sink.RecordServiceWorkerRequestEnd(5003, "/late", 5, -1, -2);
  const auto lost = One(metadata);
  // The gap names the row it leaves unfinished as a request_tab_link names a
  // renderer record: by process and request ID, with no frame.
  assert(GapReason(lost) == "service_worker_end_lost" && Core(lost).header.session_id == 65 &&
         lost.header.request_id == 0 && lost.header.frame_id == 0 &&
         lost.header.initiator_process_id == lost.header.process_id &&
         lost.header.initiator_request_id == 5003);
  // The slot still holds the newer start, which finishes normally.
  sink.RecordServiceWorkerRequestEnd(5003 + 1024, "/new", 4, -1, -2);
  assert(Core(One(metadata)).header.request_id == 5003 + 1024);

  // A start of an earlier configuration is not finished into this one.
  static_cast<void>(sink.RecordRequestInitiated(5004, "GET", "https", "example.test"));
  One(metadata);
  ConfigureScope(metadata, false, false, 66);
  sink.RecordServiceWorkerRequestEnd(5004, "/old", 4, -1, -2);
  assert(Drain(metadata) == 0);

  // The kSentBody boundary: one completion whichever side ends the request.
  // A response the worker sent carries from_service_worker, so the loader's
  // client finishes the row and the loader does not.
  auto answered = sink.RecordRequestInitiated(5005, "GET", "https", "example.test");
  One(metadata);
  answered.NoteResponse(200, true, false);
  sink.RecordRendererRequestComplete(answered, "/ok", 3, -1, 0, 10, 10);
  if (reb::NativeServiceWorkerEndsRequest(/*response_sent=*/true, false, false)) {
    sink.RecordServiceWorkerRequestEnd(5005, "/ok", 3, -1, -2);
  }
  assert(Core(One(metadata)).header.type == reb::EventType::kRequestCompleted);
  // An error before any response: the loader ends it, and the client's own
  // completion, which has no service-worker response, adds nothing.
  auto unanswered = sink.RecordRequestInitiated(5006, "GET", "https", "example.test");
  One(metadata);
  if (reb::NativeServiceWorkerEndsRequest(false, false, false)) {
    sink.RecordServiceWorkerRequestEnd(5006, "/no", 3, -1, -2);
  }
  sink.RecordRendererRequestComplete(unanswered, "/no", 3, -1, -2, 0, 0);
  assert(Core(One(metadata)).header.type == reb::EventType::kRequestFailed);
  assert(!reb::NativeServiceWorkerEndsRequest(false, /*completed=*/true, false) &&
         !reb::NativeServiceWorkerEndsRequest(false, false, /*network_answered=*/true));

  transport.Disable();
  const auto before = allocations.load();
  for (int index = 0; index < 1000; ++index) {
    sink.RecordServiceWorkerRequestEnd(5000, "/api", 4, -1, -2);
  }
  assert(allocations == before && Drain(metadata) == 0);
  std::cout << "PASS service-worker ends finish the recorded https start with its frame, target "
               "and error; evicted, earlier-configuration, non-http and inactive ends\n";
}

// The start table is a Boehm-style sequence lock, correct only if a reader
// never accepts a slot that writers half filled. Every field here is a
// function of the request ID, so any accepted mix shows. Accepting every read
// (a broken lock) fails this within a few thousand reads.
void ServiceWorkerStartSequenceLock() {
  static reb::NativeServiceWorkerStarts starts;
  constexpr int kWriters = 4;
  constexpr std::uint32_t kStarts = 250000;
  constexpr std::uint32_t kSlot = 7;
  const auto start_of = [](const std::uint32_t id) {
    reb::NativeRendererRequest start;
    start.request_id = id;
    start.generation = std::uint64_t{id} * 2 + 2;
    start.initiated_sequence = std::uint64_t{id} * 3 + 1;
    start.initiated_time_ns = std::uint64_t{id} * 5 + 7;
    start.frame_id = std::uint64_t{id} * 11 + 13;
    start.thread_id = id ^ 0x5a5a5a5aU;
    start.scheme_class =
        (id & 1024U) != 0 ? reb::NativeSchemeClass::kHttps : reb::NativeSchemeClass::kHttp;
    return start;
  };
  std::atomic<int> running{kWriters};
  std::vector<std::thread> writers;
  for (int writer = 0; writer < kWriters; ++writer) {
    writers.emplace_back([&, writer] {
      for (std::uint32_t index = 0; index < kStarts; ++index) {
        starts.Keep(
            start_of(kSlot + 1024U * (static_cast<std::uint32_t>(writer) * kStarts + index)));
        // A short pause between writes lets the reader in between them too.
        for (int spin = 0; spin < 32; ++spin) {
          static_cast<void>(running.load(std::memory_order_relaxed));
        }
      }
      running.fetch_sub(1, std::memory_order_acq_rel);
    });
  }
  std::uint64_t accepted = 0, busy = 0, torn = 0;
  while (running.load(std::memory_order_acquire) != 0) {
    reb::NativeRendererRequest read;
    if (!starts.Read(kSlot, read)) {
      ++busy;
      continue;
    }
    ++accepted;
    if (read.request_id == 0) {
      continue;
    }
    const auto expected = start_of(read.request_id);
    torn += read.generation != expected.generation ||
            read.initiated_sequence != expected.initiated_sequence ||
            read.initiated_time_ns != expected.initiated_time_ns ||
            read.frame_id != expected.frame_id || read.thread_id != expected.thread_id ||
            read.scheme_class != expected.scheme_class;
  }
  for (auto& writer : writers) {
    writer.join();
  }
  assert(torn == 0);
  assert(accepted > 1000);
  std::cout << "PASS service-worker start slots: " << accepted << " reads racing " << kWriters
            << " writers accepted no torn slot (" << busy << " found it busy)\n";
}

// protocol/native-network-v3.md: the path and query a target keeps, without
// the fragment, never outside the spec whatever the parser left.
void RequestTargetRanges() {
  using reb::NativeRequestTargetRange;
  // "https://a.test/p?q#f": path 14+2, query 17+1, ref 19+1, 20 bytes.
  const auto check = [](const reb::NativeTargetRange range, const std::size_t begin,
                        const std::size_t length) {
    assert(range.begin == begin && range.length == length);
  };
  check(NativeRequestTargetRange(20, 14, 2, 17, 1, 19, 1), 14, 4);
  check(NativeRequestTargetRange(19, 14, 2, 17, 1, 0, -1), 14, 4);
  check(NativeRequestTargetRange(16, 14, 2, 0, -1, 0, -1), 14, 2);
  // No components at all: an empty target at the end, never a wrapped length.
  check(NativeRequestTargetRange(20, 0, -1, 0, -1, 0, -1), 20, 0);
  check(NativeRequestTargetRange(0, 0, -1, 0, -1, 0, -1), 0, 0);
  // Invalid path with a query or ref still keeps nothing.
  check(NativeRequestTargetRange(20, 0, -1, 17, 1, 19, 1), 20, 0);
  // A ref before the path, a query past the spec, a path past the spec.
  check(NativeRequestTargetRange(20, 14, 2, 0, -1, 10, 1), 14, 0);
  check(NativeRequestTargetRange(20, 14, 2, 17, 50, 0, -1), 14, 6);
  check(NativeRequestTargetRange(20, 25, 2, 0, -1, 0, -1), 20, 0);
  check(NativeRequestTargetRange(20, 14, 2, 0, -1, 0, 0), 14, 0);
  // "data:image/png;base64,AAAA": the path is all after the scheme.
  check(NativeRequestTargetRange(26, 5, 21, 0, -1, 0, -1), 5, 21);
  std::cout << "PASS request target ranges: fragment dropped, empty and invalid components "
               "give an empty target, every range stays inside the spec\n";
}

reb::MemoryCacheReusePayload ReuseOf(const reb::EventRecord& record) {
  assert(record.header.type == reb::EventType::kMemoryCacheReuse);
  reb::MemoryCacheReusePayload value;
  assert(reb::DecodeMemoryCacheReusePayload(record.inline_payload, value));
  return value;
}

// protocol/native-network-v3.md "Memory-cache reuse".
void MemoryCacheReuses() {
  NativeProbeQueue queue;
  ConfigureScope(queue, true, false, 67);
  // The page check, then the budget, then the record.
  const auto record = [](const reb::NativeMemoryCacheReuse& value, const bool ordinary = true) {
    const reb::NativeMemoryCacheAdmission admission = sink.AdmitMemoryCacheReuse(ordinary);
    sink.RecordMemoryCacheReuse(admission, value);
    return admission;
  };
  // Field by field: GCC's -Wmissing-field-initializers rejects partial designated lists.
  const auto reuse_of = [](const std::int32_t request_id, const std::string_view scheme,
                           const std::uint8_t resource_type) {
    reb::NativeMemoryCacheReuse value;
    value.request_id = request_id;
    value.scheme = scheme;
    value.resource_type = resource_type;
    return value;
  };
  auto image = reuse_of(6000, "https", 1);
  image.owner = {reb::NativeLoaderKind::kDocument, 0x6161};
  image.host = "cdn.example.test";
  image.target = "/logo.png?v=2";
  image.target_length = 13;
  image.status_code = 200;
  image.decoded_body_length = 5120;
  assert(record(image).capture_request_content);
  const auto reuse = Core(Pop(queue));
  const auto target = TargetOf(One(queue));
  const auto payload = ReuseOf(reuse);
  assert(reuse.header.request_id == 6000 && reuse.header.frame_id == 0x6161 &&
         reuse.header.loader_kind == 16 && reuse.header.scheme_class == 2 &&
         reuse.header.status_code == 200 && reuse.header.decoded_body_length == 5120 &&
         reuse.header.encoded_data_length == 0 && reuse.header.parent_event_id == 0);
  assert(payload.resource_type == 1 && payload.flags == 0 && payload.host_length == 16 &&
         std::string_view(reinterpret_cast<const char*>(payload.host.data()), 16) ==
             "cdn.example.test");
  assert(target.target_length == 13 &&
         target.scheme == static_cast<std::uint8_t>(reb::RequestScheme::kHttps));

  // Static data has no host, no status of its own beyond Blink's 200, and no owner here:
  // the running script's frame stands in, as on request_initiated.
  auto decoded = reuse_of(6001, "data", 1);
  decoded.target = "image/png;base64,AAAA";
  decoded.target_length = 21;
  decoded.static_data = true;
  decoded.status_code = 200;
  decoded.decoded_body_length = 3;
  blink::test_frame_present = true;
  record(decoded);
  blink::test_frame_present = false;
  const auto data = Core(Pop(queue));
  Pop(queue);
  assert(data.header.loader_kind == 21 && data.header.frame_id != 0 &&
         data.header.scheme_class == 5 && ReuseOf(data).flags == 1 &&
         ReuseOf(data).host_length == 0);

  // A long host keeps 120 bytes and says so; a negative length or status is never written.
  const std::string long_host(200, 'h');
  auto script = reuse_of(6002, "https", 3);
  script.owner = {reb::NativeLoaderKind::kDedicatedWorker, 0x77};
  script.host = long_host;
  script.status_code = -1;
  script.decoded_body_length = -1;
  record(script);
  const auto worker = Core(Pop(queue));
  Pop(queue);
  assert(ReuseOf(worker).host_length == 120 && ReuseOf(worker).flags == 2 &&
         worker.header.loader_kind == 17 && worker.header.status_code == 0 &&
         worker.header.decoded_body_length == 0);

  // Browser-internal URLs are counted like requests unless the session opts in.
  record(reuse_of(6003, "chrome", 3));
  assert(Drain(queue) == 0 && queue.ExclusionCount(0) == 1 && queue.ExclusionCount(5) == 0);
  // An SVG image's own document or a page popup belongs to no tab: counted
  // as class 71, apart from the budget's overflow.
  assert(!record(image, /*ordinary=*/false).admitted());
  assert(Drain(queue) == 0 && queue.ExclusionCount(5) == 0 && queue.ExclusionCount(6) == 1 &&
         reb::NativeRendererExclusionClass(6) == reb::kNativeNonOrdinaryPageReuseExclusion);

  // Metadata sessions record the reuse without its path, at most 4,096 per
  // configuration; the rest are counted as class 70. An internal URL counted
  // by its scheme class returns its budget charge.
  auto metadata_ring = std::make_unique<NativeProbeQueue>();
  auto& metadata = *metadata_ring;
  ConfigureScope(metadata, false, false, 68);
  record(reuse_of(6004, "devtools", 3));
  for (std::uint32_t index = 0; index < reb::kNativeMemoryCacheReuseBudget + 10; ++index) {
    image.request_id = static_cast<std::int32_t>(7000 + index);
    record(image);
  }
  assert(Drain(metadata) == reb::kNativeMemoryCacheReuseBudget && metadata.DroppedCount() == 0);
  assert(metadata.ExclusionCount(3) == 1 && metadata.ExclusionCount(5) == 10 &&
         reb::NativeRendererExclusionClass(5) == reb::kNativeMemoryCacheReuseExclusion);
  // Past the budget a reuse costs its checks and one counter increment.
  auto before = allocations.load();
  for (int index = 0; index < 1000; ++index) {
    assert(!sink.AdmitMemoryCacheReuse(true).admitted());
  }
  assert(allocations == before && metadata.ExclusionCount(5) == 1010 &&
         metadata.ExclusionCount(6) == 0);
  // A new configuration starts a fresh count, and a reuse admitted by the
  // replaced one is never recorded into it.
  ConfigureScope(metadata, false, false, 68);
  const auto fresh = sink.AdmitMemoryCacheReuse(true);
  assert(fresh.admitted() && !fresh.capture_request_content);
  ConfigureScope(metadata, false, false, 68);
  sink.RecordMemoryCacheReuse(fresh, image);
  assert(Drain(metadata) == 0);
  record(image);
  assert(Core(One(metadata)).header.type == reb::EventType::kMemoryCacheReuse);

  transport.Disable();
  before = allocations.load();
  for (int index = 0; index < 1000; ++index) {
    record(image);
  }
  assert(allocations == before && Drain(metadata) == 0);
  std::cout << "PASS memory-cache reuses record their owner, host, status, size and content "
               "target; count browser-internal URLs, pages that are not ordinary and every reuse "
               "past 4,096; a new configuration starts a fresh budget\n";
}

}  // namespace
