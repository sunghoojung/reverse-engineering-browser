#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>

#include "reb/event.hpp"
#include "reb/origin_trace.hpp"

#define CHECK(condition)                                                                   \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " << #condition \
                << '\n';                                                                   \
      return 1;                                                                            \
    }                                                                                      \
  } while (false)

namespace {

reb::EventRecord Event(const reb::EventCategory category,
                       const reb::EventType type,
                       const std::uint64_t sequence,
                       const std::uint32_t process = 10) {
  reb::EventRecord event = reb::MakeEvent(category, type, sequence, sequence * 100, 7);
  event.header.process_id = process;
  event.header.thread_id = 1;
  event.header.navigation_id = 100;
  event.header.frame_id = 200;
  static_cast<void>(reb::SetInlinePayload(event, "evidence"));
  return event;
}

}  // namespace

int main() {
  bool rejected_zero_capacity = false;
  try {
    reb::OriginTraceIndex invalid(0);
  } catch (const std::invalid_argument&) {
    rejected_zero_capacity = true;
  }
  CHECK(rejected_zero_capacity);

  reb::OriginTraceIndex index(16);
  const reb::EventRecord canvas = Event(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 1);
  CHECK(index.Ingest(canvas).count == 0);

  reb::EventRecord wasm = Event(reb::EventCategory::kWasm, reb::EventType::kModuleInstantiated, 2);
  wasm.header.parent_event_id = 1;
  const reb::OriginTraceEdgeBatch parent = index.Ingest(wasm);
  CHECK(parent.count == 1);
  CHECK(parent.edges[0].relation == reb::OriginTraceRelation::kParentEvent);
  CHECK(parent.edges[0].confidence == reb::OriginTraceConfidence::kObserved);
  CHECK(parent.edges[0].from.sequence_number == 2);
  CHECK(parent.edges[0].to.sequence_number == 1);
  CHECK(reb::IsValidOriginTraceEdge(parent.edges[0]));

  reb::EventRecord initiated =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestInitiated, 3, 20);
  initiated.header.request_id = 55;
  initiated.header.artifact_id = 300;
  CHECK(index.Ingest(initiated).count == 0);

  reb::EventRecord started =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestStarted, 4, 30);
  started.header.request_id = 900;
  started.header.initiator_process_id = 20;
  started.header.initiator_request_id = 55;
  started.header.browser_context_id_high = 11;
  started.header.browser_context_id_low = 12;
  const reb::OriginTraceEdgeBatch initiator = index.Ingest(started);
  CHECK(initiator.count == 1);
  CHECK(initiator.edges[0].relation == reb::OriginTraceRelation::kRequestInitiator);
  CHECK(initiator.edges[0].to.process_id == 20);
  CHECK(initiator.edges[0].to.sequence_number == 3);

  reb::EventRecord response =
      Event(reb::EventCategory::kNetwork, reb::EventType::kResponseStarted, 5, 30);
  response.header.request_id = 900;
  response.header.browser_context_id_high = 11;
  response.header.browser_context_id_low = 12;
  const reb::OriginTraceEdgeBatch lifecycle = index.Ingest(response);
  CHECK(lifecycle.count == 1);
  CHECK(lifecycle.edges[0].relation == reb::OriginTraceRelation::kRequestLifecycle);
  CHECK(lifecycle.edges[0].to.sequence_number == 4);

  reb::EventRecord completed =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestCompleted, 6, 30);
  completed.header.request_id = 900;
  completed.header.browser_context_id_high = 11;
  completed.header.browser_context_id_low = 12;
  completed.header.parent_event_id = 5;
  const reb::OriginTraceEdgeBatch deduplicated = index.Ingest(completed);
  CHECK(deduplicated.count == 1);
  CHECK(deduplicated.edges[0].relation == reb::OriginTraceRelation::kParentEvent);

  reb::EventRecord artifact =
      Event(reb::EventCategory::kArtifact, reb::EventType::kArtifactCaptured, 7, 30);
  artifact.header.request_id = 900;
  artifact.header.artifact_id = 301;
  const reb::OriginTraceEdgeBatch artifact_edge = index.Ingest(artifact);
  CHECK(artifact_edge.count == 1);
  CHECK(artifact_edge.edges[0].relation == reb::OriginTraceRelation::kArtifactRequest);
  CHECK(artifact_edge.edges[0].confidence == reb::OriginTraceConfidence::kCorrelated);
  CHECK(artifact_edge.edges[0].to.sequence_number == 6);

  reb::EventRecord context_a =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestStarted, 8, 40);
  context_a.header.request_id = 1;
  context_a.header.browser_context_id_low = 1;
  CHECK(index.Ingest(context_a).count == 0);
  reb::EventRecord context_b = context_a;
  context_b.header.sequence_number = 9;
  context_b.header.monotonic_time_ns = 900;
  context_b.header.browser_context_id_low = 2;
  CHECK(index.Ingest(context_b).count == 0);

  const reb::OriginTraceIndexStats stats = index.Stats();
  CHECK(stats.indexed_events == 9);
  CHECK(stats.emitted_edges == 5);
  CHECK(stats.duplicate_events == 0);
  CHECK(index.Ingest(context_b).count == 0);
  CHECK(index.Stats().duplicate_events == 1);
  CHECK(index.Size() == 9);

  reb::EventRecord invalid = canvas;
  invalid.header.protocol_version = 99;
  CHECK(index.Ingest(invalid).count == 0);
  CHECK(index.Stats().indexed_events == 9);

  CHECK(reb::OriginTraceEdgeToJson(initiator.edges[0]) ==
        "{\"protocol_version\":1,\"session_id\":\"7\",\"from_process_id\":30,"
        "\"from_sequence_number\":\"4\",\"to_process_id\":20,"
        "\"to_sequence_number\":\"3\",\"relation\":\"request_initiator\","
        "\"confidence\":\"observed\",\"request_id\":\"900\","
        "\"artifact_id\":\"0\"}");

  reb::OriginTraceEdge malformed = initiator.edges[0];
  malformed.to.session_id = 8;
  CHECK(!reb::IsValidOriginTraceEdge(malformed));
  malformed = initiator.edges[0];
  malformed.relation = reb::OriginTraceRelation::kUnknown;
  CHECK(!reb::IsValidOriginTraceEdge(malformed));

  reb::OriginTraceIndex bounded(2);
  CHECK(bounded.Ingest(canvas).count == 0);
  CHECK(bounded.Ingest(wasm).count == 1);
  reb::EventRecord third = Event(reb::EventCategory::kNavigator, reb::EventType::kPropertyRead, 3);
  CHECK(bounded.Ingest(third).count == 0);
  reb::EventRecord missing_parent =
      Event(reb::EventCategory::kWasm, reb::EventType::kModuleCompiled, 4);
  missing_parent.header.parent_event_id = 1;
  CHECK(bounded.Ingest(missing_parent).count == 0);
  CHECK(bounded.Size() == 2);
  CHECK(bounded.Stats().evicted_events == 2);

  constexpr std::uint64_t kStressEventCount = 250'000;
  reb::OriginTraceIndex stress_index(10'000);
  const auto stress_start = std::chrono::steady_clock::now();
  for (std::uint64_t sequence = 1; sequence <= kStressEventCount; ++sequence) {
    reb::EventRecord stress_event = Event(
        sequence % 5 == 0 ? reb::EventCategory::kCanvas : reb::EventCategory::kNetwork,
        sequence % 5 == 0 ? reb::EventType::kApiCall : reb::EventType::kRequestStarted, sequence);
    if (stress_event.header.category == reb::EventCategory::kNetwork) {
      stress_event.header.request_id = sequence % 256 + 1;
      stress_event.header.browser_context_id_low = 1;
    }
    static_cast<void>(stress_index.Ingest(stress_event));
  }
  const auto stress_elapsed = std::chrono::steady_clock::now() - stress_start;
  CHECK(stress_index.Stats().indexed_events == kStressEventCount);
  CHECK(stress_index.Size() == 10'000);
  const double elapsed_seconds = std::chrono::duration<double>(stress_elapsed).count();
  const auto events_per_second =
      static_cast<std::uint64_t>(static_cast<double>(kStressEventCount) / elapsed_seconds);

  std::cout << "origin_trace_test passed (" << events_per_second << " cold-path events/s)\n";
  return 0;
}
