#ifndef REB_TESTS_REQUEST_CHILD_CHECK_HPP_
#define REB_TESTS_REQUEST_CHILD_CHECK_HPP_

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

#include "reb/event.hpp"
#include "reb/origin_trace.hpp"

namespace reb_test {

// A link or watch record joins its request by parent only: the next lifecycle
// record must still point at the previous lifecycle record, not at the child.
// Every record is checked for validity, since the index ignores invalid ones.
[[nodiscard]] inline bool StaysRequestChild(const reb::EventRecord& child) {
  const auto lifecycle = [&](const reb::EventType type, const std::uint64_t sequence) {
    reb::EventRecord event = reb::MakeEvent(reb::EventCategory::kNetwork, type, sequence, sequence,
                                            child.header.session_id);
    event.header.process_id = child.header.process_id;
    event.header.request_id = child.header.request_id;
    event.header.browser_context_id_high = child.header.browser_context_id_high;
    event.header.browser_context_id_low = child.header.browser_context_id_low;
    event.header.scheme_class = 2;
    event.header.loader_kind = 3;
    static_cast<void>(reb::SetInlinePayload(event, std::string_view("GET example.test")));
    return event;
  };
  const reb::EventRecord started =
      lifecycle(reb::EventType::kRequestStarted, child.header.parent_event_id);
  reb::EventRecord response =
      lifecycle(reb::EventType::kResponseStarted, child.header.sequence_number + 1);
  response.header.scheme_class = 0;
  response.header.loader_kind = 0;
  if (!reb::IsValidEvent(started) || !reb::IsValidEvent(child) || !reb::IsValidEvent(response)) {
    return false;
  }
  reb::OriginTraceIndex index(16);
  static_cast<void>(index.Ingest(started));
  const auto linked = index.Ingest(child);
  const auto points_to = [](const reb::OriginTraceEdgeBatch& batch,
                            const reb::OriginTraceRelation relation, const std::uint64_t from,
                            const std::uint64_t to) {
    return std::ranges::any_of(batch.edges, [&](const reb::OriginTraceEdge& edge) {
      return edge.relation == relation && edge.from.sequence_number == from &&
             edge.to.sequence_number == to;
    });
  };
  if (!points_to(linked, reb::OriginTraceRelation::kParentEvent, child.header.sequence_number,
                 child.header.parent_event_id)) {
    return false;
  }
  const auto answered = index.Ingest(response);
  return points_to(answered, reb::OriginTraceRelation::kRequestLifecycle,
                   response.header.sequence_number, child.header.parent_event_id) &&
         !points_to(answered, reb::OriginTraceRelation::kRequestLifecycle,
                    response.header.sequence_number, child.header.sequence_number);
}

}  // namespace reb_test

#endif  // REB_TESTS_REQUEST_CHILD_CHECK_HPP_
