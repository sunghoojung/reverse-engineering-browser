#include "reb/origin_trace.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <stdexcept>
#include <tuple>

namespace reb {
namespace {

template <typename Integer>
void AppendInteger(std::string& output, const Integer value) {
  std::array<char, std::numeric_limits<Integer>::digits10 + 3> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  output.append(buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data()));
}

std::size_t HashCombine(const std::size_t current, const std::size_t value) noexcept {
  return current ^ (value + 0x9e3779b9U + (current << 6U) + (current >> 2U));
}

OriginTraceEventReference Reference(const EventRecord& event) noexcept {
  return {.session_id = event.header.session_id,
          .sequence_number = event.header.sequence_number,
          .process_id = event.header.process_id};
}

bool HasBrowserContext(const EventRecord& event) noexcept {
  return event.header.browser_context_id_high != 0 || event.header.browser_context_id_low != 0;
}

bool IsBrowserRequestLifecycle(const EventRecord& event) noexcept {
  if (event.header.category != EventCategory::kNetwork || event.header.request_id == 0) {
    return false;
  }
  const EventType type = event.header.type;
  return type == EventType::kRequestStarted || type == EventType::kRequestRedirected ||
         type == EventType::kResponseStarted || type == EventType::kResponseCompleted ||
         type == EventType::kRequestCompleted || type == EventType::kRequestFailed;
}

bool IsRequestEvidence(const EventRecord& event) noexcept {
  return event.header.request_id != 0 && (event.header.category == EventCategory::kNetwork ||
                                          event.header.category == EventCategory::kArtifact);
}

}  // namespace

OriginTraceIndex::OriginTraceIndex(const std::size_t capacity) : capacity_(capacity) {
  if (capacity == 0) {
    throw std::invalid_argument("OriginTraceIndex capacity must be greater than zero");
  }
  events_.reserve(capacity);
  requests_.reserve(capacity);
  legacy_requests_.reserve(capacity);
  pending_initiators_.reserve(capacity);
}

std::size_t OriginTraceIndex::EventReferenceHash::operator()(
    const OriginTraceEventReference& value) const noexcept {
  std::size_t result = std::hash<std::uint64_t>{}(value.session_id);
  result = HashCombine(result, std::hash<std::uint32_t>{}(value.process_id));
  return HashCombine(result, std::hash<std::uint64_t>{}(value.sequence_number));
}

std::size_t OriginTraceIndex::RequestKeyHash::operator()(const RequestKey& value) const noexcept {
  std::size_t result = std::hash<std::uint64_t>{}(value.session_id);
  result = HashCombine(result, std::hash<std::uint32_t>{}(value.process_id));
  result = HashCombine(result, std::hash<std::uint64_t>{}(value.request_id));
  result = HashCombine(result, std::hash<std::uint64_t>{}(value.browser_context_id_high));
  return HashCombine(result, std::hash<std::uint64_t>{}(value.browser_context_id_low));
}

std::size_t OriginTraceIndex::LegacyRequestKeyHash::operator()(
    const LegacyRequestKey& value) const noexcept {
  std::size_t result = std::hash<std::uint64_t>{}(value.session_id);
  result = HashCombine(result, std::hash<std::uint32_t>{}(value.process_id));
  return HashCombine(result, std::hash<std::uint64_t>{}(value.request_id));
}

bool OriginTraceIndex::Contains(const OriginTraceEventReference& event) const {
  return events_.contains(event);
}

OriginTraceEventReference OriginTraceIndex::FindLegacyRequest(const LegacyRequestKey& key) const {
  const auto found = legacy_requests_.find(key);
  if (found == legacy_requests_.end() || found->second.ambiguous ||
      !Contains(found->second.event)) {
    return {};
  }
  return found->second.event;
}

OriginTraceEventReference OriginTraceIndex::FindInitiator(const LegacyRequestKey& key) const {
  const auto found = legacy_requests_.find(key);
  if (found == legacy_requests_.end() || found->second.ambiguous ||
      !Contains(found->second.initiator)) {
    return {};
  }
  return found->second.initiator;
}

void OriginTraceIndex::RememberPendingInitiator(const EventRecord& event,
                                                const LegacyRequestKey& key) {
  // Bound the insertion history too: resolved entries may remain as tombstones
  // in this FIFO, but neither it nor the pending multimap can exceed capacity.
  if (pending_initiator_order_.size() == capacity_) {
    const auto& [expired_key, expired_event] = pending_initiator_order_.front();
    const auto [begin, end] = pending_initiators_.equal_range(expired_key);
    for (auto pending = begin; pending != end; ++pending) {
      if (pending->second.from == expired_event) {
        pending_initiators_.erase(pending);
        break;
      }
    }
    pending_initiator_order_.pop_front();
  }
  const OriginTraceEventReference source = Reference(event);
  pending_initiators_.emplace(key, OriginTraceEdge{
                                       .relation = OriginTraceRelation::kRequestInitiator,
                                       .confidence = OriginTraceConfidence::kObserved,
                                       .from = source,
                                       .request_id = event.header.request_id,
                                       .artifact_id = event.header.artifact_id,
                                   });
  pending_initiator_order_.emplace_back(key, source);
}

void OriginTraceIndex::ResolvePendingInitiators(const EventRecord& event,
                                                OriginTraceEdgeBatch& batch) {
  if (event.header.category != EventCategory::kNetwork ||
      event.header.type != EventType::kRequestInitiated || event.header.request_id == 0) {
    return;
  }
  const LegacyRequestKey key{event.header.session_id, event.header.request_id,
                             event.header.process_id};
  const OriginTraceEventReference target = FindInitiator(key);
  const auto [begin, end] = pending_initiators_.equal_range(key);
  const std::size_t direct_count = batch.edges.size();
  for (auto pending = begin; pending != end; ++pending) {
    OriginTraceEdge edge = pending->second;
    if (target.session_id != 0 && Contains(edge.from) && edge.from != target) {
      edge.to = target;
      batch.edges.push_back(edge);
    }
  }
  pending_initiators_.erase(begin, end);
  // Hash iteration order is not evidence order. Keep sidecar replays stable.
  std::sort(batch.edges.begin() + static_cast<std::ptrdiff_t>(direct_count), batch.edges.end(),
            [](const OriginTraceEdge& left, const OriginTraceEdge& right) {
              return std::tie(left.from.process_id, left.from.sequence_number) <
                     std::tie(right.from.process_id, right.from.sequence_number);
            });
}

OriginTraceEventReference OriginTraceIndex::FindRequest(const EventRecord& event) const {
  if (!IsRequestEvidence(event)) {
    return {};
  }
  if (HasBrowserContext(event)) {
    const RequestKey key{event.header.session_id, event.header.request_id,
                         event.header.browser_context_id_high, event.header.browser_context_id_low,
                         event.header.process_id};
    const auto found = requests_.find(key);
    if (found != requests_.end() && Contains(found->second)) {
      return found->second;
    }
    return {};
  }
  return FindLegacyRequest(
      {event.header.session_id, event.header.request_id, event.header.process_id});
}

void OriginTraceIndex::RememberEvent(const OriginTraceEventReference& event) {
  if (events_.size() == capacity_) {
    events_.erase(event_order_.front());
    event_order_.pop_front();
    ++stats_.evicted_events;
  }
  events_.emplace(event);
  event_order_.push_back(event);
}

void OriginTraceIndex::RememberRequest(const EventRecord& event,
                                       const OriginTraceEventReference& reference) {
  if (!IsRequestEvidence(event)) {
    return;
  }

  if (HasBrowserContext(event)) {
    const RequestKey key{event.header.session_id, event.header.request_id,
                         event.header.browser_context_id_high, event.header.browser_context_id_low,
                         event.header.process_id};
    const auto found = requests_.find(key);
    if (found != requests_.end()) {
      found->second = reference;
    } else {
      if (requests_.size() == capacity_) {
        requests_.erase(request_order_.front());
        request_order_.pop_front();
      }
      requests_.emplace(key, reference);
      request_order_.push_back(key);
    }
  }

  const LegacyRequestKey legacy_key{event.header.session_id, event.header.request_id,
                                    event.header.process_id};
  const auto legacy = legacy_requests_.find(legacy_key);
  if (legacy == legacy_requests_.end()) {
    if (legacy_requests_.size() == capacity_) {
      legacy_requests_.erase(legacy_request_order_.front());
      legacy_request_order_.pop_front();
    }
    legacy_requests_.emplace(
        legacy_key, LegacyRequestState{reference, event.header.browser_context_id_high,
                                       event.header.browser_context_id_low, false,
                                       event.header.category == EventCategory::kNetwork &&
                                               event.header.type == EventType::kRequestInitiated
                                           ? reference
                                           : OriginTraceEventReference{}});
    legacy_request_order_.push_back(legacy_key);
    return;
  }

  LegacyRequestState& state = legacy->second;
  const bool state_has_context =
      state.browser_context_id_high != 0 || state.browser_context_id_low != 0;
  const bool event_has_context = HasBrowserContext(event);
  if (state_has_context && event_has_context &&
      (state.browser_context_id_high != event.header.browser_context_id_high ||
       state.browser_context_id_low != event.header.browser_context_id_low)) {
    state.ambiguous = true;
    return;
  }
  if (event.header.category == EventCategory::kNetwork &&
      event.header.type == EventType::kRequestInitiated) {
    if (state.initiator.session_id != 0 && state.initiator != reference) {
      state.ambiguous = true;
    } else {
      state.initiator = reference;
    }
  }
  if (!state.ambiguous) {
    state.event = reference;
    if (event_has_context) {
      state.browser_context_id_high = event.header.browser_context_id_high;
      state.browser_context_id_low = event.header.browser_context_id_low;
    }
  }
}

void OriginTraceIndex::AddEdge(OriginTraceEdgeBatch& batch,
                               const EventRecord& event,
                               const OriginTraceEventReference& target,
                               const OriginTraceRelation relation,
                               const OriginTraceConfidence confidence) {
  const OriginTraceEventReference source = Reference(event);
  if (target.session_id == 0 || target == source || !Contains(target)) {
    return;
  }
  for (const OriginTraceEdge& edge : batch.edges) {
    if (edge.from == source && edge.to == target) {
      return;
    }
  }
  if (batch.edges.size() == kMaxDirectOriginTraceEdgesPerEvent) {
    return;
  }
  batch.edges.push_back({
      .relation = relation,
      .confidence = confidence,
      .from = source,
      .to = target,
      .request_id = event.header.request_id,
      .artifact_id = event.header.artifact_id,
  });
}

OriginTraceEdgeBatch OriginTraceIndex::Ingest(const EventRecord& event) {
  OriginTraceEdgeBatch batch;
  if (!IsValidEvent(event)) {
    return batch;
  }
  const OriginTraceEventReference source = Reference(event);
  if (Contains(source)) {
    ++stats_.duplicate_events;
    return batch;
  }

  if (event.header.parent_event_id != 0) {
    AddEdge(batch, event,
            {.session_id = event.header.session_id,
             .sequence_number = event.header.parent_event_id,
             .process_id = event.header.process_id},
            OriginTraceRelation::kParentEvent, OriginTraceConfidence::kObserved);
  }

  if (IsBrowserRequestLifecycle(event) && event.header.initiator_process_id != 0 &&
      event.header.initiator_request_id != 0) {
    const LegacyRequestKey key{event.header.session_id, event.header.initiator_request_id,
                               event.header.initiator_process_id};
    const OriginTraceEventReference initiator = FindInitiator(key);
    AddEdge(batch, event, initiator, OriginTraceRelation::kRequestInitiator,
            OriginTraceConfidence::kObserved);
    if (initiator.session_id == 0) {
      RememberPendingInitiator(event, key);
    }
  }

  const OriginTraceEventReference previous_request_event = FindRequest(event);
  AddEdge(batch, event, previous_request_event,
          event.header.category == EventCategory::kArtifact
              ? OriginTraceRelation::kArtifactRequest
              : OriginTraceRelation::kRequestLifecycle,
          event.header.category == EventCategory::kArtifact ? OriginTraceConfidence::kCorrelated
                                                            : OriginTraceConfidence::kObserved);

  RememberEvent(source);
  RememberRequest(event, source);
  ResolvePendingInitiators(event, batch);
  ++stats_.indexed_events;
  stats_.emitted_edges += batch.edges.size();
  return batch;
}

OriginTraceIndexStats OriginTraceIndex::Stats() const noexcept {
  return stats_;
}

std::size_t OriginTraceIndex::Size() const noexcept {
  return events_.size();
}

bool IsValidOriginTraceEdge(const OriginTraceEdge& edge) noexcept {
  const bool known_relation = edge.relation == OriginTraceRelation::kParentEvent ||
                              edge.relation == OriginTraceRelation::kRequestInitiator ||
                              edge.relation == OriginTraceRelation::kRequestLifecycle ||
                              edge.relation == OriginTraceRelation::kArtifactRequest;
  const bool known_confidence = edge.confidence == OriginTraceConfidence::kObserved ||
                                edge.confidence == OriginTraceConfidence::kCorrelated;
  return edge.protocol_version == kOriginTraceProtocolVersion && known_relation &&
         known_confidence && edge.reserved == 0 && edge.from.reserved == 0 &&
         edge.to.reserved == 0 && edge.from.session_id != 0 &&
         edge.from.session_id == edge.to.session_id && edge.from.sequence_number != 0 &&
         edge.to.sequence_number != 0 && edge.from != edge.to;
}

std::string OriginTraceEdgeToJson(const OriginTraceEdge& edge) {
  std::string output;
  output.reserve(384);
  output.append("{\"protocol_version\":");
  AppendInteger(output, edge.protocol_version);
  output.append(",\"session_id\":\"");
  AppendInteger(output, edge.from.session_id);
  output.append("\",\"from_process_id\":");
  AppendInteger(output, edge.from.process_id);
  output.append(",\"from_sequence_number\":\"");
  AppendInteger(output, edge.from.sequence_number);
  output.append("\",\"to_process_id\":");
  AppendInteger(output, edge.to.process_id);
  output.append(",\"to_sequence_number\":\"");
  AppendInteger(output, edge.to.sequence_number);
  output.append("\",\"relation\":\"");
  output.append(OriginTraceRelationName(edge.relation));
  output.append("\",\"confidence\":\"");
  output.append(OriginTraceConfidenceName(edge.confidence));
  output.append("\",\"request_id\":\"");
  AppendInteger(output, edge.request_id);
  output.append("\",\"artifact_id\":\"");
  AppendInteger(output, edge.artifact_id);
  output.append("\"}");
  return output;
}

std::string_view OriginTraceRelationName(const OriginTraceRelation relation) noexcept {
  switch (relation) {
    case OriginTraceRelation::kParentEvent:
      return "parent_event";
    case OriginTraceRelation::kRequestInitiator:
      return "request_initiator";
    case OriginTraceRelation::kRequestLifecycle:
      return "request_lifecycle";
    case OriginTraceRelation::kArtifactRequest:
      return "artifact_request";
    case OriginTraceRelation::kUnknown:
      return "unknown";
  }
  return "unknown";
}

std::string_view OriginTraceConfidenceName(const OriginTraceConfidence confidence) noexcept {
  switch (confidence) {
    case OriginTraceConfidence::kObserved:
      return "observed";
    case OriginTraceConfidence::kCorrelated:
      return "correlated";
    case OriginTraceConfidence::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace reb
