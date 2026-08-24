#include "reb/request_signal_profile.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <stdexcept>

namespace reb {
namespace {

constexpr std::array<EventCategory, kRequestSignalProfileCategoryCount> kSignalCategories = {
    EventCategory::kCanvas,    EventCategory::kWebGl,       EventCategory::kWebAudio,
    EventCategory::kNavigator, EventCategory::kPermissions, EventCategory::kStorage,
    EventCategory::kWebRtc,
};

template <typename Integer>
void AppendInteger(std::string& output, const Integer value) {
  std::array<char, std::numeric_limits<Integer>::digits10 + 3> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  output.append(buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data()));
}

std::size_t HashCombine(const std::size_t current, const std::size_t value) noexcept {
  return current ^ (value + 0x9e3779b9U + (current << 6U) + (current >> 2U));
}

RequestSignalEventReference Reference(const EventRecord& event) noexcept {
  return {.session_id = event.header.session_id,
          .sequence_number = event.header.sequence_number,
          .process_id = event.header.process_id};
}

std::size_t SignalCategoryIndex(const EventCategory category) noexcept {
  const auto found = std::ranges::find(kSignalCategories, category);
  return found == kSignalCategories.end()
             ? kSignalCategories.size()
             : static_cast<std::size_t>(found - kSignalCategories.begin());
}

bool IsRequestProfileRoot(const EventRecord& event) noexcept {
  return event.header.category == EventCategory::kNetwork && event.header.session_id != 0 &&
         event.header.sequence_number != 0 && event.header.request_id != 0 &&
         (event.header.type == EventType::kRequestInitiated ||
          event.header.type == EventType::kRequestStarted);
}

bool ReferenceIsSet(const RequestSignalEventReference& reference) noexcept {
  return reference.session_id != 0 && reference.sequence_number != 0;
}

RequestSignalEvidence* FindSignal(RequestSignalProfile& profile,
                                  const EventCategory category) noexcept {
  for (std::size_t index = 0; index < profile.signal_count; ++index) {
    if (profile.signals[index].category == category) {
      return &profile.signals[index];
    }
  }
  return nullptr;
}

RequestSignalEvidence* AddSignal(RequestSignalProfile& profile,
                                 const EventCategory category,
                                 const RequestSignalRelation relation) noexcept {
  if (RequestSignalEvidence* const existing = FindSignal(profile, category)) {
    return existing;
  }
  if (profile.signal_count == profile.signals.size()) {
    return nullptr;
  }
  RequestSignalEvidence& signal = profile.signals[profile.signal_count++];
  signal.category = category;
  signal.relation = relation;
  return &signal;
}

void SortSignals(RequestSignalProfile& profile) noexcept {
  // The array contains at most seven entries. This makes the maximum sorting
  // work explicit instead of routing the small range through generic helpers.
  for (std::size_t index = 1; index < profile.signal_count; ++index) {
    const RequestSignalEvidence value = profile.signals[index];
    std::size_t destination = index;
    while (destination > 0 &&
           static_cast<std::uint16_t>(value.category) <
               static_cast<std::uint16_t>(profile.signals[destination - 1].category)) {
      profile.signals[destination] = profile.signals[destination - 1];
      --destination;
    }
    profile.signals[destination] = value;
  }
}

void AppendReference(std::string& output, const RequestSignalEventReference& reference) {
  output.append("{\"process_id\":");
  AppendInteger(output, reference.process_id);
  output.append(",\"sequence_number\":\"");
  AppendInteger(output, reference.sequence_number);
  output.append("\"}");
}

}  // namespace

RequestSignalProfileIndex::RequestSignalProfileIndex(const std::size_t capacity)
    : capacity_(capacity) {
  if (capacity == 0) {
    throw std::invalid_argument("RequestSignalProfileIndex capacity must be greater than zero");
  }
  events_.reserve(capacity);
  contexts_.reserve(capacity);
  request_profiles_.reserve(capacity);
}

std::size_t RequestSignalProfileIndex::EventReferenceHash::operator()(
    const RequestSignalEventReference& value) const noexcept {
  std::size_t result = std::hash<std::uint64_t>{}(value.session_id);
  result = HashCombine(result, std::hash<std::uint32_t>{}(value.process_id));
  return HashCombine(result, std::hash<std::uint64_t>{}(value.sequence_number));
}

std::size_t RequestSignalProfileIndex::ContextKeyHash::operator()(
    const ContextKey& value) const noexcept {
  std::size_t result = std::hash<std::uint64_t>{}(value.session_id);
  result = HashCombine(result, std::hash<std::uint32_t>{}(value.process_id));
  result = HashCombine(result, std::hash<std::uint64_t>{}(value.navigation_id));
  return HashCombine(result, std::hash<std::uint64_t>{}(value.frame_id));
}

std::size_t RequestSignalProfileIndex::RequestKeyHash::operator()(
    const RequestKey& value) const noexcept {
  std::size_t result = std::hash<std::uint64_t>{}(value.session_id);
  result = HashCombine(result, std::hash<std::uint32_t>{}(value.process_id));
  return HashCombine(result, std::hash<std::uint64_t>{}(value.request_id));
}

bool RequestSignalProfileIndex::Contains(const RequestSignalEventReference& reference) const {
  return events_.contains(reference);
}

void RequestSignalProfileIndex::AddParentSignals(const EventRecord& event,
                                                 RequestSignalProfile& profile) const {
  std::uint64_t parent_event_id = event.header.parent_event_id;
  while (parent_event_id != 0 && profile.parent_depth < kRequestSignalProfileParentDepthLimit) {
    const RequestSignalEventReference reference{event.header.session_id, parent_event_id,
                                                event.header.process_id};
    const auto found = events_.find(reference);
    if (found == events_.end()) {
      profile.retention_truncated = true;
      break;
    }
    const EventState& state = found->second;
    ++profile.parent_depth;
    if (IsFingerprintSignalCategory(state.category)) {
      RequestSignalEvidence* const signal =
          AddSignal(profile, state.category, RequestSignalRelation::kParentChain);
      if (signal) {
        if (!ReferenceIsSet(signal->last_event)) {
          signal->last_event = state.reference;
        }
        signal->first_event = state.reference;
        ++signal->event_count;
      }
    }
    parent_event_id = state.parent_event_id;
  }
  if (parent_event_id != 0 && profile.parent_depth == kRequestSignalProfileParentDepthLimit) {
    profile.parent_depth_limited = true;
  }
}

void RequestSignalProfileIndex::AddContextSignals(const EventRecord& event,
                                                  RequestSignalProfile& profile) const {
  const ContextKey key{event.header.session_id, event.header.navigation_id, event.header.frame_id,
                       event.header.process_id};
  const auto context = contexts_.find(key);
  if (context == contexts_.end()) {
    return;
  }
  for (std::size_t index = 0; index < kSignalCategories.size(); ++index) {
    const ContextSignalState& state = context->second.signals[index];
    if (state.event_count == 0 || FindSignal(profile, kSignalCategories[index])) {
      continue;
    }
    if (!Contains(state.last_event)) {
      profile.retention_truncated = true;
      continue;
    }
    RequestSignalEvidence* const signal =
        AddSignal(profile, kSignalCategories[index], RequestSignalRelation::kSameContext);
    if (!signal) {
      continue;
    }
    signal->event_count = state.event_count;
    signal->last_event = state.last_event;
    signal->first_event = state.first_event;
    profile.count_saturated = profile.count_saturated || state.count_saturated;
    if (!Contains(state.first_event)) {
      signal->first_event = state.last_event;
      profile.retention_truncated = true;
    }
  }
}

RequestSignalProfile RequestSignalProfileIndex::BuildProfile(const EventRecord& event) const {
  RequestSignalProfile profile;
  profile.root_event = Reference(event);
  profile.request_id = event.header.request_id;
  profile.navigation_id = event.header.navigation_id;
  profile.frame_id = event.header.frame_id;
  AddParentSignals(event, profile);
  AddContextSignals(event, profile);
  SortSignals(profile);
  return profile;
}

std::optional<RequestSignalProfile> RequestSignalProfileIndex::FindInitiatorProfile(
    const EventRecord& event) const {
  if (event.header.type != EventType::kRequestStarted || event.header.initiator_process_id == 0 ||
      event.header.initiator_request_id == 0) {
    return std::nullopt;
  }
  const RequestKey key{event.header.session_id, event.header.initiator_request_id,
                       event.header.initiator_process_id};
  const auto found = request_profiles_.find(key);
  return found == request_profiles_.end() ? std::nullopt
                                          : std::optional<RequestSignalProfile>(found->second);
}

void RequestSignalProfileIndex::RememberEvent(const EventRecord& event) {
  if (events_.size() == capacity_) {
    events_.erase(event_order_.front());
    event_order_.pop_front();
    ++stats_.evicted_events;
  }
  const RequestSignalEventReference reference = Reference(event);
  events_.emplace(reference,
                  EventState{reference, event.header.parent_event_id, event.header.category});
  event_order_.push_back(reference);
}

void RequestSignalProfileIndex::RememberContextSignal(const EventRecord& event) {
  const std::size_t category_index = SignalCategoryIndex(event.header.category);
  if (category_index == kSignalCategories.size()) {
    return;
  }
  const RequestSignalEventReference reference = Reference(event);
  if (!ReferenceIsSet(reference)) {
    return;
  }
  const ContextKey key{event.header.session_id, event.header.navigation_id, event.header.frame_id,
                       event.header.process_id};
  auto context = contexts_.find(key);
  if (context == contexts_.end()) {
    if (contexts_.size() == capacity_) {
      contexts_.erase(context_order_.front());
      context_order_.pop_front();
      ++stats_.evicted_contexts;
    }
    context = contexts_.emplace(key, ContextState{}).first;
    context_order_.push_back(key);
  }
  ContextSignalState& signal = context->second.signals[category_index];
  if (signal.event_count == 0) {
    signal.first_event = reference;
  }
  if (signal.event_count != std::numeric_limits<std::uint64_t>::max()) {
    ++signal.event_count;
  } else {
    signal.count_saturated = true;
  }
  signal.last_event = reference;
}

void RequestSignalProfileIndex::RememberRequestProfile(const EventRecord& event,
                                                       const RequestSignalProfile& profile) {
  if (event.header.type != EventType::kRequestInitiated) {
    return;
  }
  const RequestKey key{event.header.session_id, event.header.request_id, event.header.process_id};
  const auto found = request_profiles_.find(key);
  if (found != request_profiles_.end()) {
    found->second = profile;
    return;
  }
  if (request_profiles_.size() == capacity_) {
    request_profiles_.erase(request_profile_order_.front());
    request_profile_order_.pop_front();
    ++stats_.evicted_profiles;
  }
  request_profiles_.emplace(key, profile);
  request_profile_order_.push_back(key);
}

std::optional<RequestSignalProfile> RequestSignalProfileIndex::Ingest(const EventRecord& event) {
  if (!IsValidEvent(event)) {
    return std::nullopt;
  }
  const RequestSignalEventReference reference = Reference(event);
  if (Contains(reference)) {
    ++stats_.duplicate_events;
    return std::nullopt;
  }

  std::optional<RequestSignalProfile> profile;
  if (IsRequestProfileRoot(event)) {
    profile = FindInitiatorProfile(event);
    if (profile) {
      profile->initiator_event = profile->root_event;
      profile->root_event = reference;
      profile->request_id = event.header.request_id;
      profile->navigation_id = event.header.navigation_id;
      profile->frame_id = event.header.frame_id;
      profile->copied_from_initiator = true;
      ++stats_.copied_profiles;
    } else {
      profile = BuildProfile(event);
      if (event.header.type == EventType::kRequestStarted &&
          event.header.initiator_process_id != 0 && event.header.initiator_request_id != 0 &&
          stats_.evicted_profiles != 0) {
        profile->retention_truncated = true;
      }
    }
  }

  RememberEvent(event);
  RememberContextSignal(event);
  if (profile) {
    RememberRequestProfile(event, *profile);
    ++stats_.emitted_profiles;
  }
  ++stats_.indexed_events;
  return profile;
}

RequestSignalProfileIndexStats RequestSignalProfileIndex::Stats() const noexcept {
  return stats_;
}

std::size_t RequestSignalProfileIndex::Size() const noexcept {
  return events_.size();
}

bool IsFingerprintSignalCategory(const EventCategory category) noexcept {
  return SignalCategoryIndex(category) != kSignalCategories.size();
}

bool IsValidRequestSignalProfile(const RequestSignalProfile& profile) noexcept {
  if (profile.protocol_version != kRequestSignalProfileProtocolVersion || profile.reserved != 0 ||
      profile.signal_count > profile.signals.size() || profile.request_id == 0 ||
      !ReferenceIsSet(profile.root_event) || profile.root_event.reserved != 0 ||
      profile.parent_depth > kRequestSignalProfileParentDepthLimit ||
      (profile.parent_depth_limited &&
       profile.parent_depth != kRequestSignalProfileParentDepthLimit) ||
      (profile.copied_from_initiator != ReferenceIsSet(profile.initiator_event)) ||
      profile.initiator_event.reserved != 0 ||
      (ReferenceIsSet(profile.initiator_event) &&
       profile.initiator_event.session_id != profile.root_event.session_id)) {
    return false;
  }
  std::array<bool, kRequestSignalProfileCategoryCount> categories{};
  bool has_saturated_count = false;
  const std::uint32_t expected_process_id = ReferenceIsSet(profile.initiator_event)
                                                ? profile.initiator_event.process_id
                                                : profile.root_event.process_id;
  for (std::size_t index = 0; index < profile.signal_count; ++index) {
    const RequestSignalEvidence& signal = profile.signals[index];
    const std::size_t category_index = SignalCategoryIndex(signal.category);
    if (category_index == categories.size() || categories[category_index] ||
        (signal.relation != RequestSignalRelation::kParentChain &&
         signal.relation != RequestSignalRelation::kSameContext) ||
        signal.event_count == 0 || !ReferenceIsSet(signal.first_event) ||
        !ReferenceIsSet(signal.last_event) || signal.first_event.reserved != 0 ||
        signal.last_event.reserved != 0 || signal.first_event.process_id != expected_process_id ||
        signal.last_event.process_id != expected_process_id ||
        signal.first_event.session_id != profile.root_event.session_id ||
        signal.last_event.session_id != profile.root_event.session_id) {
      return false;
    }
    has_saturated_count =
        has_saturated_count || signal.event_count == std::numeric_limits<std::uint64_t>::max();
    categories[category_index] = true;
  }
  return !profile.count_saturated || has_saturated_count;
}

std::string RequestSignalProfileToJson(const RequestSignalProfile& profile) {
  std::string output;
  output.reserve(2048);
  output.append("{\"protocol_version\":");
  AppendInteger(output, profile.protocol_version);
  output.append(",\"document_kind\":\"request-signal-profile\",\"session_id\":\"");
  AppendInteger(output, profile.root_event.session_id);
  output.append("\",\"request_id\":\"");
  AppendInteger(output, profile.request_id);
  output.append("\",\"root_event\":");
  AppendReference(output, profile.root_event);
  output.append(",\"initiator_event\":");
  if (ReferenceIsSet(profile.initiator_event)) {
    AppendReference(output, profile.initiator_event);
  } else {
    output.append("null");
  }
  output.append(",\"navigation_id\":\"");
  AppendInteger(output, profile.navigation_id);
  output.append("\",\"frame_id\":\"");
  AppendInteger(output, profile.frame_id);
  output.append("\",\"signals\":[");
  for (std::size_t index = 0; index < profile.signal_count; ++index) {
    if (index != 0) {
      output.push_back(',');
    }
    const RequestSignalEvidence& signal = profile.signals[index];
    output.append("{\"category\":\"");
    output.append(EventCategoryName(signal.category));
    output.append("\",\"relation\":\"");
    output.append(RequestSignalRelationName(signal.relation));
    output.append("\",\"confidence\":\"");
    output.append(signal.relation == RequestSignalRelation::kParentChain ? "observed"
                                                                         : "correlated");
    output.append("\",\"event_count\":\"");
    AppendInteger(output, signal.event_count);
    output.append("\",\"first_event\":");
    AppendReference(output, signal.first_event);
    output.append(",\"last_event\":");
    AppendReference(output, signal.last_event);
    output.push_back('}');
  }
  output.append("],\"coverage\":{\"parent_depth\":");
  AppendInteger(output, profile.parent_depth);
  output.append(",\"parent_depth_limit\":");
  AppendInteger(output, kRequestSignalProfileParentDepthLimit);
  output.append(",\"copied_from_initiator\":");
  output.append(profile.copied_from_initiator ? "true" : "false");
  output.append(",\"retention_truncated\":");
  output.append(profile.retention_truncated ? "true" : "false");
  output.append(",\"parent_depth_limited\":");
  output.append(profile.parent_depth_limited ? "true" : "false");
  output.append(",\"count_saturated\":");
  output.append(profile.count_saturated ? "true" : "false");
  output.append("}}");
  return output;
}

std::string_view RequestSignalRelationName(const RequestSignalRelation relation) noexcept {
  switch (relation) {
    case RequestSignalRelation::kParentChain:
      return "parent_chain";
    case RequestSignalRelation::kSameContext:
      return "same_context";
    case RequestSignalRelation::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace reb
