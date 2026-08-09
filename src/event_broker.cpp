#include "reb/event_broker.hpp"

#include <algorithm>
#include <stdexcept>

namespace reb {

EventBroker::EventBroker(const std::size_t capacity) : capacity_(capacity) {
  if (capacity == 0) {
    throw std::invalid_argument("EventBroker capacity must be greater than zero");
  }
}

IngestStatus EventBroker::Ingest(const EventRecord& event) {
  std::scoped_lock lock(mutex_);
  if (!IsValidEvent(event)) {
    ++stats_.invalid;
    return IngestStatus::kInvalid;
  }

  const auto high_water = session_high_water_marks_.find(event.header.session_id);
  if (high_water != session_high_water_marks_.end()) {
    if (event.header.sequence_number > high_water->second &&
        event.header.sequence_number - high_water->second > 1) {
      stats_.sequence_gaps += event.header.sequence_number - high_water->second - 1;
    }
    high_water->second = std::max(high_water->second, event.header.sequence_number);
  } else {
    session_high_water_marks_.emplace(event.header.session_id,
                                      event.header.sequence_number);
  }

  if (events_.size() == capacity_) {
    events_.pop_front();
    ++stats_.evicted;
  }
  events_.push_back(event);
  ++stats_.accepted;
  return IngestStatus::kAccepted;
}

std::vector<EventRecord> EventBroker::Snapshot(const std::size_t limit) const {
  std::scoped_lock lock(mutex_);
  const std::size_t count = std::min(limit, events_.size());
  const auto begin = events_.end() - static_cast<std::ptrdiff_t>(count);
  return std::vector<EventRecord>(begin, events_.end());
}

BrokerStats EventBroker::Stats() const {
  std::scoped_lock lock(mutex_);
  return stats_;
}

std::size_t EventBroker::Size() const {
  std::scoped_lock lock(mutex_);
  return events_.size();
}

}  // namespace reb
