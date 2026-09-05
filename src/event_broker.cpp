#include "reb/event_broker.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <stdexcept>

namespace reb {

namespace {

std::uint64_t MonotonicTimeNs() noexcept {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch())
                                        .count());
}

}  // namespace

bool SessionPolicy::IsValid() const noexcept {
  return category_mask != 0 && (category_mask & ~kAllEventCategoryMask) == 0 &&
         expires_at_monotonic_ns != 0;
}

bool SessionPolicy::Allows(const EventCategory category) const noexcept {
  const std::uint64_t category_bit = EventCategoryMask(category);
  return category_bit != 0 && (category_mask & category_bit) != 0;
}

bool SessionPolicy::IsExpired(const std::uint64_t monotonic_now_ns) const noexcept {
  return monotonic_now_ns >= expires_at_monotonic_ns;
}

EventBroker::EventBroker(const std::size_t capacity, const SessionPolicy policy)
    : capacity_(capacity), policy_(policy) {
  if (capacity == 0) {
    throw std::invalid_argument("EventBroker capacity must be greater than zero");
  }
  if (!policy.IsValid()) {
    throw std::invalid_argument("EventBroker session policy is invalid");
  }
  events_.reserve(capacity);
  stream_high_water_marks_.reserve(capacity);
}

IngestStatus EventBroker::Ingest(const EventRecord& event) {
  return IngestAt(event, MonotonicTimeNs());
}

IngestStatus EventBroker::IngestAt(const EventRecord& event, const std::uint64_t monotonic_now_ns) {
  std::scoped_lock lock(mutex_);
  if (!IsValidEvent(event)) {
    ++stats_.invalid;
    return IngestStatus::kInvalid;
  }
  if (policy_.IsExpired(monotonic_now_ns)) {
    ++stats_.expired;
    return IngestStatus::kSessionExpired;
  }
  if (!policy_.Allows(event.header.category)) {
    ++stats_.category_rejected;
    return IngestStatus::kCategoryRejected;
  }

  const StreamKey stream{event.header.session_id, event.header.process_id};
  auto high_water = stream_high_water_marks_.find(stream);
  if (high_water == stream_high_water_marks_.end() &&
      stream_high_water_marks_.size() == capacity_) {
    stream_high_water_marks_.erase(stream_insertion_order_.front());
    stream_insertion_order_.pop_front();
    ++stats_.sequence_tracking_evictions;
  }

  if (high_water != stream_high_water_marks_.end()) {
    if (event.header.sequence_number > high_water->second &&
        event.header.sequence_number - high_water->second > 1) {
      const std::uint64_t missing = event.header.sequence_number - high_water->second - 1;
      if (missing > std::numeric_limits<std::uint64_t>::max() - stats_.sequence_gaps) {
        stats_.sequence_gaps = std::numeric_limits<std::uint64_t>::max();
        stats_.sequence_gaps_saturated = true;
      } else {
        stats_.sequence_gaps += missing;
      }
    }
    high_water->second = std::max(high_water->second, event.header.sequence_number);
  } else {
    stream_high_water_marks_.emplace(stream, event.header.sequence_number);
    stream_insertion_order_.push_back(stream);
  }

  if (events_.size() == capacity_) {
    events_[next_event_] = event;
    ++stats_.evicted;
  } else {
    events_.push_back(event);
  }
  if (++next_event_ == capacity_) {
    next_event_ = 0;
  }
  ++stats_.accepted;
  return IngestStatus::kAccepted;
}

std::vector<EventRecord> EventBroker::Snapshot(const std::size_t limit) const {
  std::scoped_lock lock(mutex_);
  const std::size_t count = std::min(limit, events_.size());
  std::vector<EventRecord> snapshot;
  snapshot.reserve(count);
  if (count == 0) {
    return snapshot;
  }
  // The newest suffix spans at most two contiguous ranges, even after wrap.
  const std::size_t start =
      next_event_ >= count ? next_event_ - count : events_.size() - (count - next_event_);
  const std::size_t first_count = std::min(count, events_.size() - start);
  const auto begin = events_.begin() + static_cast<std::ptrdiff_t>(start);
  snapshot.insert(snapshot.end(), begin, begin + static_cast<std::ptrdiff_t>(first_count));
  snapshot.insert(snapshot.end(), events_.begin(),
                  events_.begin() + static_cast<std::ptrdiff_t>(count - first_count));
  return snapshot;
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
