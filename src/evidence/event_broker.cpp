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

void SaturateAdd(std::uint64_t& total, bool& saturated, const std::uint64_t amount) noexcept {
  if (amount > std::numeric_limits<std::uint64_t>::max() - total) {
    total = std::numeric_limits<std::uint64_t>::max();
    saturated = true;
    return;
  }
  total += amount;
}

// A gap payload is a decimal drop count. Anything else weighs one event, matching
// the research UI and the native probe queue.
std::uint64_t ReportedQueueDrops(const EventRecord& event) noexcept {
  const std::span<const std::byte> payload = InlinePayload(event);
  if (payload.empty() || payload.size() > 20) {
    return 1;
  }
  const auto first = std::to_integer<unsigned char>(payload.front());
  if (first < static_cast<unsigned char>('1') || first > static_cast<unsigned char>('9')) {
    return 1;
  }
  std::uint64_t count = 0;
  for (const std::byte byte : payload) {
    const auto digit = std::to_integer<unsigned char>(byte);
    if (digit < static_cast<unsigned char>('0') || digit > static_cast<unsigned char>('9')) {
      return 1;
    }
    const auto value = static_cast<std::uint64_t>(digit - static_cast<unsigned char>('0'));
    if (count > (std::numeric_limits<std::uint64_t>::max() - value) / 10) {
      return 1;
    }
    count = count * 10 + value;
  }
  return count;
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
  sequence_trackers_.reserve(capacity);
}

void EventBroker::EvictSequenceTracker() {
  const auto found = sequence_trackers_.find(stream_insertion_order_.front());
  missing_interval_count_ -= found->second.missing.size();
  sequence_trackers_.erase(found);
  stream_insertion_order_.pop_front();
  ++stats_.sequence_tracking_evictions;
}
void EventBroker::TrackSequence(const StreamKey& stream, const std::uint64_t sequence) {
  auto found = sequence_trackers_.find(stream);
  if (found == sequence_trackers_.end()) {
    if (sequence_trackers_.size() == capacity_)
      EvictSequenceTracker();
    sequence_trackers_.emplace(stream, SequenceTracker{sequence, sequence, {}});
    stream_insertion_order_.push_back(stream);
    return;
  }
  auto& tracker = found->second;
  const auto previous_size = tracker.missing.size();
  if (sequence > tracker.high) {
    if (sequence - tracker.high > 1)
      tracker.missing.emplace(tracker.high + 1, sequence - 1);
    tracker.high = sequence;
  } else if (sequence < tracker.low) {
    if (tracker.low - sequence > 1)
      tracker.missing.emplace(sequence + 1, tracker.low - 1);
    tracker.low = sequence;
  } else {
    auto hole = tracker.missing.upper_bound(sequence);
    if (hole != tracker.missing.begin()) {
      --hole;
      const auto [first, last] = *hole;
      if (sequence <= last) {
        tracker.missing.erase(hole);
        if (first < sequence)
          tracker.missing.emplace(first, sequence - 1);
        if (sequence < last)
          tracker.missing.emplace(sequence + 1, last);
      }
    }
  }
  missing_interval_count_ -= previous_size;
  missing_interval_count_ += tracker.missing.size();
  // Bound all interval storage, not just process streams. Evicted uncertainty
  // is explicit, never frozen as a fabricated permanent loss.
  while (missing_interval_count_ > capacity_)
    EvictSequenceTracker();
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

  TrackSequence({event.header.session_id, event.header.process_id}, event.header.sequence_number);

  if (event.header.type == EventType::kGap) {
    SaturateAdd(stats_.queue_drops, stats_.queue_drops_saturated, ReportedQueueDrops(event));
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
  // This low-level ring retains the newest arrivals in chronological order. The
  // disk-backed API owns independent general/network windows; a snapshot must
  // not imply that evicted records remain in this ring.
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
  auto result = stats_;
  result.sequence_gaps = 0;
  result.sequence_gaps_saturated = false;
  for (const auto& [stream, tracker] : sequence_trackers_) {
    static_cast<void>(stream);
    for (const auto& [first, last] : tracker.missing) {
      SaturateAdd(result.sequence_gaps, result.sequence_gaps_saturated, last - first + 1);
    }
  }
  return result;
}

std::size_t EventBroker::Size() const {
  std::scoped_lock lock(mutex_);
  return events_.size();
}

}  // namespace reb
