#include "reb/event_broker.hpp"

#include <algorithm>
#include <chrono>
#include <deque>
#include <limits>
#include <stdexcept>
#include <utility>

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

bool IsGapRecord(const EventRecord& event) noexcept {
  return event.header.type == EventType::kGap;
}

bool IsRetainedNetworkEvent(const EventRecord& event) noexcept {
  switch (event.header.type) {
    case EventType::kRequestInitiated:
    case EventType::kRequestStarted:
    case EventType::kResponseStarted:
    case EventType::kRequestCompleted:
      return true;
    default:
      return false;
  }
}

bool IsDisplaceableCanvasEvent(const EventRecord& event) noexcept {
  return event.header.category == EventCategory::kCanvas &&
         (event.header.type == EventType::kApiCall ||
          event.header.type == EventType::kPropertyRead);
}

void PushCapped(std::deque<std::size_t>& retained,
                const std::size_t index,
                const std::size_t limit) {
  retained.push_back(index);
  if (retained.size() > limit) {
    retained.pop_front();
  }
}

// `chronological` is oldest first. The returned window stays at `limit` and
// puts gap records, then the listed network events, ahead of canvas api_call
// and property_read rows. Other event kinds keep newest-window order.
std::vector<EventRecord> PreferCaptureWindow(std::vector<EventRecord> chronological,
                                             const std::size_t limit) {
  if (chronological.size() <= limit) {
    return chronological;
  }
  std::deque<std::size_t> window;
  std::deque<std::size_t> evicted_gaps;
  std::deque<std::size_t> evicted_network;
  for (std::size_t index = 0; index < chronological.size(); ++index) {
    window.push_back(index);
    if (window.size() <= limit) {
      continue;
    }
    const std::size_t evicted = window.front();
    window.pop_front();
    const EventRecord& event = chronological[evicted];
    if (IsGapRecord(event)) {
      PushCapped(evicted_gaps, evicted, limit);
    } else if (IsRetainedNetworkEvent(event)) {
      PushCapped(evicted_network, evicted, limit);
    }
  }
  const auto restore = [&](const std::deque<std::size_t>& evicted) {
    for (const std::size_t index : evicted) {
      const auto canvas = std::ranges::find_if(window, [&](const std::size_t candidate) {
        return IsDisplaceableCanvasEvent(chronological[candidate]);
      });
      if (canvas == window.end()) {
        return;
      }
      *canvas = index;
    }
  };
  restore(evicted_gaps);
  restore(evicted_network);
  std::vector<std::size_t> selected(window.begin(), window.end());
  std::ranges::sort(selected);
  std::vector<EventRecord> snapshot;
  snapshot.reserve(selected.size());
  for (const std::size_t index : selected) {
    snapshot.push_back(std::move(chronological[index]));
  }
  return snapshot;
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
      SaturateAdd(stats_.sequence_gaps, stats_.sequence_gaps_saturated, missing);
    }
    high_water->second = std::max(high_water->second, event.header.sequence_number);
  } else {
    stream_high_water_marks_.emplace(stream, event.header.sequence_number);
    stream_insertion_order_.push_back(stream);
  }

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
  const std::size_t available = events_.size();
  if (available == 0 || limit == 0) {
    return {};
  }
  // The retained ring is still the newest `capacity` events. A smaller snapshot
  // keeps gap records and network lifecycle events ahead of canvas noise.
  std::vector<EventRecord> chronological;
  chronological.reserve(available);
  const std::size_t start = next_event_ >= available ? next_event_ - available
                                                     : events_.size() - (available - next_event_);
  const std::size_t first_count = std::min(available, events_.size() - start);
  const auto begin = events_.begin() + static_cast<std::ptrdiff_t>(start);
  chronological.insert(chronological.end(), begin,
                       begin + static_cast<std::ptrdiff_t>(first_count));
  chronological.insert(chronological.end(), events_.begin(),
                       events_.begin() + static_cast<std::ptrdiff_t>(available - first_count));
  if (chronological.size() <= limit) {
    return chronological;
  }
  return PreferCaptureWindow(std::move(chronological), limit);
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
