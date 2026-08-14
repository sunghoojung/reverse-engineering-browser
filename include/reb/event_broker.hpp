#ifndef REB_EVENT_BROKER_HPP_
#define REB_EVENT_BROKER_HPP_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "reb/event.hpp"

namespace reb {

enum class IngestStatus {
  kAccepted,
  kInvalid,
  kCategoryRejected,
  kSessionExpired,
};

inline constexpr std::uint64_t kAllEventCategoryMask =
    (std::uint64_t{1} << static_cast<std::uint16_t>(EventCategory::kNetwork)) - 1;

[[nodiscard]] constexpr std::uint64_t EventCategoryMask(const EventCategory category) noexcept {
  const auto value = static_cast<std::uint16_t>(category);
  return value == 0 || value > static_cast<std::uint16_t>(EventCategory::kNetwork)
             ? 0
             : std::uint64_t{1} << (value - 1U);
}

struct SessionPolicy final {
  std::uint64_t category_mask = kAllEventCategoryMask;
  std::uint64_t expires_at_monotonic_ns = std::numeric_limits<std::uint64_t>::max();

  [[nodiscard]] bool IsValid() const noexcept;
  [[nodiscard]] bool Allows(EventCategory category) const noexcept;
  [[nodiscard]] bool IsExpired(std::uint64_t monotonic_now_ns) const noexcept;
};

struct BrokerStats final {
  std::uint64_t accepted = 0;
  std::uint64_t invalid = 0;
  std::uint64_t category_rejected = 0;
  std::uint64_t expired = 0;
  std::uint64_t sequence_gaps = 0;
  bool sequence_gaps_saturated = false;
  std::uint64_t sequence_tracking_evictions = 0;
  std::uint64_t evicted = 0;
};

class EventBroker final {
 public:
  explicit EventBroker(std::size_t capacity, SessionPolicy policy = {});

  EventBroker(const EventBroker&) = delete;
  EventBroker& operator=(const EventBroker&) = delete;

  [[nodiscard]] IngestStatus Ingest(const EventRecord& event);
  [[nodiscard]] IngestStatus IngestAt(const EventRecord& event, std::uint64_t monotonic_now_ns);
  [[nodiscard]] std::vector<EventRecord> Snapshot(std::size_t limit) const;
  [[nodiscard]] BrokerStats Stats() const;
  [[nodiscard]] std::size_t Size() const;

 private:
  struct StreamKey final {
    std::uint64_t session_id = 0;
    std::uint32_t process_id = 0;

    bool operator==(const StreamKey&) const = default;
  };

  struct StreamKeyHash final {
    [[nodiscard]] std::size_t operator()(const StreamKey& key) const noexcept {
      return std::hash<std::uint64_t>{}(key.session_id) ^
             (std::hash<std::uint32_t>{}(key.process_id) << 1U);
    }
  };

  const std::size_t capacity_;
  const SessionPolicy policy_;
  mutable std::mutex mutex_;
  std::deque<EventRecord> events_;
  BrokerStats stats_;
  std::unordered_map<StreamKey, std::uint64_t, StreamKeyHash> stream_high_water_marks_;
  std::deque<StreamKey> stream_insertion_order_;
};

}  // namespace reb

#endif  // REB_EVENT_BROKER_HPP_
