#ifndef REB_EVENT_BROKER_HPP_
#define REB_EVENT_BROKER_HPP_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "reb/event.hpp"

namespace reb {

enum class IngestStatus {
  kAccepted,
  kInvalid,
};

struct BrokerStats final {
  std::uint64_t accepted = 0;
  std::uint64_t invalid = 0;
  std::uint64_t sequence_gaps = 0;
  bool sequence_gaps_saturated = false;
  std::uint64_t sequence_tracking_evictions = 0;
  std::uint64_t evicted = 0;
};

class EventBroker final {
 public:
  explicit EventBroker(std::size_t capacity);

  EventBroker(const EventBroker&) = delete;
  EventBroker& operator=(const EventBroker&) = delete;

  [[nodiscard]] IngestStatus Ingest(const EventRecord& event);
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
  mutable std::mutex mutex_;
  std::deque<EventRecord> events_;
  BrokerStats stats_;
  std::unordered_map<StreamKey, std::uint64_t, StreamKeyHash> stream_high_water_marks_;
  std::deque<StreamKey> stream_insertion_order_;
};

}  // namespace reb

#endif  // REB_EVENT_BROKER_HPP_
