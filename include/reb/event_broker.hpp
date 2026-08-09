#ifndef REB_EVENT_BROKER_HPP_
#define REB_EVENT_BROKER_HPP_

#include <cstddef>
#include <cstdint>
#include <deque>
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
  const std::size_t capacity_;
  mutable std::mutex mutex_;
  std::deque<EventRecord> events_;
  BrokerStats stats_;
  std::unordered_map<std::uint64_t, std::uint64_t> session_high_water_marks_;
};

}  // namespace reb

#endif  // REB_EVENT_BROKER_HPP_
