#ifndef REB_SPSC_RING_HPP_
#define REB_SPSC_RING_HPP_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace reb {

template <typename T, std::size_t Capacity>
class SpscRing final {
  static_assert(Capacity >= 2);
  static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two");
  static_assert(std::is_trivially_copyable_v<T>, "Ring records must be trivially copyable");

 public:
  SpscRing() = default;

  SpscRing(const SpscRing&) = delete;
  SpscRing& operator=(const SpscRing&) = delete;

  [[nodiscard]] bool TryPush(const T& value) noexcept {
    const std::uint64_t head = head_.load(std::memory_order_relaxed);
    const std::uint64_t tail = tail_.load(std::memory_order_acquire);

    if (head - tail == Capacity) {
      dropped_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }

    slots_[static_cast<std::size_t>(head) & kIndexMask] = value;
    head_.store(head + 1, std::memory_order_release);
    return true;
  }

  [[nodiscard]] bool TryPop(T& value) noexcept {
    const std::uint64_t tail = tail_.load(std::memory_order_relaxed);
    const std::uint64_t head = head_.load(std::memory_order_acquire);

    if (tail == head) {
      return false;
    }

    value = slots_[static_cast<std::size_t>(tail) & kIndexMask];
    tail_.store(tail + 1, std::memory_order_release);
    return true;
  }

  [[nodiscard]] std::size_t SizeApprox() const noexcept {
    const std::uint64_t head = head_.load(std::memory_order_acquire);
    const std::uint64_t tail = tail_.load(std::memory_order_acquire);
    return static_cast<std::size_t>(head - tail);
  }

  [[nodiscard]] constexpr std::size_t CapacityValue() const noexcept { return Capacity; }

  [[nodiscard]] std::uint64_t DroppedCount() const noexcept {
    return dropped_.load(std::memory_order_relaxed);
  }

 private:
  static constexpr std::size_t kIndexMask = Capacity - 1;

  alignas(64) std::atomic<std::uint64_t> head_{0};
  alignas(64) std::atomic<std::uint64_t> tail_{0};
  alignas(64) std::atomic<std::uint64_t> dropped_{0};
  alignas(64) std::array<T, Capacity> slots_{};
};

}  // namespace reb

#endif  // REB_SPSC_RING_HPP_
