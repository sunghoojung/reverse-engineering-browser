#include <atomic>
#include <cstdint>
#include <iostream>
#include <thread>

#include "reb/spsc_ring.hpp"

#define CHECK(condition)                                                               \
  do {                                                                                 \
    if (!(condition)) {                                                                \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": "          \
                << #condition << '\n';                                                  \
      return 1;                                                                        \
    }                                                                                  \
  } while (false)

namespace {

bool BasicFifoTest() {
  reb::SpscRing<std::uint64_t, 4> ring;
  std::uint64_t value = 0;

  if (!ring.TryPush(10) || !ring.TryPush(20) || !ring.TryPush(30)) {
    return false;
  }
  if (!ring.TryPop(value) || value != 10) {
    return false;
  }
  if (!ring.TryPop(value) || value != 20) {
    return false;
  }
  if (!ring.TryPop(value) || value != 30) {
    return false;
  }
  return !ring.TryPop(value);
}

bool FullRingTest() {
  reb::SpscRing<std::uint64_t, 4> ring;

  for (std::uint64_t value = 0; value < 4; ++value) {
    if (!ring.TryPush(value)) {
      return false;
    }
  }

  if (ring.TryPush(99) || ring.DroppedCount() != 1 || ring.SizeApprox() != 4) {
    return false;
  }

  for (std::uint64_t expected = 0; expected < 4; ++expected) {
    std::uint64_t value = 0;
    if (!ring.TryPop(value) || value != expected) {
      return false;
    }
  }

  return ring.SizeApprox() == 0;
}

bool WraparoundTest() {
  reb::SpscRing<std::uint64_t, 8> ring;

  for (std::uint64_t cycle = 0; cycle < 1000; ++cycle) {
    for (std::uint64_t offset = 0; offset < 8; ++offset) {
      if (!ring.TryPush(cycle * 8 + offset)) {
        return false;
      }
    }
    for (std::uint64_t offset = 0; offset < 8; ++offset) {
      std::uint64_t value = 0;
      if (!ring.TryPop(value) || value != cycle * 8 + offset) {
        return false;
      }
    }
  }

  return ring.SizeApprox() == 0 && ring.DroppedCount() == 0;
}

bool ConcurrentTest() {
  constexpr std::uint64_t kCount = 250'000;
  reb::SpscRing<std::uint64_t, 1024> ring;
  std::atomic<bool> producer_failed{false};
  std::atomic<bool> producer_done{false};
  std::atomic<bool> stop_requested{false};

  std::thread producer([&ring, &producer_failed, &producer_done, &stop_requested] {
    for (std::uint64_t value = 1; value <= kCount; ++value) {
      while (ring.SizeApprox() >= ring.CapacityValue()) {
        if (stop_requested.load(std::memory_order_acquire)) {
          producer_done.store(true, std::memory_order_release);
          return;
        }
        std::this_thread::yield();
      }
      if (!ring.TryPush(value)) {
        producer_failed.store(true, std::memory_order_release);
        break;
      }
    }
    producer_done.store(true, std::memory_order_release);
  });

  bool ordered = true;
  std::uint64_t expected = 1;
  while (expected <= kCount) {
    std::uint64_t value = 0;
    if (!ring.TryPop(value)) {
      if (producer_done.load(std::memory_order_acquire)) {
        break;
      }
      std::this_thread::yield();
      continue;
    }
    if (value != expected) {
      ordered = false;
      stop_requested.store(true, std::memory_order_release);
      break;
    }
    ++expected;
  }

  producer.join();
  return ordered && !producer_failed.load(std::memory_order_acquire) &&
         expected == kCount + 1 && ring.SizeApprox() == 0 && ring.DroppedCount() == 0;
}

}  // namespace

int main() {
  CHECK(BasicFifoTest());
  CHECK(FullRingTest());
  CHECK(WraparoundTest());
  CHECK(ConcurrentTest());

  std::cout << "spsc_ring_test passed\n";
  return 0;
}
