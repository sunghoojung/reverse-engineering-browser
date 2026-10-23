// Synthetic component benchmark. This does not measure live-browser performance.
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <new>
#include <string>
#include <string_view>

#include "reb/event.hpp"

namespace {
std::uint64_t allocations = 0;
}

void* operator new(const std::size_t size) {
  ++allocations;
  if (void* const value = std::malloc(size == 0 ? 1 : size)) {
    return value;
  }
  throw std::bad_alloc();
}
void operator delete(void* value) noexcept {
  std::free(value);
}
void operator delete(void* value, std::size_t) noexcept {
  std::free(value);
}

int main(const int argc, const char* argv[]) {
  std::uint64_t iterations = 2000000;
  if (argc == 2) {
    const std::string_view text(argv[1]);
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), iterations);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
      return 2;
    }
  } else if (argc != 1) {
    return 2;
  }
  if (iterations == 0 || iterations > 10000000) {
    return 2;
  }
  reb::EventRecord event =
      reb::MakeEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 1, 100, 7);
  event.header.process_id = 42;
  event.header.thread_id = 1;
  event.header.navigation_id = 100;
  event.header.frame_id = 200;
  if (!reb::SetInlinePayload(event, "canvas.getImageData")) {
    return 1;
  }
  std::string reused;
  reb::WriteEventJson(event, reused);  // Allocate the one-record budget before timing.
  std::uint64_t expected_checksum = 0;
  for (unsigned round = 0; round < 6; ++round) {
    for (unsigned position = 0; position < 2; ++position) {
      const bool reuse = (round + position) % 2 == 1;
      const auto before = allocations;
      std::uint64_t checksum = 0;
      const auto start = std::chrono::steady_clock::now();
      for (std::uint64_t sequence = 1; sequence <= iterations; ++sequence) {
        event.header.sequence_number = sequence;
        if (reuse) {
          reb::WriteEventJson(event, reused);
          checksum += reused.size();
        } else {
          checksum += reb::EventToJson(event).size();
        }
      }
      const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start);
      const auto calls = allocations - before;
      if ((reuse && calls != 0) || (expected_checksum != 0 && checksum != expected_checksum)) {
        std::cerr << "Serialization allocation or output-size invariant failed\n";
        return 1;
      }
      expected_checksum = checksum;
      std::cout << "{\"round\":" << round << ",\"reuse\":" << (reuse ? "true" : "false")
                << ",\"records\":" << iterations << ",\"allocations\":" << calls
                << ",\"ns_per_record\":"
                << elapsed.count() * 1000000000.0 / static_cast<double>(iterations)
                << ",\"checksum\":" << checksum << "}\n";
    }
  }
  return 0;
}
