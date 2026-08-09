#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string_view>

#include "reb/event.hpp"

namespace {

constexpr std::uint64_t kSessionId = 1;
constexpr std::uint64_t kNavigationId = 100;
constexpr std::uint64_t kFrameId = 200;
constexpr std::uint64_t kArtifactId = 300;

std::uint64_t MonotonicTimeNs() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

reb::EventRecord BuildEvent(const reb::EventCategory category,
                            const reb::EventType type,
                            const std::uint64_t sequence,
                            const std::string_view payload) {
  reb::EventRecord event =
      reb::MakeEvent(category, type, sequence, MonotonicTimeNs(), kSessionId);
  event.header.process_id = 10;
  event.header.thread_id = 20;
  event.header.navigation_id = kNavigationId;
  event.header.frame_id = kFrameId;
  event.header.artifact_id = kArtifactId;
  if (!reb::SetInlinePayload(event, payload)) {
    std::cerr << "Payload exceeds the inline event capacity\n";
    std::exit(1);
  }
  return event;
}

}  // namespace

int main() {
  const std::array events = {
      BuildEvent(reb::EventCategory::kNavigator, reb::EventType::kPropertyRead, 1,
                 "navigator.languages"),
      BuildEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 2,
                 "canvas.toDataURL"),
      BuildEvent(reb::EventCategory::kWasm, reb::EventType::kModuleInstantiated, 3,
                 "wasm-module-2"),
      BuildEvent(reb::EventCategory::kNetwork, reb::EventType::kRequestStarted, 4,
                 "POST /collect"),
  };

  for (const reb::EventRecord& event : events) {
    std::cout.write(reinterpret_cast<const char*>(&event), sizeof(event));
  }
  if (!std::cout) {
    std::cerr << "Failed to write native event stream\n";
    return 1;
  }
  return 0;
}
