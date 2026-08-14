#include <unistd.h>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>

#include "reb/event.hpp"
#include "reb/local_ipc.hpp"
#include "reb/vm_finding.hpp"

namespace {

struct Options final {
  std::string socket_path;
  std::string token_path;
  std::uint64_t session_id = 1;
};

constexpr std::uint64_t kNavigationId = 100;
constexpr std::uint64_t kFrameId = 200;
constexpr std::uint64_t kArtifactId = 300;
constexpr std::uint64_t kVmArtifactId = 302;

std::uint64_t MonotonicTimeNs() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch())
                                        .count());
}

reb::EventRecord BuildEvent(const reb::EventCategory category,
                            const reb::EventType type,
                            const std::uint64_t sequence,
                            const std::string_view payload,
                            const std::uint64_t session_id) {
  reb::EventRecord event = reb::MakeEvent(category, type, sequence, MonotonicTimeNs(), session_id);
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

reb::EventRecord BuildNetworkEvent(const reb::EventType type,
                                   const std::uint64_t sequence,
                                   const std::string_view payload,
                                   const std::uint64_t session_id) {
  reb::EventRecord event =
      BuildEvent(reb::EventCategory::kNetwork, type, sequence, payload, session_id);
  event.header.request_id = 81;
  event.header.resource_type = 13;
  return event;
}

bool ParseSessionId(const std::string_view value, std::uint64_t& session_id) {
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), session_id);
  return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && session_id != 0;
}

bool ParseOptions(const int argc, char* argv[], Options& options) {
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--socket" && index + 1 < argc) {
      options.socket_path = argv[++index];
    } else if (argument == "--token-file" && index + 1 < argc) {
      options.token_path = argv[++index];
    } else if (argument == "--session-id" && index + 1 < argc) {
      if (!ParseSessionId(argv[++index], options.session_id)) {
        return false;
      }
    } else {
      return false;
    }
  }
  return options.socket_path.empty() == options.token_path.empty();
}

reb::EventRecord BuildVmEvent(const reb::VmFindingPayload& finding,
                              const std::uint64_t sequence,
                              const std::uint64_t session_id) {
  reb::EventRecord event = reb::MakeEvent(reb::EventCategory::kVm, reb::EventType::kVmFinding,
                                          sequence, MonotonicTimeNs(), session_id);
  event.header.process_id = 10;
  event.header.thread_id = 20;
  event.header.navigation_id = kNavigationId;
  event.header.frame_id = kFrameId;
  event.header.artifact_id = kVmArtifactId;
  if (!reb::SetVmFindingPayload(event, finding)) {
    std::cerr << "Invalid VM finding\n";
    std::exit(1);
  }
  return event;
}

reb::VmFindingPayload Finding(const reb::VmFindingKind kind,
                              const reb::VmHostRuntime runtime,
                              const reb::VmFindingConfidence confidence,
                              const std::uint64_t id,
                              const std::string_view label) {
  return reb::MakeVmFinding(kind, runtime, confidence, id, 7001, label);
}

}  // namespace

int main(const int argc, char* argv[]) {
  Options options;
  if (!ParseOptions(argc, argv, options)) {
    std::cerr << "Usage: " << argv[0] << " [--socket PATH --token-file PATH --session-id ID]\n";
    return 2;
  }

  reb::VmFindingPayload interpreter =
      Finding(reb::VmFindingKind::kInterpreter, reb::VmHostRuntime::kJavaScript,
              reb::VmFindingConfidence::kHeuristic, 101, "dispatcher loop candidate");
  interpreter.subject_id = 1001;
  interpreter.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kPartial) |
                      static_cast<std::uint8_t>(reb::VmFindingFlag::kDynamic);

  reb::VmFindingPayload guest =
      Finding(reb::VmFindingKind::kGuestProgram, reb::VmHostRuntime::kJavaScript,
              reb::VmFindingConfidence::kObserved, 102, "nested guest bytecode");
  guest.subject_id = 1002;
  guest.related_subject_id = 1001;
  guest.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kPartial) |
                static_cast<std::uint8_t>(reb::VmFindingFlag::kNested);

  reb::VmFindingPayload invocation =
      Finding(reb::VmFindingKind::kInvocation, reb::VmHostRuntime::kJavaScript,
              reb::VmFindingConfidence::kObserved, 103, "guest entry invocation");
  invocation.subject_id = 1003;
  invocation.related_subject_id = 1002;
  invocation.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kDynamic);

  reb::VmFindingPayload binding =
      Finding(reb::VmFindingKind::kHostBinding, reb::VmHostRuntime::kMixed,
              reb::VmFindingConfidence::kObserved, 104, "canvas readback binding");
  binding.subject_id = 1004;
  binding.related_subject_id = 1003;

  reb::VmFindingPayload hypothesis =
      Finding(reb::VmFindingKind::kHypothesis, reb::VmHostRuntime::kJavaScript,
              reb::VmFindingConfidence::kInferred, 105, "pc and opcode candidates");
  hypothesis.subject_id = 1001;
  hypothesis.related_subject_id = 1002;
  hypothesis.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kPartial);

  reb::VmFindingPayload coverage =
      Finding(reb::VmFindingKind::kCoverage, reb::VmHostRuntime::kMixed,
              reb::VmFindingConfidence::kObserved, 106, "handlers characterized");
  coverage.subject_id = 1001;
  coverage.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kPartial);
  coverage.observed_count = 42;
  coverage.total_count = 60;

  std::array events = {
      BuildEvent(reb::EventCategory::kNavigator, reb::EventType::kPropertyRead, 1,
                 "navigator.languages", options.session_id),
      BuildEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 2, "canvas.toDataURL",
                 options.session_id),
      BuildEvent(reb::EventCategory::kWasm, reb::EventType::kModuleInstantiated, 3, "wasm-module-2",
                 options.session_id),
      BuildNetworkEvent(reb::EventType::kRequestInitiated, 4, "POST collector.example.test",
                        options.session_id),
      BuildNetworkEvent(reb::EventType::kRequestStarted, 5, "POST collector.example.test",
                        options.session_id),
      BuildNetworkEvent(reb::EventType::kResponseStarted, 6, "application/json; protocol=h2",
                        options.session_id),
      BuildNetworkEvent(reb::EventType::kRequestCompleted, 7, "completed", options.session_id),
      BuildVmEvent(interpreter, 8, options.session_id),
      BuildVmEvent(guest, 9, options.session_id),
      BuildVmEvent(invocation, 10, options.session_id),
      BuildVmEvent(binding, 11, options.session_id),
      BuildVmEvent(hypothesis, 12, options.session_id),
      BuildVmEvent(coverage, 13, options.session_id),
  };

  events[2].header.parent_event_id = 2;
  events[3].header.parent_event_id = 3;
  events[4].header.parent_event_id = 4;
  events[5].header.parent_event_id = 5;
  events[5].header.status_code = 200;
  events[6].header.parent_event_id = 6;
  events[6].header.status_code = 200;
  events[6].header.encoded_data_length = 391;
  events[6].header.decoded_body_length = 447;
  for (std::size_t index = 7; index < events.size(); ++index) {
    events[index].header.parent_event_id = static_cast<std::uint64_t>(index);
  }

  if (options.socket_path.empty()) {
    for (const reb::EventRecord& event : events) {
      std::cout.write(reinterpret_cast<const char*>(&event), sizeof(event));
    }
    if (!std::cout) {
      std::cerr << "Failed to write native event stream\n";
      return 1;
    }
  } else {
    std::string error;
    const int descriptor = reb::ConnectAuthenticatedLocalIpc(
        options.socket_path, options.token_path, options.session_id, error);
    if (descriptor < 0) {
      std::cerr << error << '\n';
      return 1;
    }
    for (const reb::EventRecord& event : events) {
      if (!reb::WriteExact(descriptor, std::as_bytes(std::span(&event, 1)), error)) {
        std::cerr << error << '\n';
        close(descriptor);
        return 1;
      }
    }
    if (close(descriptor) != 0) {
      std::cerr << "Unable to close broker connection\n";
      return 1;
    }
  }
  return 0;
}
