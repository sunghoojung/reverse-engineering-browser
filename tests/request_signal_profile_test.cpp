#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>

#include "reb/request_signal_profile.hpp"

#define CHECK(condition)                                                                   \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " << #condition \
                << '\n';                                                                   \
      return 1;                                                                            \
    }                                                                                      \
  } while (false)

namespace {

reb::EventRecord Event(const reb::EventCategory category,
                       const reb::EventType type,
                       const std::uint64_t sequence,
                       const std::uint32_t process = 10,
                       const std::uint64_t session = 7) {
  reb::EventRecord event = reb::MakeEvent(category, type, sequence, 1000 + sequence, session);
  event.header.process_id = process;
  event.header.navigation_id = 20;
  event.header.frame_id = 30;
  return event;
}

const reb::RequestSignalEvidence* Signal(const reb::RequestSignalProfile& profile,
                                         const reb::EventCategory category) {
  for (std::size_t index = 0; index < profile.signal_count; ++index) {
    if (profile.signals[index].category == category) {
      return &profile.signals[index];
    }
  }
  return nullptr;
}

}  // namespace

int main() {
  bool rejected_zero_capacity = false;
  try {
    reb::RequestSignalProfileIndex invalid(0);
  } catch (const std::invalid_argument&) {
    rejected_zero_capacity = true;
  }
  CHECK(rejected_zero_capacity);

  reb::RequestSignalProfileIndex index(64);
  reb::EventRecord navigator =
      Event(reb::EventCategory::kNavigator, reb::EventType::kPropertyRead, 1);
  reb::EventRecord canvas = Event(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 2);
  canvas.header.parent_event_id = 1;
  reb::EventRecord audio = Event(reb::EventCategory::kWebAudio, reb::EventType::kApiCall, 3);
  reb::EventRecord wasm = Event(reb::EventCategory::kWasm, reb::EventType::kModuleInstantiated, 4);
  wasm.header.parent_event_id = 2;
  reb::EventRecord initiated =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestInitiated, 5);
  initiated.header.request_id = 81;
  initiated.header.parent_event_id = 4;

  CHECK(!index.Ingest(navigator));
  CHECK(!index.Ingest(canvas));
  CHECK(!index.Ingest(audio));
  CHECK(!index.Ingest(wasm));
  const std::optional<reb::RequestSignalProfile> initiated_profile = index.Ingest(initiated);
  CHECK(initiated_profile);
  CHECK(reb::IsValidRequestSignalProfile(*initiated_profile));
  CHECK(initiated_profile->signal_count == 3);
  CHECK(initiated_profile->parent_depth == 3);
  CHECK(Signal(*initiated_profile, reb::EventCategory::kNavigator)->relation ==
        reb::RequestSignalRelation::kParentChain);
  CHECK(Signal(*initiated_profile, reb::EventCategory::kCanvas)->relation ==
        reb::RequestSignalRelation::kParentChain);
  CHECK(Signal(*initiated_profile, reb::EventCategory::kWebAudio)->relation ==
        reb::RequestSignalRelation::kSameContext);

  reb::EventRecord started =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestStarted, 1, 90);
  started.header.request_id = 9001;
  started.header.initiator_process_id = 10;
  started.header.initiator_request_id = 81;
  const std::optional<reb::RequestSignalProfile> started_profile = index.Ingest(started);
  CHECK(started_profile);
  CHECK(reb::IsValidRequestSignalProfile(*started_profile));
  CHECK(started_profile->copied_from_initiator);
  CHECK(started_profile->root_event.process_id == 90);
  CHECK(started_profile->root_event.sequence_number == 1);
  CHECK(started_profile->initiator_event.process_id == 10);
  CHECK(started_profile->initiator_event.sequence_number == 5);
  CHECK(started_profile->request_id == 9001);

  const std::string json = reb::RequestSignalProfileToJson(*started_profile);
  CHECK(json.find("\"document_kind\":\"request-signal-profile\"") != std::string::npos);
  CHECK(json.find("\"category\":\"web_audio\"") != std::string::npos);
  CHECK(json.find("\"relation\":\"parent_chain\"") != std::string::npos);
  CHECK(json.find("\"relation\":\"same_context\"") != std::string::npos);
  CHECK(json.find("\"copied_from_initiator\":true") != std::string::npos);

  CHECK(!index.Ingest(started));
  CHECK(index.Stats().duplicate_events == 1);
  CHECK(index.Stats().emitted_profiles == 2);
  CHECK(index.Stats().copied_profiles == 1);

  reb::EventRecord missing_identity =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestInitiated, 6);
  missing_identity.header.session_id = 0;
  missing_identity.header.request_id = 82;
  CHECK(!index.Ingest(missing_identity));

  reb::RequestSignalProfileIndex missing_signal_identity_index(8);
  CHECK(!missing_signal_identity_index.Ingest(
      Event(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 0)));
  reb::EventRecord request_after_missing_signal =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestInitiated, 1);
  request_after_missing_signal.header.request_id = 84;
  const auto profile_after_missing_signal =
      missing_signal_identity_index.Ingest(request_after_missing_signal);
  CHECK(profile_after_missing_signal);
  CHECK(profile_after_missing_signal->signal_count == 0);

  reb::RequestSignalProfileIndex bounded(2);
  CHECK(!bounded.Ingest(Event(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 1)));
  CHECK(!bounded.Ingest(Event(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 2)));
  CHECK(!bounded.Ingest(Event(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 3)));
  reb::EventRecord truncated_request =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestInitiated, 4);
  truncated_request.header.request_id = 2;
  const auto truncated_profile = bounded.Ingest(truncated_request);
  CHECK(truncated_profile);
  CHECK(truncated_profile->retention_truncated);
  CHECK(Signal(*truncated_profile, reb::EventCategory::kCanvas)->event_count == 3);
  CHECK(Signal(*truncated_profile, reb::EventCategory::kCanvas)->first_event.sequence_number == 3);

  reb::RequestSignalProfileIndex stale_context(2);
  CHECK(!stale_context.Ingest(Event(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 1)));
  CHECK(!stale_context.Ingest(
      Event(reb::EventCategory::kArtifact, reb::EventType::kArtifactCaptured, 2)));
  CHECK(!stale_context.Ingest(
      Event(reb::EventCategory::kArtifact, reb::EventType::kArtifactCaptured, 3)));
  reb::EventRecord stale_request =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestInitiated, 4);
  stale_request.header.request_id = 83;
  const auto stale_profile = stale_context.Ingest(stale_request);
  CHECK(stale_profile);
  CHECK(stale_profile->signal_count == 0);
  CHECK(stale_profile->retention_truncated);

  reb::RequestSignalProfileIndex evicted_profiles(2);
  for (std::uint64_t sequence = 1; sequence <= 3; ++sequence) {
    reb::EventRecord request =
        Event(reb::EventCategory::kNetwork, reb::EventType::kRequestInitiated, sequence);
    request.header.request_id = sequence;
    CHECK(evicted_profiles.Ingest(request));
  }
  CHECK(evicted_profiles.Stats().evicted_profiles == 1);
  reb::EventRecord missing_initiator =
      Event(reb::EventCategory::kNetwork, reb::EventType::kRequestStarted, 1, 90);
  missing_initiator.header.request_id = 9002;
  missing_initiator.header.initiator_process_id = 10;
  missing_initiator.header.initiator_request_id = 1;
  const auto partial_profile = evicted_profiles.Ingest(missing_initiator);
  CHECK(partial_profile);
  CHECK(!partial_profile->copied_from_initiator);
  CHECK(partial_profile->retention_truncated);

  reb::RequestSignalProfile invalid_profile = *started_profile;
  invalid_profile.signals[0].event_count = 0;
  CHECK(!reb::IsValidRequestSignalProfile(invalid_profile));
  invalid_profile = *started_profile;
  invalid_profile.signals[0].relation = static_cast<reb::RequestSignalRelation>(255);
  CHECK(!reb::IsValidRequestSignalProfile(invalid_profile));
  invalid_profile = *started_profile;
  invalid_profile.signals[0].last_event.process_id = 11;
  CHECK(!reb::IsValidRequestSignalProfile(invalid_profile));
  invalid_profile = *started_profile;
  invalid_profile.count_saturated = true;
  CHECK(!reb::IsValidRequestSignalProfile(invalid_profile));
  invalid_profile.signals[0].event_count = std::numeric_limits<std::uint64_t>::max();
  CHECK(reb::IsValidRequestSignalProfile(invalid_profile));
  CHECK(reb::RequestSignalProfileToJson(invalid_profile).find("\"count_saturated\":true") !=
        std::string::npos);

  constexpr std::uint64_t kBenchmarkEvents = 1'000'000;
  reb::RequestSignalProfileIndex benchmark(1024);
  std::size_t serialized_profile_bytes = 0;
  const auto begin = std::chrono::steady_clock::now();
  for (std::uint64_t sequence = 1; sequence <= kBenchmarkEvents; ++sequence) {
    const bool is_request = sequence % 64 == 0;
    const bool is_signal = !is_request && sequence % 16 == 0;
    reb::EventRecord event = Event(is_request  ? reb::EventCategory::kNetwork
                                   : is_signal ? reb::EventCategory::kCanvas
                                               : reb::EventCategory::kArtifact,
                                   is_request  ? reb::EventType::kRequestInitiated
                                   : is_signal ? reb::EventType::kApiCall
                                               : reb::EventType::kArtifactCaptured,
                                   sequence);
    if (is_request) {
      event.header.request_id = sequence;
      event.header.parent_event_id = sequence - 1;
    }
    const auto profile = benchmark.Ingest(event);
    if (profile) {
      serialized_profile_bytes += reb::RequestSignalProfileToJson(*profile).size();
    }
  }
  const double seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - begin).count();
  const auto events_per_second = static_cast<std::uint64_t>(kBenchmarkEvents / seconds);
  CHECK(events_per_second > 500'000);
  CHECK(serialized_profile_bytes > 0);

  std::cout << "request_signal_profile_test passed (" << events_per_second
            << " cold-path events/s)\n";
  return 0;
}
