// Overlay producer and core consumer of scheme classes and capture exclusions
// (protocol/native-network-v3.md). --golden prints every checked record with the
// core verdict for tools/check-network-scope-wire.mjs.
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "components/reverse_engineering_browser/common/native_network_scope.h"
#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "reb/event.hpp"
#include "reb/network_scope.hpp"

namespace {

int failures = 0;
std::vector<std::pair<std::string, reb::EventRecord>> golden;

void Check(const bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL " << message << '\n';
    ++failures;
  }
}

void Case(const std::string& name, const reb::EventRecord& event, const bool valid) {
  golden.emplace_back(name, event);
  Check(reb::IsValidEvent(event) == valid, name);
}

static_assert(static_cast<std::uint16_t>(reb::EventType::kCaptureExclusion) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kCaptureExclusion));
static_assert(offsetof(reb::EventHeader, scheme_class) ==
              offsetof(reb::NativeProbeHeader, scheme_class));
static_assert(sizeof(reb::EventHeader) == sizeof(reb::NativeProbeHeader));

reb::EventRecord Exclusion(const std::uint8_t exclusion_class,
                           const std::uint64_t count,
                           const std::uint32_t producer) {
  return std::bit_cast<reb::EventRecord>(
      reb::MakeNativeCaptureExclusionEvent(9, 40, 1000, 7, 8, producer, exclusion_class, count));
}

reb::EventRecord Request(const reb::EventType type, const std::uint8_t scheme_class) {
  reb::EventRecord event = reb::MakeEvent(reb::EventCategory::kNetwork, type, 41, 1001, 9);
  event.header.process_id = 7;
  event.header.request_id = 3;
  event.header.scheme_class = scheme_class;
  static_cast<void>(reb::SetInlinePayload(event, std::string_view("GET example.test")));
  return event;
}

void SchemeClasses() {
  for (const auto& [scheme, code] :
       std::vector<std::pair<std::string_view, std::uint8_t>>{{"http", 1},
                                                              {"https", 2},
                                                              {"ws", 3},
                                                              {"wss", 4},
                                                              {"data", 5},
                                                              {"blob", 6},
                                                              {"file", 7},
                                                              {"chrome-extension", 8},
                                                              {"about", 15},
                                                              {"", 15},
                                                              {"chrome", 16},
                                                              {"chrome-untrusted", 17},
                                                              {"brave", 18},
                                                              {"devtools", 19},
                                                              {"chrome-search", 20}}) {
    const auto value = reb::ClassifyNativeScheme(scheme);
    Check(static_cast<std::uint8_t>(value) == code, std::string("class of ") + std::string(scheme));
    Check(reb::IsKnownSchemeClass(code), "core knows class");
    Check(reb::IsBrowserInternalSchemeClass(value) == reb::IsBrowserInternalSchemeClass(code),
          "internal agrees");
  }
  for (const auto type : {reb::EventType::kRequestInitiated, reb::EventType::kRequestStarted,
                          reb::EventType::kRequestCompleted, reb::EventType::kRequestFailed}) {
    Case("scheme on " + std::string(reb::EventTypeName(type)), Request(type, 2), true);
  }
  Case("internal scheme recorded by opt-in", Request(reb::EventType::kRequestInitiated, 16), true);
  Case("data scheme", Request(reb::EventType::kRequestCompleted, 5), true);
  Case("no scheme", Request(reb::EventType::kRequestInitiated, 0), true);
  Case("scheme on redirect", Request(reb::EventType::kRequestRedirected, 2), false);
  Case("unknown scheme class", Request(reb::EventType::kRequestInitiated, 9), false);
  Case("scheme class above table", Request(reb::EventType::kRequestStarted, 21), false);
  auto other = Request(reb::EventType::kApiCall, 2);
  other.header.category = reb::EventCategory::kCanvas;
  Case("scheme on a canvas record", other, false);
  auto dirty = Request(reb::EventType::kRequestInitiated, 2);
  // These bytes never reach JSON, so they stay out of the golden.
  dirty.header.reserved1 = 1;
  Check(!reb::IsValidEvent(dirty), "reserved byte after scheme");
  dirty = Request(reb::EventType::kRequestInitiated, 2);
  dirty.header.reserved2 = 1;
  Check(!reb::IsValidEvent(dirty), "reserved word after scheme");
}

void Exclusions() {
  for (const std::uint8_t code : std::vector<std::uint8_t>{16, 17, 18, 19, 20}) {
    Case("exclusion class " + std::to_string(code), Exclusion(code, 3, 4242), true);
  }
  Case("webui renderers", Exclusion(64, 2, 0), true);
  Case("browser-wide scheme count", Exclusion(16, 1, 0), true);
  Case("webui renderer with a producer", Exclusion(64, 2, 4242), false);
  Case("zero count", Exclusion(16, 0, 4242), false);
  Case("unknown class", Exclusion(21, 1, 4242), false);
  Case("http is never excluded", Exclusion(2, 1, 4242), false);
  auto event = Exclusion(16, 1, 4242);
  event.inline_payload[5] = std::byte{1};
  Case("dirty reserved payload", event, false);
  event = Exclusion(16, 1, 4242);
  event.inline_payload[0] = std::byte{2};
  Case("payload version 2", event, false);
  event = Exclusion(16, 1, 4242);
  event.header.payload_size = 15;
  Case("short payload", event, false);
  event = Exclusion(16, 1, 4242);
  event.header.tab_id = 3;
  Case("exclusion with a tab", event, false);
  event = Exclusion(16, 1, 4242);
  event.header.request_id = 3;
  Case("exclusion with a request", event, false);
  event = Exclusion(16, 1, 4242);
  event.header.scheme_class = 16;
  Case("exclusion with an envelope scheme", event, false);
  event = Exclusion(16, 1, 4242);
  event.header.flags = 1;
  Case("truncated exclusion", event, false);
  event = Exclusion(16, 1, 4242);
  event.header.category = reb::EventCategory::kVm;
  Case("exclusion outside network", event, false);
  reb::CaptureExclusionPayload value;
  const auto valid = Exclusion(19, 0x0102030405060708ULL, 4242);
  Check(reb::DecodeCaptureExclusionPayload(valid.inline_payload, value) &&
            value.exclusion_class == 19 && value.count == 0x0102030405060708ULL &&
            valid.header.initiator_process_id == 4242 && valid.header.process_id == 7,
        "exclusion payload round trip");
  std::string json;
  reb::WriteEventJson(Request(reb::EventType::kRequestStarted, 2), json);
  Check(json.find("\"initiator_process_id\":0,\"scheme_class\":2,") != std::string::npos,
        "scheme class JSON");
  reb::WriteEventJson(Exclusion(16, 1, 4242), json);
  Check(json.find("scheme_class") == std::string::npos, "zero scheme class is absent");
}

}  // namespace

int main(const int argc, char** argv) {
  SchemeClasses();
  Exclusions();
  if (argc == 2 && std::string_view(argv[1]) == "--golden") {
    std::string json;
    std::cout << '[';
    for (std::size_t index = 0; index < golden.size(); ++index) {
      reb::WriteEventJson(golden[index].second, json);
      std::cout << (index ? ",\n" : "\n") << "{\"name\":\"" << golden[index].first
                << "\",\"valid\":" << (reb::IsValidEvent(golden[index].second) ? "true" : "false")
                << ",\"event\":" << json << '}';
    }
    std::cout << "\n]\n";
    return failures == 0 ? 0 : 1;
  }
  if (failures == 0) {
    std::cout << "PASS network scope: " << golden.size()
              << " scheme class and capture exclusion records; overlay and core agree\n";
  }
  return failures == 0 ? 0 : 1;
}
