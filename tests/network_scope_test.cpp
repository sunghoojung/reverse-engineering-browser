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
static_assert(static_cast<std::uint16_t>(reb::EventType::kMemoryCacheReuse) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kMemoryCacheReuse));
static_assert(static_cast<std::uint8_t>(reb::ExclusionClass::kMemoryCacheReuse) ==
              reb::kNativeMemoryCacheReuseExclusion);
static_assert(static_cast<std::uint8_t>(reb::ExclusionClass::kNonOrdinaryPageReuse) ==
              reb::kNativeNonOrdinaryPageReuseExclusion);
static_assert(reb::kMemoryCacheReusePayloadSize == reb::kNativeMemoryCacheReusePayloadSize &&
              reb::kMemoryCacheReuseHostSize == reb::kNativeMemoryCacheReuseHostSize &&
              reb::kMemoryCacheReuseStaticData == reb::kNativeMemoryCacheReuseStaticData &&
              reb::kMemoryCacheReuseHostTruncated == reb::kNativeMemoryCacheReuseHostTruncated);
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
  Case("extension worker requests of a renderer", Exclusion(65, 2, 4242), true);
  Case("extension worker requests at the proxy", Exclusion(65, 1, 0), true);
  Case("devtools loads", Exclusion(66, 4, 0), true);
  Case("devtools loads with a producer", Exclusion(66, 1, 4242), false);
  Case("webui requests at the proxy", Exclusion(67, 3, 0), true);
  Case("webui requests with a producer", Exclusion(67, 1, 4242), false);
  Case("pageless service worker requests of a renderer", Exclusion(68, 2, 4242), true);
  Case("pageless service worker scripts at the proxy", Exclusion(68, 1, 0), true);
  Case("browser prefetches with no page", Exclusion(69, 1, 0), true);
  Case("browser prefetches with a producer", Exclusion(69, 1, 4242), false);
  Case("memory-cache reuses of a renderer", Exclusion(70, 4097, 4242), true);
  Case("memory-cache reuses with no renderer", Exclusion(70, 1, 0), false);
  Case("non-ordinary-page reuses of a renderer", Exclusion(71, 3, 4242), true);
  Case("non-ordinary-page reuses with no renderer", Exclusion(71, 1, 0), false);
  Case("exclusion class above the table", Exclusion(72, 1, 4242), false);
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

// The producer's encoder in the envelope the renderer sink writes.
reb::EventRecord Reuse(const std::uint8_t resource_type,
                       const bool static_data,
                       const std::string_view host,
                       const std::uint8_t scheme_class = 2) {
  reb::NativeProbeEvent event;
  event.header.category = reb::NativeProbeCategory::kNetwork;
  event.header.type = reb::NativeProbeType::kMemoryCacheReuse;
  event.header.session_id = 9;
  event.header.sequence_number = 44;
  event.header.monotonic_time_ns = 1002;
  event.header.process_id = 7;
  event.header.thread_id = 8;
  event.header.frame_id = 0x6161;
  event.header.request_id = 6000;
  event.header.status_code = 200;
  event.header.decoded_body_length = 5120;
  event.header.scheme_class = scheme_class;
  event.header.loader_kind = 16;
  event.header.payload_size = reb::kNativeMemoryCacheReusePayloadSize;
  event.inline_payload = reb::EncodeNativeMemoryCacheReusePayload(resource_type, static_data, host);
  return std::bit_cast<reb::EventRecord>(event);
}

void MemoryCacheReuses() {
  Case("memory-cache image", Reuse(1, false, "cdn.example.test"), true);
  Case("memory-cache static data", Reuse(1, true, "", 5), true);
  Case("memory-cache dictionary", Reuse(15, false, "example.test"), true);
  const std::string long_host(200, 'h');
  const auto truncated = Reuse(3, false, long_host);
  reb::MemoryCacheReusePayload value;
  Check(reb::DecodeMemoryCacheReusePayload(truncated.inline_payload, value) &&
            value.host_length == 120 && value.flags == reb::kMemoryCacheReuseHostTruncated &&
            value.resource_type == 3,
        "long host keeps 120 bytes");
  Case("memory-cache long host", truncated, true);
  auto event = Reuse(1, false, "example.test");
  event.header.tab_id = 5;
  Case("memory-cache with the drain's tab", event, true);
  event.header.loader_kind = 17;
  event.header.frame_id = 0x77;
  Case("memory-cache in a dedicated worker", event, true);
  Case("memory-cache resource type 0", Reuse(0, false, "example.test"), false);
  Case("memory-cache resource type above the table", Reuse(16, false, "example.test"), false);
  Case("memory-cache without a scheme", Reuse(1, false, "example.test", 0), false);
  event = Reuse(1, false, "example.test");
  event.header.loader_kind = 3;
  Case("memory-cache with a browser loader kind", event, false);
  event.header.loader_kind = 0;
  Case("memory-cache without a loader kind", event, false);
  event = Reuse(1, false, "example.test");
  event.inline_payload[5] = std::byte{4};
  Case("memory-cache unknown flag", event, false);
  event = Reuse(1, false, "example.test");
  event.inline_payload[5] = std::byte{2};
  Case("memory-cache truncated short host", event, false);
  event = Reuse(1, false, "example.test");
  event.inline_payload[7] = std::byte{1};
  Case("memory-cache dirty reserved byte", event, false);
  event = Reuse(1, false, "example.test");
  event.inline_payload[8 + 12] = std::byte{'x'};
  Case("memory-cache byte after the host", event, false);
  event = Reuse(1, false, "example.test");
  event.inline_payload[8 + 3] = std::byte{' '};
  Case("memory-cache space in the host", event, false);
  event = Reuse(1, false, "example.test");
  event.inline_payload[6] = std::byte{121};
  Case("memory-cache host length above 120", event, false);
  event = Reuse(1, false, "example.test");
  event.inline_payload[0] = std::byte{2};
  Case("memory-cache payload version 2", event, false);
  event = Reuse(1, false, "example.test");
  event.header.payload_size = 127;
  Case("memory-cache short payload", event, false);
  event = Reuse(1, false, "example.test");
  event.header.parent_event_id = 3;
  Case("memory-cache with a parent", event, false);
  event = Reuse(1, false, "example.test");
  event.header.encoded_data_length = 10;
  Case("memory-cache with transferred bytes", event, false);
  event = Reuse(1, false, "example.test");
  event.header.error_code = -2;
  Case("memory-cache with an error", event, false);
  event = Reuse(1, false, "example.test");
  event.header.status_code = -1;
  Case("memory-cache negative status", event, false);
  event = Reuse(1, false, "example.test");
  event.header.decoded_body_length = -1;
  Case("memory-cache negative size", event, false);
  event = Reuse(1, false, "example.test");
  event.header.resource_type = 4;
  Case("memory-cache envelope resource type", event, false);
  event = Reuse(1, false, "example.test");
  event.header.flags = 2;
  Case("memory-cache envelope flags", event, false);
  event = Reuse(1, false, "example.test");
  event.header.initiator_process_id = 7;
  Case("memory-cache with initiator fields", event, false);
  event = Reuse(1, false, "example.test");
  event.header.category = reb::EventCategory::kVm;
  Case("memory-cache outside network", event, false);
  std::string json;
  reb::WriteEventJson(Reuse(1, false, "example.test"), json);
  Check(json.find("\"type\":\"memory_cache_reuse\"") != std::string::npos &&
            json.find("\"scheme_class\":2,\"loader_kind\":16,") != std::string::npos,
        "memory-cache JSON");
}

}  // namespace

int main(const int argc, char** argv) {
  SchemeClasses();
  Exclusions();
  MemoryCacheReuses();
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
              << " scheme class, capture exclusion and memory-cache records; overlay and core "
                 "agree\n";
  }
  return failures == 0 ? 0 : 1;
}
