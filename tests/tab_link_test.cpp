// Overlay producer and core consumer of loader kinds, tab sets and request tab
// links (protocol/native-network-v3.md "Request owners and tabs"). --golden
// prints every checked record with the core verdict for
// tools/check-tab-link-wire.mjs.
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "components/reverse_engineering_browser/common/native_tab_link.h"
#include "reb/event.hpp"
#include "reb/tab_link.hpp"
#include "request_child_check.hpp"

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

static_assert(static_cast<std::uint16_t>(reb::EventType::kTabSet) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kTabSet));
static_assert(static_cast<std::uint16_t>(reb::EventType::kRequestTabLink) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kRequestTabLink));
static_assert(static_cast<std::uint16_t>(reb::EventType::kRequestExtensionLink) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kRequestExtensionLink));
static_assert(reb::kRequestExtensionLinkPayloadSize == reb::kNativeRequestExtensionLinkPayloadSize);
static_assert(reb::kExtensionIdSize == std::tuple_size_v<reb::NativeExtensionId>);
static_assert(offsetof(reb::EventHeader, loader_kind) ==
              offsetof(reb::NativeProbeHeader, loader_kind));
static_assert(reb::kTabSetPartTabs == reb::kNativeTabSetPartTabs);
static_assert(reb::kTabSetPayloadSize == reb::kNativeTabSetPayloadSize);
static_assert(reb::kRequestTabLinkPayloadSize == reb::kNativeRequestTabLinkPayloadSize);
static_assert(static_cast<int>(reb::LoaderKind::kScriptContext) ==
              static_cast<int>(reb::NativeLoaderKind::kScriptContext));
static_assert(static_cast<int>(reb::TabLinkKind::kServiceWorkerLastClients) ==
              static_cast<int>(reb::NativeTabLinkKind::kServiceWorkerLastClients));
static_assert(reb::NativeBrowserLoaderKind(0) == reb::NativeLoaderKind::kNavigation &&
              reb::NativeBrowserLoaderKind(9) == reb::NativeLoaderKind::kEarlyHints &&
              reb::NativeBrowserLoaderKind(10) == reb::NativeLoaderKind::kNotRecorded);

reb::NativeProbeHeader Identity(const std::uint64_t sequence) {
  reb::NativeProbeHeader identity;
  identity.session_id = 9;
  identity.sequence_number = sequence;
  identity.monotonic_time_ns = 1000;
  identity.process_id = 7;
  identity.thread_id = 8;
  return identity;
}

reb::EventRecord Part(const std::vector<std::uint32_t>& tabs,
                      const std::size_t part,
                      const bool last = false,
                      const std::uint64_t sequence = 50) {
  return std::bit_cast<reb::EventRecord>(
      reb::MakeNativeTabSetPart(Identity(sequence), reb::NativeLoaderKind::kServiceWorker, 0xabc,
                                last, 3, tabs, part, part == 0 ? 0 : sequence - 1));
}

reb::EventRecord Link(
    const std::vector<std::uint32_t>& tabs,
    const reb::NativeTabLinkKind kind = reb::NativeTabLinkKind::kServiceWorkerClients) {
  reb::NativeProbeHeader linked;
  linked.process_id = 4242;
  linked.sequence_number = 31;
  linked.request_id = 17;
  linked.frame_id = 0xabc;
  linked.monotonic_time_ns = 999;
  return std::bit_cast<reb::EventRecord>(
      reb::MakeNativeRequestTabLink(linked, Identity(60), kind, 3, tabs));
}

// A frameless browser record: a service-worker script the browser fetched.
reb::NativeProbeHeader BrowserRecord() {
  reb::NativeProbeHeader linked;
  linked.process_id = 7;
  linked.sequence_number = 32;
  linked.request_id = 900;
  linked.browser_context_id_high = 11;
  linked.browser_context_id_low = 12;
  linked.monotonic_time_ns = 999;
  return linked;
}

reb::EventRecord BrowserLink(const std::vector<std::uint32_t>& tabs) {
  return std::bit_cast<reb::EventRecord>(reb::MakeNativeRequestTabLink(
      BrowserRecord(), Identity(61), reb::NativeTabLinkKind::kServiceWorkerClients, 3, tabs, true));
}

reb::EventRecord ExtensionLink(const reb::NativeLoaderKind kind, const bool browser_record) {
  reb::NativeExtensionId id;
  static_cast<void>(reb::ParseNativeExtensionId("abcdefghijklmnopabcdefghijklmnop", id));
  reb::NativeProbeHeader linked = browser_record ? BrowserRecord() : reb::NativeProbeHeader{};
  if (!browser_record) {
    linked.process_id = 4242;
    linked.sequence_number = 31;
    linked.request_id = 17;
    linked.frame_id = 0xabc;
  }
  return std::bit_cast<reb::EventRecord>(
      reb::MakeNativeRequestExtensionLink(linked, Identity(62), kind, id, browser_record));
}

reb::EventRecord Request(const reb::EventType type, const std::uint8_t loader_kind) {
  reb::EventRecord event = reb::MakeEvent(reb::EventCategory::kNetwork, type, 41, 1001, 9);
  event.header.process_id = 7;
  event.header.request_id = 3;
  event.header.scheme_class = 2;
  event.header.loader_kind = loader_kind;
  static_cast<void>(reb::SetInlinePayload(event, std::string_view("GET example.test")));
  return event;
}

void LoaderKinds() {
  for (std::uint8_t kind = 1; kind <= 10; ++kind) {
    Case("browser loader kind " + std::to_string(kind),
         Request(reb::EventType::kRequestStarted, kind), true);
  }
  for (std::uint8_t kind = 16; kind <= 21; ++kind) {
    Case("renderer loader kind " + std::to_string(kind),
         Request(reb::EventType::kRequestInitiated, kind), true);
  }
  Case("browser kind on a renderer start", Request(reb::EventType::kRequestInitiated, 3), false);
  Case("renderer kind on a browser start", Request(reb::EventType::kRequestStarted, 16), false);
  Case("loader kind 11", Request(reb::EventType::kRequestStarted, 11), false);
  Case("loader kind 22", Request(reb::EventType::kRequestInitiated, 22), false);
  Case("loader kind on a completion", Request(reb::EventType::kRequestCompleted, 3), false);
  std::string json;
  reb::WriteEventJson(Request(reb::EventType::kRequestStarted, 3), json);
  Check(json.find("\"scheme_class\":2,\"loader_kind\":3,") != std::string::npos,
        "loader kind JSON");
  reb::WriteEventJson(Request(reb::EventType::kRequestStarted, 0), json);
  Check(json.find("loader_kind") == std::string::npos, "zero loader kind is absent");
}

void TabSets() {
  Case("one-part set", Part({4, 9}, 0), true);
  Case("last-clients set", Part({4}, 0, true), true);
  std::vector<std::uint32_t> thirty;
  for (std::uint32_t tab = 100; tab < 130; ++tab) {
    thirty.push_back(tab);
  }
  Case("first of two parts", Part(thirty, 0), true);
  Case("second of two parts", Part(thirty, 1, false, 51), true);
  auto event = Part(thirty, 1, false, 51);
  event.header.parent_event_id = 0;
  Case("second part without its chain", event, false);
  event = Part({4, 9}, 0);
  event.header.parent_event_id = 3;
  Case("first part with a parent", event, false);
  event = Part({9, 4}, 0);
  Case("descending tabs", event, false);
  event = Part({4, 4}, 0);
  Case("repeated tab", event, false);
  event = Part({4, 9}, 0);
  event.header.tab_id = 9;
  Case("envelope tab is not the first", event, false);
  event = Part({4, 9}, 0);
  event.inline_payload[4] = std::byte{16};
  Case("document owner kind", event, false);
  event = Part({4, 9}, 0);
  event.inline_payload[5] = std::byte{2};
  Case("unknown set flag", event, false);
  event = Part({4, 9}, 0);
  event.inline_payload[8] = std::byte{0};
  Case("set id 0", event, false);
  event = Part({4, 9}, 0);
  event.inline_payload[6] = std::byte{1};
  Case("part beyond the set", event, false);
  event = Part({4, 9}, 0);
  event.inline_payload[20] = std::byte{1};
  Case("part count disagrees with the set", event, false);
  event = Part({4, 9}, 0);
  event.inline_payload[32] = std::byte{1};
  Case("tab in an unused slot", event, false);
  event = Part({4, 9}, 0);
  event.header.request_id = 2;
  Case("set naming a request", event, false);
  event = Part({4, 9}, 0);
  event.header.frame_id = 0;
  Case("set of a version that has not run", event, true);
  event = Part({4, 9}, 0);
  event.header.initiator_process_id = 4242;
  Case("set with an initiator", event, false);
  event = Part({4, 9}, 0);
  event.header.payload_size = 127;
  Case("short set", event, false);
  reb::TabSetPayload value;
  const auto valid = Part(thirty, 1, false, 51);
  Check(reb::DecodeTabSetPayload(valid.inline_payload, value) && value.total_tabs == 30 &&
            value.part_tabs == 4 && value.tabs[0] == 126 && value.tabs[3] == 129 &&
            value.set_id == 3 && value.owner_kind == 19,
        "tab set round trip");
}

void Links() {
  Case("link to one tab", Link({4}), true);
  Check(reb_test::StaysRequestChild(BrowserLink({4})),
        "browser-named tab link stays a request child");
  Case("link to two tabs", Link({4, 9}, reb::NativeTabLinkKind::kSharedWorkerClients), true);
  Case("dedicated worker link", Link({4}, reb::NativeTabLinkKind::kDedicatedWorker), true);
  Case("last clients link", Link({4}, reb::NativeTabLinkKind::kServiceWorkerLastClients), true);
  auto event = Link({4, 9});
  event.header.tab_id = 4;
  Case("several tabs with an envelope tab", event, false);
  event = Link({4});
  event.header.tab_id = 0;
  Case("one tab without an envelope tab", event, false);
  event = Link({4});
  event.inline_payload[4] = std::byte{5};
  Case("link kind 5", event, false);
  event = Link({4});
  event.inline_payload[4] = std::byte{0};
  Case("link kind 0", event, false);
  event = Link({4});
  event.inline_payload[8] = std::byte{0};
  Case("link to set 0", event, false);
  event = Link({4});
  event.header.request_id = 17;
  Case("link with a request id", event, false);
  event = Link({4});
  event.header.initiator_process_id = 0;
  Case("link without its record's process", event, false);
  event = Link({4});
  event.header.parent_event_id = 0;
  Case("link without its record", event, false);
  event = Link({4});
  event.header.loader_kind = 17;
  Case("link with a loader kind", event, false);
  event = Link({4});
  event.inline_payload[21] = std::byte{1};
  Case("dirty reserved link", event, false);
  Case("browser record link to two tabs", BrowserLink({4, 9}), true);
  Case("browser record link to one tab", BrowserLink({4}), true);
  event = BrowserLink({4, 9});
  event.header.browser_context_id_high = 0;
  event.header.browser_context_id_low = 0;
  Case("browser record link without its BrowserContext", event, false);
  event = BrowserLink({4, 9});
  event.header.initiator_process_id = 4242;
  Case("link naming both a renderer and a browser record", event, false);
  event = BrowserLink({4, 9});
  event.header.request_id = 0;
  Case("browser record link without its request", event, false);
  const auto valid = Link({4, 9});
  reb::RequestTabLinkPayload value;
  Check(reb::DecodeRequestTabLinkPayload(valid.inline_payload, value) && value.set_id == 3 &&
            value.tab_count == 2 && valid.header.initiator_request_id == 17 &&
            valid.header.parent_event_id == 31 && valid.header.frame_id == 0xabc,
        "link round trip");
}

void ExtensionLinks() {
  Check(
      reb_test::StaysRequestChild(ExtensionLink(reb::NativeLoaderKind::kServiceWorkerScript, true)),
      "browser-named extension link stays a request child");
  Case("extension service-worker script",
       ExtensionLink(reb::NativeLoaderKind::kServiceWorkerScript, true), true);
  Case("extension worker main script",
       ExtensionLink(reb::NativeLoaderKind::kWorkerMainResource, true), true);
  Case("extension service-worker request",
       ExtensionLink(reb::NativeLoaderKind::kServiceWorker, false), true);
  Case("extension dedicated worker request",
       ExtensionLink(reb::NativeLoaderKind::kDedicatedWorker, false), true);
  Case("browser kind on a renderer record",
       ExtensionLink(reb::NativeLoaderKind::kServiceWorkerScript, false), false);
  Case("worker kind on a browser record",
       ExtensionLink(reb::NativeLoaderKind::kServiceWorker, true), false);
  Case("document kind", ExtensionLink(reb::NativeLoaderKind::kDocument, false), false);
  auto event = ExtensionLink(reb::NativeLoaderKind::kServiceWorker, false);
  event.inline_payload[20] = std::byte{'q'};
  Case("extension id outside a to p", event, false);
  event = ExtensionLink(reb::NativeLoaderKind::kServiceWorker, false);
  event.header.tab_id = 4;
  Case("extension link with a tab", event, false);
  event = ExtensionLink(reb::NativeLoaderKind::kServiceWorker, false);
  event.header.parent_event_id = 0;
  Case("extension link without its record", event, false);
  event = ExtensionLink(reb::NativeLoaderKind::kServiceWorker, false);
  event.inline_payload[6] = std::byte{1};
  Case("dirty reserved extension link", event, false);
  event = ExtensionLink(reb::NativeLoaderKind::kServiceWorker, false);
  event.header.payload_size = 39;
  Case("short extension link", event, false);
  reb::RequestExtensionLinkPayload value;
  const auto valid = ExtensionLink(reb::NativeLoaderKind::kServiceWorkerScript, true);
  Check(reb::DecodeRequestExtensionLinkPayload(valid.inline_payload, value) &&
            value.loader_kind == 6 && value.extension_id[0] == 'a' &&
            value.extension_id[31] == 'p' && valid.header.request_id == 900 &&
            valid.header.parent_event_id == 32,
        "extension link round trip");
  reb::NativeExtensionId id;
  Check(!reb::ParseNativeExtensionId("abcdefghijklmnopabcdefghijklmnoq", id) &&
            !reb::ParseNativeExtensionId("abc", id),
        "extension ids are 32 letters a to p");
}

}  // namespace

int main(const int argc, char** argv) {
  LoaderKinds();
  TabSets();
  Links();
  ExtensionLinks();
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
    std::cout
        << "PASS tab links: " << golden.size()
        << " loader kind, tab set, request tab link and extension link records; overlay and core "
           "agree\n";
  }
  return failures == 0 ? 0 : 1;
}
