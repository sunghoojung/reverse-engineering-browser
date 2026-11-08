#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <unistd.h>

#include "components/reverse_engineering_browser/common/native_artifact_header.h"
#include "components/reverse_engineering_browser/common/native_network_request.h"
#include "components/reverse_engineering_browser/common/native_network_response_body.h"
#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "reb/artifact.hpp"
#include "reb/event.hpp"
#include "reb/network_request.hpp"
#include "reb/network_response_body.hpp"

namespace {

int failures = 0;
// Every record checked here, for the cross-language golden (--golden).
std::vector<std::pair<std::string, reb::EventRecord>> golden;

void Check(const bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL " << message << '\n';
    ++failures;
  }
}

static_assert(static_cast<std::uint16_t>(reb::EventType::kRequestBody) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kRequestBody));
static_assert(static_cast<std::uint16_t>(reb::EventType::kRequestTarget) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kRequestTarget));
static_assert(static_cast<std::uint16_t>(reb::ArtifactKind::kRequestBody) ==
              static_cast<std::uint16_t>(reb::NativeArtifactKind::kRequestBody));
static_assert(static_cast<std::uint16_t>(reb::ArtifactCaptureOrigin::kNetworkRequest) ==
              static_cast<std::uint16_t>(reb::NativeArtifactCaptureOrigin::kNetworkRequest));
static_assert(reb::kRequestTargetPrefixBytes == reb::kNativeRequestTargetPrefixBytes);
static_assert(reb::kRequestContentTypeBytes == reb::kNativeRequestContentTypeBytes);
static_assert(reb::kRequestBodyDigestBytes == reb::kNativeRequestBodyDigestBytes);
static_assert(static_cast<std::uint8_t>(reb::RequestBodyState::kNotCapturedCredentialForm) ==
              static_cast<std::uint8_t>(reb::NativeRequestBodyState::kNotCapturedCredentialForm));
static_assert(static_cast<std::uint8_t>(reb::RequestBodyKind::kUnknown) ==
              static_cast<std::uint8_t>(reb::NativeRequestBodyKind::kUnknown));
static_assert(reb::kRequestBodyContentTypeOmitted == reb::kNativeRequestBodyContentTypeOmitted);
static_assert(static_cast<std::uint8_t>(reb::RequestScheme::kWss) ==
              static_cast<std::uint8_t>(reb::NativeRequestScheme::kWss));
static_assert(reb::kRequestTargetPayloadVersion == reb::kNativeRequestTargetPayloadVersion);
static_assert(static_cast<std::uint8_t>(reb::RequestTargetRetention::kNotRetainedUrl) ==
              static_cast<std::uint8_t>(reb::NativeRequestTargetRetention::kNotRetainedUrl));
static_assert(static_cast<std::uint16_t>(reb::ArtifactKind::kRequestTarget) ==
              static_cast<std::uint16_t>(reb::NativeArtifactKind::kRequestTarget));

reb::NativeRequestBodySummary Summary(const reb::NativeRequestBodyKind kind,
                                      const reb::NativeRequestBodyState state,
                                      const bool content,
                                      const std::uint64_t length,
                                      const std::uint64_t captured = 0) {
  reb::NativeRequestBodySummary value;
  value.kind = kind;
  value.state = state;
  value.body_length = length;
  value.captured_length = captured;
  value.element_count = kind == reb::NativeRequestBodyKind::kNone    ? 0
                        : kind == reb::NativeRequestBodyKind::kMixed ? 2
                                                                     : 1;
  value.flags = content ? reb::kNativeRequestBodyContentCapture : 0;
  if (kind == reb::NativeRequestBodyKind::kBytes &&
      state != reb::NativeRequestBodyState::kNotCapturedCredentialForm) {
    if (length <= reb::kNativeRequestBodyDigestBytes) {
      value.flags |= reb::kNativeRequestBodyDigestPresent;
      value.sha256.fill(0xab);
    } else {
      value.flags |= reb::kNativeRequestBodyDigestSizeLimit;
    }
  }
  if (kind != reb::NativeRequestBodyKind::kNone && kind != reb::NativeRequestBodyKind::kBytes) {
    value.flags |= reb::kNativeRequestBodyLengthPartial;
  }
  std::uint8_t type_length = 0;
  if (reb::NormalizeNativeContentType("application/json", value.content_type, type_length)) {
    value.content_type_length = type_length;
    value.flags |= reb::kNativeRequestBodyContentTypePresent;
  }
  return value;
}

reb::EventRecord Event(const reb::EventType type, const std::array<std::byte, 128>& payload) {
  reb::EventRecord event{};
  event.header.category = reb::EventCategory::kNetwork;
  event.header.type = type;
  event.header.session_id = 7;
  event.header.sequence_number = 12;
  event.header.monotonic_time_ns = 99;
  event.header.process_id = 42;
  event.header.thread_id = 3;
  event.header.request_id = 17;
  event.header.parent_event_id = 11;
  event.header.payload_size = 128;
  event.inline_payload = payload;
  return event;
}

reb::EventRecord BodyEvent(const reb::NativeRequestBodySummary& summary,
                           const std::uint64_t artifact_id = 0) {
  auto event = Event(reb::EventType::kRequestBody, reb::EncodeNativeRequestBodyPayload(summary));
  event.header.artifact_id = artifact_id;
  return event;
}

void CheckParity() {
  reb::NativeRequestBodySummary body;
  body.kind = reb::NativeRequestBodyKind::kMixed;
  body.state = reb::NativeRequestBodyState::kNotCapturedSessionBudget;
  body.flags = 0x2a;
  body.content_type_length = 0x3f;
  body.body_length = 0x0102030405060708ULL;
  body.captured_length = 0x1112131415161718ULL;
  body.element_count = 0x21222324U;
  for (std::size_t i = 0; i < body.sha256.size(); ++i) {
    body.sha256[i] = static_cast<std::uint8_t>(0xc0 + i);
  }
  for (std::size_t i = 0; i < body.content_type.size(); ++i) {
    body.content_type[i] = static_cast<char>('a' + i % 26);
  }
  reb::RequestBodyPayload decoded;
  Check(reb::DecodeRequestBodyPayload(reb::EncodeNativeRequestBodyPayload(body), decoded),
        "body payload decodes");
  Check(decoded.protocol_version == 1 && decoded.payload_size == 128 && decoded.kind == 5 &&
            decoded.state == 10 && decoded.flags == 0x2a && decoded.content_type_length == 0x3f &&
            decoded.body_length == body.body_length &&
            decoded.captured_length == body.captured_length &&
            decoded.element_count == body.element_count && decoded.reserved0 == 0 &&
            decoded.sha256 == body.sha256 &&
            std::equal(decoded.content_type.begin(), decoded.content_type.end(),
                       body.content_type.begin()),
        "every body field crosses the overlay/core boundary at its documented offset");

  reb::NativeRequestTarget target;
  target.target_length = 0x01020304U;
  target.scheme = reb::NativeRequestScheme::kWs;
  target.retention = reb::NativeRequestTargetRetention::kNotRetainedSessionBudget;
  target.port = 0x0506;
  for (std::size_t i = 0; i < target.prefix.size(); ++i) {
    target.prefix[i] = static_cast<char>('A' + i % 26);
  }
  reb::RequestTargetPayload target_decoded;
  Check(reb::DecodeRequestTargetPayload(reb::EncodeNativeRequestTargetPayload(target),
                                        target_decoded),
        "target payload decodes");
  Check(target_decoded.protocol_version == 2 && target_decoded.payload_size == 128 &&
            target_decoded.target_length == target.target_length && target_decoded.scheme == 3 &&
            target_decoded.reserved0 == 4 && target_decoded.port == 0x0506 &&
            std::equal(target_decoded.target_prefix.begin(), target_decoded.target_prefix.end(),
                       target.prefix.begin()),
        "every target field crosses the overlay/core boundary at its documented offset");
}

void CheckContentTypes() {
  struct Case {
    std::string_view header;
    std::string_view normalized;
  };
  for (const Case& item :
       {Case{"application/json", "application/json"},
        Case{" Application/JSON ; charset=UTF-8", "application/json"},
        Case{"multipart/form-data; boundary=----x", "multipart/form-data"},
        Case{"\ttext/plain\t", "text/plain"},
        Case{"application/x-www-form-urlencoded;charset=UTF-8",
             "application/x-www-form-urlencoded"},
        Case{"application/vnd.api+json", "application/vnd.api+json"}, Case{"", ""}, Case{";", ""},
        Case{"json", ""}, Case{"/json", ""}, Case{"application/", ""}, Case{"a/b/c", ""},
        Case{"text/pl ain", ""}, Case{"text/<b>", ""}, Case{"t\xc3\xa9xt/plain", ""}}) {
    std::array<char, reb::kNativeRequestContentTypeBytes> out{};
    std::uint8_t length = 0;
    const bool ok = reb::NormalizeNativeContentType(item.header, out, length);
    const std::string_view value(out.data(), length);
    Check(ok == !item.normalized.empty() && value == item.normalized &&
              std::all_of(out.begin() + length, out.end(), [](char c) { return c == '\0'; }),
          "content type normalization: " + std::string(item.header));
    Check(!ok || reb::IsNormalizedContentType(value), "normalized type passes the core rule");
  }
  std::array<char, reb::kNativeRequestContentTypeBytes> out{};
  std::uint8_t length = 0;
  Check(!reb::NormalizeNativeContentType("application/" + std::string(60, 'x'), out, length) &&
            length == 0,
        "a media type longer than 64 bytes is omitted, not truncated");
  Check(!reb::IsNormalizedContentType("Application/json") &&
            !reb::IsNormalizedContentType("application/json;charset=utf-8"),
        "the core rule rejects unnormalized types");
}

void CheckBodyStates() {
  using K = reb::NativeRequestBodyKind;
  using S = reb::NativeRequestBodyState;
  struct Valid {
    const char* name;
    reb::NativeRequestBodySummary summary;
    std::uint64_t artifact_id;
  };
  auto no_body = Summary(K::kNone, S::kNoBody, false, 0);
  no_body.flags &= static_cast<std::uint8_t>(~reb::kNativeRequestBodyContentTypePresent);
  no_body.content_type = {};
  no_body.content_type_length = 0;
  const Valid valid[] = {
      {"no body, metadata session", no_body, 0},
      {"no body, content session", Summary(K::kNone, S::kNoBody, true, 0), 0},
      {"empty bytes body", Summary(K::kBytes, S::kEmpty, false, 0), 0},
      {"metadata-only JSON body", Summary(K::kBytes, S::kMetadataOnly, false, 816), 0},
      {"metadata-only file body", Summary(K::kFile, S::kMetadataOnly, false, 0), 0},
      {"metadata-only over digest bound", Summary(K::kBytes, S::kMetadataOnly, false, 5 << 20), 0},
      {"captured body", Summary(K::kBytes, S::kCaptured, true, 816, 816), 901},
      {"truncated body", Summary(K::kBytes, S::kCapturedTruncated, true, 300000, 262144), 902},
      {"truncated over digest bound",
       Summary(K::kBytes, S::kCapturedTruncated, true, 5 << 20, 262144), 903},
      {"file not captured", Summary(K::kFile, S::kNotCapturedBodyKind, true, 0), 0},
      {"blob data pipe not captured", Summary(K::kDataPipe, S::kNotCapturedBodyKind, true, 0), 0},
      {"stream not captured", Summary(K::kChunkedDataPipe, S::kNotCapturedBodyKind, true, 0), 0},
      {"mixed not captured", Summary(K::kMixed, S::kNotCapturedBodyKind, true, 12), 0},
      {"unknown element not captured", Summary(K::kUnknown, S::kNotCapturedBodyKind, true, 0), 0},
      {"artifact channel unavailable",
       Summary(K::kBytes, S::kNotCapturedArtifactUnavailable, true, 10), 0},
      {"transfer refused", Summary(K::kBytes, S::kNotCapturedTransferRefused, true, 10), 0},
      {"unsupported URL", Summary(K::kBytes, S::kNotCapturedUrl, true, 10), 0},
      {"session budget", Summary(K::kBytes, S::kNotCapturedSessionBudget, true, 10), 0},
      {"credential form, metadata", Summary(K::kBytes, S::kNotCapturedCredentialForm, false, 40),
       0},
      {"credential form, content", Summary(K::kBytes, S::kNotCapturedCredentialForm, true, 40), 0},
  };
  for (const Valid& item : valid) {
    golden.emplace_back(item.name, BodyEvent(item.summary, item.artifact_id));
    Check(reb::IsValidEvent(golden.back().second), std::string("valid body state: ") + item.name);
  }

  using Mutation = std::function<void(reb::NativeRequestBodySummary&, reb::EventRecord&)>;
  struct Invalid {
    const char* name;
    reb::NativeRequestBodySummary base;
    std::uint64_t artifact_id;
    Mutation mutate;
  };
  const auto captured = Summary(K::kBytes, S::kCaptured, true, 816, 816);
  const auto metadata = Summary(K::kBytes, S::kMetadataOnly, false, 816);
  const auto file = Summary(K::kFile, S::kNotCapturedBodyKind, true, 0);
  const auto payload = [](std::size_t offset, std::byte value) {
    return [offset, value](reb::NativeRequestBodySummary&, reb::EventRecord& event) {
      event.inline_payload[offset] = value;
    };
  };
  const Invalid invalid[] = {
      {"version", captured, 901, payload(0, std::byte{2})},
      {"payload size field", captured, 901, payload(2, std::byte{127})},
      {"reserved bytes", captured, 901, payload(28, std::byte{1})},
      {"unknown kind", captured, 901, payload(4, std::byte{7})},
      {"zero state", captured, 901, payload(5, std::byte{0})},
      {"unknown state", captured, 901, payload(5, std::byte{12})},
      {"unknown flag", captured, 901, payload(6, std::byte{0x40 | 0x13})},
      {"content type dirty tail", captured, 901, payload(100, std::byte{'x'})},
      {"content type upper case", captured, 901, payload(64, std::byte{'A'})},
      {"content type length past field", captured, 901, payload(7, std::byte{65})},
      {"captured without artifact", captured, 0, {}},
      {"metadata with artifact", metadata, 901, {}},
      {"captured without content flag", captured, 901,
       [](auto& s, auto&) { s.flags &= static_cast<std::uint8_t>(~1U); }},
      {"metadata-only in content session", metadata, 0, [](auto& s, auto&) { s.flags |= 1; }},
      {"captured length past body", captured, 901, [](auto& s, auto&) { s.captured_length = 817; }},
      {"captured state with short prefix", captured, 901,
       [](auto& s, auto&) { s.captured_length = 800; }},
      {"truncated without truncation",
       Summary(K::kBytes, S::kCapturedTruncated, true, 816, 816),
       901,
       {}},
      {"digest bytes without flag", metadata, 0,
       [](auto& s, auto&) { s.flags &= static_cast<std::uint8_t>(~2U); }},
      {"bytes with neither digest nor bound flag", metadata, 0,
       [](auto& s, auto&) {
         s.flags &= static_cast<std::uint8_t>(~2U);
         s.sha256 = {};
       }},
      {"digest on a file body", file, 0,
       [](auto& s, auto&) {
         s.flags |= 2;
         s.sha256.fill(1);
       }},
      {"digest bound below limit", metadata, 0,
       [](auto& s, auto&) {
         s.flags = static_cast<std::uint8_t>((s.flags & ~2U) | 4U);
         s.sha256 = {};
       }},
      {"file without partial length", file, 0,
       [](auto& s, auto&) { s.flags &= static_cast<std::uint8_t>(~8U); }},
      {"bytes with partial length", metadata, 0, [](auto& s, auto&) { s.flags |= 8; }},
      {"no body with elements", Summary(K::kNone, S::kNoBody, false, 0), 0,
       [](auto& s, auto&) { s.element_count = 1; }},
      {"body kind claiming no body", metadata, 0, [](auto& s, auto&) { s.state = S::kNoBody; }},
      {"mixed from one element", Summary(K::kMixed, S::kNotCapturedBodyKind, true, 1), 0,
       [](auto& s, auto&) { s.element_count = 1; }},
      {"empty state with bytes", Summary(K::kBytes, S::kEmpty, false, 0), 0,
       [](auto& s, auto&) { s.body_length = 3; }},
      {"credential form with digest", Summary(K::kBytes, S::kNotCapturedCredentialForm, true, 40),
       0,
       [](auto& s, auto&) {
         s.flags |= 2;
         s.sha256.fill(1);
       }},
      {"body kind refusal on bytes", Summary(K::kBytes, S::kNotCapturedBodyKind, true, 10), 0, {}},
      {"budget refusal in metadata session",
       Summary(K::kBytes, S::kNotCapturedSessionBudget, false, 10),
       0,
       {}},
      {"type present and omitted", metadata, 0, [](auto& s, auto&) { s.flags |= 0x20; }},
      {"envelope flags", captured, 901, [](auto&, auto& e) { e.header.flags = 1; }},
      {"envelope without parent", captured, 901,
       [](auto&, auto& e) { e.header.parent_event_id = 0; }},
      {"envelope parent after child", captured, 901,
       [](auto&, auto& e) { e.header.parent_event_id = 12; }},
      {"envelope category", captured, 901,
       [](auto&, auto& e) { e.header.category = reb::EventCategory::kArtifact; }},
      {"envelope status", captured, 901, [](auto&, auto& e) { e.header.status_code = 200; }},
      {"envelope resource type", captured, 901,
       [](auto&, auto& e) { e.header.resource_type = 13; }},
      {"envelope payload size", captured, 901, [](auto&, auto& e) { e.header.payload_size = 127; }},
      {"envelope navigation", captured, 901, [](auto&, auto& e) { e.header.navigation_id = 1; }},
  };
  for (const Invalid& item : invalid) {
    // A mutation edits the summary before encoding, or the encoded record
    // afterwards; each lambda touches only one of the two.
    auto summary = item.base;
    reb::EventRecord unused{};
    if (item.mutate) {
      item.mutate(summary, unused);
    }
    auto event = BodyEvent(summary, item.artifact_id);
    auto ignored = summary;
    if (item.mutate) {
      item.mutate(ignored, event);
    }
    golden.emplace_back(item.name, event);
    Check(!reb::IsValidEvent(event), std::string("malformed body rejected: ") + item.name);
  }
}

void CheckTargets() {
  using Retention = reb::NativeRequestTargetRetention;
  reb::NativeRequestTarget target;
  target.scheme = reb::NativeRequestScheme::kHttps;
  target.retention = Retention::kRetained;
  const std::string path =
      "/checksiteconfig?v=1&host=accounts.example&sitekey=" + std::string(90, 'k');
  target.target_length = static_cast<std::uint32_t>(path.size());
  std::copy_n(path.begin(), target.prefix.size(), target.prefix.begin());
  auto event = Event(reb::EventType::kRequestTarget, reb::EncodeNativeRequestTargetPayload(target));
  event.header.artifact_id = 31;
  golden.emplace_back("truncated target", event);
  Check(reb::IsValidEvent(event), "a long target names its full-target artifact");
  reb::RequestTargetPayload decoded;
  Check(reb::DecodeRequestTargetPayload(event.inline_payload, decoded) &&
            decoded.target_length == path.size() &&
            std::string_view(decoded.target_prefix.data(), decoded.target_prefix.size()) ==
                std::string_view(path).substr(0, 116),
        "target prefix and original length survive");
  for (const auto [name, retention] :
       {std::pair{"target not retained: artifact channel",
                  Retention::kNotRetainedArtifactUnavailable},
        std::pair{"target not retained: transfer refused", Retention::kNotRetainedTransferRefused},
        std::pair{"target not retained: session budget", Retention::kNotRetainedSessionBudget},
        std::pair{"target not retained: url", Retention::kNotRetainedUrl}}) {
    auto refused = event;
    refused.header.artifact_id = 0;
    refused.inline_payload[9] = static_cast<std::byte>(retention);
    golden.emplace_back(name, refused);
    Check(reb::IsValidEvent(refused), std::string("named refusal is valid: ") + name);
  }
  auto legacy = event;
  legacy.header.artifact_id = 0;
  legacy.inline_payload[0] = std::byte{1};
  legacy.inline_payload[9] = std::byte{0};
  golden.emplace_back("version 1 truncated target", legacy);
  Check(reb::IsValidEvent(legacy), "a stored version 1 target keeps its meaning");

  reb::NativeRequestTarget empty;
  Check(reb::IsValidEvent(
            Event(reb::EventType::kRequestTarget, reb::EncodeNativeRequestTargetPayload(empty))),
        "an invalid URL reports an empty target, not a guessed one");

  const auto mutate = [&](const char* name, const std::function<void(reb::EventRecord&)>& change,
                          const reb::EventRecord& base) {
    auto copy = base;
    change(copy);
    golden.emplace_back(name, copy);
    Check(!reb::IsValidEvent(copy), std::string("malformed target rejected: ") + name);
  };
  mutate("NUL inside prefix", [](auto& e) { e.inline_payload[20] = std::byte{0}; }, event);
  mutate("scheme", [](auto& e) { e.inline_payload[8] = std::byte{5}; }, event);
  mutate("retention unknown", [](auto& e) { e.inline_payload[9] = std::byte{6}; }, event);
  mutate("retained without artifact", [](auto& e) { e.header.artifact_id = 0; }, event);
  mutate("refused with artifact", [](auto& e) { e.inline_payload[9] = std::byte{4}; }, event);
  mutate("long target marked complete", [](auto& e) { e.inline_payload[9] = std::byte{0}; }, event);
  mutate("version", [](auto& e) { e.inline_payload[0] = std::byte{3}; }, event);
  mutate("version 1 with artifact", [](auto& e) { e.header.artifact_id = 1; }, legacy);
  mutate("version 1 with retention", [](auto& e) { e.inline_payload[9] = std::byte{4}; }, legacy);
  mutate("flags", [](auto& e) { e.header.flags = 1; }, event);
  mutate("parent", [](auto& e) { e.header.parent_event_id = 0; }, event);
  reb::NativeRequestTarget short_target;
  short_target.target_length = 3;
  std::copy_n("/ab", 3, short_target.prefix.begin());
  auto dirty =
      Event(reb::EventType::kRequestTarget, reb::EncodeNativeRequestTargetPayload(short_target));
  golden.emplace_back("short target", dirty);
  Check(reb::IsValidEvent(dirty), "short target valid");
  mutate("short target not retained", [](auto& e) { e.inline_payload[9] = std::byte{2}; }, dirty);
  dirty.inline_payload[12 + 3] = std::byte{'x'};
  golden.emplace_back("target dirty tail", dirty);
  Check(!reb::IsValidEvent(dirty), "bytes after the recorded target are rejected");
}

std::string Frame(const reb::ArtifactHeader& header,
                  const std::string& url,
                  const std::string& mime,
                  const std::string& content) {
  std::string bytes(reinterpret_cast<const char*>(&header), sizeof(header));
  return bytes + url + mime + content;
}

void CheckArtifacts() {
  reb::ArtifactHeader header;
  header.kind = reb::ArtifactKind::kRequestBody;
  header.capture_origin = reb::ArtifactCaptureOrigin::kNetworkRequest;
  header.flags = reb::kArtifactFlagSensitive;
  header.session_id = 7;
  header.artifact_id = 5;
  header.creator_event_id = 12;
  const std::string url = "https://api.example.test/getcaptcha/site?s=1";
  const std::string mime = "application/x-www-form-urlencoded";
  const std::string content = "v=1&sitekey=site&motionData=%7B%7D";
  header.url_size = static_cast<std::uint32_t>(url.size());
  header.mime_type_size = static_cast<std::uint32_t>(mime.size());
  header.content_size = content.size();
  Check(reb::IsValidArtifactHeader(header), "request body artifact header is valid");
  const auto invalid = [&](const char* name, const std::function<void(reb::ArtifactHeader&)>& f) {
    auto copy = header;
    f(copy);
    Check(!reb::IsValidArtifactHeader(copy), std::string("request body header rejected: ") + name);
  };
  invalid("not sensitive", [](auto& h) { h.flags = 0; });
  invalid("response origin",
          [](auto& h) { h.capture_origin = reb::ArtifactCaptureOrigin::kNetworkResponse; });
  invalid("unknown origin",
          [](auto& h) { h.capture_origin = reb::ArtifactCaptureOrigin::kUnknown; });
  invalid("execution context", [](auto& h) { h.execution_context_id = 3; });
  invalid("missing creator", [](auto& h) { h.creator_event_id = 0; });
  invalid("other kind with request origin", [](auto& h) {
    h.kind = reb::ArtifactKind::kJavaScript;
    h.flags = 0;
  });
  auto target_header = header;
  target_header.kind = reb::ArtifactKind::kRequestTarget;
  Check(reb::IsValidArtifactHeader(target_header), "request target artifact header is valid");
  target_header.flags = 0;
  Check(!reb::IsValidArtifactHeader(target_header), "a request target is always sensitive");
  target_header.flags = reb::kArtifactFlagSensitive;
  target_header.capture_origin = reb::ArtifactCaptureOrigin::kNetworkResponse;
  Check(!reb::IsValidArtifactHeader(target_header), "a request target has the request origin");

  const auto root = std::filesystem::temp_directory_path() /
                    ("reb-network-request-test-" + std::to_string(::getpid()));
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  {
    reb::ArtifactReceiver refusing(root / "refusing",
                                   {.max_artifact_bytes = 1U << 20, .max_store_bytes = 1U << 22});
    std::istringstream stream(Frame(header, url, mime, content));
    Check(refusing.ReceiveOne(stream) == reb::ArtifactReceiveStatus::kSensitiveCaptureDisabled,
          "default receiver refuses request bodies");
  }
  {
    reb::ArtifactReceiver receiver(
        root / "allowed",
        {.max_artifact_bytes = 1U << 20, .max_store_bytes = 1U << 22, .allow_sensitive = true});
    std::istringstream stream(Frame(header, url, mime, content));
    Check(receiver.ReceiveOne(stream) == reb::ArtifactReceiveStatus::kAccepted,
          "receiver started with --allow-sensitive keeps request bodies: " + receiver.LastError());
  }
  std::ifstream manifest(root / "allowed" / "manifest.jsonl");
  const std::string line{std::istreambuf_iterator<char>(manifest), {}};
  Check(line.find("\"capture_origin\":\"network_request\",\"kind\":\"request_body\"") !=
                std::string::npos &&
            line.find("\"sensitive\":true") != std::string::npos &&
            line.find(url) != std::string::npos,
        "manifest records kind, origin, full URL and the sensitive flag");
  {
    // Reopening validates every retained manifest line again.
    reb::ArtifactReceiver reopened(
        root / "allowed",
        {.max_artifact_bytes = 1U << 20, .max_store_bytes = 1U << 22, .allow_sensitive = true});
    std::istringstream duplicate(Frame(header, url, mime, content));
    Check(reopened.ReceiveOne(duplicate) == reb::ArtifactReceiveStatus::kConflict,
          "reopened store accepted the request body manifest line and kept its identity");
  }
  std::filesystem::remove_all(root, ignored);
}

}  // namespace

static_assert(static_cast<std::uint16_t>(reb::EventType::kResponseBody) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kResponseBody));
static_assert(reb::kResponseBodyCaptureBytes == reb::kNativeResponseBodyCaptureBytes);
static_assert(reb::kResponseBodyPayloadVersion == reb::kNativeResponseBodyPayloadVersion);
static_assert(static_cast<std::uint8_t>(reb::ResponseBodyState::kNotCapturedSessionBudget) ==
              static_cast<std::uint8_t>(reb::NativeResponseBodyState::kNotCapturedSessionBudget));
static_assert(static_cast<std::uint8_t>(reb::ResponseBodyState::kPartial) ==
              static_cast<std::uint8_t>(reb::NativeResponseBodyState::kPartial));
static_assert(reb::kResponseBodyContentTypePresent == reb::kNativeResponseBodyContentTypePresent);
static_assert(reb::kResponseBodyCompletionUnobserved ==
              reb::kNativeResponseBodyCompletionUnobserved);
static_assert(reb::kResponseBodyShared == reb::kNativeResponseBodyShared);
static_assert(reb::IsNativeResponseMedia(5, "font/woff2") &&
              reb::IsNativeResponseMedia(4, "image/png") &&
              !reb::IsNativeResponseMedia(13, "image/png") &&
              !reb::IsNativeResponseMedia(4, "image/svg+xml") &&
              reb::IsNativeResponseMedia(13, "video/mp4") &&
              reb::IsNativeResponseMedia(13, "application/vnd.ms-fontobject") &&
              !reb::IsNativeResponseMedia(0, "text/html") &&
              !reb::IsNativeResponseMedia(13, "application/json"));

reb::NativeResponseBodySummary ResponseSummary(const reb::NativeResponseBodyState state,
                                               const std::uint64_t body,
                                               const std::uint64_t captured = 0) {
  reb::NativeResponseBodySummary value;
  value.state = state;
  value.body_length = body;
  value.captured_length = captured;
  if (captured != 0) {
    value.sha256.fill(0xcd);
  }
  if (state == reb::NativeResponseBodyState::kPartial) {
    value.partial_index = 1;
  }
  reb::SetNativeResponseContentType("application/json", value);
  return value;
}

reb::EventRecord ResponseEvent(const reb::NativeResponseBodySummary& summary,
                               const std::uint64_t artifact_id = 0) {
  auto event = Event(reb::EventType::kResponseBody, reb::EncodeNativeResponseBodyPayload(summary));
  event.header.artifact_id = artifact_id;
  return event;
}

void CheckResponseBodies() {
  using S = reb::NativeResponseBodyState;
  constexpr std::uint64_t kCap = reb::kNativeResponseBodyCaptureBytes;
  reb::NativeResponseBodySummary full;
  full.state = S::kPartial;
  full.flags = 0x5a;
  full.content_type_length = 0x3f;
  full.coding_count = 3;
  full.body_length = 0x0102030405060708ULL;
  full.captured_length = 0x1112131415161718ULL;
  full.codings = {reb::NativeResponseCoding::kGzip, reb::NativeResponseCoding::kBrotli,
                  reb::NativeResponseCoding::kOther, reb::NativeResponseCoding::kZstd};
  full.partial_index = 0x2122;
  for (std::size_t i = 0; i < full.sha256.size(); ++i) {
    full.sha256[i] = static_cast<std::uint8_t>(0xc0 + i);
  }
  for (std::size_t i = 0; i < full.content_type.size(); ++i) {
    full.content_type[i] = static_cast<char>('a' + i % 26);
  }
  reb::ResponseBodyPayload decoded;
  Check(reb::DecodeResponseBodyPayload(reb::EncodeNativeResponseBodyPayload(full), decoded) &&
            decoded.protocol_version == 1 && decoded.payload_size == 128 && decoded.state == 3 &&
            decoded.flags == 0x5a && decoded.content_type_length == 0x3f &&
            decoded.coding_count == 3 && decoded.body_length == full.body_length &&
            decoded.captured_length == full.captured_length &&
            decoded.codings == std::array<std::uint8_t, 4>{1, 3, 15, 4} &&
            decoded.partial_index == 0x2122 && decoded.reserved0 == 0 &&
            decoded.sha256 == full.sha256 &&
            std::equal(decoded.content_type.begin(), decoded.content_type.end(),
                       full.content_type.begin()),
        "response body payload layout matches between overlay and core");

  const auto codings = [](std::string_view header) {
    reb::NativeResponseBodySummary value;
    reb::SetNativeResponseCodings(header, value);
    return value;
  };
  const auto two = codings(" gzip , BR ");
  Check(two.coding_count == 2 && two.codings[0] == reb::NativeResponseCoding::kGzip &&
            two.codings[1] == reb::NativeResponseCoding::kBrotli && two.flags == 0,
        "codings keep their order and case-insensitive names");
  const auto plain = codings("identity, , ");
  Check(plain.coding_count == 0 && plain.flags == 0, "identity and empty members are not codings");
  const auto many = codings("x-gzip,deflate,zstd,dcb,dcz");
  Check(many.coding_count == 4 && many.codings[0] == reb::NativeResponseCoding::kGzip &&
            many.codings[3] == reb::NativeResponseCoding::kDcb &&
            (many.flags & reb::kNativeResponseBodyCodingsOmitted) != 0,
        "a fifth coding is marked omitted");
  Check(codings("x-compress, aes128gcm").codings[1] == reb::NativeResponseCoding::kOther,
        "an unrecognized coding is kOther");

  struct Valid {
    const char* name;
    reb::NativeResponseBodySummary summary;
    std::uint64_t artifact_id;
  };
  auto shared = ResponseSummary(S::kCaptured, 900, 900);
  shared.flags |= reb::kNativeResponseBodyShared | reb::kNativeResponseBodyFromCache;
  auto encoded = ResponseSummary(S::kCaptured, 40, 40);
  reb::SetNativeResponseCodings("gzip, br", encoded);
  encoded.flags |= reb::kNativeResponseBodyStillEncoded | reb::kNativeResponseBodyServiceWorker;
  auto unobserved = ResponseSummary(S::kCaptured, 12, 12);
  unobserved.flags |= reb::kNativeResponseBodyCompletionUnobserved;
  auto untyped = ResponseSummary(S::kNotModified, 0);
  untyped.flags = 0;
  untyped.content_type = {};
  untyped.content_type_length = 0;
  const Valid valid[] = {
      {"response captured", ResponseSummary(S::kCaptured, 900, 900), 911},
      {"response captured shared", shared, 911},
      {"response captured still encoded", encoded, 912},
      {"response captured unobserved completion", unobserved, 913},
      {"response truncated", ResponseSummary(S::kCapturedTruncated, kCap + 5, kCap), 914},
      {"response partial", ResponseSummary(S::kPartial, 300, 300), 915},
      {"response partial past cap", ResponseSummary(S::kPartial, kCap + 1, kCap), 916},
      {"response aborted prefix", ResponseSummary(S::kAborted, 2048, 2048), 917},
      {"response aborted nothing kept", ResponseSummary(S::kAborted, 0), 0},
      {"response cancelled prefix", ResponseSummary(S::kCancelled, 10, 10), 918},
      {"response cancelled before bytes", ResponseSummary(S::kCancelled, 0), 0},
      {"response empty", ResponseSummary(S::kEmpty, 0), 0},
      {"response not modified", untyped, 0},
      {"response redirected", ResponseSummary(S::kRedirected, 0), 0},
      {"response type skipped", ResponseSummary(S::kNotCapturedType, 0), 0},
      {"response artifact unavailable", ResponseSummary(S::kNotCapturedArtifactUnavailable, 77), 0},
      {"response transfer refused", ResponseSummary(S::kNotCapturedTransferRefused, 0), 0},
      {"response session budget", ResponseSummary(S::kNotCapturedSessionBudget, 4096), 0},
  };
  for (const Valid& item : valid) {
    golden.emplace_back(item.name, ResponseEvent(item.summary, item.artifact_id));
    Check(reb::IsValidEvent(golden.back().second),
          std::string("valid response body state: ") + item.name);
  }

  using Mutation = std::function<void(reb::NativeResponseBodySummary&, reb::EventRecord&)>;
  struct Invalid {
    const char* name;
    reb::NativeResponseBodySummary base;
    std::uint64_t artifact_id;
    Mutation mutate;
  };
  const auto captured = ResponseSummary(S::kCaptured, 900, 900);
  const auto refused = ResponseSummary(S::kNotCapturedSessionBudget, 900);
  const auto summary = [](auto change) {
    return [change](reb::NativeResponseBodySummary& value, reb::EventRecord&) { change(value); };
  };
  const auto byte = [](std::size_t offset, std::byte value) {
    return [offset, value](reb::NativeResponseBodySummary&, reb::EventRecord& event) {
      event.inline_payload[offset] = value;
    };
  };
  const Invalid invalid[] = {
      {"response version 2", captured, 911, byte(0, std::byte{2})},
      {"response reserved", captured, 911, byte(30, std::byte{1})},
      {"response state 0", captured, 911, byte(4, std::byte{0})},
      {"response state 13", refused, 0, byte(4, std::byte{13})},
      {"response unknown flag", captured, 911, byte(5, std::byte{0xc0})},
      {"response captured without artifact", captured, 0, {}},
      {"response artifact without bytes", refused, 911, {}},
      {"response digest without bytes", refused, 0,
       summary([](auto& value) { value.sha256.fill(1); })},
      {"response bytes without digest", captured, 911,
       summary([](auto& value) { value.sha256 = {}; })},
      {"response captured past body", captured, 911,
       summary([](auto& value) { value.captured_length = 901; })},
      {"response captured short", captured, 911,
       summary([](auto& value) { value.captured_length = 899; })},
      {"response shared without artifact", refused, 0,
       summary([](auto& value) { value.flags |= reb::kNativeResponseBodyShared; })},
      {"response partial index on captured", captured, 911,
       summary([](auto& value) { value.partial_index = 1; })},
      {"response partial without index", ResponseSummary(S::kPartial, 30, 30), 911,
       summary([](auto& value) { value.partial_index = 0; })},
      {"response partial short of cap", ResponseSummary(S::kPartial, kCap + 1, kCap), 911,
       summary([](auto& value) { value.captured_length = kCap - 1; })},
      {"response unobserved on aborted", ResponseSummary(S::kAborted, 0), 0,
       summary([](auto& value) { value.flags |= reb::kNativeResponseBodyCompletionUnobserved; })},
      {"response truncated under cap", ResponseSummary(S::kCapturedTruncated, kCap, kCap), 911, {}},
      {"response empty with bytes", ResponseSummary(S::kEmpty, 0), 0,
       summary([](auto& value) { value.body_length = 3; })},
      {"response redirect with length", ResponseSummary(S::kRedirected, 0), 0,
       summary([](auto& value) { value.body_length = 3; })},
      {"response five codings", captured, 911, byte(7, std::byte{5})},
      {"response zero coding", captured, 911, summary([](auto& value) { value.coding_count = 1; })},
      {"response coding 8", captured, 911, summary([](auto& value) {
         value.coding_count = 1;
         value.codings[0] = static_cast<reb::NativeResponseCoding>(8);
       })},
      {"response coding past count", captured, 911,
       summary([](auto& value) { value.codings[0] = reb::NativeResponseCoding::kGzip; })},
      {"response codings omitted under four", captured, 911, summary([](auto& value) {
         value.flags |= reb::kNativeResponseBodyCodingsOmitted;
         value.coding_count = 1;
         value.codings[0] = reb::NativeResponseCoding::kGzip;
       })},
      {"response type without flag", captured, 911,
       summary([](auto& value) { value.flags &= ~reb::kNativeResponseBodyContentTypePresent; })},
      {"response unnormalized type", captured, 911, byte(64, std::byte{'A'})},
      {"response type dirty tail", captured, 911, byte(127, std::byte{'x'})},
      {"response envelope flags", captured, 911,
       [](auto&, reb::EventRecord& event) { event.header.flags = 1; }},
      {"response envelope status", captured, 911,
       [](auto&, reb::EventRecord& event) { event.header.status_code = 200; }},
      {"response envelope no parent", captured, 911,
       [](auto&, reb::EventRecord& event) { event.header.parent_event_id = 0; }},
  };
  for (const Invalid& item : invalid) {
    auto value = item.base;
    reb::EventRecord event = ResponseEvent(value, item.artifact_id);
    if (item.mutate) {
      item.mutate(value, event);
      // Summary mutations re-encode; payload and envelope mutations stand.
      const auto mutated = ResponseEvent(value, item.artifact_id);
      if (mutated.inline_payload != ResponseEvent(item.base, item.artifact_id).inline_payload) {
        event.inline_payload = mutated.inline_payload;
      }
    }
    Check(!reb::IsValidEvent(event), std::string("invalid response body: ") + item.name);
    golden.emplace_back(item.name, event);
  }
}

int main(int argc, char** argv) {
  CheckParity();
  CheckContentTypes();
  CheckBodyStates();
  CheckTargets();
  CheckResponseBodies();
  if (failures != 0) {
    return 1;
  }
  if (argc == 2 && std::string_view(argv[1]) == "--golden") {
    // The C++ verdict is the reference the Python and UI decoders must match.
    std::string json;
    std::cout << "[";
    for (std::size_t index = 0; index < golden.size(); ++index) {
      reb::WriteEventJson(golden[index].second, json);
      std::cout << (index ? ",\n" : "\n") << "{\"name\":\"" << golden[index].first
                << "\",\"valid\":" << (reb::IsValidEvent(golden[index].second) ? "true" : "false")
                << ",\"event\":" << json << "}";
    }
    std::cout << "\n]\n";
    return 0;
  }
  CheckArtifacts();
  if (failures != 0) {
    return 1;
  }
  std::cout << "PASS network request wire: overlay/core parity, content types, every body "
               "state and malformed record, targets, request_body artifact policy, every "
               "response_body state, codings and malformed record\n";
  return 0;
}
