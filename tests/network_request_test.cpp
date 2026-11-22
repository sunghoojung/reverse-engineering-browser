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
#include "components/reverse_engineering_browser/common/native_network_cookies.h"
#include "components/reverse_engineering_browser/common/native_network_headers.h"
#include "components/reverse_engineering_browser/common/native_network_request.h"
#include "components/reverse_engineering_browser/common/native_network_response_body.h"
#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "reb/artifact.hpp"
#include "reb/event.hpp"
#include "reb/network_cookies.hpp"
#include "reb/network_headers.hpp"
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
static_assert(reb::kRequestBodyPayloadVersion == reb::kNativeRequestBodyPayloadVersion);
static_assert(reb::kRequestBodyRead == reb::kNativeRequestBodyRead);
static_assert(reb::kRequestBodyCredentialForm == reb::kNativeRequestBodyCredentialForm);
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
static_assert(static_cast<std::uint16_t>(reb::EventType::kRequestHeaders) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kRequestHeaders));
static_assert(static_cast<std::uint16_t>(reb::EventType::kResponseHeaders) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kResponseHeaders));
static_assert(static_cast<std::uint16_t>(reb::ArtifactKind::kRequestHeaders) ==
              static_cast<std::uint16_t>(reb::NativeArtifactKind::kRequestHeaders));
static_assert(static_cast<std::uint16_t>(reb::ArtifactKind::kResponseHeaders) ==
              static_cast<std::uint16_t>(reb::NativeArtifactKind::kResponseHeaders));
static_assert(reb::kHeaderPayloadVersion == reb::kNativeHeaderPayloadVersion);
static_assert(reb::kHeaderLengthUnrepresentable == reb::kNativeHeaderLengthUnrepresentable);
static_assert(static_cast<std::uint8_t>(reb::HeaderState::kNotCapturedUrl) ==
              static_cast<std::uint8_t>(reb::NativeHeaderState::kNotCapturedUrl));
static_assert(static_cast<std::uint8_t>(reb::HeaderSource::kEarlyHints) ==
              static_cast<std::uint8_t>(reb::NativeHeaderSource::kEarlyHints));
static_assert(static_cast<std::uint16_t>(reb::EventType::kCookieList) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kCookieList));
static_assert(static_cast<std::uint16_t>(reb::EventType::kScriptCookie) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kScriptCookie));
static_assert(static_cast<std::uint16_t>(reb::ArtifactKind::kCookieList) ==
              static_cast<std::uint16_t>(reb::NativeArtifactKind::kCookieList));
static_assert(reb::kCookiePayloadVersion == reb::kNativeCookiePayloadVersion);
static_assert(reb::kCookieEntryBytes == reb::kNativeCookieEntryBytes);
static_assert(reb::kScriptCookieNamePrefixBytes == reb::kNativeScriptCookieNamePrefixBytes);
static_assert(static_cast<std::uint8_t>(reb::ScriptCookieApi::kCookieStoreDelete) ==
              static_cast<std::uint8_t>(reb::NativeScriptCookieApi::kCookieStoreDelete));
static_assert(reb::kScriptCookieTableFull == reb::kNativeScriptCookieTableFull);
static_assert(reb::kScriptCookieReadRecord == reb::kNativeScriptCookieReadRecord);
static_assert(reb::kScriptCookiePayloadVersion == reb::kNativeScriptCookiePayloadVersion);

// A version 2 record the UI thread wrote without reading the body
// (native-network-v3.md): only an empty in-memory body has a digest there.
reb::NativeRequestBodySummary Summary(const reb::NativeRequestBodyKind kind,
                                      const reb::NativeRequestBodyState state,
                                      const bool content,
                                      const std::uint64_t length,
                                      const std::uint64_t captured = 0) {
  using S = reb::NativeRequestBodyState;
  reb::NativeRequestBodySummary value;
  value.kind = kind;
  value.state = state;
  value.body_length = length;
  value.captured_length = captured;
  value.element_count = kind == reb::NativeRequestBodyKind::kNone    ? 0
                        : kind == reb::NativeRequestBodyKind::kMixed ? 2
                                                                     : 1;
  value.flags = content ? reb::kNativeRequestBodyContentCapture : 0;
  if (state == S::kEmpty) {
    value.flags |= reb::kNativeRequestBodyDigestPresent;
    value.sha256.fill(0xab);
  }
  if (state == S::kNotCapturedCredentialForm) {
    value.flags |= reb::kNativeRequestBodyCredentialForm;
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

// A body read, or in a Metadata only session hashed, off the UI thread: its
// lengths and digest are exact when it was read whole.
reb::NativeRequestBodySummary Read(const reb::NativeRequestBodyKind kind,
                                   const reb::NativeRequestBodyState state,
                                   const std::uint64_t length,
                                   const std::uint64_t captured = 0,
                                   const bool content = true) {
  using S = reb::NativeRequestBodyState;
  auto value = Summary(kind, state, content, length, captured);
  value.flags |= reb::kNativeRequestBodyRead;
  if (state == S::kEmpty || state == S::kCaptured || state == S::kMetadataOnly) {
    value.flags &= static_cast<std::uint8_t>(~reb::kNativeRequestBodyLengthPartial);
    value.flags |= reb::kNativeRequestBodyDigestPresent;
    value.sha256.fill(0xab);
  }
  return value;
}

// A stored version 1 record (native-network-v2.md): in-memory bodies up to
// 4 MiB were hashed, and a read kept at most a 16 MiB prefix.
reb::NativeRequestBodySummary Version1(const reb::NativeRequestBodyKind kind,
                                       const reb::RequestBodyState state,
                                       const bool content,
                                       const std::uint64_t length,
                                       const std::uint64_t captured = 0,
                                       const bool read = false) {
  using S = reb::RequestBodyState;
  auto value =
      Summary(kind, static_cast<reb::NativeRequestBodyState>(state), content, length, captured);
  value.flags &= static_cast<std::uint8_t>(
      ~(reb::kNativeRequestBodyDigestPresent | reb::kNativeRequestBodyCredentialForm));
  value.sha256 = {};
  if (read) {
    value.flags |= reb::kNativeRequestBodyRead;
  }
  if (read && (state == S::kEmpty || state == S::kCaptured || state == S::kCapturedTruncated)) {
    value.flags &= static_cast<std::uint8_t>(~reb::kNativeRequestBodyLengthPartial);
  }
  const bool hashed =
      read ? state == S::kEmpty || state == S::kCaptured
           : kind == reb::NativeRequestBodyKind::kBytes && state != S::kNotCapturedCredentialForm;
  if (hashed && (read || length <= reb::kRequestBodyDigestBytes)) {
    value.flags |= reb::kNativeRequestBodyDigestPresent;
    value.sha256.fill(0xab);
  } else if (hashed || (read && state == S::kCapturedTruncated)) {
    value.flags |= reb::kRequestBodyDigestSizeLimit;
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
                           const std::uint64_t artifact_id = 0,
                           const std::uint16_t version = reb::kNativeRequestBodyPayloadVersion) {
  auto event = Event(reb::EventType::kRequestBody, reb::EncodeNativeRequestBodyPayload(summary));
  // Older records differ only in their version and the rules it selects.
  event.inline_payload[0] = static_cast<std::byte>(version);
  event.header.artifact_id = artifact_id;
  return event;
}

void CheckParity() {
  reb::NativeRequestBodySummary body;
  body.kind = reb::NativeRequestBodyKind::kMixed;
  body.state = reb::NativeRequestBodyState::kNotCapturedReadIncomplete;
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
  Check(decoded.protocol_version == 2 && decoded.payload_size == 128 && decoded.kind == 5 &&
            decoded.state == 12 && decoded.flags == 0x2a && decoded.content_type_length == 0x3f &&
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
  using V1 = reb::RequestBodyState;
  constexpr std::uint16_t kVersion1 = 1;
  constexpr std::uint64_t kMiB = 1ULL << 20U;
  struct Valid {
    const char* name;
    reb::NativeRequestBodySummary summary;
    std::uint64_t artifact_id;
    std::uint16_t version = reb::kNativeRequestBodyPayloadVersion;
  };
  auto no_body = Summary(K::kNone, S::kNoBody, false, 0);
  no_body.flags &= static_cast<std::uint8_t>(~reb::kNativeRequestBodyContentTypePresent);
  no_body.content_type = {};
  no_body.content_type_length = 0;
  auto credential = Read(K::kBytes, S::kCaptured, 40, 40);
  credential.flags |= reb::kNativeRequestBodyCredentialForm;
  auto refused_credential = Read(K::kBytes, S::kNotCapturedDiskReserve, 40);
  refused_credential.flags |= reb::kNativeRequestBodyCredentialForm;
  const Valid valid[] = {
      {"no body, metadata session", no_body, 0},
      {"no body, content session", Summary(K::kNone, S::kNoBody, true, 0), 0},
      {"empty bytes body", Summary(K::kBytes, S::kEmpty, false, 0), 0},
      {"empty bytes body, content session", Summary(K::kBytes, S::kEmpty, true, 0), 0},
      {"metadata-only JSON body", Read(K::kBytes, S::kMetadataOnly, 816, 0, false), 0},
      {"metadata-only body hashed past 4 MiB",
       Read(K::kBytes, S::kMetadataOnly, 70 * kMiB, 0, false), 0},
      {"metadata-only body not hashed", Summary(K::kBytes, S::kMetadataOnly, false, 816), 0},
      {"metadata-only file body", Summary(K::kFile, S::kMetadataOnly, false, 0), 0},
      {"captured body", Read(K::kBytes, S::kCaptured, 816, 816), 901},
      {"captured body past 16 MiB", Read(K::kBytes, S::kCaptured, 70 * kMiB, 70 * kMiB), 902},
      {"captured credential form", credential, 903},
      {"credential form refused by the disk reserve", refused_credential, 0},
      {"file not captured", Summary(K::kFile, S::kNotCapturedBodyKind, true, 0), 0},
      {"blob data pipe not captured", Summary(K::kDataPipe, S::kNotCapturedBodyKind, true, 0), 0},
      {"stream not captured", Summary(K::kChunkedDataPipe, S::kNotCapturedBodyKind, true, 0), 0},
      {"mixed not captured", Summary(K::kMixed, S::kNotCapturedBodyKind, true, 12), 0},
      {"unknown element not captured", Summary(K::kUnknown, S::kNotCapturedBodyKind, true, 0), 0},
      {"artifact channel unavailable",
       Summary(K::kBytes, S::kNotCapturedArtifactUnavailable, true, 10), 0},
      {"transfer refused", Summary(K::kBytes, S::kNotCapturedTransferRefused, true, 10), 0},
      {"unsupported URL", Summary(K::kBytes, S::kNotCapturedUrl, true, 10), 0},
      {"credential form, metadata", Summary(K::kBytes, S::kNotCapturedCredentialForm, false, 40),
       0},
      {"file body unavailable before read",
       Summary(K::kFile, S::kNotCapturedArtifactUnavailable, true, 0), 0},
      {"multipart body refused before read",
       Summary(K::kMixed, S::kNotCapturedTransferRefused, true, 120), 0},
      {"blob body on unsupported URL", Summary(K::kDataPipe, S::kNotCapturedUrl, true, 0), 0},
      {"read multipart body with a file", Read(K::kMixed, S::kCaptured, 4096, 4096), 904},
      {"read stream body", Read(K::kChunkedDataPipe, S::kCaptured, 77, 77), 905},
      {"read empty blob", Read(K::kDataPipe, S::kEmpty, 0), 0},
      {"read file past 16 MiB", Read(K::kFile, S::kCaptured, 16 * kMiB + 9, 16 * kMiB + 9), 906},
      {"read refused by the disk reserve", Read(K::kFile, S::kNotCapturedDiskReserve, 65536), 0},
      {"read in-memory body refused", Read(K::kBytes, S::kNotCapturedTransferRefused, 816), 0},
      {"read stream refused", Read(K::kChunkedDataPipe, S::kNotCapturedTransferRefused, 12), 0},
      {"read incomplete", Read(K::kFile, S::kNotCapturedReadIncomplete, 0), 0},
      // Stored version 1 records keep their meaning.
      {"version 1 metadata-only JSON body", Version1(K::kBytes, V1::kMetadataOnly, false, 816), 0,
       kVersion1},
      {"version 1 metadata-only over digest bound",
       Version1(K::kBytes, V1::kMetadataOnly, false, 5 * kMiB), 0, kVersion1},
      {"version 1 captured body", Version1(K::kBytes, V1::kCaptured, true, 816, 816), 901,
       kVersion1},
      {"version 1 truncated body",
       Version1(K::kBytes, V1::kCapturedTruncated, true, 300000, 262144), 902, kVersion1},
      {"version 1 truncated over digest bound",
       Version1(K::kBytes, V1::kCapturedTruncated, true, 5 * kMiB, 262144), 903, kVersion1},
      {"version 1 session budget", Version1(K::kBytes, V1::kNotCapturedSessionBudget, true, 10), 0,
       kVersion1},
      {"version 1 stream body past the session budget before read",
       Version1(K::kChunkedDataPipe, V1::kNotCapturedSessionBudget, true, 0), 0, kVersion1},
      {"version 1 credential form, content",
       Version1(K::kBytes, V1::kNotCapturedCredentialForm, true, 40), 0, kVersion1},
      {"version 1 read file past 16 MiB",
       Version1(K::kFile, V1::kCapturedTruncated, true, 16 * kMiB + 9, 16 * kMiB, true), 906,
       kVersion1},
      {"version 1 read stopped by the session budget",
       Version1(K::kDataPipe, V1::kNotCapturedSessionBudget, true, 70000, 0, true), 0, kVersion1},
  };
  for (const Valid& item : valid) {
    golden.emplace_back(item.name, BodyEvent(item.summary, item.artifact_id, item.version));
    Check(reb::IsValidEvent(golden.back().second), std::string("valid body state: ") + item.name);
  }

  using Mutation = std::function<void(reb::NativeRequestBodySummary&, reb::EventRecord&)>;
  struct Invalid {
    const char* name;
    reb::NativeRequestBodySummary base;
    std::uint64_t artifact_id;
    Mutation mutate;
    std::uint16_t version = reb::kNativeRequestBodyPayloadVersion;
  };
  const auto captured = Read(K::kBytes, S::kCaptured, 816, 816);
  const auto metadata = Read(K::kBytes, S::kMetadataOnly, 816, 0, false);
  const auto file = Summary(K::kFile, S::kNotCapturedBodyKind, true, 0);
  const auto refused = Read(K::kFile, S::kNotCapturedTransferRefused, 40);
  const auto state = [](const V1 value) { return static_cast<S>(value); };
  const auto payload = [](std::size_t offset, std::byte value) {
    return [offset, value](reb::NativeRequestBodySummary&, reb::EventRecord& event) {
      event.inline_payload[offset] = value;
    };
  };
  const auto digest = [](auto& s, auto&) {
    s.flags |= reb::kNativeRequestBodyDigestPresent;
    s.sha256.fill(1);
  };
  const auto credential_flag = [](auto& s, auto&) {
    s.flags |= reb::kNativeRequestBodyCredentialForm;
  };
  const Invalid invalid[] = {
      {"version", captured, 901, payload(0, std::byte{3})},
      {"version 0", captured, 901, payload(0, std::byte{0})},
      {"payload size field", captured, 901, payload(2, std::byte{127})},
      {"reserved bytes", captured, 901, payload(28, std::byte{1})},
      {"unknown kind", captured, 901, payload(4, std::byte{7})},
      {"zero state", captured, 901, payload(5, std::byte{0})},
      {"unknown state", captured, 901, payload(5, std::byte{14})},
      {"retired truncation", Read(K::kFile, state(V1::kCapturedTruncated), 40, 39), 904, {}},
      {"retired session budget",
       Summary(K::kBytes, state(V1::kNotCapturedSessionBudget), true, 10),
       0,
       {}},
      {"retired digest size flag", Summary(K::kBytes, S::kMetadataOnly, false, 816), 0,
       [](auto& s, auto&) { s.flags |= reb::kRequestBodyDigestSizeLimit; }},
      {"disk reserve without read flag",
       Summary(K::kFile, S::kNotCapturedDiskReserve, true, 0),
       0,
       {}},
      {"read incomplete without read flag",
       Summary(K::kFile, S::kNotCapturedReadIncomplete, true, 0),
       0,
       {}},
      {"captured without a read", Summary(K::kBytes, S::kCaptured, true, 816, 816), 901, {}},
      {"read flag on an unknown element",
       Read(K::kUnknown, S::kNotCapturedReadIncomplete, 0),
       0,
       {}},
      {"read flag on no body", Read(K::kNone, S::kNoBody, 0), 0, {}},
      {"read capture without digest", Read(K::kFile, S::kCaptured, 40, 40), 904,
       [](auto& s, auto&) {
         s.flags &= static_cast<std::uint8_t>(~2U);
         s.sha256 = {};
       }},
      {"read capture with partial length", Read(K::kFile, S::kCaptured, 40, 40), 904,
       [](auto& s, auto&) { s.flags |= 8; }},
      {"read capture short of the body", Read(K::kFile, S::kCaptured, 40, 39), 904, {}},
      {"read capture of an empty body", Read(K::kFile, S::kCaptured, 0, 0), 904, {}},
      {"read capture without artifact", Read(K::kDataPipe, S::kCaptured, 40, 40), 0, {}},
      {"read refusal with exact length", refused, 0,
       [](auto& s, auto&) { s.flags &= static_cast<std::uint8_t>(~8U); }},
      {"read refusal with digest", refused, 0, digest},
      {"read refusal keeping bytes", refused, 0, [](auto& s, auto&) { s.captured_length = 10; }},
      {"read in-memory refusal with partial length",
       Read(K::kBytes, S::kNotCapturedTransferRefused, 816), 0,
       [](auto& s, auto&) { s.flags |= 8; }},
      {"read stream of two elements", Read(K::kChunkedDataPipe, S::kCaptured, 40, 40), 905,
       [](auto& s, auto&) { s.element_count = 2; }},
      {"read state outside the read set", Read(K::kFile, S::kNotCapturedUrl, 0), 0, {}},
      {"read metadata state in a content session", metadata, 0,
       [](auto& s, auto&) { s.flags |= 1; }},
      {"metadata read of a file", Read(K::kFile, S::kMetadataOnly, 40, 0, false), 0, {}},
      {"metadata read of an empty body", Read(K::kBytes, S::kMetadataOnly, 0, 0, false), 0, {}},
      {"metadata read of a credential form", metadata, 0, credential_flag},
      {"metadata read keeping bytes", Read(K::kBytes, S::kCaptured, 816, 816, false), 901, {}},
      {"metadata read refused",
       Read(K::kBytes, S::kNotCapturedTransferRefused, 816, 0, false),
       0,
       {}},
      {"content type dirty tail", captured, 901, payload(100, std::byte{'x'})},
      {"content type upper case", captured, 901, payload(64, std::byte{'A'})},
      {"content type length past field", captured, 901, payload(7, std::byte{65})},
      {"captured without artifact", captured, 0, {}},
      {"metadata with artifact", metadata, 901, {}},
      {"captured without content flag", captured, 901,
       [](auto& s, auto&) { s.flags &= static_cast<std::uint8_t>(~1U); }},
      {"metadata-only in content session", Summary(K::kFile, S::kMetadataOnly, true, 0), 0, {}},
      {"captured length past body", captured, 901, [](auto& s, auto&) { s.captured_length = 817; }},
      {"captured state with short prefix", captured, 901,
       [](auto& s, auto&) { s.captured_length = 800; }},
      {"digest bytes without flag", metadata, 0,
       [](auto& s, auto&) { s.flags &= static_cast<std::uint8_t>(~2U); }},
      {"digest flag without bytes", metadata, 0, [](auto& s, auto&) { s.sha256 = {}; }},
      {"digest on a file body", file, 0, digest},
      {"digest on an unread body", Summary(K::kBytes, S::kMetadataOnly, false, 816), 0, digest},
      {"empty body without digest", Summary(K::kBytes, S::kEmpty, false, 0), 0,
       [](auto& s, auto&) {
         s.flags &= static_cast<std::uint8_t>(~2U);
         s.sha256 = {};
       }},
      {"file without partial length", file, 0,
       [](auto& s, auto&) { s.flags &= static_cast<std::uint8_t>(~8U); }},
      {"bytes with partial length", metadata, 0, [](auto& s, auto&) { s.flags |= 8; }},
      {"no body with elements", Summary(K::kNone, S::kNoBody, false, 0), 0,
       [](auto& s, auto&) { s.element_count = 1; }},
      {"no body with a length", Summary(K::kNone, S::kNoBody, false, 0), 0,
       [](auto& s, auto&) { s.body_length = 3; }},
      {"no body marked a credential form", Summary(K::kNone, S::kNoBody, true, 0), 0,
       credential_flag},
      {"body kind claiming no body", metadata, 0, [](auto& s, auto&) { s.state = S::kNoBody; }},
      {"mixed from one element", Summary(K::kMixed, S::kNotCapturedBodyKind, true, 1), 0,
       [](auto& s, auto&) { s.element_count = 1; }},
      {"empty state with bytes", Summary(K::kBytes, S::kEmpty, false, 0), 0,
       [](auto& s, auto&) { s.body_length = 3; }},
      {"credential form left out in a content session",
       Summary(K::kBytes, S::kNotCapturedCredentialForm, true, 40),
       0,
       {}},
      {"credential form without its flag",
       Summary(K::kBytes, S::kNotCapturedCredentialForm, false, 40), 0,
       [](auto& s, auto&) { s.flags &= static_cast<std::uint8_t>(~0x80U); }},
      {"credential flag on a metadata body", Summary(K::kFile, S::kMetadataOnly, false, 0), 0,
       credential_flag},
      {"credential form with digest", Summary(K::kBytes, S::kNotCapturedCredentialForm, false, 40),
       0, digest},
      {"body kind refusal on bytes", Summary(K::kBytes, S::kNotCapturedBodyKind, true, 10), 0, {}},
      {"refusal in metadata session",
       Summary(K::kBytes, S::kNotCapturedTransferRefused, false, 10),
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
      // Version 1 kept its own limits and knew no credential flag.
      {"version 1 credential flag", Version1(K::kBytes, V1::kCaptured, true, 816, 816), 901,
       credential_flag, kVersion1},
      {"version 1 read capture past 16 MiB untruncated",
       Version1(K::kFile, V1::kCaptured, true, 16 * kMiB + 1, 16 * kMiB + 1, true),
       904,
       {},
       kVersion1},
      {"version 1 read truncation with a short prefix",
       Version1(K::kFile, V1::kCapturedTruncated, true, 16 * kMiB + 9, 1024, true),
       906,
       {},
       kVersion1},
      {"version 1 truncated without truncation",
       Version1(K::kBytes, V1::kCapturedTruncated, true, 816, 816),
       901,
       {},
       kVersion1},
      {"version 1 digest bound below limit", Version1(K::kBytes, V1::kMetadataOnly, false, 816), 0,
       [](auto& s, auto&) {
         s.flags = static_cast<std::uint8_t>((s.flags & ~2U) | 4U);
         s.sha256 = {};
       },
       kVersion1},
      {"version 1 read flag on in-memory bytes", Version1(K::kBytes, V1::kCaptured, true, 816, 816),
       901, [](auto& s, auto&) { s.flags |= reb::kNativeRequestBodyRead; }, kVersion1},
      {"version 1 read refused by the disk reserve",
       Version1(K::kFile, V1::kNotCapturedDiskReserve, true, 65536, 0, true),
       0,
       {},
       kVersion1},
      {"version 1 session budget in metadata session",
       Version1(K::kBytes, V1::kNotCapturedSessionBudget, false, 10),
       0,
       {},
       kVersion1},
  };
  for (const Invalid& item : invalid) {
    // A mutation edits the summary before encoding, or the encoded record
    // afterwards; each lambda touches only one of the two.
    auto summary = item.base;
    reb::EventRecord unused{};
    if (item.mutate) {
      item.mutate(summary, unused);
    }
    auto event = BodyEvent(summary, item.artifact_id, item.version);
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
  for (const auto& [name, retention] :
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

reb::EventRecord HeaderEvent(const bool response,
                             const reb::NativeHeaderBlockSummary& summary,
                             const std::uint64_t artifact_id = 0) {
  auto event = Event(response ? reb::EventType::kResponseHeaders : reb::EventType::kRequestHeaders,
                     reb::EncodeNativeHeaderBlockPayload(summary));
  event.header.artifact_id = artifact_id;
  return event;
}

// Every state and source of native-network-v3.md, valid and malformed, through
// the overlay encoder and the core decoder; each joins the golden.
void CheckHeaderBlocks() {
  using Source = reb::NativeHeaderSource;
  using State = reb::NativeHeaderState;
  const auto block = [](const Source source, const State state) {
    reb::NativeHeaderBlockSummary value;
    value.source = source;
    value.state = state;
    value.referrer_policy = source == Source::kBrowser ? 4 : 0;
    value.header_count = state == State::kEmpty ? 0 : 2;
    value.block_length = state == State::kEmpty ? 0
                         : state == State::kNotCapturedBlockLimit
                             ? static_cast<std::uint32_t>(reb::kNativeHeaderLengthUnrepresentable)
                             : 40;
    if (state != State::kNotCapturedBlockLimit) {
      value.sha256.fill(0xcd);
    }
    value.hop = 1;
    return value;
  };
  const auto response = [&block](const Source source, const State state) {
    auto value = block(source, state);
    value.referrer_policy = 0;
    value.status_code = source == Source::kEarlyHints ? 103 : 302;
    if (source == Source::kBrowser) {
      value.address_family = 6;
      value.remote_port = 443;
      value.remote_address.fill(0x20);
    }
    return value;
  };
  const auto add = [](const std::string& name, const reb::EventRecord& event, const bool valid) {
    golden.emplace_back(name, event);
    Check(reb::IsValidEvent(event) == valid, "header record verdict: " + name);
  };
  for (const State state :
       {State::kCaptured, State::kCapturedShared, State::kEmpty, State::kNotCapturedBlockLimit,
        State::kNotCapturedArtifactUnavailable, State::kNotCapturedTransferRefused,
        State::kNotCapturedSessionBudget, State::kNotCapturedUrl}) {
    const bool retained = state == State::kCaptured || state == State::kCapturedShared;
    const std::uint64_t artifact = retained ? 77 : 0;
    const std::string suffix = std::to_string(static_cast<unsigned>(state));
    add("request headers browser state " + suffix,
        HeaderEvent(false, block(Source::kBrowser, state), artifact), true);
    add("request headers network state " + suffix,
        HeaderEvent(false, block(Source::kNetwork, state), artifact), true);
    add("response headers browser state " + suffix,
        HeaderEvent(true, response(Source::kBrowser, state), artifact), true);
    add("response headers network state " + suffix,
        HeaderEvent(true, response(Source::kNetwork, state), artifact), true);
    add("response headers early hints state " + suffix,
        HeaderEvent(true, response(Source::kEarlyHints, state), artifact), true);
    add("header artifact disagrees with state " + suffix,
        HeaderEvent(false, block(Source::kBrowser, state), retained ? 0 : 77), false);
  }
  const auto captured = block(Source::kBrowser, State::kCaptured);
  const auto answered = response(Source::kBrowser, State::kCaptured);
  struct Bad {
    const char* name;
    bool response;
    std::function<void(reb::NativeHeaderBlockSummary&)> mutate;
  };
  const Bad bad[] = {
      {"request status", false, [](auto& v) { v.status_code = 200; }},
      {"request address", false, [](auto& v) { v.address_family = 4; }},
      {"request early hints source", false, [](auto& v) { v.source = Source::kEarlyHints; }},
      {"request browser without policy", false, [](auto& v) { v.referrer_policy = 0; }},
      {"request policy out of range", false, [](auto& v) { v.referrer_policy = 9; }},
      {"network request with policy", false,
       [](auto& v) {
         v.source = Source::kNetwork;
         v.referrer_policy = 1;
       }},
      {"source zero", false, [](auto& v) { v.source = static_cast<Source>(0); }},
      {"state zero", false, [](auto& v) { v.state = static_cast<State>(0); }},
      {"state nine", false, [](auto& v) { v.state = static_cast<State>(9); }},
      {"count without length", false, [](auto& v) { v.block_length = 0; }},
      {"length below five per header", false, [](auto& v) { v.block_length = 9; }},
      {"empty with headers", false, [](auto& v) { v.state = State::kEmpty; }},
      {"limit state under the limit", false,
       [](auto& v) {
         v.state = State::kNotCapturedBlockLimit;
         v.sha256 = {};
       }},
      {"limit state below the length ceiling", false,
       [](auto& v) {
         v.state = State::kNotCapturedBlockLimit;
         v.block_length = 400 * 1024;
         v.sha256 = {};
       }},
      {"captured at the length ceiling", false,
       [](auto& v) { v.block_length = reb::kHeaderLengthUnrepresentable; }},
      {"missing digest", false, [](auto& v) { v.sha256 = {}; }},
      {"response policy", true, [](auto& v) { v.referrer_policy = 1; }},
      {"network response address", true, [](auto& v) { v.source = Source::kNetwork; }},
      {"network response status below 100", true,
       [](auto& v) {
         v.source = Source::kNetwork;
         v.address_family = 0;
         v.remote_port = 0;
         v.remote_address = {};
         v.status_code = 42;
       }},
      {"response status above 999", true, [](auto& v) { v.status_code = 1000; }},
      {"response status below 100", true, [](auto& v) { v.status_code = 42; }},
      {"early hints status", true,
       [](auto& v) {
         v.source = Source::kEarlyHints;
         v.address_family = 0;
         v.remote_port = 0;
         v.remote_address = {};
         v.status_code = 200;
       }},
      {"early hints address", true,
       [](auto& v) {
         v.source = Source::kEarlyHints;
         v.status_code = 103;
       }},
      {"address family five", true, [](auto& v) { v.address_family = 5; }},
      {"IPv4 tail", true, [](auto& v) { v.address_family = 4; }},
      {"port without address", true,
       [](auto& v) {
         v.address_family = 0;
         v.remote_address = {};
       }},
  };
  for (const auto& item : bad) {
    auto value = item.response ? answered : captured;
    item.mutate(value);
    add(std::string("header ") + item.name, HeaderEvent(item.response, value, 77), false);
  }
  // Version 2 retains a block of any length; version 1 had a 320 KiB limit.
  auto long_block = captured;
  long_block.block_length = 400 * 1024;
  add("header captured past 320 KiB", HeaderEvent(false, long_block, 77), true);
  const auto version = [](reb::EventRecord event, const std::uint16_t number) {
    event.inline_payload[0] = static_cast<std::byte>(number & 0xffU);
    event.inline_payload[1] = static_cast<std::byte>(number >> 8U);
    return event;
  };
  add("header version 1 captured past 320 KiB", version(HeaderEvent(false, long_block, 77), 1),
      false);
  add("header version 1 captured", version(HeaderEvent(false, captured, 77), 1), true);
  auto v1_limited = block(Source::kBrowser, State::kNotCapturedBlockLimit);
  v1_limited.block_length = 400 * 1024;
  add("header version 1 past its 320 KiB limit", version(HeaderEvent(false, v1_limited, 0), 1),
      true);
  add("header version 3", version(HeaderEvent(false, captured, 77), 3), false);
  auto unparsed = answered;
  unparsed.status_code = 0;
  add("response status unparsed", HeaderEvent(true, unparsed, 77), true);
  auto received = unparsed;
  received.source = reb::NativeHeaderSource::kNetwork;
  received.address_family = 0;
  received.remote_port = 0;
  received.remote_address = {};
  add("network response status unparsed", HeaderEvent(true, received, 77), true);
  auto ipv4 = answered;
  ipv4.address_family = 4;
  ipv4.remote_address = {127, 0, 0, 1};
  add("response IPv4 endpoint", HeaderEvent(true, ipv4, 77), true);
  auto event = HeaderEvent(false, captured, 77);
  event.inline_payload[44] = std::byte{1};
  add("header reserved word", event, false);
  event = HeaderEvent(false, captured, 77);
  event.inline_payload[127] = std::byte{1};
  add("header reserved tail", event, false);
  event = HeaderEvent(false, captured, 77);
  event.header.status_code = 200;
  add("header envelope status", event, false);
  event = HeaderEvent(false, captured, 77);
  event.header.parent_event_id = event.header.sequence_number;
  add("header parent not earlier", event, false);
  event = HeaderEvent(false, captured, 77);
  event.inline_payload[0] = std::byte{0};
  add("header payload version", event, false);
}

// Cookie lists and script cookie records ("Cookies" in native-network-v3.md),
// through the overlay encoders and the core decoders; each joins the golden.
void CheckCookies() {
  using State = reb::NativeHeaderState;
  const auto add = [](const std::string& name, const reb::EventRecord& event, const bool valid) {
    golden.emplace_back(name, event);
    Check(reb::IsValidEvent(event) == valid, "cookie record verdict: " + name);
  };
  const auto list = [](const reb::NativeCookieDirection direction, const State state) {
    reb::NativeCookieListSummary value;
    value.direction = direction;
    value.state = state;
    value.cookie_count = state == State::kEmpty ? 0 : 2;
    value.blocked_count = state == State::kEmpty ? 0 : 1;
    value.list_length = state == State::kEmpty ? 0
                        : state == State::kNotCapturedBlockLimit
                            ? static_cast<std::uint32_t>(reb::kNativeHeaderLengthUnrepresentable)
                            : 200;
    if (state != State::kNotCapturedBlockLimit) {
      value.sha256.fill(0xab);
    }
    value.hop = 2;
    value.unattributed_lists = 1;
    return value;
  };
  const auto list_event = [](const reb::NativeCookieListSummary& value,
                             const std::uint64_t artifact) {
    auto event = Event(reb::EventType::kCookieList, reb::EncodeNativeCookieListPayload(value));
    event.header.artifact_id = artifact;
    return event;
  };
  for (const State state :
       {State::kCaptured, State::kCapturedShared, State::kEmpty, State::kNotCapturedBlockLimit,
        State::kNotCapturedArtifactUnavailable, State::kNotCapturedTransferRefused,
        State::kNotCapturedSessionBudget, State::kNotCapturedUrl}) {
    const bool retained = state == State::kCaptured || state == State::kCapturedShared;
    const std::string suffix = std::to_string(static_cast<unsigned>(state));
    add("cookie list sent state " + suffix,
        list_event(list(reb::NativeCookieDirection::kSent, state), retained ? 78 : 0), true);
    add("cookie list received state " + suffix,
        list_event(list(reb::NativeCookieDirection::kReceived, state), retained ? 78 : 0), true);
    add("cookie list artifact disagrees with state " + suffix,
        list_event(list(reb::NativeCookieDirection::kSent, state), retained ? 0 : 78), false);
  }
  const auto captured = list(reb::NativeCookieDirection::kSent, State::kCaptured);
  struct BadList {
    const char* name;
    std::function<void(reb::NativeCookieListSummary&)> mutate;
  };
  const BadList bad_lists[] = {
      {"direction zero", [](auto& v) { v.direction = static_cast<reb::NativeCookieDirection>(0); }},
      {"direction three",
       [](auto& v) { v.direction = static_cast<reb::NativeCookieDirection>(3); }},
      {"state nine", [](auto& v) { v.state = static_cast<State>(9); }},
      {"blocked above count", [](auto& v) { v.blocked_count = 3; }},
      {"count without length", [](auto& v) { v.list_length = 0; }},
      {"length below one entry each", [](auto& v) { v.list_length = 143; }},
      {"captured at the length ceiling",
       [](auto& v) { v.list_length = reb::kHeaderLengthUnrepresentable; }},
      {"limit state below the length ceiling",
       [](auto& v) {
         v.state = State::kNotCapturedBlockLimit;
         v.list_length = 3U * 1024U * 1024U;
         v.sha256 = {};
       }},
      {"missing digest", [](auto& v) { v.sha256 = {}; }},
      {"empty with cookies", [](auto& v) { v.state = State::kEmpty; }},
  };
  for (const auto& item : bad_lists) {
    auto value = captured;
    item.mutate(value);
    add(std::string("cookie list ") + item.name, list_event(value, 78), false);
  }
  auto minimal = captured;
  minimal.list_length = 144;
  add("cookie list minimal length", list_event(minimal, 78), true);
  // Version 2 retains a list of any length; version 1 had a 2 MiB limit.
  auto long_list = captured;
  long_list.list_length = 3U * 1024U * 1024U;
  add("cookie list captured past 2 MiB", list_event(long_list, 78), true);
  const auto version = [](reb::EventRecord record, const std::uint16_t number) {
    record.inline_payload[0] = static_cast<std::byte>(number & 0xffU);
    record.inline_payload[1] = static_cast<std::byte>(number >> 8U);
    return record;
  };
  add("cookie list version 1 captured past 2 MiB", version(list_event(long_list, 78), 1), false);
  add("cookie list version 1 captured", version(list_event(captured, 78), 1), true);
  auto v1_limited = list(reb::NativeCookieDirection::kSent, State::kNotCapturedBlockLimit);
  v1_limited.list_length = 3U * 1024U * 1024U;
  add("cookie list version 1 past its 2 MiB limit", version(list_event(v1_limited, 0), 1), true);
  add("cookie list version 3", version(list_event(captured, 78), 3), false);
  auto event = list_event(captured, 78);
  event.inline_payload[6] = std::byte{1};
  add("cookie list reserved word", event, false);
  event = list_event(captured, 78);
  event.inline_payload[127] = std::byte{1};
  add("cookie list reserved tail", event, false);
  event = list_event(captured, 78);
  event.header.parent_event_id = 0;
  add("cookie list without parent", event, false);

  const auto script = [](const reb::NativeScriptCookieApi api) {
    reb::NativeScriptCookieSummary value;
    value.api = api;
    const bool write = api == reb::NativeScriptCookieApi::kDocumentCookieSet ||
                       api == reb::NativeScriptCookieApi::kCookieStoreSet ||
                       api == reb::NativeScriptCookieApi::kCookieStoreDelete;
    value.name_length = 3;
    value.name_prefix = {'s', 'i', 'd'};
    value.value_length = write ? 6 : 0;
    value.count = write ? 1 : 4;
    value.string_length = api == reb::NativeScriptCookieApi::kDocumentCookieSet   ? 20
                          : api == reb::NativeScriptCookieApi::kDocumentCookieGet ? 64
                                                                                  : 0;
    if (write) {
      value.value_sha256.fill(0x5a);
    }
    value.frame = {1, 0, 0, 77, 1234, 0};
    value.flags = reb::kNativeScriptCookieFrameRecorded;
    value.thread = 1;  // the document main thread
    return value;
  };
  const auto script_event = [](const reb::NativeScriptCookieSummary& value) {
    auto record = Event(reb::EventType::kScriptCookie, reb::EncodeNativeScriptCookiePayload(value));
    record.header.request_id = 0;
    record.header.parent_event_id = 0;
    record.header.frame_id = 9;
    return record;
  };
  for (const auto api :
       {reb::NativeScriptCookieApi::kDocumentCookieSet,
        reb::NativeScriptCookieApi::kDocumentCookieGet, reb::NativeScriptCookieApi::kCookieStoreSet,
        reb::NativeScriptCookieApi::kCookieStoreGet, reb::NativeScriptCookieApi::kCookieStoreGetAll,
        reb::NativeScriptCookieApi::kCookieStoreDelete}) {
    add("script cookie api " + std::to_string(static_cast<unsigned>(api)),
        script_event(script(api)), true);
  }
  const auto set = script(reb::NativeScriptCookieApi::kDocumentCookieSet);
  const auto get = script(reb::NativeScriptCookieApi::kDocumentCookieGet);
  auto value = set;
  value.flags = 0;
  value.frame = {};
  add("script cookie without frame", script_event(value), true);
  value = set;
  value.name_length = 30;
  value.string_length = 40;
  value.name_prefix.fill('n');
  value.flags |= reb::kNativeScriptCookieNameTruncated;
  add("script cookie long name", script_event(value), true);
  value = set;
  value.stack_digest.fill(0x11);
  value.flags |= reb::kNativeScriptCookieStackRecorded;
  add("script cookie with stack", script_event(value), true);
  // Version 3: a document.cookie read is a nameless read record, whose offset
  // 16 counts the names no name record counts, plus one record per name.
  const auto read_record = [&get] {
    auto read = get;
    read.name_length = 0;
    read.name_prefix = {};
    read.flags |= reb::kNativeScriptCookieReadRecord;
    read.unrecorded_names = 7;
    return read;
  }();
  event = script_event(read_record);
  add("script cookie read record", event, true);
  reb::ScriptCookiePayload decoded;
  Check(reb::DecodeScriptCookiePayload(event.inline_payload, decoded) &&
            decoded.value_length == 7 && reb::IsScriptCookieReadRecord(decoded),
        "a read record carries its unrecorded names at offset 16");
  value = read_record;
  value.flags |= reb::kNativeScriptCookieTableFull;
  value.count = 1;
  add("script cookie read table full", script_event(value), true);
  value = get;
  value.name_length = 0;
  value.name_prefix = {};
  add("script cookie empty name read", script_event(value), true);
  // Version 1 and 2 reads were the whole jar, with no name record.
  event = script_event(get);
  event.inline_payload[0] = std::byte{2};
  add("script cookie version 2 read", event, true);
  event = script_event(read_record);
  event.inline_payload[0] = std::byte{2};
  add("script cookie version 2 read record flag", event, false);
  // Version 2 names the isolate: a service worker's cookieStore write names
  // the worker by its context ID as frame_id.
  value = script(reb::NativeScriptCookieApi::kCookieStoreSet);
  value.thread = 4;  // a service worker
  value.stack_digest.fill(0x22);
  value.flags |= reb::kNativeScriptCookieStackRecorded;
  event = script_event(value);
  event.header.frame_id = 0x5157;
  add("script cookie service worker", event, true);
  event.header.frame_id = 0;
  add("script cookie service worker without its context ID", event, false);
  value = set;
  value.thread = 0;
  value.flags = 0;
  value.frame = {};
  add("script cookie thread not named", script_event(value), true);
  // Version 1 records, written before the thread byte, read as the document's.
  event = script_event(set);
  event.inline_payload[0] = std::byte{1};
  event.inline_payload[6] = std::byte{0};
  add("script cookie version 1", event, true);
  event.inline_payload[6] = std::byte{1};
  add("script cookie version 1 thread byte", event, false);
  struct BadScript {
    const char* name;
    reb::NativeScriptCookieSummary base;
    std::function<void(reb::NativeScriptCookieSummary&)> mutate;
  };
  const BadScript bad_scripts[] = {
      {"api zero", set, [](auto& v) { v.api = static_cast<reb::NativeScriptCookieApi>(0); }},
      {"api seven", set, [](auto& v) { v.api = static_cast<reb::NativeScriptCookieApi>(7); }},
      {"write count two", set, [](auto& v) { v.count = 2; }},
      {"read count zero", get, [](auto& v) { v.count = 0; }},
      {"write without digest", set, [](auto& v) { v.value_sha256 = {}; }},
      {"read with digest", get, [](auto& v) { v.value_sha256.fill(1); }},
      {"read with value", get, [](auto& v) { v.value_length = 1; }},
      {"short set string", set, [](auto& v) { v.string_length = 8; }},
      {"store string length", script(reb::NativeScriptCookieApi::kCookieStoreSet),
       [](auto& v) { v.string_length = 9; }},
      {"long name unmarked", set,
       [](auto& v) {
         v.name_length = 30;
         v.string_length = 40;
       }},
      {"short name marked", set, [](auto& v) { v.flags |= reb::kNativeScriptCookieNameTruncated; }},
      {"name tail dirty", set, [](auto& v) { v.name_prefix[10] = 'x'; }},
      {"frame flag without frame", set, [](auto& v) { v.frame = {}; }},
      {"frame without flag", set, [](auto& v) { v.flags = 0; }},
      {"frame kind three", set, [](auto& v) { v.frame.kind = 3; }},
      {"frame combinator", set, [](auto& v) { v.frame.combinator = 1; }},
      {"stack without flag", set, [](auto& v) { v.stack_digest.fill(1); }},
      {"stack flag without digest", set,
       [](auto& v) { v.flags |= reb::kNativeScriptCookieStackRecorded; }},
      {"table full write", set, [](auto& v) { v.flags |= reb::kNativeScriptCookieTableFull; }},
      {"unknown flag", set, [](auto& v) { v.flags |= 0x20; }},
      {"read record on a write", set,
       [](auto& v) { v.flags |= reb::kNativeScriptCookieReadRecord; }},
      {"read record on a store read", script(reb::NativeScriptCookieApi::kCookieStoreGet),
       [](auto& v) { v.flags |= reb::kNativeScriptCookieReadRecord; }},
      {"read record with a name", get,
       [](auto& v) { v.flags |= reb::kNativeScriptCookieReadRecord; }},
      {"name read table full", get, [](auto& v) { v.flags |= reb::kNativeScriptCookieTableFull; }},
      {"name read shorter than its name", get, [](auto& v) { v.string_length = 2; }},
      {"thread five", set, [](auto& v) { v.thread = 5; }},
      {"frame without thread", set, [](auto& v) { v.thread = 0; }},
  };
  for (const auto& item : bad_scripts) {
    value = item.base;
    item.mutate(value);
    add(std::string("script cookie ") + item.name, script_event(value), false);
  }
  event = script_event(set);
  event.header.request_id = 17;
  add("script cookie with request", event, false);
  event = script_event(set);
  event.header.parent_event_id = 3;
  add("script cookie with parent", event, false);
  event = script_event(set);
  event.inline_payload[7] = std::byte{1};
  add("script cookie reserved byte", event, false);
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
    reb::ArtifactReceiver refusing(root / "refusing", {});
    std::istringstream stream(Frame(header, url, mime, content));
    Check(refusing.ReceiveOne(stream) == reb::ArtifactReceiveStatus::kSensitiveCaptureDisabled,
          "default receiver refuses request bodies");
  }
  {
    reb::ArtifactReceiver receiver(root / "allowed", {.allow_sensitive = true});
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
    reb::ArtifactReceiver reopened(root / "allowed", {.allow_sensitive = true});
    std::istringstream duplicate(Frame(header, url, mime, content));
    Check(reopened.ReceiveOne(duplicate) == reb::ArtifactReceiveStatus::kConflict,
          "reopened store accepted the request body manifest line and kept its identity");
  }
  // Header blocks share the request-body policy (native-network-v3.md).
  const std::string text = "Set-Cookie: sid=1\r\n";
  reb::ArtifactHeader block = header;
  for (const auto kind :
       {reb::ArtifactKind::kRequestHeaders, reb::ArtifactKind::kResponseHeaders}) {
    block = header;
    block.kind = kind;
    block.artifact_id = kind == reb::ArtifactKind::kRequestHeaders ? 6 : 7;
    block.content_size = text.size();
    block.mime_type_size = 10;
    Check(reb::IsValidArtifactHeader(block), "header block artifact header is valid");
    auto plain = block;
    plain.flags = 0;
    Check(!reb::IsValidArtifactHeader(plain), "header block artifact must be sensitive");
    auto other = block;
    other.capture_origin = reb::ArtifactCaptureOrigin::kNetworkResponse;
    Check(!reb::IsValidArtifactHeader(other), "header block artifact keeps the request origin");
    reb::ArtifactReceiver receiver(root / "allowed", {.allow_sensitive = true});
    std::istringstream stream(Frame(block, url, "text/plain", text));
    Check(receiver.ReceiveOne(stream) == reb::ArtifactReceiveStatus::kAccepted,
          "receiver keeps header blocks: " + receiver.LastError());
  }
  {
    reb::ArtifactReceiver reopened(root / "allowed", {.allow_sensitive = true});
    std::istringstream duplicate(Frame(block, url, "text/plain", text));
    Check(reopened.ReceiveOne(duplicate) == reb::ArtifactReceiveStatus::kConflict,
          "reopened store accepted the header block manifest lines");
    std::ifstream lines(root / "allowed" / "manifest.jsonl");
    const std::string stored{std::istreambuf_iterator<char>(lines), {}};
    Check(stored.find("\"kind\":\"request_headers\"") != std::string::npos &&
              stored.find("\"kind\":\"response_headers\"") != std::string::npos,
          "manifest names both header kinds");
  }
  {
    reb::ArtifactHeader list = header;
    list.kind = reb::ArtifactKind::kCookieList;
    list.artifact_id = 8;
    list.content_size = 16;
    list.mime_type_size = 29;
    Check(reb::IsValidArtifactHeader(list), "cookie list artifact header is valid");
    auto plain = list;
    plain.flags = 0;
    Check(!reb::IsValidArtifactHeader(plain), "cookie list artifact must be sensitive");
    reb::ArtifactReceiver receiver(root / "allowed", {.allow_sensitive = true});
    std::istringstream stream(
        Frame(list, url, "application/x-reb-cookie-list",
              std::string("RBCK\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)));
    Check(receiver.ReceiveOne(stream) == reb::ArtifactReceiveStatus::kAccepted,
          "receiver keeps cookie lists: " + receiver.LastError());
    std::ifstream lines(root / "allowed" / "manifest.jsonl");
    const std::string stored{std::istreambuf_iterator<char>(lines), {}};
    Check(stored.find("\"kind\":\"cookie_list\"") != std::string::npos,
          "manifest names cookie lists");
  }
  std::filesystem::remove_all(root, ignored);
}

}  // namespace

static_assert(static_cast<std::uint16_t>(reb::EventType::kResponseBody) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kResponseBody));
static_assert(reb::kResponseBodyPayloadVersion == reb::kNativeResponseBodyPayloadVersion);
static_assert(static_cast<std::uint8_t>(reb::ResponseBodyState::kNotCapturedDiskReserve) ==
              static_cast<std::uint8_t>(reb::NativeResponseBodyState::kNotCapturedDiskReserve));
static_assert(static_cast<std::uint8_t>(reb::RequestBodyState::kNotCapturedDiskReserve) ==
              static_cast<std::uint8_t>(reb::NativeRequestBodyState::kNotCapturedDiskReserve));
static_assert(static_cast<std::uint8_t>(reb::ResponseBodyState::kPartial) ==
              static_cast<std::uint8_t>(reb::NativeResponseBodyState::kPartial));
static_assert(reb::kResponseBodyContentTypePresent == reb::kNativeResponseBodyContentTypePresent);
static_assert(reb::kResponseBodyCompletionUnobserved ==
              reb::kNativeResponseBodyCompletionUnobserved);
static_assert(reb::kResponseBodyShared == reb::kNativeResponseBodyShared);
static_assert(reb::kResponseBodySnapshotsWithheld == reb::kNativeResponseBodySnapshotsWithheld);

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

reb::EventRecord ResponseEvent(
    const reb::NativeResponseBodySummary& summary,
    const std::uint64_t artifact_id = 0,
    const std::uint16_t version = reb::kNativeResponseBodyPayloadVersion) {
  auto event = Event(reb::EventType::kResponseBody, reb::EncodeNativeResponseBodyPayload(summary));
  // Older records differ only in their version and the rules it selects.
  event.inline_payload[0] = static_cast<std::byte>(version);
  event.header.artifact_id = artifact_id;
  return event;
}

void CheckResponseBodies() {
  using S = reb::NativeResponseBodyState;
  using Older = reb::ResponseBodyState;
  // Versions 1 and 2 kept at most this prefix of a body.
  constexpr std::uint64_t kCap = reb::kResponseBodyCaptureBytes;
  const auto older = [](const Older value) { return static_cast<S>(value); };
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
            decoded.protocol_version == 3 && decoded.payload_size == 128 && decoded.state == 3 &&
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
    std::uint16_t version = reb::kNativeResponseBodyPayloadVersion;
  };
  auto shared = ResponseSummary(S::kCaptured, 900, 900);
  shared.flags |= reb::kNativeResponseBodyShared | reb::kNativeResponseBodyFromCache;
  auto encoded = ResponseSummary(S::kCaptured, 40, 40);
  reb::SetNativeResponseCodings("gzip, br", encoded);
  encoded.flags |= reb::kNativeResponseBodyStillEncoded | reb::kNativeResponseBodyServiceWorker;
  auto unobserved = ResponseSummary(S::kCaptured, 12, 12);
  unobserved.flags |= reb::kNativeResponseBodyCompletionUnobserved;
  // Bit 7: a snapshot the spacing allowed was withheld by the body's copy bound.
  auto withheld = ResponseSummary(S::kPartial, 300, 300);
  withheld.flags |= reb::kNativeResponseBodySnapshotsWithheld;
  auto withheld_end = ResponseSummary(S::kNotCapturedDiskReserve, 4096);
  withheld_end.flags |= reb::kNativeResponseBodySnapshotsWithheld;
  auto withheld_budget = ResponseSummary(older(Older::kNotCapturedSessionBudget), 4096);
  withheld_budget.flags |= reb::kNativeResponseBodySnapshotsWithheld;
  auto untyped = ResponseSummary(S::kNotModified, 0);
  untyped.flags = 0;
  untyped.content_type = {};
  untyped.content_type_length = 0;
  const Valid valid[] = {
      {"response captured", ResponseSummary(S::kCaptured, 900, 900), 911},
      {"response captured shared", shared, 911},
      {"response captured still encoded", encoded, 912},
      {"response captured unobserved completion", unobserved, 913},
      {"response captured past 16 MiB", ResponseSummary(S::kCaptured, kCap * 5, kCap * 5), 914},
      {"response partial", ResponseSummary(S::kPartial, 300, 300), 915},
      {"response partial past 16 MiB", ResponseSummary(S::kPartial, kCap + 1, kCap + 1), 916},
      {"response aborted prefix", ResponseSummary(S::kAborted, 2048, 2048), 917},
      {"response aborted past 16 MiB", ResponseSummary(S::kAborted, kCap * 3, kCap * 3), 917},
      {"response aborted nothing kept", ResponseSummary(S::kAborted, 0), 0},
      {"response cancelled prefix", ResponseSummary(S::kCancelled, 10, 10), 918},
      {"response cancelled before bytes", ResponseSummary(S::kCancelled, 0), 0},
      {"response empty", ResponseSummary(S::kEmpty, 0), 0},
      {"response not modified", untyped, 0},
      {"response redirected", ResponseSummary(S::kRedirected, 0), 0},
      {"response artifact unavailable", ResponseSummary(S::kNotCapturedArtifactUnavailable, 77), 0},
      {"response transfer refused", ResponseSummary(S::kNotCapturedTransferRefused, 0), 0},
      {"response disk reserve", ResponseSummary(S::kNotCapturedDiskReserve, 4096), 0},
      {"response partial with snapshots withheld", withheld, 919},
      {"response refused with snapshots withheld", withheld_end, 0},
      // Stored version 1 and 2 records keep their 16 MiB prefix, media choice
      // and session budget.
      {"response version 1", ResponseSummary(S::kCaptured, 900, 900), 911, 1},
      {"response version 2 truncated",
       ResponseSummary(older(Older::kCapturedTruncated), kCap + 5, kCap), 914, 2},
      {"response version 2 partial past cap", ResponseSummary(S::kPartial, kCap + 1, kCap), 916, 2},
      {"response version 2 aborted past cap", ResponseSummary(S::kAborted, kCap * 3, kCap), 917, 2},
      {"response version 2 type skipped", ResponseSummary(older(Older::kNotCapturedType), 0), 0, 2},
      {"response version 2 session budget",
       ResponseSummary(older(Older::kNotCapturedSessionBudget), 4096), 0, 2},
      {"response version 2 budget with snapshots withheld", withheld_budget, 0, 2},
      {"response version 1 session budget",
       ResponseSummary(older(Older::kNotCapturedSessionBudget), 4096), 0, 1},
  };
  for (const Valid& item : valid) {
    golden.emplace_back(item.name, ResponseEvent(item.summary, item.artifact_id, item.version));
    Check(reb::IsValidEvent(golden.back().second),
          std::string("valid response body state: ") + item.name);
  }

  using Mutation = std::function<void(reb::NativeResponseBodySummary&, reb::EventRecord&)>;
  struct Invalid {
    const char* name;
    reb::NativeResponseBodySummary base;
    std::uint64_t artifact_id;
    Mutation mutate;
    std::uint16_t version = reb::kNativeResponseBodyPayloadVersion;
  };
  const auto captured = ResponseSummary(S::kCaptured, 900, 900);
  const auto refused = ResponseSummary(S::kNotCapturedTransferRefused, 900);
  const auto summary = [](auto change) {
    return [change](reb::NativeResponseBodySummary& value, reb::EventRecord&) { change(value); };
  };
  const auto byte = [](std::size_t offset, std::byte value) {
    return [offset, value](reb::NativeResponseBodySummary&, reb::EventRecord& event) {
      event.inline_payload[offset] = value;
    };
  };
  const Invalid invalid[] = {
      {"response version 4", captured, 911, byte(0, std::byte{4})},
      {"response version 0", captured, 911, byte(0, std::byte{0})},
      {"response version 1 with bit 7", captured, 911,
       summary([](auto& value) { value.flags |= reb::kNativeResponseBodySnapshotsWithheld; }), 1},
      {"response reserved", captured, 911, byte(30, std::byte{1})},
      {"response state 0", captured, 911, byte(4, std::byte{0})},
      {"response state 14", refused, 0, byte(4, std::byte{14})},
      {"response truncated in version 3",
       ResponseSummary(older(Older::kCapturedTruncated), kCap + 5, kCap),
       914,
       {}},
      {"response type skipped in version 3",
       ResponseSummary(older(Older::kNotCapturedType), 0),
       0,
       {}},
      {"response session budget in version 3",
       ResponseSummary(older(Older::kNotCapturedSessionBudget), 4096),
       0,
       {}},
      {"response partial cut at 16 MiB in version 3",
       ResponseSummary(S::kPartial, kCap + 1, kCap),
       916,
       {}},
      {"response aborted cut at 16 MiB in version 3",
       ResponseSummary(S::kAborted, kCap * 3, kCap),
       917,
       {}},
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
      {"response partial short", ResponseSummary(S::kPartial, 30, 29), 911, {}},
      {"response version 2 partial short of cap", ResponseSummary(S::kPartial, kCap + 1, kCap), 911,
       summary([](auto& value) { value.captured_length = kCap - 1; }), 2},
      {"response unobserved on aborted", ResponseSummary(S::kAborted, 0), 0,
       summary([](auto& value) { value.flags |= reb::kNativeResponseBodyCompletionUnobserved; })},
      {"response version 2 truncated under cap",
       ResponseSummary(older(Older::kCapturedTruncated), kCap, kCap),
       911,
       {},
       2},
      {"response version 2 disk reserve",
       ResponseSummary(S::kNotCapturedDiskReserve, 4096),
       0,
       {},
       2},
      {"response version 2 type skipped with length",
       ResponseSummary(older(Older::kNotCapturedType), 3),
       0,
       {},
       2},
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
      {"response type without flag", captured, 911, summary([](auto& value) {
         value.flags =
             static_cast<std::uint8_t>(value.flags & ~reb::kNativeResponseBodyContentTypePresent);
       })},
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
    reb::EventRecord event = ResponseEvent(value, item.artifact_id, item.version);
    if (item.mutate) {
      item.mutate(value, event);
      // Summary mutations re-encode; payload and envelope mutations stand.
      const auto mutated = ResponseEvent(value, item.artifact_id, item.version);
      if (mutated.inline_payload !=
          ResponseEvent(item.base, item.artifact_id, item.version).inline_payload) {
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
  CheckHeaderBlocks();
  CheckCookies();
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
               "response_body state, codings and malformed record, header blocks, cookie lists "
               "and script cookie records, header and cookie list artifact policy\n";
  return 0;
}
