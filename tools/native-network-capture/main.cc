#include <algorithm>
#include <bit>
#include <cassert>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_network_headers.h"
#include "brave/components/reverse_engineering_browser/common/native_network_headers_hook.h"
#include "brave/components/reverse_engineering_browser/common/native_network_lifecycle.h"
#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/common/native_request_namespace.h"
#include "chromium_stubs.h"
#include "crypto/hash.h"
#include "reb/event.hpp"
#include "reb/network_cookies.hpp"
#include "reb/network_headers.hpp"
#include "reb/network_request.hpp"
#include "reb/network_response_body.hpp"
namespace {
std::vector<reb::NativeProbeEvent> events;
reb::NativeProbeQueue queue;
void Emit(const reb::NativeProbeEvent& event) noexcept {
  events.push_back(event);
}
void Queue(const reb::NativeProbeEvent& event) noexcept {
  static_cast<void>(queue.TryPush(event));
}
std::string Payload(const reb::NativeProbeEvent& event) {
  return {reinterpret_cast<const char*>(event.inline_payload.data()), event.header.payload_size};
}
const reb::NativeProbeEvent& Last(reb::NativeProbeType type) {
  const auto found = std::find_if(events.rbegin(), events.rend(),
                                  [type](const auto& event) { return event.header.type == type; });
  assert(found != events.rend());
  return *found;
}
// Every record the browser produces must pass the broker's core validator.
bool AllValid() {
  return std::all_of(events.begin(), events.end(), [](const reb::NativeProbeEvent& event) {
    return reb::IsValidEvent(std::bit_cast<reb::EventRecord>(event));
  });
}
reb::RequestBodyPayload Body(const reb::NativeProbeEvent& event) {
  reb::RequestBodyPayload value;
  assert(event.header.type == reb::NativeProbeType::kRequestBody);
  assert(reb::DecodeRequestBodyPayload(event.inline_payload, value));
  return value;
}
reb::RequestTargetPayload Target(const reb::NativeProbeEvent& event) {
  reb::RequestTargetPayload value;
  assert(event.header.type == reb::NativeProbeType::kRequestTarget);
  assert(reb::DecodeRequestTargetPayload(event.inline_payload, value));
  return value;
}
std::shared_ptr<network::ResourceRequestBody> BytesBody(
    std::vector<std::vector<std::uint8_t>> parts) {
  auto body = std::make_shared<network::ResourceRequestBody>();
  for (auto& part : parts) {
    body->elements_mutable()->emplace_back(network::DataElementBytes(std::move(part)));
  }
  return body;
}
std::vector<std::uint8_t> Bytes(const std::string& text) {
  return {text.begin(), text.end()};
}
std::string Type(const reb::RequestBodyPayload& body) {
  return {body.content_type.data(), body.content_type_length};
}
using State = reb::RequestBodyState;
using Kind = reb::RequestBodyKind;

reb::HeaderBlockPayload Headers(const reb::NativeProbeEvent& event) {
  reb::HeaderBlockPayload value;
  assert(event.header.type == reb::NativeProbeType::kRequestHeaders ||
         event.header.type == reb::NativeProbeType::kResponseHeaders);
  assert(reb::DecodeHeaderBlockPayload(event.inline_payload, value));
  return value;
}
std::string Text(const std::vector<std::uint8_t>& bytes) {
  return {bytes.begin(), bytes.end()};
}
std::vector<network::mojom::HttpRawHeaderPairPtr> Raw(
    std::vector<std::pair<std::string, std::string>> pairs) {
  std::vector<network::mojom::HttpRawHeaderPairPtr> out;
  for (auto& [key, value] : pairs) {
    out.push_back(std::make_unique<network::mojom::HttpRawHeaderPair>(
        network::mojom::HttpRawHeaderPair{std::move(key), std::move(value)}));
  }
  return out;
}
std::size_t CountType(reb::NativeProbeType type) {
  return static_cast<std::size_t>(
      std::count_if(events.begin(), events.end(),
                    [type](const auto& event) { return event.header.type == type; }));
}
using HeaderState = reb::HeaderState;
constexpr auto kRaw = reb::NativeNetworkHeadersKind::kRawRequest;

// protocol/native-network-v3.md, through the production sink and hook.
void HeaderBlocks() {
  auto& sink = reb::NativeNetworkCaptureSink::Get();
  auto& artifacts = reb::NativeArtifactCaptureSink::Get();
  const auto mask = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork);
  base::test_now_ns = 100;
  network::ResourceRequest request;
  request.url = GURL("https", "echo.test", "/start", "a=1");
  request.referrer_policy = net::ReferrerPolicy::NO_REFERRER;
  request.headers.SetHeader("Accept", "*/*");
  request.headers.SetHeader("X-Trace", "one: two");
  request.cors_exempt_headers.SetHeader("Purpose", "prefetch");
  const auto start = [&](std::uint64_t id) {
    sink.RecordRequestStarted(id, 0, 0, 4, 5, 11, 12, request);
    sink.AssignNetworkHeadersId(id, request);
  };
  const std::string id = "reb-00000000000001f4";

  // Metadata-only: no header record, no ID and no hook observer.
  sink.SetEmitter(Emit, 30, mask, 200);
  events.clear();
  artifacts.header_calls.clear();
  start(500);
  reb::NotifyNativeNetworkHeaders(kRaw, id, Raw({{"cookie", "sid=1"}}));
  assert(CountType(reb::NativeProbeType::kRequestHeaders) == 0 && !request.devtools_request_id &&
         artifacts.header_calls.empty());

  // Provisional request headers at start, retained as one block.
  sink.SetEmitter(Emit, 30, mask, 200, true);
  events.clear();
  start(500);
  assert(request.devtools_request_id == id && AllValid());
  const auto started = Last(reb::NativeProbeType::kRequestStarted).header;
  const auto& provisional = Last(reb::NativeProbeType::kRequestHeaders);
  auto value = Headers(provisional);
  const std::string provisional_text = "Accept: */*\r\nX-Trace: one: two\r\nPurpose: prefetch\r\n";
  assert(provisional.header.parent_event_id == started.sequence_number &&
         value.source == static_cast<std::uint8_t>(reb::HeaderSource::kBrowser) &&
         value.state == static_cast<std::uint8_t>(HeaderState::kCaptured) &&
         value.header_count == 3 && value.block_length == provisional_text.size() &&
         value.referrer_policy == 8 && value.hop == 0 && value.address_family == 0 &&
         value.sha256 == crypto::hash::Sha256(provisional_text));
  assert(artifacts.header_calls.size() == 1);
  const auto& provisional_call = artifacts.header_calls.back();
  assert(provisional_call.kind == reb::NativeArtifactKind::kRequestHeaders &&
         provisional_call.creator_event_id == provisional.header.sequence_number &&
         provisional_call.url == "https://echo.test/start?a=1" &&
         Text(provisional_call.content) == provisional_text &&
         provisional.header.artifact_id == artifacts.next_artifact_id - 1);

  // Hop 0: the network stack's headers, pseudo-headers and Cookie included.
  reb::NotifyNativeNetworkHeaders(
      kRaw, id, Raw({{":method", "GET"}, {":path", "/start?a=1"}, {"cookie", "sid=1"}}));
  const auto& sent = events.back();
  value = Headers(sent);
  assert(AllValid() && sent.header.parent_event_id == started.sequence_number &&
         value.source == static_cast<std::uint8_t>(reb::HeaderSource::kNetwork) &&
         value.referrer_policy == 0 && value.hop == 0 && value.header_count == 3 &&
         Text(artifacts.header_calls.back().content) ==
             ":method: GET\r\n:path: /start?a=1\r\ncookie: sid=1\r\n");

  // Hop 0 ends in a 302 with Set-Cookie and a remote endpoint.
  net::RedirectInfo redirect;
  redirect.new_url = GURL("https", "echo.test", "/second");
  network::mojom::URLResponseHead head;
  head.headers = std::make_shared<net::HttpResponseHeaders>();
  head.headers->code = 302;
  head.headers->lines = {{"Location", "/second"}, {"Set-Cookie", "a=b; Secure"}};
  head.emitted_extra_info = true;
  head.remote_endpoint.ip.value = {{127, 0, 0, 1}, 4};
  head.remote_endpoint.port_number = 8443;
  events.clear();
  sink.RecordRequestRedirected(500, 0, 0, 4, 5, 11, 12, redirect, head);
  const auto first_redirect = events.front().header;
  value = Headers(events.back());
  assert(AllValid() && events.back().header.type == reb::NativeProbeType::kResponseHeaders &&
         events.back().header.parent_event_id == first_redirect.sequence_number &&
         value.status_code == 302 && value.hop == 0 && value.address_family == 4 &&
         value.remote_port == 8443 && value.remote_address[0] == 127 &&
         value.remote_address[3] == 1 &&
         Text(artifacts.header_calls.back().content) ==
             "Location: /second\r\nSet-Cookie: a=b; Secure\r\n" &&
         artifacts.header_calls.back().url == "https://echo.test/start?a=1");

  // Hop 1 ends before its raw request arrives; that block still joins hop 1.
  redirect.new_url = GURL("https", "echo.test", "/final");
  head.headers->code = 307;
  head.headers->lines = {{"Location", "/final"}};
  events.clear();
  sink.RecordRequestRedirected(500, 0, 0, 4, 5, 11, 12, redirect, head);
  const auto second_redirect = events.front().header;
  assert(Headers(events.back()).hop == 1 &&
         artifacts.header_calls.back().url == "https://echo.test/second");
  events.clear();
  reb::NotifyNativeNetworkHeaders(kRaw, id, Raw({{":path", "/second"}}));
  reb::NotifyNativeNetworkHeaders(kRaw, id, Raw({{":path", "/final"}}));
  assert(events.size() == 2 && AllValid() &&
         events[0].header.parent_event_id == first_redirect.sequence_number &&
         Headers(events[0]).hop == 1 &&
         events[1].header.parent_event_id == second_redirect.sequence_number &&
         Headers(events[1]).hop == 2 &&
         artifacts.header_calls.back().url == "https://echo.test/final");

  // A 103 joins the open hop.
  events.clear();
  reb::NotifyNativeNetworkHeaders(reb::NativeNetworkHeadersKind::kEarlyHints, id,
                                  Raw({{"link", "</app.css>; rel=preload"}}));
  value = Headers(events.back());
  assert(AllValid() && events.back().header.type == reb::NativeProbeType::kResponseHeaders &&
         events.back().header.parent_event_id == second_redirect.sequence_number &&
         value.source == static_cast<std::uint8_t>(reb::HeaderSource::kEarlyHints) &&
         value.status_code == 103 && value.hop == 2);

  // A 200 KiB response block is retained whole, before Brave's own rewrite.
  head.headers->code = 200;
  head.headers->lines = {{"X-Large", std::string(200 * 1024, 'v')}, {"Set-Cookie", "c=d"}};
  network::mojom::URLResponseHead rewritten = head;
  rewritten.headers = std::make_shared<net::HttpResponseHeaders>();
  rewritten.headers->lines = {{"X-Rewritten", "1"}};
  events.clear();
  const auto response_sequence =
      sink.RecordResponseStarted(500, 0, 0, 4, 5, 11, 12, rewritten, false, head.headers.get());
  value = Headers(events.back());
  const std::string large_text =
      "X-Large: " + std::string(200 * 1024, 'v') + "\r\nSet-Cookie: c=d\r\n";
  assert(AllValid() && events.back().header.parent_event_id == response_sequence &&
         value.state == static_cast<std::uint8_t>(HeaderState::kCaptured) && value.hop == 2 &&
         value.block_length == large_text.size() &&
         Text(artifacts.header_calls.back().content) == large_text);

  // Completion ends tracking; a later raw block is counted, not attached.
  network::URLLoaderCompletionStatus status;
  sink.RecordRequestCompleted(500, 0, 0, 4, 5, 11, 12, status);
  events.clear();
  reb::NotifyNativeNetworkHeaders(kRaw, id, Raw({{"cookie", "late"}}));
  reb::NotifyNativeNetworkHeaders(kRaw, "preflight-token", Raw({{"origin", "x"}}));
  assert(events.empty());

  // Identical provisional headers are retained once; the count shows the loss.
  const auto calls = artifacts.header_calls.size();
  request.devtools_request_id.reset();
  start(501);
  value = Headers(Last(reb::NativeProbeType::kRequestHeaders));
  assert(AllValid() && value.state == static_cast<std::uint8_t>(HeaderState::kCapturedShared) &&
         Last(reb::NativeProbeType::kRequestHeaders).header.artifact_id ==
             provisional.header.artifact_id &&
         value.unattributed_blocks == 1 && artifacts.header_calls.size() == calls);

  // A DevTools-owned ID is kept and matched by value.
  request.devtools_request_id = "1234.5";
  start(502);
  assert(request.devtools_request_id == "1234.5");
  events.clear();
  reb::NotifyNativeNetworkHeaders(kRaw, "1234.5", Raw({{"host", "echo.test"}}));
  assert(events.size() == 1 && Headers(events[0]).hop == 0 && events[0].header.request_id == 502);

  // Beyond 320 KiB: count and length only, no digest, no artifact.
  head.headers->lines = {{"X-Huge", std::string(reb::kNativeHeaderBlockLimitBytes, 'h')}};
  events.clear();
  static_cast<void>(sink.RecordResponseStarted(502, 0, 0, 4, 5, 11, 12, head));
  value = Headers(events.back());
  assert(AllValid() &&
         value.state == static_cast<std::uint8_t>(HeaderState::kNotCapturedBlockLimit) &&
         value.block_length == reb::kNativeHeaderBlockLimitBytes + 10 && value.header_count == 1 &&
         events.back().header.artifact_id == 0);

  // Synthetic Shields responses and empty blocks.
  events.clear();
  static_cast<void>(sink.RecordResponseStarted(502, 0, 0, 4, 5, 11, 12, head, true));
  assert(CountType(reb::NativeProbeType::kResponseHeaders) == 0);
  head.headers->lines.clear();
  static_cast<void>(sink.RecordResponseStarted(502, 0, 0, 4, 5, 11, 12, head));
  assert(AllValid() &&
         Headers(events.back()).state == static_cast<std::uint8_t>(HeaderState::kEmpty));

  // Unavailable, refused and unsupported-URL outcomes.
  request.devtools_request_id.reset();
  request.headers.SetHeader("X-Unique", "1");
  artifacts.enabled = false;
  start(503);
  assert(Headers(Last(reb::NativeProbeType::kRequestHeaders)).state ==
         static_cast<std::uint8_t>(HeaderState::kNotCapturedArtifactUnavailable));
  artifacts.enabled = true;
  artifacts.refuse = true;
  start(503);
  assert(Headers(Last(reb::NativeProbeType::kRequestHeaders)).state ==
         static_cast<std::uint8_t>(HeaderState::kNotCapturedTransferRefused));
  artifacts.refuse = false;
  request.url = GURL("wss", "socket.test", "/stream");
  start(503);
  assert(AllValid() && Headers(Last(reb::NativeProbeType::kRequestHeaders)).state ==
                           static_cast<std::uint8_t>(HeaderState::kNotCapturedUrl));

  // The per-configuration byte budget ends retention visibly.
  sink.SetEmitter(Emit, 30, mask, 200, true);
  request.url = GURL("https", "echo.test", "/beacon");
  request.headers = {};
  const std::size_t block = 300 * 1024;
  std::size_t retained = 0;
  for (std::size_t i = 0; retained + block <= reb::kNativeHeaderSessionBytes; ++i) {
    request.headers = {};
    request.headers.SetHeader("X-Fill", std::string(block - 12, 'f') + std::to_string(i % 10) +
                                            static_cast<char>('a' + (i / 10) % 26) +
                                            static_cast<char>('a' + (i / 260) % 26));
    events.clear();
    start(600 + i);
    assert(Headers(Last(reb::NativeProbeType::kRequestHeaders)).state ==
           static_cast<std::uint8_t>(HeaderState::kCaptured));
    retained += Headers(Last(reb::NativeProbeType::kRequestHeaders)).block_length;
  }
  request.headers.SetHeader("X-Over", "1");
  events.clear();
  start(599);
  assert(AllValid() && Headers(Last(reb::NativeProbeType::kRequestHeaders)).state ==
                           static_cast<std::uint8_t>(HeaderState::kNotCapturedSessionBudget));

  // Ending the session removes the hook observer.
  sink.SetEmitter(nullptr, 0, 0, 0, true);
  events.clear();
  reb::NotifyNativeNetworkHeaders(kRaw, "reb-0000000000000257", Raw({{"a", "b"}}));
  assert(events.empty());
  std::cout << "PASS native header blocks: metadata-only none, provisional/network/response over "
               "two redirect hops, out-of-order raw request, early hints, pseudo-headers, "
               "200 KiB retained whole, network headers before rewrite, sharing, unattributed "
               "count, DevTools-owned ID, block limit, unavailable/refused/URL, session budget\n";
}

void RequestContent() {
  auto& sink = reb::NativeNetworkCaptureSink::Get();
  auto& artifacts = reb::NativeArtifactCaptureSink::Get();
  const auto mask = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork);
  base::test_now_ns = 100;
  network::ResourceRequest request;
  request.method = "POST";
  request.url = GURL("https", "api.hcaptcha.test", "/checksiteconfig",
                     "v=1&host=accounts.hcaptcha.test&sitekey=site");
  request.headers.SetHeader("Content-Type", "Application/JSON; charset=UTF-8");
  const std::string json(816, '{');
  request.request_body = BytesBody({Bytes(json.substr(0, 300)), Bytes(json.substr(300))});
  const auto start = [&] {
    sink.RecordRequestStarted(172, 0, 0, 4, 5, 11, 12, request, reb::NativeBrowserLoaderKind(2));
  };

  // Metadata-only session: host-only start, body summary without bytes or path.
  events.clear();
  artifacts.calls.clear();
  sink.SetEmitter(Emit, 22, mask, 200);
  start();
  assert(events.size() == 2 && AllValid());
  assert(events[0].header.type == reb::NativeProbeType::kRequestStarted &&
         Payload(events[0]) == "POST api.hcaptcha.test" && events[0].header.scheme_class == 2 &&
         events[1].header.scheme_class == 0 && events[0].header.loader_kind == 3 &&
         events[1].header.loader_kind == 0);
  auto body = Body(events[1]);
  assert(events[1].header.parent_event_id == events[0].header.sequence_number);
  assert(events[1].header.request_id == 172 && events[1].header.tab_id == 4 &&
         events[1].header.frame_id == 5 && events[1].header.browser_context_id_high == 11 &&
         events[1].header.browser_context_id_low == 12 && events[1].header.artifact_id == 0);
  assert(body.state == static_cast<std::uint8_t>(State::kMetadataOnly) &&
         body.kind == static_cast<std::uint8_t>(Kind::kBytes) && body.body_length == 816 &&
         body.element_count == 2 && body.captured_length == 0 &&
         (body.flags & reb::kRequestBodyContentCapture) == 0 &&
         (body.flags & reb::kRequestBodyDigestPresent) != 0 && Type(body) == "application/json");
  assert(body.sha256 == crypto::hash::Sha256(json));
  assert(artifacts.calls.empty());

  // Content session: raw target, body record and one artifact handoff, then
  // the provisional header block (HeaderBlocks covers it).
  events.clear();
  sink.SetEmitter(Emit, 22, mask, 200, true);
  start();
  assert(events.size() == 4 && AllValid() &&
         events[3].header.type == reb::NativeProbeType::kRequestHeaders);
  const auto target = Target(events[1]);
  const std::string expected_target =
      "/checksiteconfig?v=1&host=accounts.hcaptcha.test&sitekey=site";
  assert(events[1].header.parent_event_id == events[0].header.sequence_number);
  assert(target.scheme == static_cast<std::uint8_t>(reb::RequestScheme::kHttps) &&
         target.port == 0 && target.target_length == expected_target.size() &&
         std::string(target.target_prefix.data(), expected_target.size()) == expected_target);
  body = Body(events[2]);
  assert(events[2].header.parent_event_id == events[0].header.sequence_number);
  assert(body.state == static_cast<std::uint8_t>(State::kCaptured) && body.captured_length == 816 &&
         (body.flags & reb::kRequestBodyContentCapture) != 0 &&
         events[2].header.artifact_id == 900);
  assert(artifacts.calls.size() == 1);
  const auto& call = artifacts.calls.back();
  assert(call.kind == reb::NativeArtifactKind::kRequestBody &&
         call.creator_event_id == events[2].header.sequence_number && call.request_id == 172 &&
         call.frame_id == 5 && call.mime_type == "application/json" &&
         call.url == "https://api.hcaptcha.test" + expected_target &&
         std::string(call.content.begin(), call.content.end()) == json);

  // A long target keeps its original length and is retained whole under its
  // origin; the body artifact URL stays whole.
  const std::string key(300, 'k');
  request.url = GURL("https", "api.hcaptcha.test", "/checkcaptcha/site/" + key, "", 8443);
  request.headers = {};
  events.clear();
  start();
  assert(AllValid());
  const auto long_record = Last(reb::NativeProbeType::kRequestTarget);
  const auto long_target = Target(long_record);
  assert(long_target.target_length == 19 + key.size() && long_target.port == 8443 &&
         long_target.reserved0 ==
             static_cast<std::uint8_t>(reb::RequestTargetRetention::kRetained) &&
         long_record.header.artifact_id != 0);
  const auto& full = artifacts.calls[artifacts.calls.size() - 2];
  assert(full.kind == reb::NativeArtifactKind::kRequestTarget &&
         full.creator_event_id == long_record.header.sequence_number &&
         full.url == "https://api.hcaptcha.test:8443" && full.mime_type == "text/plain" &&
         std::string(full.content.begin(), full.content.end()) == "/checkcaptcha/site/" + key);
  assert(artifacts.calls.back().url == "https://api.hcaptcha.test:8443/checkcaptcha/site/" + key);
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(body.content_type_length == 0 && (body.flags & 0x30) == 0 &&
         artifacts.calls.back().mime_type == "application/octet-stream");

  // Past 16 MiB a body keeps that prefix and its original length.
  request.headers.SetHeader("content-type", "text/plain");
  const std::vector<std::uint8_t> large(reb::kNativeRequestBodyCaptureBytes + 1000, 'x');
  request.request_body = BytesBody({large});
  events.clear();
  start();
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() && body.state == static_cast<std::uint8_t>(State::kCapturedTruncated) &&
         body.body_length == large.size() &&
         body.captured_length == reb::kNativeRequestBodyCaptureBytes &&
         (body.flags & reb::kRequestBodyDigestSizeLimit) != 0 &&
         artifacts.calls.back().content.size() == reb::kNativeRequestBodyCaptureBytes);

  // Above the 4 MiB digest bound: explicit flag, and the whole body is retained.
  const std::vector<std::uint8_t> five(5U * 1024U * 1024U, 'y');
  request.request_body = BytesBody({five});
  events.clear();
  start();
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() && (body.flags & reb::kRequestBodyDigestSizeLimit) != 0 &&
         (body.flags & reb::kRequestBodyDigestPresent) == 0 &&
         body.state == static_cast<std::uint8_t>(State::kCaptured) &&
         body.captured_length == five.size() && artifacts.calls.back().content == five);

  // File, blob, stream and mixed bodies are read once the hook hands the
  // request over; the record follows the read. An unknown part is named, not read.
  const auto calls = artifacts.Count(reb::NativeArtifactKind::kRequestBody);
  const auto kind_case = [&](network::DataElement first, Kind kind, bool with_bytes) {
    auto element_body = std::make_shared<network::ResourceRequestBody>();
    if (with_bytes) {
      element_body->elements_mutable()->emplace_back(network::DataElementBytes(Bytes("abc")));
    }
    element_body->elements_mutable()->push_back(std::move(first));
    request.request_body = element_body;
    events.clear();
    artifacts.read_calls.clear();
    start();
    if (kind == Kind::kUnknown) {
      const auto value = Body(Last(reb::NativeProbeType::kRequestBody));
      assert(AllValid() && value.state == static_cast<std::uint8_t>(State::kNotCapturedBodyKind) &&
             (value.flags & reb::kRequestBodyLengthPartial) != 0);
      return;
    }
    assert(std::none_of(events.begin(), events.end(), [](const auto& event) {
      return event.header.type == reb::NativeProbeType::kRequestBody;
    }));
    sink.TeeRequestBody(172, request);
    assert(artifacts.read_calls.size() == 1 && artifacts.read_calls[0].request_id == 172 &&
           artifacts.read_calls[0].url ==
               "https://api.hcaptcha.test:8443/checkcaptcha/site/" + key &&
           artifacts.read_calls[0].mime_type == "text/plain");
    reb::NativeRequestBodyReadOutcome outcome;
    outcome.state = reb::NativeRequestBodyState::kCaptured;
    outcome.artifact_id = 960;
    outcome.body_length = 4096;
    outcome.captured_length = 4096;
    outcome.sha256.fill(0x5a);
    const auto creator = std::move(artifacts.read_calls[0].record).Run(outcome);
    const auto& record = Last(reb::NativeProbeType::kRequestBody);
    const auto value = Body(record);
    assert(AllValid() && creator == record.header.sequence_number &&
           record.header.artifact_id == 960 &&
           record.header.parent_event_id ==
               Last(reb::NativeProbeType::kRequestStarted).header.sequence_number &&
           value.kind == static_cast<std::uint8_t>(kind) &&
           value.state == static_cast<std::uint8_t>(State::kCaptured) &&
           (value.flags & reb::kRequestBodyRead) != 0 &&
           (value.flags & reb::kRequestBodyLengthPartial) == 0 &&
           (value.flags & reb::kRequestBodyDigestPresent) != 0 && value.body_length == 4096);
  };
  kind_case(network::DataElement(network::DataElementFile{}), Kind::kFile, false);
  kind_case(network::DataElement(network::DataElementDataPipe{}), Kind::kDataPipe, false);
  kind_case(network::DataElement(network::DataElementChunkedDataPipe{}), Kind::kChunkedDataPipe,
            false);
  kind_case(network::DataElement(), Kind::kUnknown, false);
  kind_case(network::DataElement(network::DataElementFile{}), Kind::kMixed, true);
  assert(artifacts.Count(reb::NativeArtifactKind::kRequestBody) == calls);
  // A read the artifact sink refuses at the hook is recorded at once, unread.
  request.request_body = std::make_shared<network::ResourceRequestBody>();
  request.request_body->elements_mutable()->emplace_back(network::DataElementFile{});
  for (const auto [admission, state] :
       {std::pair{reb::NativeRequestContentAdmission::kSessionBudget,
                  State::kNotCapturedSessionBudget},
        std::pair{reb::NativeRequestContentAdmission::kRefused, State::kNotCapturedTransferRefused},
        std::pair{reb::NativeRequestContentAdmission::kUnavailable,
                  State::kNotCapturedArtifactUnavailable}}) {
    artifacts.read_admission = admission;
    events.clear();
    start();
    sink.TeeRequestBody(172, request);
    const auto value = Body(Last(reb::NativeProbeType::kRequestBody));
    assert(AllValid() && value.state == static_cast<std::uint8_t>(state) &&
           (value.flags & reb::kRequestBodyRead) == 0 &&
           (value.flags & reb::kRequestBodyLengthPartial) != 0);
  }
  artifacts.read_admission = reb::NativeRequestContentAdmission::kQueued;
  // A read still running at capture end is recorded incomplete; its late result is dropped.
  events.clear();
  artifacts.read_calls.clear();
  start();
  sink.TeeRequestBody(172, request);
  sink.SetEmitter(Emit, 22, mask, 200, true);
  const auto flushed = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() &&
         flushed.state == static_cast<std::uint8_t>(State::kNotCapturedReadIncomplete) &&
         (flushed.flags & reb::kRequestBodyRead) != 0);
  assert(std::move(artifacts.read_calls[0].record).Run({}) == 0);

  // Password form posts keep neither bytes nor a digest.
  request.request_body = BytesBody({Bytes("user=a&password=b")});
  request.request_body->set_contains_sensitive_info(true);
  events.clear();
  start();
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() && body.state == static_cast<std::uint8_t>(State::kNotCapturedCredentialForm) &&
         body.body_length == 17 && (body.flags & 0x06) == 0 &&
         artifacts.Count(reb::NativeArtifactKind::kRequestBody) == calls);

  // Empty, unavailable, refused and unsupported-URL outcomes are explicit.
  request.request_body = BytesBody({{}});
  events.clear();
  start();
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() && body.state == static_cast<std::uint8_t>(State::kEmpty) &&
         body.sha256 == crypto::hash::Sha256(std::string_view()));
  request.request_body = BytesBody({Bytes("payload")});
  const auto retention = [] {
    return static_cast<reb::RequestTargetRetention>(
        Target(Last(reb::NativeProbeType::kRequestTarget)).reserved0);
  };
  artifacts.enabled = false;
  events.clear();
  start();
  assert(AllValid() &&
         Body(Last(reb::NativeProbeType::kRequestBody)).state ==
             static_cast<std::uint8_t>(State::kNotCapturedArtifactUnavailable) &&
         retention() == reb::RequestTargetRetention::kNotRetainedArtifactUnavailable);
  artifacts.enabled = true;
  for (const auto [admission, state, target_retention] :
       {std::tuple{reb::NativeRequestContentAdmission::kRefused, State::kNotCapturedTransferRefused,
                   reb::RequestTargetRetention::kNotRetainedTransferRefused},
        std::tuple{reb::NativeRequestContentAdmission::kSessionBudget,
                   State::kNotCapturedSessionBudget,
                   reb::RequestTargetRetention::kNotRetainedSessionBudget},
        std::tuple{reb::NativeRequestContentAdmission::kUnavailable,
                   State::kNotCapturedArtifactUnavailable,
                   reb::RequestTargetRetention::kNotRetainedArtifactUnavailable}}) {
    artifacts.admission = admission;
    events.clear();
    start();
    assert(AllValid() &&
           Body(Last(reb::NativeProbeType::kRequestBody)).state ==
               static_cast<std::uint8_t>(state) &&
           retention() == target_retention &&
           Last(reb::NativeProbeType::kRequestTarget).header.artifact_id == 0);
  }
  artifacts.admission = reb::NativeRequestContentAdmission::kQueued;
  request.url = GURL("wss", "socket.test", "/stream");
  events.clear();
  start();
  assert(AllValid() &&
         Body(Last(reb::NativeProbeType::kRequestBody)).state ==
             static_cast<std::uint8_t>(State::kNotCapturedUrl) &&
         Target(Last(reb::NativeProbeType::kRequestTarget)).scheme ==
             static_cast<std::uint8_t>(reb::RequestScheme::kWss));
  // A body to a URL past the manifest's 8 KiB keeps its origin; its target is whole.
  const std::string long_path = "/" + std::string(reb::kNativeArtifactMaxUrlBytes, 'p');
  request.url = GURL("https", "api.test", long_path);
  events.clear();
  start();
  assert(AllValid() &&
         Body(Last(reb::NativeProbeType::kRequestBody)).state ==
             static_cast<std::uint8_t>(State::kCaptured) &&
         artifacts.calls.back().url == "https://api.test" &&
         artifacts.calls[artifacts.calls.size() - 2].content.size() == long_path.size() &&
         retention() == reb::RequestTargetRetention::kRetained);
  request.url = GURL("ftp", "files.test", long_path);
  events.clear();
  start();
  assert(AllValid() &&
         Body(Last(reb::NativeProbeType::kRequestBody)).state ==
             static_cast<std::uint8_t>(State::kNotCapturedUrl) &&
         retention() == reb::RequestTargetRetention::kNotRetainedUrl);
  request.url.valid_ = false;
  events.clear();
  start();
  assert(AllValid() && Target(Last(reb::NativeProbeType::kRequestTarget)).target_length == 0);

  // Redirects in a content session carry their new target as a child.
  net::RedirectInfo redirect;
  redirect.new_method = "GET";
  redirect.new_url = GURL("https", "accounts.hcaptcha.test", "/demo", "sitekey=site");
  network::mojom::URLResponseHead head;
  head.headers = std::make_shared<net::HttpResponseHeaders>();
  head.headers->code = 307;
  head.headers->content_encoding = "gzip";
  head.mime_type = "text/html";
  events.clear();
  sink.RecordRequestRedirected(172, 0, 0, 4, 5, 11, 12, redirect, head);
  assert(events.size() == 4 && AllValid() &&
         events[1].header.parent_event_id == events[0].header.sequence_number &&
         Target(events[1]).target_length == 18);
  // Chromium discards a redirect's body, so the hop says so instead of looking empty.
  reb::ResponseBodyPayload hop;
  assert(events[2].header.type == reb::NativeProbeType::kResponseBody &&
         events[2].header.parent_event_id == events[0].header.sequence_number &&
         events[2].header.artifact_id == 0 &&
         reb::DecodeResponseBodyPayload(events[2].inline_payload, hop) &&
         hop.state == static_cast<std::uint8_t>(reb::ResponseBodyState::kRedirected) &&
         hop.coding_count == 1 && hop.codings[0] == 1 &&
         std::string_view(hop.content_type.data(), hop.content_type_length) == "text/html" &&
         events[3].header.type == reb::NativeProbeType::kResponseHeaders);

  // The body record's parent is noted for the tee, or says the channel is down.
  auto& bodies = reb::NativeResponseBodyCapture::Get();
  bodies.noted.clear();
  events.clear();
  const auto response = sink.RecordResponseStarted(172, 0, 0, 4, 5, 11, 12, head);
  assert(events.size() == 2 && bodies.noted.size() == 1 &&
         bodies.noted[0].sequence_number == response && bodies.noted[0].tab_id == 4);
  artifacts.enabled = false;
  events.clear();
  static_cast<void>(sink.RecordResponseStarted(172, 0, 0, 4, 5, 11, 12, head));
  assert(events.size() == 3 && AllValid() && bodies.noted.size() == 1);
  reb::ResponseBodyPayload unavailable;
  assert(reb::DecodeResponseBodyPayload(events[1].inline_payload, unavailable) &&
         unavailable.state ==
             static_cast<std::uint8_t>(reb::ResponseBodyState::kNotCapturedArtifactUnavailable) &&
         events[1].header.parent_event_id == events[0].header.sequence_number);
  artifacts.enabled = true;
  events.clear();
  static_cast<void>(sink.RecordResponseStarted(172, 0, 0, 4, 5, 11, 12, head, true));
  assert(events.size() == 1 && bodies.noted.size() == 1);
  network::URLLoaderCompletionStatus aborted;
  aborted.error_code = -3;
  sink.RecordRequestCompleted(172, 0, 0, 4, 5, 11, 12, aborted);
  assert(bodies.completions.size() == 1 && bodies.completions[0].request_id == 172 &&
         bodies.completions[0].frame_id == 5 && bodies.completions[0].error_code == -3);

  // Reconfiguring without content returns to metadata-only.
  sink.SetEmitter(Emit, 22, mask, 200);
  events.clear();
  sink.RecordRequestRedirected(172, 0, 0, 4, 5, 11, 12, redirect, head);
  static_cast<void>(sink.RecordResponseStarted(172, 0, 0, 4, 5, 11, 12, head));
  sink.RecordRequestCompleted(172, 0, 0, 4, 5, 11, 12, aborted);
  start();
  assert(std::none_of(events.begin(), events.end(),
                      [](const auto& event) {
                        return event.header.type == reb::NativeProbeType::kRequestTarget ||
                               event.header.type == reb::NativeProbeType::kResponseBody;
                      }) &&
         bodies.noted.size() == 1 && bodies.completions.size() == 1);
  sink.SetEmitter(nullptr, 0, 0, 0, true);
  events.clear();
  start();
  assert(events.empty());
  std::cout << "PASS native request content: metadata-only digest/type/length, content target and "
               "body handoff, truncation, digest bound, file/blob/stream/mixed kinds, credential "
               "form, unavailable/refused/budget/URL outcomes for bodies and full targets, "
               "redirect target, redirected and unavailable response bodies, tee parent and "
               "completion hand-off\n";
}

reb::CookieListPayload Cookies(const reb::NativeProbeEvent& event) {
  reb::CookieListPayload value;
  assert(event.header.type == reb::NativeProbeType::kCookieList);
  assert(reb::DecodeCookieListPayload(event.inline_payload, value));
  return value;
}
std::uint64_t Le(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::size_t width) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i) {
    value |= static_cast<std::uint64_t>(bytes[offset + i]) << (8U * i);
  }
  return value;
}
// One decoded cookie of a list artifact: fixed fields and the six strings.
struct ListedCookie {
  std::uint64_t exclusions = 0;
  std::uint64_t warnings = 0;
  std::int64_t expiry = 0;
  std::uint8_t flags = 0, same_site = 0, priority = 0, effective = 0, scheme = 0;
  std::int32_t port = 0;
  std::array<std::string, 6> strings;
};
std::vector<ListedCookie> ParseList(const std::vector<std::uint8_t>& bytes,
                                    std::uint8_t direction) {
  assert(bytes.size() >= 16 && Text({bytes.begin(), bytes.begin() + 4}) == "RBCK" &&
         Le(bytes, 4, 2) == 1 && bytes[6] == direction && bytes[7] == 0 && Le(bytes, 12, 4) == 0);
  std::vector<ListedCookie> out(Le(bytes, 8, 4));
  std::size_t offset = 16;
  for (auto& cookie : out) {
    cookie.exclusions = Le(bytes, offset, 8);
    cookie.warnings = Le(bytes, offset + 8, 8);
    cookie.expiry = static_cast<std::int64_t>(Le(bytes, offset + 16, 8));
    cookie.flags = bytes[offset + 24];
    cookie.same_site = bytes[offset + 25];
    cookie.priority = bytes[offset + 26];
    cookie.effective = bytes[offset + 27];
    cookie.scheme = bytes[offset + 28];
    cookie.port = static_cast<std::int32_t>(Le(bytes, offset + 32, 4));
    std::size_t text = offset + 64;
    for (std::size_t i = 0; i < 6; ++i) {
      const auto length = Le(bytes, offset + 36 + 4 * i, 4);
      cookie.strings[i] = Text({bytes.begin() + static_cast<std::ptrdiff_t>(text),
                                bytes.begin() + static_cast<std::ptrdiff_t>(text + length)});
      text += length;
    }
    offset = text;
  }
  assert(offset == bytes.size());
  return out;
}

// "Cookies" in protocol/native-network-v3.md, through the production sink and hook.
void CookieLists() {
  auto& sink = reb::NativeNetworkCaptureSink::Get();
  auto& artifacts = reb::NativeArtifactCaptureSink::Get();
  const auto mask = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork);
  network::ResourceRequest request;
  request.url = GURL("https", "echo.test", "/login", "next=1");
  const auto start = [&](std::uint64_t id) {
    request.devtools_request_id.reset();
    sink.RecordRequestStarted(id, 0, 0, 4, 5, 11, 12, request);
    sink.AssignNetworkHeadersId(id, request);
  };
  net::CookieWithAccessResult session;
  session.cookie.name = "sid";
  session.cookie.value = "s3cret";
  session.cookie.domain = ".echo.test";
  session.cookie.path = "/";
  session.cookie.secure = true;
  session.cookie.http_only = true;
  session.cookie.same_site = net::CookieSameSite::LAX_MODE;
  session.cookie.priority = net::COOKIE_PRIORITY_HIGH;
  session.cookie.expiry.ms = 1700000000000;
  session.cookie.source_scheme = net::CookieSourceScheme::kSecure;
  session.cookie.source_port = 443;
  session.cookie.partition_key = net::CookiePartitionKey{{"https://top.test"}, true};
  session.access_result.effective_same_site = net::CookieEffectiveSameSite::LAX_MODE;
  net::CookieWithAccessResult strict;
  strict.cookie.name = "pref";
  strict.cookie.value = "dark";
  strict.cookie.domain = "echo.test";
  strict.cookie.path = "/settings";
  strict.cookie.same_site = net::CookieSameSite::STRICT_MODE;
  strict.access_result.status.exclusions = 1U << 5U;  // EXCLUDE_SAMESITE_STRICT
  strict.access_result.status.warnings = 1U << 0U;
  strict.access_result.effective_same_site = net::CookieEffectiveSameSite::STRICT_MODE;
  const std::vector<net::CookieWithAccessResult> sent = {session, strict};
  const reb::NativeNetworkCookies sent_cookies{.sent = &sent};
  const std::string id = "reb-00000000000002bc";

  // Metadata-only: no cookie record.
  sink.SetEmitter(Emit, 31, mask, 200);
  events.clear();
  start(700);
  reb::NotifyNativeNetworkHeaders(kRaw, id, Raw({{"cookie", "sid=s3cret"}}), sent_cookies);
  assert(CountType(reb::NativeProbeType::kCookieList) == 0);

  // A raw request's sent list joins its hop with the excluded cookie and reasons.
  sink.SetEmitter(Emit, 31, mask, 200, true);
  start(700);
  const auto started = Last(reb::NativeProbeType::kRequestStarted).header;
  events.clear();
  reb::NotifyNativeNetworkHeaders(kRaw, id, Raw({{"cookie", "sid=s3cret"}}), sent_cookies);
  const auto list = Last(reb::NativeProbeType::kCookieList);
  auto value = Cookies(list);
  assert(AllValid() && list.header.parent_event_id == started.sequence_number &&
         list.header.request_id == 700 &&
         value.direction == static_cast<std::uint8_t>(reb::CookieDirection::kSent) &&
         value.state == static_cast<std::uint8_t>(reb::HeaderState::kCaptured) &&
         value.cookie_count == 2 && value.blocked_count == 1 && value.hop == 0);
  const auto& call = artifacts.header_calls.back();
  assert(call.kind == reb::NativeArtifactKind::kCookieList &&
         call.creator_event_id == list.header.sequence_number &&
         call.url == "https://echo.test/login?next=1" && call.content.size() == value.list_length &&
         value.sha256 == crypto::hash::Sha256(Text(call.content)) &&
         list.header.artifact_id == artifacts.next_artifact_id - 1);
  auto cookies = ParseList(call.content, 1);
  assert(cookies.size() == 2);
  assert(cookies[0].exclusions == 0 && cookies[0].flags == 0x3f && cookies[0].same_site == 3 &&
         cookies[0].priority == 3 && cookies[0].effective == 2 && cookies[0].scheme == 2 &&
         cookies[0].port == 443 && cookies[0].expiry == 1700000000000 &&
         (cookies[0].strings ==
          std::array<std::string, 6>{"sid", "s3cret", ".echo.test", "/", "https://top.test", ""}));
  assert(cookies[1].exclusions == 32 && cookies[1].warnings == 1 && cookies[1].flags == 1 &&
         cookies[1].same_site == 4 && cookies[1].priority == 2 && cookies[1].effective == 3 &&
         cookies[1].port == -1 && cookies[1].expiry == 0 && cookies[1].strings[0] == "pref");

  // The received list follows on the same pipe and joins that hop; an
  // unparsed line keeps only its reasons and text.
  net::CookieAndLineWithAccessResult blocked;
  blocked.cookie = session.cookie;
  blocked.cookie->name = "track";
  blocked.cookie->partition_key.reset();
  blocked.cookie_string = "track=1; SameSite=None";
  blocked.access_result.status.exclusions = 1U << 8U;  // EXCLUDE_SAMESITE_NONE_INSECURE
  net::CookieAndLineWithAccessResult unparsed;
  unparsed.cookie_string = "bad\x01=1";
  unparsed.access_result.status.exclusions = 1U << 24U;  // EXCLUDE_DISALLOWED_CHARACTER
  const std::vector<net::CookieAndLineWithAccessResult> received = {blocked, unparsed};
  events.clear();
  reb::NotifyNativeNetworkHeaders(reb::NativeNetworkHeadersKind::kRawResponse, id,
                                  Raw({{"set-cookie", "track=1; SameSite=None"}}),
                                  {.received = &received});
  assert(events.size() == 1 && AllValid());
  value = Cookies(events[0]);
  assert(events[0].header.parent_event_id == started.sequence_number &&
         value.direction == static_cast<std::uint8_t>(reb::CookieDirection::kReceived) &&
         value.cookie_count == 2 && value.blocked_count == 2 && value.hop == 0);
  cookies = ParseList(artifacts.header_calls.back().content, 2);
  assert(cookies[0].strings[0] == "track" && cookies[0].strings[5] == "track=1; SameSite=None" &&
         cookies[0].flags == 0x27 && cookies[0].exclusions == 256);
  assert(cookies[1].flags == 0 && cookies[1].same_site == 0 && cookies[1].priority == 0 &&
         cookies[1].effective == 0 && cookies[1].port == 0 &&
         cookies[1].exclusions == (1U << 24U) &&
         (cookies[1].strings == std::array<std::string, 6>{"", "", "", "", "", "bad\x01=1"}));

  // An empty list after a redirect is recorded for hop 1, with no artifact.
  net::RedirectInfo redirect;
  redirect.new_url = GURL("https", "echo.test", "/home");
  network::mojom::URLResponseHead head;
  head.headers = std::make_shared<net::HttpResponseHeaders>();
  head.headers->code = 302;
  head.emitted_extra_info = true;
  sink.RecordRequestRedirected(700, 0, 0, 4, 5, 11, 12, redirect, head);
  const auto redirected = Last(reb::NativeProbeType::kRequestRedirected).header;
  const std::vector<net::CookieWithAccessResult> none;
  events.clear();
  reb::NotifyNativeNetworkHeaders(kRaw, id, Raw({{":path", "/home"}}), {.sent = &none});
  value = Cookies(Last(reb::NativeProbeType::kCookieList));
  assert(AllValid() &&
         Last(reb::NativeProbeType::kCookieList).header.parent_event_id ==
             redirected.sequence_number &&
         value.state == static_cast<std::uint8_t>(reb::HeaderState::kEmpty) && value.hop == 1 &&
         value.cookie_count == 0 && value.list_length == 0 &&
         Last(reb::NativeProbeType::kCookieList).header.artifact_id == 0 &&
         value.sha256 == crypto::hash::Sha256(std::string()));

  // A later request sending the same cookies shares the retained list.
  const auto calls = artifacts.header_calls.size();
  start(701);
  events.clear();
  reb::NotifyNativeNetworkHeaders(kRaw, "reb-00000000000002bd", Raw({{"cookie", "sid=s3cret"}}),
                                  sent_cookies);
  value = Cookies(Last(reb::NativeProbeType::kCookieList));
  assert(AllValid() &&
         value.state == static_cast<std::uint8_t>(reb::HeaderState::kCapturedShared) &&
         Last(reb::NativeProbeType::kCookieList).header.artifact_id == list.header.artifact_id &&
         artifacts.header_calls.size() == calls);

  // A response with no raw request yet, and one after completion, are counted.
  start(702);
  events.clear();
  reb::NotifyNativeNetworkHeaders(reb::NativeNetworkHeadersKind::kRawResponse,
                                  "reb-00000000000002be", {}, {.received = &received});
  network::URLLoaderCompletionStatus status;
  sink.RecordRequestCompleted(701, 0, 0, 4, 5, 11, 12, status);
  reb::NotifyNativeNetworkHeaders(reb::NativeNetworkHeadersKind::kRawResponse,
                                  "reb-00000000000002bd", {}, {.received = &received});
  assert(CountType(reb::NativeProbeType::kCookieList) == 0);
  reb::NotifyNativeNetworkHeaders(kRaw, "reb-00000000000002be", Raw({{"a", "b"}}), sent_cookies);
  assert(Cookies(Last(reb::NativeProbeType::kCookieList)).unattributed_lists == 2);

  // Beyond 2 MiB: counts and length only.
  std::vector<net::CookieWithAccessResult> huge(520, session);
  for (auto& item : huge) {
    item.cookie.value.assign(4000, 'v');
  }
  start(703);
  events.clear();
  reb::NotifyNativeNetworkHeaders(kRaw, "reb-00000000000002bf", Raw({{"a", "b"}}), {.sent = &huge});
  value = Cookies(Last(reb::NativeProbeType::kCookieList));
  assert(AllValid() &&
         value.state == static_cast<std::uint8_t>(reb::HeaderState::kNotCapturedBlockLimit) &&
         value.cookie_count == 520 && value.list_length > reb::kCookieListLimitBytes &&
         Last(reb::NativeProbeType::kCookieList).header.artifact_id == 0);
  sink.SetEmitter(nullptr, 0, 0, 0, true);
  std::cout << "PASS native cookie lists: metadata-only none, sent list with excluded cookie and "
               "reasons, every attribute, received list joined to its raw request's hop, "
               "unparsed line, empty redirect list, sharing, early and late lists counted, "
               "2 MiB limit\n";
}
}  // namespace
int main() {
  auto& sink = reb::NativeNetworkCaptureSink::Get();
  network::ResourceRequest request;
  auto start = [&] { sink.RecordRequestStarted(17, 9, 42, 3, 5, 11, 12, request); };
  start();
  assert(events.empty() && base::test_clock_reads == 0);
  assert(!sink.IsEnabled() && base::test_clock_reads == 0);
  content::BrowserContext owned(base::FilePath("/owned/Default"), false);
  content::BrowserContext other(base::FilePath("/other/Default"), false);
  content::BrowserContext system(base::FilePath("/owned/System Profile"), false);
  content::BrowserContext otr(base::FilePath("/owned/Default"), true);
  assert(!sink.IsOwnedContext(&owned));
  sink.SetOwnedProfilePath(base::FilePath("/owned/Default"));
  assert(sink.IsOwnedContext(&owned) && !sink.IsOwnedContext(&other));
  assert(!sink.IsOwnedContext(&system) && !sink.IsOwnedContext(&otr));
  assert(!sink.IsOwnedContext(nullptr));
  const auto mask = reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork);
  sink.SetEmitter(Emit, 22, mask, 200);
  reb::NativeNetworkLifecycle active(sink.generation());
  reb::NativeNetworkLifecycle disabled;
  assert(!disabled.IsCurrent(sink.generation()));
  start();
  const auto* started = &Last(reb::NativeProbeType::kRequestStarted);
  assert(started->header.session_id == 22 && started->header.request_id == 17);
  assert(started->header.browser_context_id_high == 11 &&
         started->header.browser_context_id_low == 12);
  assert(started->header.tab_id == 3 && started->header.frame_id == 5);
  assert(Payload(*started) == "GET fixture.test" && started->header.scheme_class == 2);
  assert(Body(events.back()).state == static_cast<std::uint8_t>(State::kNoBody) && AllValid());
  request.originated_from_service_worker = true;
  request.resource_type = -1;
  start();
  started = &Last(reb::NativeProbeType::kRequestStarted);
  assert(started->header.resource_type == 0 && (started->header.flags & 4) != 0);
  request.method.assign(200, 'A');
  start();
  started = &Last(reb::NativeProbeType::kRequestStarted);
  assert(started->header.payload_size == 128 && (started->header.flags & 1) != 0);
  net::RedirectInfo redirect;
  network::mojom::URLResponseHead head;
  head.headers = std::make_shared<net::HttpResponseHeaders>();
  head.headers->code = 302;
  sink.RecordRequestRedirected(17, 9, 42, 3, 5, 11, 12, redirect, head);
  assert(events.back().header.status_code == 302 && Payload(events.back()) == "GET fixture.test");
  head.headers->code = 200;
  head.was_fetched_via_cache = true;
  head.was_fetched_via_service_worker = true;
  assert(sink.RecordResponseStarted(17, 9, 42, 3, 5, 11, 12, head) != 0);
  assert(events.back().header.status_code == 200 && (events.back().header.flags & 6) == 6);
  assert(sink.RecordResponseStarted(17, 9, 42, 3, 5, 11, 12, head, true) != 0);
  assert(Payload(events.back()) == "synthetic_shields; text/plain");
  network::URLLoaderCompletionStatus status;
  status.error_code = -3;
  if (active.Finish(sink.generation()))
    sink.RecordRequestCompleted(17, 9, 42, 3, 5, 11, 12, status, "proxy_destroyed");
  assert(Payload(events.back()) == "proxy_destroyed" && events.back().header.error_code == -3);
  assert(events.back().header.type == reb::NativeProbeType::kRequestFailed);
  assert(!active.Finish(sink.generation()) && !active.IsCurrent(sink.generation()));
  reb::NativeNetworkLifecycle old(sink.generation());
  sink.SetEmitter(Emit, 22, mask, 200);
  assert(!old.IsCurrent(sink.generation()) && !old.Finish(sink.generation()));
  const auto before_expiry = events.size();
  base::test_now_ns = 200;
  start();
  assert(!sink.IsEnabled() && events.size() == before_expiry);
  base::test_now_ns = 100;
  sink.SetEmitter(Emit, 22, 1, 200, true);
  start();
  assert(!sink.IsEnabled() && events.size() == before_expiry);
  // Each admitted metadata-only start now produces its start and body records.
  sink.SetEmitter(Queue, 22, mask, 200);
  for (std::size_t i = 0; i < reb::kNativeProbeQueueCapacity + 7; ++i)
    start();
  assert(queue.DroppedCount() == reb::kNativeProbeQueueCapacity + 14);
  reb::NativeProbeEvent event;
  assert(queue.TryPop(event));
  const auto gap = reb::MakeNativeProbeGapEvent(event, queue.DroppedCount());
  assert(gap.header.type == reb::NativeProbeType::kGap);
  assert(reb::NativeProbeDropWeight(gap) == reb::kNativeProbeQueueCapacity + 14);
  assert(gap.header.tab_id == 0 && gap.header.request_id == 0);
  sink.SetEmitter(nullptr, 0, 0, 0);
  const auto reads = base::test_clock_reads;
  start();
  assert(base::test_clock_reads == reads);
  assert(reb::NativeRendererIssuedRequestId(2));
  assert(reb::NativeRendererIssuedRequestId(4));
  assert(reb::NativeRendererIssuedRequestId(6));
  for (const int browser_issued : {0, 1, 3, 5, 7, 8, 9}) {
    assert(!reb::NativeRendererIssuedRequestId(browser_issued));
  }
  std::cout
      << "PASS native network sink: disabled/expiry/category, owned profile, stable identity, "
         "synthetic/abort provenance, terminal-once/session rollover, truncation/queue loss\n";
  RequestContent();
  HeaderBlocks();
  CookieLists();
}
