#include <algorithm>
#include <bit>
#include <cassert>
#include <iostream>
#include <string>
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
#include "reb/network_headers.hpp"
#include "reb/network_request.hpp"
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
  const auto start = [&] { sink.RecordRequestStarted(172, 0, 0, 4, 5, 11, 12, request); };

  // Metadata-only session: host-only start, body summary without bytes or path.
  events.clear();
  artifacts.calls.clear();
  sink.SetEmitter(Emit, 22, mask, 200);
  start();
  assert(events.size() == 2 && AllValid());
  assert(events[0].header.type == reb::NativeProbeType::kRequestStarted &&
         Payload(events[0]) == "POST api.hcaptcha.test");
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
  assert(call.creator_event_id == events[2].header.sequence_number && call.request_id == 172 &&
         call.frame_id == 5 && call.mime_type == "application/json" &&
         call.url == "https://api.hcaptcha.test" + expected_target &&
         std::string(call.content.begin(), call.content.end()) == json);

  // A long target keeps its original length; the artifact URL stays whole.
  const std::string key(300, 'k');
  request.url = GURL("https", "api.hcaptcha.test", "/checkcaptcha/site/" + key, "", 8443);
  request.headers = {};
  events.clear();
  start();
  assert(AllValid());
  const auto long_target = Target(Last(reb::NativeProbeType::kRequestTarget));
  assert(long_target.target_length == 19 + key.size() && long_target.port == 8443);
  assert(artifacts.calls.back().url == "https://api.hcaptcha.test:8443/checkcaptcha/site/" + key);
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(body.content_type_length == 0 && (body.flags & 0x30) == 0 &&
         artifacts.calls.back().mime_type == "application/octet-stream");

  // Truncation keeps the original length and full-body digest.
  request.headers.SetHeader("content-type", "text/plain");
  const std::vector<std::uint8_t> large(reb::kNativeRequestBodyCaptureBytes + 1000, 'x');
  request.request_body = BytesBody({large});
  events.clear();
  start();
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() && body.state == static_cast<std::uint8_t>(State::kCapturedTruncated) &&
         body.body_length == large.size() &&
         body.captured_length == reb::kNativeRequestBodyCaptureBytes &&
         body.sha256 == crypto::hash::Sha256(large) &&
         artifacts.calls.back().content.size() == reb::kNativeRequestBodyCaptureBytes);

  // Above the digest bound: explicit flag, still a bounded prefix.
  request.request_body =
      BytesBody({std::vector<std::uint8_t>(reb::kNativeRequestBodyDigestBytes + 1, 'y')});
  events.clear();
  start();
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() && (body.flags & reb::kRequestBodyDigestSizeLimit) != 0 &&
         (body.flags & reb::kRequestBodyDigestPresent) == 0 &&
         body.state == static_cast<std::uint8_t>(State::kCapturedTruncated));

  // File, blob, stream, unknown and mixed bodies are named, never read.
  const auto calls = artifacts.calls.size();
  const auto kind_case = [&](network::DataElement first, Kind kind, bool with_bytes) {
    auto element_body = std::make_shared<network::ResourceRequestBody>();
    if (with_bytes) {
      element_body->elements_mutable()->emplace_back(network::DataElementBytes(Bytes("abc")));
    }
    element_body->elements_mutable()->push_back(std::move(first));
    request.request_body = element_body;
    events.clear();
    start();
    const auto value = Body(Last(reb::NativeProbeType::kRequestBody));
    assert(AllValid() && value.kind == static_cast<std::uint8_t>(kind) &&
           value.state == static_cast<std::uint8_t>(State::kNotCapturedBodyKind) &&
           (value.flags & reb::kRequestBodyLengthPartial) != 0 &&
           value.body_length == (with_bytes ? 3U : 0U));
  };
  kind_case(network::DataElement(network::DataElementFile{}), Kind::kFile, false);
  kind_case(network::DataElement(network::DataElementDataPipe{}), Kind::kDataPipe, false);
  kind_case(network::DataElement(network::DataElementChunkedDataPipe{}), Kind::kChunkedDataPipe,
            false);
  kind_case(network::DataElement(), Kind::kUnknown, false);
  kind_case(network::DataElement(network::DataElementFile{}), Kind::kMixed, true);
  assert(artifacts.calls.size() == calls);

  // Password form posts keep neither bytes nor a digest.
  request.request_body = BytesBody({Bytes("user=a&password=b")});
  request.request_body->set_contains_sensitive_info(true);
  events.clear();
  start();
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() && body.state == static_cast<std::uint8_t>(State::kNotCapturedCredentialForm) &&
         body.body_length == 17 && (body.flags & 0x06) == 0 && artifacts.calls.size() == calls);

  // Empty, unavailable, refused and unsupported-URL outcomes are explicit.
  request.request_body = BytesBody({{}});
  events.clear();
  start();
  body = Body(Last(reb::NativeProbeType::kRequestBody));
  assert(AllValid() && body.state == static_cast<std::uint8_t>(State::kEmpty) &&
         body.sha256 == crypto::hash::Sha256(std::string_view()));
  request.request_body = BytesBody({Bytes("payload")});
  artifacts.enabled = false;
  events.clear();
  start();
  assert(AllValid() && Body(Last(reb::NativeProbeType::kRequestBody)).state ==
                           static_cast<std::uint8_t>(State::kNotCapturedArtifactUnavailable));
  artifacts.enabled = true;
  artifacts.refuse = true;
  events.clear();
  start();
  assert(AllValid() && Body(Last(reb::NativeProbeType::kRequestBody)).state ==
                           static_cast<std::uint8_t>(State::kNotCapturedTransferRefused));
  artifacts.refuse = false;
  request.url = GURL("wss", "socket.test", "/stream");
  events.clear();
  start();
  assert(AllValid() &&
         Body(Last(reb::NativeProbeType::kRequestBody)).state ==
             static_cast<std::uint8_t>(State::kNotCapturedUrl) &&
         Target(Last(reb::NativeProbeType::kRequestTarget)).scheme ==
             static_cast<std::uint8_t>(reb::RequestScheme::kWss));
  request.url = GURL("https", "api.test", "/" + std::string(reb::kNativeArtifactMaxUrlBytes, 'p'));
  events.clear();
  start();
  assert(AllValid() && Body(Last(reb::NativeProbeType::kRequestBody)).state ==
                           static_cast<std::uint8_t>(State::kNotCapturedUrl));
  request.url.valid_ = false;
  events.clear();
  start();
  assert(AllValid() && Target(Last(reb::NativeProbeType::kRequestTarget)).target_length == 0);

  // The per-configuration count and byte budgets end retention visibly.
  request.url = GURL("https", "api.test", "/beacon");
  sink.SetEmitter(Emit, 22, mask, 200, true);
  artifacts.calls.clear();
  for (std::size_t i = 0; i < reb::kNativeRequestBodySessionCount; ++i) {
    events.clear();
    start();
  }
  assert(artifacts.calls.size() == reb::kNativeRequestBodySessionCount);
  events.clear();
  start();
  assert(AllValid() && Body(Last(reb::NativeProbeType::kRequestBody)).state ==
                           static_cast<std::uint8_t>(State::kNotCapturedSessionBudget));
  sink.SetEmitter(Emit, 22, mask, 200, true);
  artifacts.calls.clear();
  request.request_body = BytesBody({large});
  const std::size_t byte_budget =
      reb::kNativeRequestBodySessionBytes / reb::kNativeRequestBodyCaptureBytes;
  for (std::size_t i = 0; i < byte_budget; ++i) {
    events.clear();
    start();
    artifacts.calls.clear();
  }
  events.clear();
  start();
  assert(AllValid() && Body(Last(reb::NativeProbeType::kRequestBody)).state ==
                           static_cast<std::uint8_t>(State::kNotCapturedSessionBudget));

  // Redirects in a content session carry their new target as a child.
  net::RedirectInfo redirect;
  redirect.new_method = "GET";
  redirect.new_url = GURL("https", "accounts.hcaptcha.test", "/demo", "sitekey=site");
  network::mojom::URLResponseHead head;
  head.headers = std::make_shared<net::HttpResponseHeaders>();
  head.headers->code = 307;
  events.clear();
  sink.RecordRequestRedirected(172, 0, 0, 4, 5, 11, 12, redirect, head);
  assert(events.size() == 3 && AllValid() &&
         events[1].header.parent_event_id == events[0].header.sequence_number &&
         Target(events[1]).target_length == 18 &&
         events[2].header.type == reb::NativeProbeType::kResponseHeaders);

  // Reconfiguring without content returns to metadata-only.
  sink.SetEmitter(Emit, 22, mask, 200);
  events.clear();
  sink.RecordRequestRedirected(172, 0, 0, 4, 5, 11, 12, redirect, head);
  start();
  assert(std::none_of(events.begin(), events.end(), [](const auto& event) {
    return event.header.type == reb::NativeProbeType::kRequestTarget;
  }));
  sink.SetEmitter(nullptr, 0, 0, 0, true);
  events.clear();
  start();
  assert(events.empty());
  std::cout << "PASS native request content: metadata-only digest/type/length, content target and "
               "body handoff, truncation, digest bound, file/blob/stream/mixed kinds, credential "
               "form, unavailable/refused/URL outcomes, count and byte budgets, redirect target\n";
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
  assert(Payload(*started) == "GET fixture.test");
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
}
