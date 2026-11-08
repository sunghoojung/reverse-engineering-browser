#include <algorithm>
#include <bit>
#include <cassert>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_network_lifecycle.h"
#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"
#include "brave/components/reverse_engineering_browser/common/native_request_namespace.h"
#include "chromium_stubs.h"
#include "crypto/hash.h"
#include "reb/event.hpp"
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

  // Content session: raw target, body record and one artifact handoff.
  events.clear();
  sink.SetEmitter(Emit, 22, mask, 200, true);
  start();
  assert(events.size() == 3 && AllValid());
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

  // File, blob, stream, unknown and mixed bodies are named, never read.
  const auto calls = artifacts.Count(reb::NativeArtifactKind::kRequestBody);
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
  assert(artifacts.Count(reb::NativeArtifactKind::kRequestBody) == calls);

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
  events.clear();
  sink.RecordRequestRedirected(172, 0, 0, 4, 5, 11, 12, redirect, head);
  assert(events.size() == 2 && AllValid() &&
         events[1].header.parent_event_id == events[0].header.sequence_number &&
         Target(events[1]).target_length == 18);

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
               "form, unavailable/refused/budget/URL outcomes for bodies and full targets, "
               "redirect target\n";
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
}
