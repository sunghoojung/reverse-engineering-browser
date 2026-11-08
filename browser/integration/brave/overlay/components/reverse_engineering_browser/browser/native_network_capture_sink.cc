// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#include "brave/components/reverse_engineering_browser/common/native_network_scope.h"
#include "content/public/browser/browser_context.h"
#include "crypto/hash.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/data_element.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "url/gurl.h"

namespace reb {

namespace {

void SetPayload(NativeProbeEvent& event,
                const std::string_view first,
                const std::string_view second = {},
                const std::string_view third = {}) noexcept {
  std::size_t written = 0;
  bool complete = true;
  for (const std::string_view value : std::array<std::string_view, 3>{first, second, third}) {
    const std::size_t available = event.inline_payload.size() - written;
    const std::size_t size = std::min(value.size(), available);
    std::transform(value.begin(), value.begin() + static_cast<std::ptrdiff_t>(size),
                   event.inline_payload.begin() + static_cast<std::ptrdiff_t>(written),
                   [](const char character) {
                     return static_cast<std::byte>(static_cast<unsigned char>(character));
                   });
    written += size;
    complete = complete && size == value.size();
  }
  event.header.payload_size = static_cast<std::uint32_t>(written);
  if (!complete) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated);
  }
}

NativeProbeEvent MakeNetworkEvent(const NativeProbeType type,
                                  const std::uint64_t sequence_number,
                                  const std::uint64_t monotonic_time_ns,
                                  const std::uint64_t session_id,
                                  const std::uint64_t request_id,
                                  const std::int32_t initiator_request_id,
                                  const std::uint32_t initiator_process_id,
                                  const std::uint32_t tab_id,
                                  const std::uint64_t frame_id,
                                  const std::uint64_t browser_context_id_high,
                                  const std::uint64_t browser_context_id_low) noexcept {
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = type;
  event.header.sequence_number = sequence_number;
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.session_id = session_id;
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.tab_id = tab_id;
  event.header.request_id = request_id;
  event.header.initiator_request_id = static_cast<std::uint32_t>(initiator_request_id);
  event.header.initiator_process_id = initiator_process_id;
  event.header.frame_id = frame_id;
  event.header.browser_context_id_high = browser_context_id_high;
  event.header.browser_context_id_low = browser_context_id_low;
  return event;
}

// A follow-up record for the same request: identical identity and time, its
// own browser sequence, and an explicit parent instead of inferred adjacency.
NativeProbeEvent MakeChildEvent(const NativeProbeType type,
                                const NativeProbeHeader& parent) noexcept {
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = type;
  event.header.sequence_number = NativeProbeSession::Get().NextBrowserSequence();
  event.header.monotonic_time_ns = parent.monotonic_time_ns;
  event.header.session_id = parent.session_id;
  event.header.process_id = parent.process_id;
  event.header.thread_id = parent.thread_id;
  event.header.tab_id = parent.tab_id;
  event.header.request_id = parent.request_id;
  event.header.initiator_request_id = parent.initiator_request_id;
  event.header.initiator_process_id = parent.initiator_process_id;
  event.header.frame_id = parent.frame_id;
  event.header.browser_context_id_high = parent.browser_context_id_high;
  event.header.browser_context_id_low = parent.browser_context_id_low;
  event.header.parent_event_id = parent.sequence_number;
  event.header.payload_size = static_cast<std::uint32_t>(kNativeRequestPayloadSize);
  return event;
}

NativeRequestScheme SchemeOf(const GURL& url) noexcept {
  return url.SchemeIs("https")  ? NativeRequestScheme::kHttps
         : url.SchemeIs("http") ? NativeRequestScheme::kHttp
         : url.SchemeIs("wss")  ? NativeRequestScheme::kWss
         : url.SchemeIs("ws")   ? NativeRequestScheme::kWs
                                : NativeRequestScheme::kOther;
}

// Path plus `?query`, never credentials or a fragment. GURL returns views into
// its own spec, so the inactive and metadata paths copy nothing here.
NativeRequestTarget TargetOf(const GURL& url) noexcept {
  NativeRequestTarget target;
  if (!url.is_valid()) {
    return target;
  }
  target.scheme = SchemeOf(url);
  const int port = url.IntPort();
  target.port = port > 0 && port <= 65535 ? static_cast<std::uint16_t>(port) : 0;
  const std::string_view path = url.path();
  const std::string_view query = url.has_query() ? url.query() : std::string_view();
  const std::size_t length = path.size() + (url.has_query() ? 1 + query.size() : 0);
  target.target_length = static_cast<std::uint32_t>(
      std::min<std::size_t>(length, std::numeric_limits<std::uint32_t>::max()));
  std::size_t written = 0;
  const auto append = [&target, &written](const std::string_view part) {
    const std::size_t size = std::min(part.size(), target.prefix.size() - written);
    std::copy_n(part.begin(), size, target.prefix.begin() + static_cast<std::ptrdiff_t>(written));
    written += size;
  };
  append(path);
  if (url.has_query()) {
    append("?");
    append(query);
  }
  return target;
}

// The URL stored with a body artifact: scheme, host, explicit port, path and
// query. Empty for schemes whose bodies are not retained.
std::string ArtifactUrlOf(const GURL& url, const NativeRequestTarget& target) {
  if (target.scheme != NativeRequestScheme::kHttp && target.scheme != NativeRequestScheme::kHttps) {
    return {};
  }
  std::string spec(target.scheme == NativeRequestScheme::kHttps ? "https://" : "http://");
  spec.append(url.host());
  if (target.port != 0) {
    spec.append(":").append(std::to_string(target.port));
  }
  spec.append(url.path());
  if (url.has_query()) {
    spec.append("?").append(url.query());
  }
  return spec;
}

NativeRequestBodyKind KindOf(const network::DataElement& element) noexcept {
  return element.TryAs<network::DataElementBytes>()      ? NativeRequestBodyKind::kBytes
         : element.TryAs<network::DataElementFile>()     ? NativeRequestBodyKind::kFile
         : element.TryAs<network::DataElementDataPipe>() ? NativeRequestBodyKind::kDataPipe
         : element.TryAs<network::DataElementChunkedDataPipe>()
             ? NativeRequestBodyKind::kChunkedDataPipe
             : NativeRequestBodyKind::kUnknown;
}

}  // namespace

NativeNetworkCaptureSink::NativeNetworkCaptureSink() = default;

NativeNetworkCaptureSink& NativeNetworkCaptureSink::Get() {
  static base::NoDestructor<NativeNetworkCaptureSink> sink;
  return *sink;
}

bool NativeNetworkCaptureSink::IsEnabled() const noexcept {
  if (emitter_.load(std::memory_order_acquire) == nullptr ||
      (category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0) {
    return false;
  }
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  return now < expires_at_monotonic_ns_.load(std::memory_order_relaxed);
}

void NativeNetworkCaptureSink::SetOwnedProfilePath(base::FilePath path) {
  owned_profile_path_ = std::move(path);
}

bool NativeNetworkCaptureSink::IsOwnedContext(content::BrowserContext* context) const {
  return context && !context->IsOffTheRecord() && !owned_profile_path_.empty() &&
         context->GetPath() == owned_profile_path_;
}

std::uint64_t NativeNetworkCaptureSink::generation() const noexcept {
  return generation_.load(std::memory_order_acquire);
}

void NativeNetworkCaptureSink::SetEmitter(const NativeProbeEmitter emitter,
                                          const std::uint64_t session_id,
                                          const std::uint64_t category_mask,
                                          const std::uint64_t expires_at_monotonic_ns,
                                          const bool capture_content) noexcept {
  emitter_.store(nullptr, std::memory_order_release);
  generation_.fetch_add(1, std::memory_order_acq_rel);
  session_id_.store(emitter ? session_id : 0, std::memory_order_relaxed);
  category_mask_.store(emitter ? category_mask : 0, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(emitter ? expires_at_monotonic_ns : 0, std::memory_order_relaxed);
  capture_content_.store(emitter && capture_content, std::memory_order_relaxed);
  request_body_count_.store(0, std::memory_order_relaxed);
  request_body_bytes_.store(0, std::memory_order_relaxed);
  emitter_.store(emitter, std::memory_order_release);
}

void NativeNetworkCaptureSink::EmitRequestTarget(const NativeProbeEmitter emitter,
                                                 const NativeProbeHeader& parent,
                                                 const GURL& url) noexcept {
  NativeProbeEvent event = MakeChildEvent(NativeProbeType::kRequestTarget, parent);
  event.inline_payload = EncodeNativeRequestTargetPayload(TargetOf(url));
  emitter(event);
}

void NativeNetworkCaptureSink::EmitRequestBody(const NativeProbeEmitter emitter,
                                               const NativeProbeHeader& parent,
                                               const network::ResourceRequest& request,
                                               const bool capture_content) noexcept {
  NativeRequestBodySummary summary;
  if (capture_content) {
    summary.flags |= kNativeRequestBodyContentCapture;
  }
  // Content-Type is the one request header this record keeps, normalized and
  // without parameters.
  if (const auto header = request.headers.GetHeaderView(net::HttpRequestHeaders::kContentType)) {
    summary.flags |=
        NormalizeNativeContentType(*header, summary.content_type, summary.content_type_length)
            ? kNativeRequestBodyContentTypePresent
            : kNativeRequestBodyContentTypeOmitted;
  }
  // The body is only described here. File, blob and stream elements are never
  // read, waited on or moved; the request continues unchanged.
  const auto* elements = request.request_body ? request.request_body->elements() : nullptr;
  bool bytes_only = elements && !elements->empty();
  if (elements) {
    for (const network::DataElement& element : *elements) {
      const NativeRequestBodyKind kind = KindOf(element);
      summary.kind =
          summary.element_count == 0 || summary.kind == kind ? kind : NativeRequestBodyKind::kMixed;
      ++summary.element_count;
      if (const auto* bytes = element.TryAs<network::DataElementBytes>()) {
        summary.body_length += bytes->bytes().size();
      } else {
        bytes_only = false;
      }
    }
  }

  NativeProbeEvent event = MakeChildEvent(NativeProbeType::kRequestBody, parent);
  if (summary.kind == NativeRequestBodyKind::kNone) {
    summary.state = NativeRequestBodyState::kNoBody;
  } else if (request.request_body->contains_sensitive_info()) {
    // Chromium marks password form posts. Neither bytes nor a digest, which
    // could confirm a guessed credential, leave the browser.
    summary.state = NativeRequestBodyState::kNotCapturedCredentialForm;
    if (!bytes_only) {
      summary.flags |= kNativeRequestBodyLengthPartial;
    }
  } else if (!bytes_only) {
    summary.flags |= kNativeRequestBodyLengthPartial;
    summary.state = capture_content ? NativeRequestBodyState::kNotCapturedBodyKind
                                    : NativeRequestBodyState::kMetadataOnly;
  } else {
    if (summary.body_length <= kNativeRequestBodyDigestBytes) {
      crypto::hash::Hasher hasher(crypto::hash::HashKind::kSha256);
      for (const network::DataElement& element : *elements) {
        hasher.Update(element.As<network::DataElementBytes>().bytes());
      }
      hasher.Finish(summary.sha256);
      summary.flags |= kNativeRequestBodyDigestPresent;
    } else {
      summary.flags |= kNativeRequestBodyDigestSizeLimit;
    }
    const std::size_t captured = static_cast<std::size_t>(
        std::min<std::uint64_t>(summary.body_length, kNativeRequestBodyCaptureBytes));
    auto& artifacts = NativeArtifactCaptureSink::Get();
    const NativeRequestTarget target =
        capture_content ? TargetOf(request.url) : NativeRequestTarget();
    if (summary.body_length == 0) {
      summary.state = NativeRequestBodyState::kEmpty;
    } else if (!capture_content) {
      summary.state = NativeRequestBodyState::kMetadataOnly;
    } else if (!artifacts.IsEnabled()) {
      summary.state = NativeRequestBodyState::kNotCapturedArtifactUnavailable;
    } else if (std::string url = ArtifactUrlOf(request.url, target);
               url.empty() || url.size() > kNativeArtifactMaxUrlBytes) {
      summary.state = NativeRequestBodyState::kNotCapturedUrl;
    } else if (request_body_count_.load(std::memory_order_relaxed) >=
                   kNativeRequestBodySessionCount ||
               captured > kNativeRequestBodySessionBytes -
                              std::min(kNativeRequestBodySessionBytes,
                                       request_body_bytes_.load(std::memory_order_relaxed))) {
      summary.state = NativeRequestBodyState::kNotCapturedSessionBudget;
    } else {
      std::vector<std::uint8_t> content;
      content.reserve(captured);
      for (const network::DataElement& element : *elements) {
        const auto& bytes = element.As<network::DataElementBytes>().bytes();
        const std::size_t size = std::min(bytes.size(), captured - content.size());
        content.insert(content.end(), bytes.begin(),
                       bytes.begin() + static_cast<std::ptrdiff_t>(size));
        if (content.size() == captured) {
          break;
        }
      }
      const std::string_view mime_type =
          summary.content_type_length != 0
              ? std::string_view(summary.content_type.data(), summary.content_type_length)
              : std::string_view("application/octet-stream");
      // The body record is the artifact's creator, so the later ACK result
      // joins this record by sequence rather than by URL.
      event.header.artifact_id = artifacts.CaptureRequestBody(
          parent.request_id, parent.frame_id, event.header.sequence_number, std::move(url),
          std::string(mime_type), std::move(content));
      if (event.header.artifact_id == 0) {
        summary.state = NativeRequestBodyState::kNotCapturedTransferRefused;
      } else {
        request_body_count_.fetch_add(1, std::memory_order_relaxed);
        request_body_bytes_.fetch_add(captured, std::memory_order_relaxed);
        summary.captured_length = captured;
        summary.state = captured == summary.body_length
                            ? NativeRequestBodyState::kCaptured
                            : NativeRequestBodyState::kCapturedTruncated;
      }
    }
  }
  event.inline_payload = EncodeNativeRequestBodyPayload(summary);
  emitter(event);
}

void NativeNetworkCaptureSink::RecordRequestStarted(const std::uint64_t request_id,
                                                    const std::int32_t initiator_request_id,
                                                    const std::uint32_t initiator_process_id,
                                                    const std::uint32_t tab_id,
                                                    const std::uint64_t frame_id,
                                                    const std::uint64_t browser_context_id_high,
                                                    const std::uint64_t browser_context_id_low,
                                                    const network::ResourceRequest& request,
                                                    const NativeLoaderKind loader_kind) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }

  NativeProbeEvent event = MakeNetworkEvent(
      NativeProbeType::kRequestStarted, NativeProbeSession::Get().NextBrowserSequence(),
      monotonic_time_ns, session_id_.load(std::memory_order_relaxed), request_id,
      initiator_request_id, initiator_process_id, tab_id, frame_id, browser_context_id_high,
      browser_context_id_low);
  event.header.resource_type =
      static_cast<std::uint16_t>(std::clamp(request.resource_type, 0, 65535));
  event.header.scheme_class = static_cast<std::uint8_t>(ClassifyNativeScheme(request.url.scheme()));
  event.header.loader_kind = static_cast<std::uint8_t>(loader_kind);
  if (request.originated_from_service_worker) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kFromServiceWorker);
  }
  SetPayload(event, request.method, " ", request.url.host());
  emitter(event);
  // Raw path and query are content; the body summary is metadata. Both follow
  // the start record as children so a dropped start cannot leave them unowned.
  const bool capture_content = capture_content_.load(std::memory_order_relaxed);
  if (capture_content) {
    EmitRequestTarget(emitter, event.header, request.url);
  }
  EmitRequestBody(emitter, event.header, request, capture_content);
}

void NativeNetworkCaptureSink::RecordRequestRedirected(
    const std::uint64_t request_id,
    const std::int32_t initiator_request_id,
    const std::uint32_t initiator_process_id,
    const std::uint32_t tab_id,
    const std::uint64_t frame_id,
    const std::uint64_t browser_context_id_high,
    const std::uint64_t browser_context_id_low,
    const net::RedirectInfo& redirect_info,
    const network::mojom::URLResponseHead& response_head) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }

  NativeProbeEvent event = MakeNetworkEvent(
      NativeProbeType::kRequestRedirected, NativeProbeSession::Get().NextBrowserSequence(),
      monotonic_time_ns, session_id_.load(std::memory_order_relaxed), request_id,
      initiator_request_id, initiator_process_id, tab_id, frame_id, browser_context_id_high,
      browser_context_id_low);
  event.header.status_code = response_head.headers ? response_head.headers->response_code() : 0;
  event.header.encoded_data_length = response_head.encoded_data_length;
  SetPayload(event, redirect_info.new_method, " ", redirect_info.new_url.host());
  emitter(event);
  if (capture_content_.load(std::memory_order_relaxed)) {
    EmitRequestTarget(emitter, event.header, redirect_info.new_url);
  }
}

std::uint64_t NativeNetworkCaptureSink::RecordResponseStarted(
    const std::uint64_t request_id,
    const std::int32_t initiator_request_id,
    const std::uint32_t initiator_process_id,
    const std::uint32_t tab_id,
    const std::uint64_t frame_id,
    const std::uint64_t browser_context_id_high,
    const std::uint64_t browser_context_id_low,
    const network::mojom::URLResponseHead& response_head,
    const bool synthetic) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return 0;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return 0;
  }

  const std::uint64_t sequence_number = NativeProbeSession::Get().NextBrowserSequence();
  NativeProbeEvent event = MakeNetworkEvent(
      NativeProbeType::kResponseStarted, sequence_number, monotonic_time_ns,
      session_id_.load(std::memory_order_relaxed), request_id, initiator_request_id,
      initiator_process_id, tab_id, frame_id, browser_context_id_high, browser_context_id_low);
  event.header.status_code = response_head.headers ? response_head.headers->response_code() : 0;
  event.header.encoded_data_length = response_head.encoded_data_length;
  if (response_head.was_fetched_via_cache) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kFromCache);
  }
  if (response_head.was_fetched_via_service_worker) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kFromServiceWorker);
  }
  if (synthetic) {
    SetPayload(event, "synthetic_shields; ", response_head.mime_type);
  } else {
    SetPayload(event, response_head.mime_type,
               "; protocol=", response_head.alpn_negotiated_protocol);
  }
  emitter(event);
  return sequence_number;
}

void NativeNetworkCaptureSink::RecordRequestCompleted(
    const std::uint64_t request_id,
    const std::int32_t initiator_request_id,
    const std::uint32_t initiator_process_id,
    const std::uint32_t tab_id,
    const std::uint64_t frame_id,
    const std::uint64_t browser_context_id_high,
    const std::uint64_t browser_context_id_low,
    const network::URLLoaderCompletionStatus& status,
    const std::string_view disposition) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) [[likely]] {
    return;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }

  NativeProbeEvent event = MakeNetworkEvent(
      status.error_code == 0 ? NativeProbeType::kRequestCompleted : NativeProbeType::kRequestFailed,
      NativeProbeSession::Get().NextBrowserSequence(), monotonic_time_ns,
      session_id_.load(std::memory_order_relaxed), request_id, initiator_request_id,
      initiator_process_id, tab_id, frame_id, browser_context_id_high, browser_context_id_low);
  event.header.error_code = status.error_code;
  event.header.encoded_data_length = status.encoded_data_length;
  event.header.decoded_body_length = status.decoded_body_length;
  SetPayload(event,
             disposition.empty() ? (status.error_code == 0 ? "completed" : "failed") : disposition);
  emitter(event);
}

}  // namespace reb
