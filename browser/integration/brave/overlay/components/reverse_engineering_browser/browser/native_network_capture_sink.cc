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
#include "brave/components/reverse_engineering_browser/common/native_network_headers.h"
#include "brave/components/reverse_engineering_browser/common/native_network_request.h"
#include "content/public/browser/browser_context.h"
#include "crypto/hash.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_access_result.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_partition_key.h"
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

constexpr std::string_view kHeaderIdPrefix = "reb-";

std::string HeaderIdOf(const std::uint64_t request_id) {
  constexpr std::string_view kHex = "0123456789abcdef";
  std::string id(kHeaderIdPrefix);
  for (int shift = 60; shift >= 0; shift -= 4) {
    id.push_back(kHex[(request_id >> shift) & 0xfU]);
  }
  return id;
}

// The request ID inside an ID this sink assigned, or 0.
std::uint64_t RequestIdOfHeaderId(const std::string_view id) noexcept {
  if (id.size() != kHeaderIdPrefix.size() + 16 || !id.starts_with(kHeaderIdPrefix)) {
    return 0;
  }
  std::uint64_t value = 0;
  for (const char c : id.substr(kHeaderIdPrefix.size())) {
    const int digit = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
    if (digit < 0) {
      return 0;
    }
    value = (value << 4U) | static_cast<std::uint64_t>(digit);
  }
  return value;
}

void ForwardNetworkHeaders(const NativeNetworkHeadersKind kind,
                           const std::string_view devtools_request_id,
                           const std::vector<network::mojom::HttpRawHeaderPairPtr>& headers,
                           const NativeNetworkCookies cookies) {
  NativeNetworkCaptureSink::Get().RecordNetworkHeaders(kind, devtools_request_id, headers, cookies);
}

std::uint8_t SameSiteCode(const net::CookieSameSite same_site) noexcept {
  switch (same_site) {
    case net::CookieSameSite::UNSPECIFIED:
      return 1;
    case net::CookieSameSite::NO_RESTRICTION:
      return 2;
    case net::CookieSameSite::LAX_MODE:
      return 3;
    case net::CookieSameSite::STRICT_MODE:
      return 4;
  }
  return 0;
}

// One cookie as the list artifact records it. Value() and the partition site
// are copies, so the entry is only valid inside visit.
template <class Visit>
void VisitCookie(const net::CanonicalCookie* const cookie,
                 const net::CookieAccessResult& access,
                 const std::string_view line,
                 Visit&& visit) {
  NativeCookieEntry entry;
  entry.exclusion_reasons = access.status.exclusion_reasons().ToEnumBitmask();
  entry.warning_reasons = access.status.warning_reasons().ToEnumBitmask();
  entry.line = line;
  std::string value;
  std::string site;
  if (cookie) {
    value = cookie->Value();
    entry.flags = static_cast<std::uint8_t>(kNativeCookieParsed |
                                            (cookie->IsHttpOnly() ? kNativeCookieHttpOnly : 0) |
                                            (cookie->SecureAttribute() ? kNativeCookieSecure : 0) |
                                            (cookie->IsDomainCookie() ? kNativeCookieDomain : 0));
    if (const auto& key = cookie->PartitionKey()) {
      site = key->site().Serialize();
      entry.flags =
          static_cast<std::uint8_t>(entry.flags | kNativeCookiePartitioned |
                                    (key->IsThirdParty() ? kNativeCookieCrossSiteAncestor : 0));
    }
    entry.same_site = SameSiteCode(cookie->SameSite());
    entry.priority = static_cast<std::uint8_t>(static_cast<int>(cookie->Priority()) + 1);
    entry.effective_same_site =
        static_cast<std::uint8_t>(static_cast<int>(access.effective_same_site) + 1);
    entry.source_scheme = static_cast<std::uint8_t>(cookie->SourceScheme());
    entry.source_port = cookie->SourcePort();
    entry.expiry_ms =
        cookie->ExpiryDate().is_null() ? 0 : cookie->ExpiryDate().InMillisecondsSinceUnixEpoch();
    entry.name = cookie->Name();
    entry.value = value;
    entry.domain = cookie->Domain();
    entry.path = cookie->Path();
    entry.partition_site = site;
  }
  visit(static_cast<const NativeCookieEntry&>(entry));
}

auto SentCookies(const std::vector<net::CookieWithAccessResult>& list) {
  return [&list](const auto& visit) {
    for (const auto& item : list) {
      VisitCookie(&item.cookie, item.access_result, {}, visit);
    }
  };
}

auto ReceivedCookies(const std::vector<net::CookieAndLineWithAccessResult>& list) {
  return [&list](const auto& visit) {
    for (const auto& item : list) {
      VisitCookie(item.cookie ? &*item.cookie : nullptr, item.access_result, item.cookie_string,
                  visit);
    }
  };
}

std::uint8_t ReferrerPolicyCode(const net::ReferrerPolicy policy) noexcept {
  return static_cast<std::uint8_t>(std::clamp(static_cast<int>(policy), 0, 7) + 1);
}

void SetRemoteEndpoint(NativeHeaderBlockSummary& summary,
                       const network::mojom::URLResponseHead& head) noexcept {
  const auto& address = head.remote_endpoint.address();
  if (!address.IsIPv4() && !address.IsIPv6()) {
    return;
  }
  summary.address_family = address.IsIPv4() ? 4 : 6;
  summary.remote_port = head.remote_endpoint.port();
  const auto& bytes = address.bytes();
  std::copy_n(bytes.data(), std::min<std::size_t>(bytes.size(), summary.remote_address.size()),
              summary.remote_address.begin());
}

// Response header lines in received order, as DevTools enumerates them.
auto ResponseLines(const net::HttpResponseHeaders& headers) {
  return [&headers](const auto& visit) {
    std::size_t iterator = 0;
    std::string name;
    std::string value;
    while (headers.EnumerateHeaderLines(&iterator, &name, &value)) {
      visit(name, value);
    }
  };
}

std::uint16_t StatusCodeOf(const net::HttpResponseHeaders& headers) noexcept {
  const int code = headers.response_code();
  return static_cast<std::uint16_t>(code >= 100 && code <= 999 ? code : 0);
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
  {
    base::AutoLock lock(header_lock_);
    tracked_headers_.clear();
    shared_header_blocks_.clear();
    header_bytes_ = 0;
    unattributed_header_blocks_ = 0;
    unattributed_cookie_lists_ = 0;
  }
  SetNativeNetworkHeadersObserver(emitter && capture_content ? &ForwardNetworkHeaders : nullptr);
  emitter_.store(emitter, std::memory_order_release);
}

template <class ForEach>
void NativeNetworkCaptureSink::EmitHeaderBlock(const NativeProbeEmitter emitter,
                                               const NativeProbeType type,
                                               const NativeProbeHeader& parent,
                                               NativeHeaderBlockSummary summary,
                                               const std::string_view url,
                                               ForEach for_each) {
  std::uint64_t length = 0;
  std::uint32_t count = 0;
  for_each([&length, &count](const std::string_view name, const std::string_view value) {
    length += name.size() + value.size() + 4;
    ++count;
  });
  summary.header_count = count;
  summary.block_length = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(length, std::numeric_limits<std::uint32_t>::max()));
  NativeProbeEvent event = MakeChildEvent(type, parent);
  if (count == 0) {
    summary.state = NativeHeaderState::kEmpty;
    crypto::hash::Hasher hasher(crypto::hash::HashKind::kSha256);
    hasher.Finish(summary.sha256);
  } else if (length > kNativeHeaderBlockLimitBytes) {
    summary.state = NativeHeaderState::kNotCapturedBlockLimit;
  } else {
    std::vector<std::uint8_t> block;
    block.reserve(static_cast<std::size_t>(length));
    for_each([&block](const std::string_view name, const std::string_view value) {
      block.insert(block.end(), name.begin(), name.end());
      block.push_back(':');
      block.push_back(' ');
      block.insert(block.end(), value.begin(), value.end());
      block.push_back('\r');
      block.push_back('\n');
    });
    crypto::hash::Hasher hasher(crypto::hash::HashKind::kSha256);
    hasher.Update(block);
    hasher.Finish(summary.sha256);
    const bool response = type == NativeProbeType::kResponseHeaders;
    summary.state = RetainBlock(
        response ? NativeArtifactKind::kResponseHeaders : NativeArtifactKind::kRequestHeaders,
        response ? 1 : 0, parent, url, std::move(block), summary.sha256, event);
  }
  summary.unattributed_blocks = unattributed_header_blocks_;
  event.inline_payload = EncodeNativeHeaderBlockPayload(summary);
  emitter(event);
}

NativeHeaderState NativeNetworkCaptureSink::RetainBlock(const NativeArtifactKind kind,
                                                        const std::uint8_t share_kind,
                                                        const NativeProbeHeader& parent,
                                                        const std::string_view url,
                                                        std::vector<std::uint8_t> block,
                                                        const std::array<std::uint8_t, 32>& sha256,
                                                        NativeProbeEvent& event) {
  std::array<std::uint8_t, 37> key{};
  key[0] = share_kind;
  for (std::size_t i = 0; i < 4; ++i) {
    key[1 + i] = static_cast<std::uint8_t>((block.size() >> (8U * i)) & 0xffU);
  }
  std::copy(sha256.begin(), sha256.end(), key.begin() + 5);
  auto& artifacts = NativeArtifactCaptureSink::Get();
  if (const auto shared = shared_header_blocks_.find(key); shared != shared_header_blocks_.end()) {
    event.header.artifact_id = shared->second;
    return NativeHeaderState::kCapturedShared;
  }
  if (!artifacts.IsEnabled()) {
    return NativeHeaderState::kNotCapturedArtifactUnavailable;
  }
  if (url.empty() || url.size() > kNativeArtifactMaxUrlBytes) {
    return NativeHeaderState::kNotCapturedUrl;
  }
  if (block.size() >
      kNativeHeaderSessionBytes - std::min(kNativeHeaderSessionBytes, header_bytes_)) {
    return NativeHeaderState::kNotCapturedSessionBudget;
  }
  const std::size_t size = block.size();
  // The record is the artifact's creator, as for request bodies.
  event.header.artifact_id = artifacts.CaptureHeaderBlock(kind, parent.request_id, parent.frame_id,
                                                          event.header.sequence_number,
                                                          std::string(url), std::move(block));
  if (event.header.artifact_id == 0) {
    return NativeHeaderState::kNotCapturedTransferRefused;
  }
  header_bytes_ += size;
  if (shared_header_blocks_.size() < kNativeHeaderShareEntries) {
    shared_header_blocks_.emplace(key, event.header.artifact_id);
  }
  return NativeHeaderState::kCaptured;
}

template <class ForEach>
void NativeNetworkCaptureSink::EmitCookieList(const NativeProbeEmitter emitter,
                                              const NativeProbeHeader& parent,
                                              NativeCookieListSummary summary,
                                              const std::string_view url,
                                              ForEach for_each) {
  std::uint64_t length = kNativeCookieListHeaderBytes;
  std::uint32_t count = 0;
  std::uint32_t blocked = 0;
  for_each([&length, &count, &blocked](const NativeCookieEntry& entry) {
    length += NativeCookieEntrySize(entry);
    ++count;
    blocked += entry.exclusion_reasons != 0 ? 1 : 0;
  });
  summary.cookie_count = count;
  summary.blocked_count = blocked;
  NativeProbeEvent event = MakeChildEvent(NativeProbeType::kCookieList, parent);
  if (count == 0) {
    summary.state = NativeHeaderState::kEmpty;
    crypto::hash::Hasher hasher(crypto::hash::HashKind::kSha256);
    hasher.Finish(summary.sha256);
  } else if (length > kNativeCookieListLimitBytes) {
    summary.list_length = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(length, std::numeric_limits<std::uint32_t>::max()));
    summary.state = NativeHeaderState::kNotCapturedBlockLimit;
  } else {
    summary.list_length = static_cast<std::uint32_t>(length);
    std::vector<std::uint8_t> list;
    list.reserve(static_cast<std::size_t>(length));
    AppendNativeCookieListHeader(list, summary.direction, count);
    for_each([&list](const NativeCookieEntry& entry) { AppendNativeCookieEntry(list, entry); });
    crypto::hash::Hasher hasher(crypto::hash::HashKind::kSha256);
    hasher.Update(list);
    hasher.Finish(summary.sha256);
    summary.state = RetainBlock(NativeArtifactKind::kCookieList,
                                summary.direction == NativeCookieDirection::kSent ? 2 : 3, parent,
                                url, std::move(list), summary.sha256, event);
  }
  summary.unattributed_lists = unattributed_cookie_lists_;
  event.inline_payload = EncodeNativeCookieListPayload(summary);
  emitter(event);
}

void NativeNetworkCaptureSink::EndHeaderHop(TrackedHeaders& tracked,
                                            const bool emitted_extra_info) {
  // Chromium follows at most 20 redirects, so at most 21 hops can wait.
  if (emitted_extra_info && !tracked.open_received && tracked.awaiting.size() < 21) {
    tracked.awaiting.push_back(tracked.open);
  }
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

void NativeNetworkCaptureSink::RecordRequestStarted(
    const std::uint64_t request_id,
    const std::int32_t initiator_request_id,
    const std::uint32_t initiator_process_id,
    const std::uint32_t tab_id,
    const std::uint64_t frame_id,
    const std::uint64_t browser_context_id_high,
    const std::uint64_t browser_context_id_low,
    const network::ResourceRequest& request) noexcept {
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
  if (!capture_content) {
    return;
  }
  // Provisional: the headers the page and browser set, before the network
  // stack adds Cookie, Host and the rest.
  std::string url = ArtifactUrlOf(request.url, TargetOf(request.url));
  NativeHeaderBlockSummary summary;
  summary.referrer_policy = ReferrerPolicyCode(request.referrer_policy);
  base::AutoLock lock(header_lock_);
  EmitHeaderBlock(emitter, NativeProbeType::kRequestHeaders, event.header, summary, url,
                  [&request](const auto& visit) {
                    for (const auto& header : request.headers.GetHeaderVector()) {
                      visit(header.key, header.value);
                    }
                    for (const auto& header : request.cors_exempt_headers.GetHeaderVector()) {
                      visit(header.key, header.value);
                    }
                  });
  if (tracked_headers_.size() < kNativeHeaderTrackedRequests ||
      tracked_headers_.contains(request_id)) {
    TrackedHeaders& tracked = tracked_headers_[request_id];
    tracked = TrackedHeaders();
    tracked.open = HeaderHop{event.header, 0, std::move(url)};
  }
}

void NativeNetworkCaptureSink::AssignNetworkHeadersId(const std::uint64_t request_id,
                                                      network::ResourceRequest& request) noexcept {
  if (!emitter_.load(std::memory_order_acquire) ||
      !capture_content_.load(std::memory_order_relaxed)) {
    return;
  }
  base::AutoLock lock(header_lock_);
  const auto tracked = tracked_headers_.find(request_id);
  if (tracked == tracked_headers_.end()) {
    return;
  }
  if (request.devtools_request_id) {
    tracked->second.devtools_id = *request.devtools_request_id;
  } else {
    request.devtools_request_id = HeaderIdOf(request_id);
  }
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
  if (!capture_content_.load(std::memory_order_relaxed)) {
    return;
  }
  EmitRequestTarget(emitter, event.header, redirect_info.new_url);
  base::AutoLock lock(header_lock_);
  const auto tracked = tracked_headers_.find(request_id);
  TrackedHeaders* const entry = tracked == tracked_headers_.end() ? nullptr : &tracked->second;
  if (response_head.headers) {
    NativeHeaderBlockSummary summary;
    summary.status_code = StatusCodeOf(*response_head.headers);
    summary.hop = entry ? entry->open.hop : 0;
    SetRemoteEndpoint(summary, response_head);
    EmitHeaderBlock(emitter, NativeProbeType::kResponseHeaders, event.header, summary,
                    entry ? std::string_view(entry->open.url) : std::string_view(),
                    ResponseLines(*response_head.headers));
  }
  if (entry) {
    EndHeaderHop(*entry, response_head.emitted_extra_info);
    entry->open = HeaderHop{event.header, entry->open.hop + 1,
                            ArtifactUrlOf(redirect_info.new_url, TargetOf(redirect_info.new_url))};
    entry->open_received = false;
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
    const bool synthetic,
    const net::HttpResponseHeaders* const network_headers) noexcept {
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
  // A Shields stub is synthetic; its headers were never received.
  if (synthetic || !capture_content_.load(std::memory_order_relaxed)) {
    return sequence_number;
  }
  // The headers the network sent, before Brave's own response-header rewrite.
  const net::HttpResponseHeaders* const headers =
      network_headers ? network_headers : response_head.headers.get();
  base::AutoLock lock(header_lock_);
  const auto tracked = tracked_headers_.find(request_id);
  TrackedHeaders* const entry = tracked == tracked_headers_.end() ? nullptr : &tracked->second;
  if (headers) {
    NativeHeaderBlockSummary summary;
    summary.status_code = StatusCodeOf(*headers);
    summary.hop = entry ? entry->open.hop : 0;
    SetRemoteEndpoint(summary, response_head);
    EmitHeaderBlock(emitter, NativeProbeType::kResponseHeaders, event.header, summary,
                    entry ? std::string_view(entry->open.url) : std::string_view(),
                    ResponseLines(*headers));
  }
  if (entry) {
    EndHeaderHop(*entry, response_head.emitted_extra_info);
  }
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
  if (capture_content_.load(std::memory_order_relaxed)) {
    base::AutoLock lock(header_lock_);
    tracked_headers_.erase(request_id);
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

void NativeNetworkCaptureSink::RecordNetworkHeaders(
    const NativeNetworkHeadersKind kind,
    const std::string_view devtools_request_id,
    const std::vector<network::mojom::HttpRawHeaderPairPtr>& headers,
    const NativeNetworkCookies cookies) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter || !capture_content_.load(std::memory_order_relaxed)) {
    return;
  }
  const std::uint64_t monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if ((category_mask_.load(std::memory_order_relaxed) &
       NativeProbeCategoryMask(NativeProbeCategory::kNetwork)) == 0 ||
      monotonic_time_ns >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }
  base::AutoLock lock(header_lock_);
  // A DevTools-owned ID is matched by value; any other unknown ID, such as a
  // CORS preflight's, is not this sink's request.
  const std::uint64_t own = RequestIdOfHeaderId(devtools_request_id);
  const auto tracked = own != 0
                           ? tracked_headers_.find(own)
                           : std::find_if(tracked_headers_.begin(), tracked_headers_.end(),
                                          [devtools_request_id](const auto& item) {
                                            return !item.second.devtools_id.empty() &&
                                                   item.second.devtools_id == devtools_request_id;
                                          });
  if (tracked == tracked_headers_.end()) {
    std::uint32_t& unattributed = kind == NativeNetworkHeadersKind::kRawResponse
                                      ? unattributed_cookie_lists_
                                      : unattributed_header_blocks_;
    if (own != 0 && unattributed != std::numeric_limits<std::uint32_t>::max()) {
      ++unattributed;
    }
    return;
  }
  TrackedHeaders& entry = tracked->second;
  if (kind == NativeNetworkHeadersKind::kRawResponse) {
    if (!entry.raw_hop) {
      if (unattributed_cookie_lists_ != std::numeric_limits<std::uint32_t>::max()) {
        ++unattributed_cookie_lists_;
      }
      return;
    }
    if (cookies.received) {
      NativeCookieListSummary summary;
      summary.direction = NativeCookieDirection::kReceived;
      summary.hop = entry.raw_hop->hop;
      EmitCookieList(emitter, entry.raw_hop->parent, summary, entry.raw_hop->url,
                     ReceivedCookies(*cookies.received));
    }
    return;
  }
  const auto lines = [&headers](const auto& visit) {
    for (const auto& header : headers) {
      if (header) {
        visit(header->key, header->value);
      }
    }
  };
  NativeHeaderBlockSummary summary;
  if (kind == NativeNetworkHeadersKind::kEarlyHints) {
    summary.source = NativeHeaderSource::kEarlyHints;
    summary.status_code = 103;
    summary.hop = entry.open.hop;
    EmitHeaderBlock(emitter, NativeProbeType::kResponseHeaders, entry.open.parent, summary,
                    entry.open.url, lines);
    return;
  }
  HeaderHop hop;
  if (!entry.awaiting.empty()) {
    hop = std::move(entry.awaiting.front());
    entry.awaiting.erase(entry.awaiting.begin());
  } else {
    hop = entry.open;
    entry.open_received = true;
  }
  summary.source = NativeHeaderSource::kNetwork;
  summary.hop = hop.hop;
  EmitHeaderBlock(emitter, NativeProbeType::kRequestHeaders, hop.parent, summary, hop.url, lines);
  if (cookies.sent) {
    NativeCookieListSummary sent;
    sent.hop = hop.hop;
    EmitCookieList(emitter, hop.parent, sent, hop.url, SentCookies(*cookies.sent));
  }
  entry.raw_hop = std::move(hop);
}

}  // namespace reb
