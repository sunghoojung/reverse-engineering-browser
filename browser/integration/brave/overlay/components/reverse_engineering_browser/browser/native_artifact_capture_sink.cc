// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/process/process_handle.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "brave/components/reverse_engineering_browser/browser/native_response_body_capture.h"
#include "crypto/hash.h"
#include "services/network/public/cpp/data_element.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "url/gurl.h"

namespace reb {
namespace {

// NativeProbeEvent has no padding, so equal bytes mean equal records.
bool SameEventBytes(const NativeProbeEvent& left, const NativeProbeEvent& right) {
  using Bytes = std::array<std::uint8_t, sizeof(NativeProbeEvent)>;
  return std::bit_cast<Bytes>(left) == std::bit_cast<Bytes>(right);
}

constexpr std::size_t kMaxArtifactBytes = kNativeArtifactMaxContentBytes;
// Bounds the dedupe set; past it, identical content is charged again.
constexpr std::size_t kRequestContentDigestLimit = 16'384;
constexpr std::size_t kRuntimeTypedArrayMinBytes = 32;
constexpr std::size_t kRuntimeTypedArrayMaxSnapshots = 16;
constexpr std::uint64_t kExpiryFlushLeadNs = 250'000'000;
// Live guest documents bound per session across all renderers.
constexpr std::size_t kGuestBindingLimit = 16;
// Synced with blink.mojom.ResourceType.kScript. MIME classification below also
// covers module and worker script requests that use another resource type.
constexpr int kScriptResourceType = 3;

bool IsJavaScriptMimeType(const std::string_view mime_type) noexcept {
  return mime_type == "application/ecmascript" || mime_type == "application/javascript" ||
         mime_type == "application/x-ecmascript" || mime_type == "application/x-javascript" ||
         mime_type == "text/ecmascript" || mime_type == "text/javascript" ||
         mime_type == "text/javascript1.0" || mime_type == "text/javascript1.1" ||
         mime_type == "text/javascript1.2" || mime_type == "text/javascript1.3" ||
         mime_type == "text/javascript1.4" || mime_type == "text/javascript1.5" ||
         mime_type == "text/jscript" || mime_type == "text/livescript" ||
         mime_type == "text/x-ecmascript" || mime_type == "text/x-javascript";
}

NativeArtifactKind Classify(const network::ResourceRequest& request,
                            const network::mojom::URLResponseHead& response_head) {
  if (response_head.mime_type == "application/wasm") {
    return NativeArtifactKind::kWasm;
  }
  if (request.resource_type == kScriptResourceType ||
      IsJavaScriptMimeType(response_head.mime_type)) {
    return NativeArtifactKind::kJavaScript;
  }
  return NativeArtifactKind::kUnknown;
}

std::string StatusName(const NativeArtifactReceiveStatus status) {
  switch (status) {
    case NativeArtifactReceiveStatus::kAccepted:
      return "accepted";
    case NativeArtifactReceiveStatus::kEndOfStream:
      return "end_of_stream";
    case NativeArtifactReceiveStatus::kInvalid:
      return "invalid";
    case NativeArtifactReceiveStatus::kTooLarge:
      return "too_large";
    case NativeArtifactReceiveStatus::kSensitiveCaptureDisabled:
      return "sensitive_capture_disabled";
    case NativeArtifactReceiveStatus::kConflict:
      return "conflict";
    case NativeArtifactReceiveStatus::kIoError:
      return "io_error";
  }
  return "unknown";
}

}  // namespace

NativeArtifactCaptureSink& NativeArtifactCaptureSink::Get() {
  static base::NoDestructor<NativeArtifactCaptureSink> sink;
  return *sink;
}

NativeArtifactCaptureSink::NativeArtifactCaptureSink() = default;
NativeArtifactCaptureSink::~NativeArtifactCaptureSink() = default;

bool NativeArtifactCaptureSink::IsEnabled() const noexcept {
  return IsEnabledFor(NativeProbeCategory::kArtifact);
}

bool NativeArtifactCaptureSink::IsEnabledFor(const NativeProbeCategory category) const noexcept {
  if (emitter_.load(std::memory_order_acquire) == nullptr ||
      !NativeArtifactSocketClient::Get().IsConnected() ||
      (category_mask_.load(std::memory_order_relaxed) & NativeProbeCategoryMask(category)) == 0) {
    return false;
  }
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  return now < expires_at_monotonic_ns_.load(std::memory_order_relaxed);
}

void NativeArtifactCaptureSink::SetEmitter(
    const NativeProbeEmitter emitter,
    const std::uint64_t session_id,
    const std::uint64_t category_mask,
    const std::uint64_t expires_at_monotonic_ns,
    const std::uint64_t request_content_budget,
    const NativeResponseBodyPolicy& response_bodies) noexcept {
  // The ending configuration's unresolved records become gaps while its
  // session can still record them.
  if (emitter_.load(std::memory_order_acquire))
    FlushPendingWork("native_guest_pending_at_capture_end",
                     "native_wasm_dispatch_pending_at_capture_end");
  emitter_.store(nullptr, std::memory_order_release);
  generation_.fetch_add(1, std::memory_order_acq_rel);
  session_id_.store(emitter ? session_id : 0, std::memory_order_relaxed);
  category_mask_.store(emitter ? category_mask : 0, std::memory_order_relaxed);
  expires_at_monotonic_ns_.store(emitter ? expires_at_monotonic_ns : 0, std::memory_order_relaxed);
  pending_.clear();
  response_streams_.clear();
  guest_groups_.clear();
  guest_invocations_.clear();
  guest_dispatches_.clear();
  guest_receipts_.clear();
  guest_routed_host_count_ = 0;
  guest_held_host_count_ = 0;
  guest_capture_count_ = 0;
  guest_host_identities_.clear();
  guest_host_malformed_gap_emitted_ = false;
  guest_host_parent_lost_gap_emitted_ = false;
  guest_host_parent_omitted_gap_emitted_ = false;
  wasm_dispatch_modules_.clear();
  wasm_dispatch_count_ = 0;
  wasm_indirect_count_ = 0;
  wasm_sample_budget_ = {};
  if ((wasm_budget_epoch_ & 1U) == 0 &&
      wasm_budget_epoch_ <= std::numeric_limits<std::uint64_t>::max() - 2)
    wasm_budget_epoch_ += 2;
  wasm_execution_count_ = 0;
  runtime_typed_array_count_.store(0, std::memory_order_relaxed);
  allocating_scripts_.clear();
  request_content_budget_ = emitter ? request_content_budget : 0;
  request_content_used_ = 0;
  request_content_digests_.clear();
  emitter_.store(emitter, std::memory_order_release);
  NativeResponseBodyCapture::Get().Configure(emitter, session_id, category_mask,
                                             expires_at_monotonic_ns, response_bodies);
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (emitter && expires_at_monotonic_ns > now && base::SequencedTaskRunner::HasCurrentDefault()) {
    // The session refuses every record after expiry, so pending guest work is
    // turned into explicit gaps slightly earlier. The generation check makes a
    // replaced configuration's flush a no-op.
    const auto lead = std::min<std::uint64_t>(kExpiryFlushLeadNs, expires_at_monotonic_ns - now);
    const auto delay = expires_at_monotonic_ns - now - lead;
    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce([](std::uint64_t generation) { Get().FlushBeforeExpiry(generation); },
                       generation_.load(std::memory_order_acquire)),
        base::Nanoseconds(static_cast<std::int64_t>(delay)));
  }
}

mojo::ScopedDataPipeConsumerHandle NativeArtifactCaptureSink::MaybeCaptureResponse(
    const std::uint64_t request_id,
    const std::uint64_t frame_id,
    const std::uint64_t creator_event_id,
    const network::ResourceRequest& request,
    const network::mojom::URLResponseHead& response_head,
    mojo::ScopedDataPipeConsumerHandle body) {
  if (!IsEnabled()) {
    return body;
  }
  const NativeArtifactKind kind = Classify(request, response_head);
  if (kind == NativeArtifactKind::kUnknown) {
    return NativeResponseBodyCapture::Get().MaybeCapture(creator_event_id, request, response_head,
                                                         std::move(body));
  }
  if (!body.is_valid()) {
    return body;
  }

  const std::uint64_t artifact_id = next_artifact_id_.fetch_add(1, std::memory_order_relaxed);
  if (response_head.content_length > 0 &&
      static_cast<std::uint64_t>(response_head.content_length) > kMaxArtifactBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, request_id, frame_id,
               "declared_size_limit");
    return body;
  }
  std::string url = request.url.spec();
  if (url.empty() || url.size() > kNativeArtifactMaxUrlBytes || response_head.mime_type.empty() ||
      response_head.mime_type.size() > kNativeArtifactMaxMimeTypeBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, request_id, frame_id,
               "metadata_limit");
    return body;
  }
  NativeArtifactHeader header;
  header.kind = kind;
  header.session_id = session_id_.load(std::memory_order_relaxed);
  header.frame_id = frame_id;
  header.artifact_id = artifact_id;
  header.creator_event_id = creator_event_id;
  header.capture_origin = NativeArtifactCaptureOrigin::kNetworkResponse;
  // The receiver hashes scripts and Wasm; nothing is hashed on this sequence.
  NativeArtifactStream stream(memory_pool_, header, std::move(url), response_head.mime_type,
                              kMaxArtifactBytes, /*keep_prefix=*/false, /*digest=*/false);
  if (!stream.is_open()) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, request_id, frame_id,
               "transfer_queue_full_or_disconnected");
    return body;
  }
  pending_.emplace(artifact_id,
                   PendingContext{.request_id = request_id,
                                  .frame_id = frame_id,
                                  .session_id = header.session_id,
                                  .generation = generation_.load(std::memory_order_acquire),
                                  .parent_event_id = creator_event_id});
  response_streams_.emplace(
      artifact_id,
      ResponseStream{.request_id = request_id, .frame_id = frame_id, .stream = std::move(stream)});
  bool started = false;
  body = NativeArtifactBodyTee::Create(std::move(body),
                                       base::BindOnce(&NativeArtifactCaptureSink::OnBodyComplete,
                                                      base::Unretained(this), artifact_id),
                                       base::BindRepeating(&NativeArtifactCaptureSink::OnBodyData,
                                                           base::Unretained(this), artifact_id),
                                       started);
  if (!started) {
    FailResponseStream(artifact_id, "tee_unavailable");
  }
  return body;
}

void NativeArtifactCaptureSink::OnBodyData(const std::uint64_t artifact_id,
                                           const std::span<const std::uint8_t> chunk) {
  const auto found = response_streams_.find(artifact_id);
  if (found == response_streams_.end()) {
    return;
  }
  NativeArtifactStream& stream = found->second.stream;
  stream.Append(chunk);
  switch (stream.state()) {
    case NativeArtifactStreamState::kOpen:
      return;
    case NativeArtifactStreamState::kTooLarge:
      FailResponseStream(artifact_id, "body_too_large");
      return;
    case NativeArtifactStreamState::kMemoryLimit:
      FailResponseStream(artifact_id, "active_memory_limit");
      return;
    default:
      FailResponseStream(artifact_id, "transfer_queue_full_or_disconnected");
      return;
  }
}

void NativeArtifactCaptureSink::OnBodyComplete(const std::uint64_t artifact_id,
                                               const NativeArtifactBodyEnd end) {
  const auto found = response_streams_.find(artifact_id);
  if (found == response_streams_.end()) {
    // Already failed, or retired by a new configuration.
    return;
  }
  if (end != NativeArtifactBodyEnd::kSourceClosed) {
    FailResponseStream(artifact_id, "body_incomplete");
    return;
  }
  if (!IsEnabled()) {
    FailResponseStream(artifact_id, "session_inactive");
    return;
  }
  if (!found->second.stream.End()) {
    FailResponseStream(artifact_id, "transfer_queue_full_or_disconnected");
    return;
  }
  // The end ACK reports it through pending_.
  response_streams_.erase(found);
}

void NativeArtifactCaptureSink::FailResponseStream(const std::uint64_t artifact_id,
                                                   const char* const reason) {
  const auto found = response_streams_.find(artifact_id);
  if (found == response_streams_.end()) {
    return;
  }
  const ResponseStream failed = std::move(found->second);
  response_streams_.erase(found);
  pending_.erase(artifact_id);
  EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, failed.request_id,
             failed.frame_id, reason);
}

std::uint64_t NativeArtifactCaptureSink::CaptureHeaderBlock(const NativeArtifactKind kind,
                                                            const std::uint64_t request_id,
                                                            const std::uint64_t frame_id,
                                                            const std::uint64_t creator_event_id,
                                                            std::string url,
                                                            std::vector<std::uint8_t> content) {
  if ((kind != NativeArtifactKind::kRequestHeaders &&
       kind != NativeArtifactKind::kResponseHeaders && kind != NativeArtifactKind::kCookieList) ||
      !IsEnabled() || creator_event_id == 0 || content.empty() ||
      content.size() > kMaxArtifactBytes || url.empty() ||
      url.size() > kNativeArtifactMaxUrlBytes) {
    return 0;
  }
  auto reservation = NativeArtifactReservation::Acquire(memory_pool_, content.size());
  if (!reservation.is_valid()) {
    return 0;
  }
  std::string mime_type =
      kind == NativeArtifactKind::kCookieList ? "application/x-reb-cookie-list" : "text/plain";
  const std::uint64_t session_id = session_id_.load(std::memory_order_relaxed);
  const std::uint64_t artifact_id = next_artifact_id_.fetch_add(1, std::memory_order_relaxed);
  auto transfer = std::make_unique<NativeArtifactTransfer>();
  transfer->header.kind = kind;
  transfer->header.flags |= kNativeArtifactFlagSensitive;
  transfer->header.session_id = session_id;
  transfer->header.frame_id = frame_id;
  transfer->header.artifact_id = artifact_id;
  transfer->header.creator_event_id = creator_event_id;
  transfer->header.capture_origin = NativeArtifactCaptureOrigin::kNetworkRequest;
  transfer->header.content_size = content.size();
  transfer->header.url_size = static_cast<std::uint32_t>(url.size());
  transfer->header.mime_type_size = static_cast<std::uint32_t>(mime_type.size());
  transfer->url = std::move(url);
  transfer->mime_type = std::move(mime_type);
  transfer->content = std::move(content);
  transfer->reservation = std::move(reservation);
  if (!NativeArtifactSocketClient::Get().Enqueue(std::move(transfer))) {
    return 0;
  }
  pending_.emplace(artifact_id,
                   PendingContext{.request_id = request_id,
                                  .frame_id = frame_id,
                                  .session_id = session_id,
                                  .generation = generation_.load(std::memory_order_acquire),
                                  .parent_event_id = creator_event_id});
  return artifact_id;
}

NativeRequestContentAdmission NativeArtifactCaptureSink::CaptureRequestContent(
    NativeRequestContent content,
    std::uint64_t& artifact_id) {
  artifact_id = 0;
  if (!IsEnabled()) {
    return NativeRequestContentAdmission::kUnavailable;
  }
  const bool body = content.kind == NativeArtifactKind::kRequestBody;
  if ((!body && content.kind != NativeArtifactKind::kRequestTarget) ||
      content.creator_event_id == 0 || content.size == 0 || content.size > kMaxArtifactBytes ||
      (body ? !content.body : content.text.size() < content.size) || content.url.empty() ||
      content.url.size() > kNativeArtifactMaxUrlBytes || content.mime_type.empty() ||
      content.mime_type.size() > kNativeArtifactMaxMimeTypeBytes) {
    return NativeRequestContentAdmission::kRefused;
  }
  if (content.size >
      request_content_budget_ - std::min(request_content_budget_, request_content_used_)) {
    return NativeRequestContentAdmission::kSessionBudget;
  }
  auto context = std::make_unique<CaptureContext>();
  context->header.kind = content.kind;
  context->header.flags |= kNativeArtifactFlagSensitive;
  context->header.session_id = session_id_.load(std::memory_order_relaxed);
  context->header.frame_id = content.frame_id;
  context->header.artifact_id = next_artifact_id_.fetch_add(1, std::memory_order_relaxed);
  context->header.creator_event_id = content.creator_event_id;
  context->header.capture_origin = NativeArtifactCaptureOrigin::kNetworkRequest;
  context->request_id = content.request_id;
  context->frame_id = content.frame_id;
  context->generation = generation_.load(std::memory_order_acquire);
  const std::uint64_t id = context->header.artifact_id;
  // The receiver verifies the digest this stream sends with its end frame.
  NativeArtifactStream stream(memory_pool_, context->header, std::move(content.url),
                              std::move(content.mime_type), content.size,
                              /*keep_prefix=*/false, /*digest=*/true);
  if (!stream.is_open()) {
    return NativeRequestContentAdmission::kRefused;
  }
  // A started body is immutable; the reference keeps it alive for the copy.
  if (!base::ThreadPool::PostTaskAndReplyWithResult(
          FROM_HERE,
          {base::TaskPriority::USER_VISIBLE, base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
          base::BindOnce(&NativeArtifactCaptureSink::CopyRequestContent, std::move(content.body),
                         std::move(content.text), content.size, std::move(stream)),
          base::BindOnce(&NativeArtifactCaptureSink::OnRequestContentCopied, base::Unretained(this),
                         std::move(context)))) {
    return NativeRequestContentAdmission::kRefused;
  }
  request_content_used_ += content.size;
  artifact_id = id;
  return NativeRequestContentAdmission::kQueued;
}

NativeArtifactCaptureSink::CopiedContent NativeArtifactCaptureSink::CopyRequestContent(
    scoped_refptr<network::ResourceRequestBody> body,
    std::string text,
    const std::size_t size,
    NativeArtifactStream stream) {
  if (body) {
    for (const network::DataElement& element : *body->elements()) {
      const auto* bytes = element.TryAs<network::DataElementBytes>();
      if (!bytes || stream.observed() >= size) {
        break;
      }
      const auto& data = bytes->bytes();
      stream.Append(std::span(data).first(
          std::min(data.size(), size - static_cast<std::size_t>(stream.observed()))));
    }
  } else {
    stream.Append(base::as_byte_span(text).first(std::min(size, text.size())));
  }
  return {.stream = std::move(stream), .size = size};
}

void NativeArtifactCaptureSink::OnRequestContentCopied(std::unique_ptr<CaptureContext> context,
                                                       CopiedContent copied) {
  if (!IsCurrentCapture(context->header.session_id, context->generation)) {
    return;
  }
  const std::uint64_t artifact_id = context->header.artifact_id;
  const std::uint64_t creator = context->header.creator_event_id;
  const std::size_t size = copied.size;
  NativeArtifactStream& stream = copied.stream;
  const char* failure = stream.state() == NativeArtifactStreamState::kMemoryLimit
                            ? "active_memory_limit"
                        : !stream.is_open()     ? "transfer_queue_full_or_disconnected"
                        : stream.kept() != size ? "request_content_changed"
                        : !IsEnabled()          ? "session_inactive"
                                                : nullptr;
  const std::array<std::uint8_t, 32> digest = stream.Digest();
  // The receiver stores one blob per digest, so a repeat costs no budget.
  const bool charged = !request_content_digests_.contains(digest);
  if (!failure && !stream.End()) {
    failure = "transfer_queue_full_or_disconnected";
  }
  if (failure) {
    stream.Abort();
    RefundRequestContent(size);
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, context->request_id,
               context->frame_id, failure, NativeProbeCategory::kArtifact, creator);
    return;
  }
  if (!charged) {
    RefundRequestContent(size);
  } else if (request_content_digests_.size() < kRequestContentDigestLimit) {
    request_content_digests_.insert(digest);
  }
  pending_.emplace(artifact_id, PendingContext{.request_id = context->request_id,
                                               .frame_id = context->frame_id,
                                               .session_id = context->header.session_id,
                                               .generation = context->generation,
                                               .parent_event_id = creator});
}

NativeRequestContentAdmission NativeArtifactCaptureSink::ReadRequestBody(
    network::ResourceRequest& request,
    const std::uint64_t request_id,
    const std::uint64_t frame_id,
    std::string url,
    std::string mime_type,
    NativeRequestBodyRecorder record) {
  if (!IsEnabled()) {
    return NativeRequestContentAdmission::kUnavailable;
  }
  if (!request.request_body || url.empty() || url.size() > kNativeArtifactMaxUrlBytes ||
      mime_type.empty() || mime_type.size() > kNativeArtifactMaxMimeTypeBytes) {
    return NativeRequestContentAdmission::kRefused;
  }
  const std::uint64_t remaining =
      request_content_budget_ - std::min(request_content_budget_, request_content_used_);
  if (remaining == 0) {
    return NativeRequestContentAdmission::kSessionBudget;
  }
  // Charged now and settled when the read ends, so parallel reads cannot
  // together pass the budget.
  const auto allowance =
      static_cast<std::size_t>(std::min<std::uint64_t>(remaining, kMaxArtifactBytes));
  NativeArtifactHeader header;
  header.kind = NativeArtifactKind::kRequestBody;
  header.flags = kNativeArtifactFlagSensitive;
  header.session_id = session_id_.load(std::memory_order_relaxed);
  header.frame_id = frame_id;
  header.artifact_id = next_artifact_id_.fetch_add(1, std::memory_order_relaxed);
  header.capture_origin = NativeArtifactCaptureOrigin::kNetworkRequest;
  // The body record is emitted when the read ends; its end frame names it.
  NativeArtifactStream stream(memory_pool_, header, std::move(url), std::move(mime_type),
                              kMaxArtifactBytes, /*keep_prefix=*/true, /*digest=*/true);
  if (!stream.is_open()) {
    return NativeRequestContentAdmission::kRefused;
  }
  if (!NativeRequestBodyReader::Start(
          *request.request_body, std::move(stream), allowance,
          base::BindOnce(&NativeArtifactCaptureSink::OnRequestBodyRead, base::Unretained(this),
                         generation_.load(std::memory_order_acquire), request_id, frame_id,
                         allowance, std::move(record)))) {
    return NativeRequestContentAdmission::kRefused;
  }
  request_content_used_ += allowance;
  return NativeRequestContentAdmission::kQueued;
}

void NativeArtifactCaptureSink::OnRequestBodyRead(const std::uint64_t generation,
                                                  const std::uint64_t request_id,
                                                  const std::uint64_t frame_id,
                                                  const std::size_t allowance,
                                                  NativeRequestBodyRecorder record,
                                                  NativeRequestBodyReadResult result) {
  if (generation != generation_.load(std::memory_order_acquire)) {
    return;
  }
  NativeArtifactStream& stream = result.stream;
  NativeRequestBodyReadOutcome outcome;
  outcome.body_length = std::max(result.body_length, stream.observed());
  const bool complete = result.end == NativeRequestBodyReadEnd::kComplete && stream.is_open();
  if (result.end == NativeRequestBodyReadEnd::kBudget) {
    outcome.state = NativeRequestBodyState::kNotCapturedSessionBudget;
  } else if (result.end == NativeRequestBodyReadEnd::kRefused ||
             stream.state() == NativeArtifactStreamState::kMemoryLimit ||
             stream.state() == NativeArtifactStreamState::kRefused) {
    outcome.state = NativeRequestBodyState::kNotCapturedTransferRefused;
  } else if (!complete) {
    outcome.state = NativeRequestBodyState::kNotCapturedReadIncomplete;
  } else if (stream.kept() == 0) {
    outcome.state = NativeRequestBodyState::kEmpty;
    outcome.sha256 = stream.Digest();
  } else {
    // The reader stops offering bytes at the cap, so a body that lands exactly
    // on it never reaches the stream's own truncation check.
    const bool truncated = stream.truncated() || outcome.body_length > stream.kept();
    outcome.state = truncated ? NativeRequestBodyState::kCapturedTruncated
                              : NativeRequestBodyState::kCaptured;
    outcome.artifact_id = stream.artifact_id();
    outcome.captured_length = stream.kept();
    if (!truncated) {
      outcome.sha256 = stream.Digest();
    }
  }
  const std::array<std::uint8_t, 32> digest = stream.Digest();
  const bool charged = outcome.artifact_id != 0 && !request_content_digests_.contains(digest);
  RefundRequestContent(allowance - (charged ? static_cast<std::size_t>(stream.kept()) : 0));
  if (charged && request_content_digests_.size() < kRequestContentDigestLimit) {
    request_content_digests_.insert(digest);
  }
  const std::uint64_t artifact_id = outcome.artifact_id;
  if (artifact_id == 0) {
    stream.Abort();
    std::move(record).Run(outcome);
    return;
  }
  const std::uint64_t creator = std::move(record).Run(outcome);
  if (creator == 0 || !stream.End(creator)) {
    // A record that names an artifact the receiver never got is followed by
    // its failure.
    stream.Abort();
    if (creator != 0) {
      EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, request_id, frame_id,
                 "transfer_queue_full_or_disconnected", NativeProbeCategory::kArtifact, creator);
    }
    return;
  }
  pending_.emplace(artifact_id,
                   PendingContext{.request_id = request_id,
                                  .frame_id = frame_id,
                                  .session_id = session_id_.load(std::memory_order_relaxed),
                                  .generation = generation,
                                  .parent_event_id = creator});
}

void NativeArtifactCaptureSink::RefundRequestContent(const std::size_t bytes) noexcept {
  request_content_used_ -= std::min<std::uint64_t>(request_content_used_, bytes);
}

void NativeArtifactCaptureSink::CaptureRuntimeTypedArray(const int renderer_process_id,
                                                         const std::uint64_t capture_session_id,
                                                         const std::uint64_t script_id,
                                                         const bool is_eval,
                                                         const std::uint64_t creator_event_id,
                                                         const std::uint64_t execution_context_id,
                                                         const std::uint64_t frame_id,
                                                         const std::string_view source_url,
                                                         mojo_base::BigBuffer script_source,
                                                         mojo_base::BigBuffer content) {
  if (!IsEnabledFor(NativeProbeCategory::kVm) || capture_session_id == 0 ||
      capture_session_id != session_id_.load(std::memory_order_relaxed)) {
    return;
  }
  if (script_id == 0 || execution_context_id == 0 || script_source.size() > kMaxArtifactBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, 0, 0, frame_id,
               "allocating_script_unavailable", NativeProbeCategory::kVm);
    return;
  }
  const ScriptKey key{renderer_process_id, execution_context_id, frame_id, script_id};
  auto parent = allocating_scripts_.find(key);
  if (parent == allocating_scripts_.end()) {
    if (script_source.size() == 0) {
      EmitResult(NativeProbeType::kArtifactCaptureFailed, 0, 0, frame_id,
                 "allocating_script_unavailable", NativeProbeCategory::kVm);
      return;
    }
    if (allocating_scripts_.size() >= kRuntimeTypedArrayMaxSnapshots) {
      EmitResult(NativeProbeType::kArtifactCaptureFailed, 0, 0, frame_id,
                 "allocating_script_registry_limit", NativeProbeCategory::kVm);
      return;
    }
    // Eval source uses the same exact-script capture path. is_eval is kept on
    // the submission for admission; it never changes the identity relation.
    static_cast<void>(is_eval);
    const std::uint64_t artifact_id = CaptureGeneratedArtifact(
        NativeArtifactKind::kJavaScript, NativeArtifactCaptureOrigin::kRuntimeAllocatingScript, 0,
        execution_context_id, frame_id, source_url, std::move(script_source));
    if (artifact_id == 0) {
      EmitResult(NativeProbeType::kArtifactCaptureFailed, 0, 0, frame_id,
                 "allocating_script_unavailable", NativeProbeCategory::kVm);
      return;
    }
    parent = allocating_scripts_.emplace(key, artifact_id).first;
  }
  CaptureGeneratedArtifact(NativeArtifactKind::kBytecodeBuffer,
                           NativeArtifactCaptureOrigin::kRuntimeTypedArray, creator_event_id,
                           execution_context_id, frame_id, source_url, std::move(content),
                           parent->second);
}

namespace {
std::uint64_t GuestField(const NativeProbeEvent& event, std::size_t offset, std::size_t width = 8) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i)
    value |= std::to_integer<std::uint64_t>(event.inline_payload[offset + i]) << (i * 8U);
  return value;
}
// The renderer writes dispatch payload version 1 and invocation version 3.
bool GuestEnvelope(const NativeProbeEvent& event, std::uint64_t payload_version) {
  const auto& h = event.header;
  return h.protocol_version == kNativeProbeProtocolVersion && h.header_size == sizeof(h) &&
         h.category == NativeProbeCategory::kVm && h.payload_size == 128 && h.flags == 0 &&
         h.loader_kind == 0 && h.session_id && h.process_id && h.thread_id && h.frame_id &&
         h.sequence_number && h.monotonic_time_ns && h.artifact_id == 0 && h.navigation_id == 0 &&
         GuestField(event, 0, 2) == payload_version && GuestField(event, 2, 2) == 128 &&
         std::all_of(event.reserved.begin(), event.reserved.end(),
                     [](auto b) { return b == std::byte{0}; });
}
bool GuestSameScope(const NativeProbeEvent& a, const NativeProbeEvent& b) {
  return a.header.session_id == b.header.session_id && a.header.process_id == b.header.process_id &&
         a.header.thread_id == b.header.thread_id && a.header.frame_id == b.header.frame_id &&
         a.header.navigation_id == b.header.navigation_id;
}
}  // namespace

void NativeArtifactCaptureSink::EmitRendererGap(const NativeProbeEvent& source,
                                                const std::string_view reason) noexcept {
  const auto emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter)
    return;
  if (!source.header.sequence_number || !source.header.process_id) {
    EmitResult(NativeProbeType::kGap, 0, 0, source.header.frame_id, std::string(reason),
               NativeProbeCategory::kVm);
    return;
  }
  NativeProbeEvent gap;
  gap.header.category = NativeProbeCategory::kVm;
  gap.header.type = NativeProbeType::kGap;
  gap.header.session_id = source.header.session_id;
  gap.header.process_id = source.header.process_id;
  gap.header.thread_id = source.header.thread_id;
  gap.header.frame_id = source.header.frame_id;
  gap.header.tab_id = source.header.tab_id;
  gap.header.sequence_number = source.header.sequence_number;
  gap.header.monotonic_time_ns = source.header.monotonic_time_ns;
  const auto size = std::min(reason.size(), gap.inline_payload.size());
  for (std::size_t i = 0; i < size; ++i)
    gap.inline_payload[i] = static_cast<std::byte>(static_cast<unsigned char>(reason[i]));
  gap.header.payload_size = static_cast<std::uint32_t>(size);
  emitter(gap);
}

void NativeArtifactCaptureSink::PublishUnparentedHost(NativeProbeEvent host,
                                                      bool& gap_emitted,
                                                      const std::string_view reason) {
  const auto emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter)
    return;
  host.header.parent_event_id = 0;
  host.header.artifact_id = 0;
  emitter(host);
  if (!gap_emitted) {
    gap_emitted = true;
    EmitResult(NativeProbeType::kGap, 0, 0, host.header.frame_id, std::string(reason),
               NativeProbeCategory::kVm);
  }
}

void NativeArtifactCaptureSink::CaptureNativeGuest(const NativeGuestCapture& capture,
                                                   const std::uint64_t epoch,
                                                   std::function<bool()> is_current_document,
                                                   std::function<void(bool)> module_status) {
  DrainGuestDependencies();
  const auto& dispatch = capture.dispatch;
  const auto& invocation = capture.invocation;
  const bool carries_module = !capture.module_bytes.empty();
  // Every refusal fills the dispatch's renderer sequence slot with an explicit
  // gap, and a refused module transfer lets the renderer resend those bytes.
  const auto refuse = [&](std::string_view reason) {
    EmitRendererGap(dispatch, reason);
    if (carries_module && module_status)
      module_status(false);
  };
  if (!emitter_.load(std::memory_order_acquire) ||
      dispatch.header.session_id != session_id_.load(std::memory_order_relaxed))
    return;
  if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled()) {
    refuse("native_guest_artifact_unavailable");
    return;
  }
  if (guest_capture_count_ >= kNativeGuestSampleLimit) {
    refuse("native_guest_browser_sample_budget");
    return;
  }
  ++guest_capture_count_;
  if (!epoch || !is_current_document || !is_current_document() || !GuestEnvelope(dispatch, 1) ||
      !GuestEnvelope(invocation, 3) || !GuestSameScope(dispatch, invocation) ||
      dispatch.header.type != NativeProbeType::kWasmGuestDispatch ||
      invocation.header.type != NativeProbeType::kWasmGuestInvocation ||
      invocation.header.parent_event_id ||
      dispatch.header.parent_event_id != invocation.header.sequence_number ||
      dispatch.header.sequence_number <= invocation.header.sequence_number ||
      !capture.execution_context_id ||
      !(capture.document_token_high || capture.document_token_low) ||
      (carries_module && capture.module_bytes.size() < 8) ||
      capture.module_bytes.size() > kMaxArtifactBytes || capture.adapter_json.empty() ||
      capture.adapter_json.size() > kNativeGuestAdapterLimit || capture.bytecode_bytes.empty() ||
      capture.bytecode_bytes.size() > kNativeGuestSnapshotLimit || capture.source_url.empty() ||
      capture.source_url.size() > kNativeArtifactMaxUrlBytes ||
      GuestField(dispatch, 72, 4) != capture.bytecode_bytes.size() ||
      GuestField(dispatch, 40) >= capture.bytecode_bytes.size() || GuestField(dispatch, 56) ||
      !GuestField(dispatch, 24) || !GuestField(dispatch, 32) ||
      GuestField(dispatch, 24) != GuestField(invocation, 8) ||
      GuestField(dispatch, 32) != GuestField(invocation, 16) ||
      GuestField(dispatch, 4, 4) != GuestField(invocation, 4, 4) || GuestField(invocation, 24) ||
      GuestField(dispatch, 20, 4) >= kNativeGuestSampleLimit ||
      // A parent is another activation; its exact dispatch names it and
      // precedes this marker. The browser does not retarget a lost parent.
      GuestField(invocation, 64) == GuestField(invocation, 16) ||
      (GuestField(invocation, 72) &&
       (!GuestField(invocation, 64) ||
        GuestField(invocation, 72) >= invocation.header.sequence_number)) ||
      // The host checked the named site against the adapter; it is bounded here.
      GuestField(invocation, 80, 4) >= kNativeGuestSiteLimit ||
      !std::all_of(invocation.inline_payload.begin() + 84, invocation.inline_payload.end(),
                   [](auto b) { return b == std::byte{0}; })) {
    refuse("native_guest_dependency_rejected");
    return;
  }
  const GuestEventKey key{dispatch.header.process_id, dispatch.header.sequence_number};
  if (guest_dispatches_.contains(key) || guest_invocations_.contains(key) ||
      guest_dispatches_.contains(
          {invocation.header.process_id, invocation.header.sequence_number}) ||
      guest_dispatches_.size() >= kNativeGuestSampleLimit) {
    refuse("native_guest_dependency_rejected");
    return;
  }
  const auto module_digest = NativeGuestDigest(capture.module_bytes);
  const auto recipe_bytes =
      std::span(reinterpret_cast<const std::uint8_t*>(capture.adapter_json.data()),
                capture.adapter_json.size());
  const auto recipe_digest = NativeGuestDigest(recipe_bytes);
  for (std::size_t i = 0; i < recipe_digest.size(); ++i) {
    if (dispatch.inline_payload[96 + i] != static_cast<std::byte>(recipe_digest[i]) ||
        invocation.inline_payload[32 + i] != static_cast<std::byte>(recipe_digest[i])) {
      refuse("native_guest_dependency_rejected");
      return;
    }
  }
  GuestGroup* group = nullptr;
  for (auto& candidate : guest_groups_) {
    if (candidate.epoch == epoch && candidate.process_id == dispatch.header.process_id &&
        candidate.document_high == capture.document_token_high &&
        candidate.document_low == capture.document_token_low &&
        candidate.context_id == capture.execution_context_id &&
        candidate.frame_id == dispatch.header.frame_id &&
        candidate.recipe_digest == recipe_digest) {
      group = &candidate;
      break;
    }
  }
  if (!group) {
    if (!carries_module) {
      refuse("native_guest_module_unbound");
      return;
    }
    if (guest_groups_.size() >= kGuestBindingLimit)
      ReclaimGuestGroups();
    if (guest_groups_.size() >= kGuestBindingLimit) {
      refuse("native_guest_document_limit");
      return;
    }
    GuestGroup created;
    created.epoch = epoch;
    created.process_id = dispatch.header.process_id;
    created.document_high = capture.document_token_high;
    created.document_low = capture.document_token_low;
    created.context_id = capture.execution_context_id;
    created.frame_id = dispatch.header.frame_id;
    created.recipe_digest = recipe_digest;
    created.current_document = is_current_document;
    guest_groups_.push_back(std::move(created));
    group = &guest_groups_.back();
  }
  if (group->binding == GuestBinding::kUnbound || group->binding == GuestBinding::kRejected) {
    // Only freshly sent module bytes bind, or revive a rejected binding.
    if (!carries_module || group->attempts >= kNativeGuestModuleAttemptLimit) {
      refuse(carries_module                             ? "native_guest_module_unavailable"
             : group->binding == GuestBinding::kUnbound ? "native_guest_module_unbound"
                                                        : "native_guest_module_lost");
      return;
    }
    ++group->attempts;
    group->binding = GuestBinding::kPending;
    group->module_digest = module_digest;
    const auto transfer_binding = [&](NativeArtifactKind kind, NativeArtifactCaptureOrigin origin,
                                      std::span<const std::uint8_t> bytes, std::uint64_t parent,
                                      std::uint64_t creator) {
      const auto id = CaptureGeneratedArtifactInternal(
          kind, origin, creator, capture.execution_context_id, dispatch.header.frame_id,
          capture.source_url, mojo_base::BigBuffer(bytes), parent, true);
      if (id)
        guest_receipts_.emplace(id, GuestReceipt::kPending);
      return id;
    };
    group->module_id =
        transfer_binding(NativeArtifactKind::kWasm, NativeArtifactCaptureOrigin::kUnknown,
                         capture.module_bytes, 0, 0);
    group->adapter_id =
        group->module_id
            ? transfer_binding(NativeArtifactKind::kWasmGuestAdapter,
                               NativeArtifactCaptureOrigin::kNativeWasmGuest, recipe_bytes,
                               group->module_id, invocation.header.sequence_number)
            : 0;
    if (!group->adapter_id) {
      group->binding = GuestBinding::kRejected;
      refuse("native_guest_module_unavailable");
      return;
    }
    if (module_status)
      group->status_waiters.push_back(std::move(module_status));
  } else if (carries_module) {
    // The renderer resent bytes before it observed this binding's verdict.
    if (group->module_digest != module_digest) {
      refuse("native_guest_dependency_rejected");
      return;
    }
    if (module_status) {
      if (group->binding == GuestBinding::kAccepted)
        module_status(true);
      else
        group->status_waiters.push_back(std::move(module_status));
    }
  }
  const GuestEventKey invocation_key{invocation.header.process_id,
                                     invocation.header.sequence_number};
  auto canonical_invocation = invocation;
  canonical_invocation.header.artifact_id = group->module_id;
  NativeGuestPut(canonical_invocation.inline_payload, 24, group->adapter_id, 8);
  if (auto prior = guest_invocations_.find(invocation_key); prior != guest_invocations_.end()) {
    // An unpublished invocation may move to a retried module binding.
    if (!prior->second.published && prior->second.module_id != group->module_id) {
      prior->second = GuestInvocation{canonical_invocation, group->module_id, group->adapter_id,
                                      is_current_document, false};
    } else if (prior->second.module_id != group->module_id ||
               !SameEventBytes(prior->second.event, canonical_invocation)) {
      refuse("native_guest_dependency_rejected");
      return;
    }
  } else {
    guest_invocations_.emplace(
        invocation_key, GuestInvocation{canonical_invocation, group->module_id, group->adapter_id,
                                        is_current_document, false});
  }
  const auto bytecode_id = CaptureGeneratedArtifactInternal(
      NativeArtifactKind::kBytecodeBuffer, NativeArtifactCaptureOrigin::kNativeWasmGuest,
      dispatch.header.sequence_number, capture.execution_context_id, dispatch.header.frame_id,
      capture.source_url, mojo_base::BigBuffer(capture.bytecode_bytes), group->module_id, true);
  if (!bytecode_id) {
    EmitRendererGap(dispatch, "native_guest_snapshot_unavailable");
    return;
  }
  guest_receipts_.emplace(bytecode_id, GuestReceipt::kPending);
  GuestDispatch pending;
  pending.event = dispatch;
  pending.event.header.artifact_id = group->module_id;
  NativeGuestPut(pending.event.inline_payload, 56, bytecode_id, 8);
  pending.invocation = invocation_key;
  pending.epoch = epoch;
  pending.module_id = group->module_id;
  pending.adapter_id = group->adapter_id;
  pending.bytecode_id = bytecode_id;
  pending.current_document = std::move(is_current_document);
  guest_dispatches_.emplace(key, std::move(pending));
  DrainGuestDependencies();
}

void NativeArtifactCaptureSink::CaptureNativeGuestHost(const NativeProbeEvent& event,
                                                       const std::uint64_t epoch) {
  DrainGuestDependencies();
  if (!emitter_.load(std::memory_order_acquire) ||
      event.header.session_id != session_id_.load(std::memory_order_relaxed))
    return;
  const auto& h = event.header;
  if (h.protocol_version != kNativeProbeProtocolVersion ||
      h.header_size != sizeof(NativeProbeHeader) || h.flags || h.loader_kind || h.artifact_id ||
      !h.parent_event_id || !h.sequence_number || !h.monotonic_time_ns ||
      h.payload_size > kNativeProbeInlinePayloadSize ||
      !std::all_of(event.reserved.begin(), event.reserved.end(),
                   [](auto b) { return b == std::byte{0}; }) ||
      (h.type != NativeProbeType::kApiCall && h.type != NativeProbeType::kPropertyRead) ||
      h.category == NativeProbeCategory::kVm || h.category == NativeProbeCategory::kArtifact ||
      h.category == NativeProbeCategory::kUnknown) {
    if (h.sequence_number && h.process_id)
      EmitRendererGap(event, "native_guest_host_malformed");
    else if (!guest_host_malformed_gap_emitted_) {
      guest_host_malformed_gap_emitted_ = true;
      EmitResult(NativeProbeType::kGap, 0, 0, h.frame_id, "native_guest_host_malformed",
                 NativeProbeCategory::kVm);
    }
    return;
  }
  if (!IsEnabled() || !IsEnabledFor(h.category)) {
    // Without the artifact channel no parent can be published; the session
    // still decides whether the host itself is recordable.
    PublishUnparentedHost(event, guest_host_parent_lost_gap_emitted_,
                          "native_guest_host_parent_lost");
    return;
  }
  const GuestEventKey identity{h.process_id, h.sequence_number};
  if (guest_host_identities_.contains(identity) || guest_dispatches_.contains(identity) ||
      guest_invocations_.contains(identity))
    return;  // A replayed record is not new evidence.
  if (guest_routed_host_count_ >= kNativeGuestHostParentLimit) {
    PublishUnparentedHost(event, guest_host_parent_omitted_gap_emitted_,
                          "native_guest_host_parent_omitted");
    return;
  }
  ++guest_routed_host_count_;
  guest_host_identities_.insert(identity);
  const auto found = guest_dispatches_.find({h.process_id, h.parent_event_id});
  if (found == guest_dispatches_.end() || found->second.failed || epoch != found->second.epoch ||
      !found->second.current_document || !found->second.current_document() ||
      !GuestSameScope(event, found->second.event) ||
      h.sequence_number <= found->second.event.header.sequence_number ||
      h.monotonic_time_ns < found->second.event.header.monotonic_time_ns) {
    // Lost parents are never retargeted; the host itself is still evidence.
    PublishUnparentedHost(event, guest_host_parent_lost_gap_emitted_,
                          "native_guest_host_parent_lost");
    return;
  }
  auto& dispatch = found->second;
  auto host = event;
  host.header.artifact_id = dispatch.module_id;
  host.header.tab_id = dispatch.event.header.tab_id;
  if (dispatch.published) {
    if (const auto emitter = emitter_.load(std::memory_order_acquire))
      emitter(host);
    return;
  }
  if (guest_held_host_count_ >= kNativeGuestHeldHostLimit) {
    PublishUnparentedHost(event, guest_host_parent_omitted_gap_emitted_,
                          "native_guest_host_parent_omitted");
    return;
  }
  dispatch.hosts.push_back(host);
  ++guest_held_host_count_;
}

void NativeArtifactCaptureSink::DrainGuestDependencies() {
  const auto now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (now >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    // FlushBeforeExpiry already reported this work while the session could
    // still record it; nothing can be published after expiry.
    guest_dispatches_.clear();
    guest_invocations_.clear();
    guest_receipts_.clear();
    guest_groups_.clear();
    guest_held_host_count_ = 0;
    return;
  }
  if (!IsEnabled() || !IsEnabledFor(NativeProbeCategory::kVm))
    return;
  const auto emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter)
    return;
  const auto receipt = [&](std::uint64_t id) {
    const auto found = guest_receipts_.find(id);
    return found == guest_receipts_.end() ? GuestReceipt::kRejected : found->second;
  };
  const auto accepted = [&](std::uint64_t id) { return receipt(id) == GuestReceipt::kAccepted; };
  const auto rejected = [&](std::uint64_t id) { return receipt(id) == GuestReceipt::kRejected; };
  for (auto& group : guest_groups_) {
    if (group.binding != GuestBinding::kPending)
      continue;
    const bool lost = rejected(group.module_id) || rejected(group.adapter_id);
    const bool bound = accepted(group.module_id) && accepted(group.adapter_id);
    if (!lost && !bound)
      continue;
    group.binding = bound ? GuestBinding::kAccepted : GuestBinding::kRejected;
    auto waiters = std::move(group.status_waiters);
    group.status_waiters.clear();
    for (auto& waiter : waiters)
      waiter(bound);
  }
  // Invocation is observed independently of successful bytecode capture.
  // Retain the first invocation that created a shared adapter artifact.
  for (auto& [identity, invocation] : guest_invocations_) {
    static_cast<void>(identity);
    if (!invocation.published && invocation.current_document && invocation.current_document() &&
        accepted(invocation.module_id) && accepted(invocation.adapter_id)) {
      emitter(invocation.event);
      invocation.published = true;
    }
  }
  for (auto& [key, pending] : guest_dispatches_) {
    static_cast<void>(key);
    if (pending.failed || pending.published)
      continue;
    if (!pending.current_document || !pending.current_document() || rejected(pending.module_id) ||
        rejected(pending.adapter_id) || rejected(pending.bytecode_id)) {
      pending.failed = true;
      EmitRendererGap(pending.event, "native_guest_dependency_lost");
      for (const auto& host : pending.hosts)
        PublishUnparentedHost(host, guest_host_parent_lost_gap_emitted_,
                              "native_guest_host_parent_lost");
      guest_held_host_count_ -= pending.hosts.size();
      pending.hosts.clear();
      continue;
    }
    if (!accepted(pending.module_id) || !accepted(pending.adapter_id) ||
        !accepted(pending.bytecode_id))
      continue;
    auto& invocation = guest_invocations_.at(pending.invocation);
    if (!invocation.published) {
      emitter(invocation.event);
      invocation.published = true;
    }
    emitter(pending.event);
    pending.published = true;
    for (const auto& host : pending.hosts)
      emitter(host);
    guest_held_host_count_ -= pending.hosts.size();
    pending.hosts.clear();
  }
}

void NativeArtifactCaptureSink::ReclaimGuestGroups() {
  std::vector<std::function<void(bool)>> waiters;
  std::erase_if(guest_groups_, [&](GuestGroup& group) {
    if (group.current_document && group.current_document())
      return false;
    std::move(group.status_waiters.begin(), group.status_waiters.end(),
              std::back_inserter(waiters));
    return true;
  });
  // Dispatches bound to a reclaimed group keep their artifact IDs and are
  // settled by DrainGuestDependencies, which sees the same lost document.
  for (auto& waiter : waiters)
    waiter(false);
}

void NativeArtifactCaptureSink::FlushBeforeExpiry(const std::uint64_t generation) {
  if (generation != generation_.load(std::memory_order_acquire))
    return;
  DrainGuestDependencies();
  FlushPendingWork("native_guest_pending_at_expiry", "native_wasm_dispatch_pending_at_expiry");
}

void NativeArtifactCaptureSink::FlushPendingWork(const std::string_view guest_reason,
                                                 const std::string_view wasm_reason) {
  NativeResponseBodyCapture::Get().Flush();
  for (auto& [key, pending] : guest_dispatches_) {
    static_cast<void>(key);
    if (pending.failed || pending.published)
      continue;
    pending.failed = true;
    EmitRendererGap(pending.event, guest_reason);
    for (const auto& host : pending.hosts)
      PublishUnparentedHost(host, guest_host_parent_lost_gap_emitted_,
                            "native_guest_host_parent_lost");
    guest_held_host_count_ -= pending.hosts.size();
    pending.hosts.clear();
  }
  for (auto& [artifact_id, context] : pending_) {
    static_cast<void>(artifact_id);
    for (const auto& [observation, unused] : context.wasm_observations) {
      static_cast<void>(unused);
      EmitRendererGap(observation, wasm_reason);
    }
    context.wasm_observations.clear();
  }
}

void NativeArtifactCaptureSink::SetWasmSampleBudgetPolicy(
    const NativeWasmSampleBudgetPolicy& policy) noexcept {
  if (!IsValidNativeWasmSampleBudgetPolicy(policy))
    return;
  wasm_sample_budget_ = policy;
}

void NativeArtifactCaptureSink::ResetWasmSampleBudgets() noexcept {
  wasm_dispatch_count_ = 0;
  wasm_indirect_count_ = 0;
  if ((wasm_budget_epoch_ & 1U) == 0 &&
      wasm_budget_epoch_ <= std::numeric_limits<std::uint64_t>::max() - 2)
    wasm_budget_epoch_ += 2;
}

void NativeArtifactCaptureSink::CaptureWasmDispatch(
    const NativeWasmDispatchObservation& observation,
    mojo_base::BigBuffer content,
    std::function<bool()> is_current_document) {
  if (!emitter_.load(std::memory_order_acquire) ||
      observation.header.session_id != session_id_.load(std::memory_order_relaxed))
    return;
  // Every refusal fills the observation's own renderer sequence slot.
  const auto gap = [&](std::string_view reason) {
    EmitRendererGap(NativeProbeEvent{.header = observation.header}, reason);
  };
  if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled()) {
    gap("native_wasm_dispatch_artifact_unavailable");
    return;
  }
  if (!is_current_document || !is_current_document()) {
    gap("native_wasm_dispatch_document_unavailable");
    return;
  }
  std::array<std::uint8_t, 32> module_digest{};
  const std::uint8_t* module_digest_bytes = nullptr;
  if (wasm_sample_budget_.module_allow_count != 0 && content.size() <= 16U * 1024U * 1024U) {
    module_digest =
        NativeGuestDigest(std::span<const std::uint8_t>(content.data(), content.size()));
    module_digest_bytes = module_digest.data();
  }
  const auto budget = AdmitNativeWasmBudgetKeys(wasm_sample_budget_, wasm_dispatch_function_keys_,
                                                {}, wasm_budget_epoch_, observation.function_index,
                                                0, module_digest_bytes);
  if (const char* reason = NativeWasmBrowserBudgetReason(budget.status, false)) {
    gap(reason);
    return;
  }
  if (wasm_dispatch_count_ >= kNativeWasmDispatchSampleBudget) {
    ReleaseNativeWasmBudgetAdmission(budget, wasm_dispatch_function_keys_, {}, wasm_budget_epoch_);
    gap("native_wasm_dispatch_browser_budget_incomplete");
    return;
  }
  ++wasm_dispatch_count_;
  // A refused record is not a retained sample. Put the slot and the per-function
  // count back so a later valid execution of that function can still be kept.
  const auto abandon = [&](std::string_view reason) {
    --wasm_dispatch_count_;
    ReleaseNativeWasmBudgetAdmission(budget, wasm_dispatch_function_keys_, {}, wasm_budget_epoch_);
    gap(reason);
  };
  if (content.size() < 8 || content.size() > 16U * 1024U * 1024U ||
      !observation.header.sequence_number || !observation.header.monotonic_time_ns ||
      !observation.header.process_id || !observation.header.thread_id ||
      observation.function_index >= 16U * 1024U * 1024U ||
      observation.table_count >= 16U * 1024U * 1024U) {
    abandon("native_wasm_dispatch_limit_or_invalid");
    return;
  }
  // Renderer shared memory remains writable: validate a private immutable copy.
  std::vector<std::uint8_t> bytes(content.begin(), content.end());
  auto checked = observation;
  checked.module_bytes = bytes;
  if (!IsValidNativeWasmDispatchInput(checked)) {
    abandon("native_wasm_dispatch_module_invalid");
    return;
  }
  NativeProbeEvent event;
  event.header = observation.header;
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = NativeProbeType::kWasmDispatchObservation;
  event.header.parent_event_id = 0;
  event.header.payload_size = 128;
  // Version 3 is the walked caller. Version 2 means the walk did not run.
  const NativeWasmDispatchObservationPayload sample{
      .protocol_version = static_cast<std::uint16_t>(observation.caller_observed ? 3 : 2),
      .function_index = observation.function_index,
      .module_byte_offset = observation.module_byte_offset,
      .selector = observation.selector,
      .table_count = observation.table_count,
      .sample_index = observation.sample_index,
      .js_invocation_state = observation.js_invocation_state,
      .js_invocation_id = observation.js_invocation_id,
      .caller_kind = observation.caller_kind,
      .caller_function_index = observation.caller_function_index};
  event.inline_payload = EncodeNativeWasmDispatchObservationPayload(sample);
  PublishAfterWasmModule(event, bytes, observation.execution_context_id,
                         observation.document_token_high, observation.document_token_low,
                         observation.source_url, std::move(is_current_document));
}

void NativeArtifactCaptureSink::CaptureWasmIndirect(
    const NativeWasmIndirectObservation& observation,
    mojo_base::BigBuffer content,
    std::function<bool()> is_current_document) {
  if (!emitter_.load(std::memory_order_acquire) ||
      observation.header.session_id != session_id_.load(std::memory_order_relaxed))
    return;
  // Every refusal fills the observation's own renderer sequence slot.
  const auto gap = [&](std::string_view reason) {
    EmitRendererGap(NativeProbeEvent{.header = observation.header}, reason);
  };
  if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled()) {
    gap("native_wasm_indirect_artifact_unavailable");
    return;
  }
  if (!is_current_document || !is_current_document()) {
    gap("native_wasm_indirect_document_unavailable");
    return;
  }
  std::array<std::uint8_t, 32> module_digest{};
  const std::uint8_t* module_digest_bytes = nullptr;
  if (wasm_sample_budget_.module_allow_count != 0 && content.size() <= 16U * 1024U * 1024U) {
    module_digest =
        NativeGuestDigest(std::span<const std::uint8_t>(content.data(), content.size()));
    module_digest_bytes = module_digest.data();
  }
  // A budget separate from br_table: one stream never starves the other.
  const auto budget = AdmitNativeWasmBudgetKeys(
      wasm_sample_budget_, wasm_indirect_function_keys_, wasm_indirect_site_keys_,
      wasm_budget_epoch_, observation.function_index, observation.module_byte_offset,
      module_digest_bytes);
  if (const char* reason = NativeWasmBrowserBudgetReason(budget.status, true)) {
    gap(reason);
    return;
  }
  if (wasm_indirect_count_ >= kNativeWasmIndirectSampleBudget) {
    ReleaseNativeWasmBudgetAdmission(budget, wasm_indirect_function_keys_, wasm_indirect_site_keys_,
                                     wasm_budget_epoch_);
    gap("native_wasm_indirect_browser_budget_incomplete");
    return;
  }
  ++wasm_indirect_count_;
  // Same as br_table: validation that fails after the claim must not spend it.
  const auto abandon = [&](std::string_view reason) {
    --wasm_indirect_count_;
    ReleaseNativeWasmBudgetAdmission(budget, wasm_indirect_function_keys_, wasm_indirect_site_keys_,
                                     wasm_budget_epoch_);
    gap(reason);
  };
  if (content.size() < 8 || content.size() > kNativeArtifactMaxContentBytes ||
      !observation.header.sequence_number || !observation.header.monotonic_time_ns ||
      !observation.header.process_id || !observation.header.thread_id) {
    abandon("native_wasm_indirect_limit_or_invalid");
    return;
  }
  // Renderer shared memory remains writable: validate a private immutable copy.
  std::vector<std::uint8_t> bytes(content.begin(), content.end());
  auto checked = observation;
  checked.module_bytes = bytes;
  if (!IsValidNativeWasmIndirectInput(checked)) {
    abandon("native_wasm_indirect_module_invalid");
    return;
  }
  NativeProbeEvent event;
  event.header = observation.header;
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = NativeProbeType::kWasmIndirectObservation;
  event.header.parent_event_id = 0;
  event.header.payload_size = 128;
  const NativeWasmIndirectObservationPayload sample{
      .function_index = observation.function_index,
      .module_byte_offset = observation.module_byte_offset,
      .table_index = observation.table_index,
      .slot = observation.slot,
      .callee_function_index = observation.callee_function_index,
      .resolution = static_cast<std::uint32_t>(observation.resolution),
      .sample_index = observation.sample_index,
      .js_invocation_state = observation.js_invocation_state,
      .js_invocation_id = observation.js_invocation_id};
  event.inline_payload = EncodeNativeWasmIndirectObservationPayload(sample);
  PublishAfterWasmModule(event, bytes, observation.execution_context_id,
                         observation.document_token_high, observation.document_token_low,
                         observation.source_url, std::move(is_current_document));
}

void NativeArtifactCaptureSink::PublishAfterWasmModule(NativeProbeEvent event,
                                                       const std::vector<std::uint8_t>& bytes,
                                                       const std::uint64_t execution_context_id,
                                                       const std::uint64_t document_token_high,
                                                       const std::uint64_t document_token_low,
                                                       const std::string_view source_url,
                                                       std::function<bool()> is_current_document) {
  // Observations of one module in one document share a single artifact,
  // whichever physical stream (br_table or call_indirect) recorded them.
  const WasmModuleKey module_key{event.header.process_id, event.header.frame_id,
                                 execution_context_id,    document_token_high,
                                 document_token_low,      NativeGuestDigest(bytes)};
  if (const auto known = wasm_dispatch_modules_.find(module_key);
      known != wasm_dispatch_modules_.end()) {
    event.header.artifact_id = known->second.first;
    if (known->second.second) {
      if (const auto emitter = emitter_.load(std::memory_order_acquire))
        emitter(event);
      return;
    }
    if (const auto pending = pending_.find(known->second.first); pending != pending_.end()) {
      pending->second.wasm_observations.emplace_back(event, std::move(is_current_document));
      return;
    }
  }
  const auto artifact_id = CaptureGeneratedArtifactInternal(
      NativeArtifactKind::kWasm, NativeArtifactCaptureOrigin::kUnknown, 0, execution_context_id,
      event.header.frame_id, source_url, mojo_base::BigBuffer(bytes), 0, true);
  const auto found = pending_.find(artifact_id);
  if (!artifact_id || found == pending_.end()) {
    EmitRendererGap(event, "native_wasm_dispatch_artifact_unavailable");
    return;
  }
  event.header.artifact_id = artifact_id;
  wasm_dispatch_modules_[module_key] = {artifact_id, false};
  found->second.wasm_observations.emplace_back(event, std::move(is_current_document));
}

void NativeArtifactCaptureSink::CaptureWasmExecution(
    const NativeWasmExecutionObservation& observation,
    mojo_base::BigBuffer content,
    std::function<bool()> is_current_document) {
  if (!emitter_.load(std::memory_order_acquire) ||
      observation.header.session_id != session_id_.load(std::memory_order_relaxed))
    return;
  const auto gap = [&](std::string_view reason) {
    EmitRendererGap(NativeProbeEvent{.header = observation.header}, reason);
  };
  if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled()) {
    gap("native_wasm_execution_artifact_unavailable");
    return;
  }
  if (!is_current_document || !is_current_document()) {
    gap("native_wasm_execution_document_unavailable");
    return;
  }
  if (wasm_execution_count_ >= kNativeWasmExecutionBudget) {
    gap("native_wasm_execution_browser_budget_incomplete");
    return;
  }
  ++wasm_execution_count_;
  if (content.size() > kNativeArtifactMaxContentBytes || !observation.header.sequence_number ||
      !observation.header.monotonic_time_ns || !observation.header.process_id ||
      !observation.header.thread_id) {
    gap("native_wasm_execution_limit_or_invalid");
    return;
  }
  std::vector<std::uint8_t> bytes(content.begin(), content.end());
  auto checked = observation;
  checked.module_bytes = bytes;
  if (!IsValidNativeWasmExecutionInput(checked)) {
    gap("native_wasm_execution_limit_or_invalid");
    return;
  }
  NativeProbeEvent event;
  event.header = observation.header;
  event.header.category = NativeProbeCategory::kVm;
  event.header.type = NativeProbeType::kWasmExecutionOutcome;
  event.header.parent_event_id = 0;
  event.header.payload_size = 128;
  const NativeWasmExecutionOutcomePayload sample{
      .kind = static_cast<std::uint8_t>(observation.kind),
      .reason = static_cast<std::uint8_t>(observation.reason),
      .bounds = static_cast<std::uint8_t>(observation.bounds),
      .known = observation.known,
      .function_index = observation.function_index,
      .module_byte_offset = observation.module_byte_offset,
      .invocation_id = observation.invocation_id,
      .related_sample_index = observation.related_sample_index,
      .related_stream = static_cast<std::uint8_t>(observation.related_stream),
      .js_invocation_state = observation.js_invocation_state,
      .js_invocation_id = observation.js_invocation_id};
  event.inline_payload = EncodeNativeWasmExecutionOutcomePayload(sample);
  if (!bytes.empty()) {
    PublishAfterWasmModule(event, bytes, observation.execution_context_id,
                           observation.document_token_high, observation.document_token_low,
                           observation.source_url, std::move(is_current_document));
    return;
  }
  WasmModuleKey matched{};
  int matches = 0;
  for (const auto& entry : wasm_dispatch_modules_) {
    const auto& key = entry.first;
    if (std::get<0>(key) != event.header.process_id || std::get<1>(key) != event.header.frame_id ||
        std::get<2>(key) != observation.execution_context_id ||
        std::get<3>(key) != observation.document_token_high ||
        std::get<4>(key) != observation.document_token_low)
      continue;
    matched = key;
    ++matches;
  }
  if (matches == 0) {
    gap("native_wasm_execution_module_unavailable");
    return;
  }
  if (matches != 1) {
    gap("native_wasm_execution_module_unresolved");
    return;
  }
  const auto known = wasm_dispatch_modules_.find(matched);
  event.header.artifact_id = known->second.first;
  if (known->second.second) {
    if (const auto emitter = emitter_.load(std::memory_order_acquire))
      emitter(event);
    return;
  }
  if (const auto pending = pending_.find(known->second.first); pending != pending_.end()) {
    pending->second.wasm_observations.emplace_back(event, std::move(is_current_document));
    return;
  }
  gap("native_wasm_execution_module_unavailable");
}

std::uint64_t NativeArtifactCaptureSink::CaptureGeneratedArtifact(
    NativeArtifactKind kind,
    NativeArtifactCaptureOrigin capture_origin,
    std::uint64_t creator_event_id,
    std::uint64_t execution_context_id,
    std::uint64_t frame_id,
    std::string_view source_url,
    mojo_base::BigBuffer content,
    std::uint64_t parent_artifact_id) {
  return CaptureGeneratedArtifactInternal(kind, capture_origin, creator_event_id,
                                          execution_context_id, frame_id, source_url,
                                          std::move(content), parent_artifact_id, false);
}

std::uint64_t NativeArtifactCaptureSink::CaptureGeneratedArtifactInternal(
    const NativeArtifactKind kind,
    const NativeArtifactCaptureOrigin capture_origin,
    const std::uint64_t creator_event_id,
    const std::uint64_t execution_context_id,
    const std::uint64_t frame_id,
    const std::string_view source_url,
    mojo_base::BigBuffer content,
    const std::uint64_t parent_artifact_id,
    const bool native_wasm_runtime) {
  const bool is_runtime_typed_array =
      kind == NativeArtifactKind::kBytecodeBuffer &&
      capture_origin == NativeArtifactCaptureOrigin::kRuntimeTypedArray;
  const bool is_allocating_script =
      kind == NativeArtifactKind::kJavaScript &&
      capture_origin == NativeArtifactCaptureOrigin::kRuntimeAllocatingScript;
  const NativeProbeCategory result_category = (is_runtime_typed_array || is_allocating_script)
                                                  ? NativeProbeCategory::kVm
                                                  : NativeProbeCategory::kArtifact;
  if (!IsEnabledFor(result_category)) {
    return 0;
  }
  const std::uint64_t capture_session_id = session_id_.load(std::memory_order_relaxed);
  const std::uint64_t capture_generation = generation_.load(std::memory_order_acquire);
  const std::uint64_t artifact_id = next_artifact_id_.fetch_add(1, std::memory_order_relaxed);
  // Canvas images are sensitive: the session's opt-in decides, not the
  // renderer's view of its configuration.
  if (kind == NativeArtifactKind::kCanvasDataUrl &&
      !NativeProbeSession::Get().capture_canvas_images()) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "canvas_image_capture_disabled", result_category);
    return 0;
  }
  const bool valid_kind_and_origin =
      (native_wasm_runtime &&
       ((kind == NativeArtifactKind::kWasm &&
         capture_origin == NativeArtifactCaptureOrigin::kUnknown) ||
        ((kind == NativeArtifactKind::kWasmGuestAdapter ||
          kind == NativeArtifactKind::kBytecodeBuffer) &&
         capture_origin == NativeArtifactCaptureOrigin::kNativeWasmGuest))) ||
      (kind == NativeArtifactKind::kJavaScript &&
       capture_origin == NativeArtifactCaptureOrigin::kDynamicJavaScript) ||
      // Request initiator stacks, protocol/native-network-v3.md.
      (((kind == NativeArtifactKind::kStack &&
         capture_origin == NativeArtifactCaptureOrigin::kRequestStack) ||
        (kind == NativeArtifactKind::kJavaScript &&
         capture_origin == NativeArtifactCaptureOrigin::kStackScript)) &&
       creator_event_id != 0) ||
      (kind == NativeArtifactKind::kWasm &&
       (capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyCompile ||
        capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyModule ||
        capture_origin == NativeArtifactCaptureOrigin::kWebAssemblyInstantiate)) ||
      (kind == NativeArtifactKind::kCanvasDataUrl &&
       capture_origin == NativeArtifactCaptureOrigin::kCanvasToDataUrl && creator_event_id != 0 &&
       execution_context_id == 0) ||
      is_runtime_typed_array || is_allocating_script;
  if (!valid_kind_and_origin ||
      (kind != NativeArtifactKind::kCanvasDataUrl && execution_context_id == 0) ||
      content.size() == 0 || content.size() > kMaxArtifactBytes ||
      (is_runtime_typed_array && content.size() < kRuntimeTypedArrayMinBytes) ||
      source_url.empty() || source_url.size() > kNativeArtifactMaxUrlBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "generated_metadata_or_size_limit", result_category);
    return 0;
  }
  if (is_runtime_typed_array &&
      runtime_typed_array_count_.fetch_add(1, std::memory_order_relaxed) >=
          kRuntimeTypedArrayMaxSnapshots) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "runtime_typed_array_session_limit", result_category);
    return 0;
  }

  const std::string captured_url(source_url);
  const std::string mime_type = kind == NativeArtifactKind::kJavaScript         ? "text/javascript"
                                : kind == NativeArtifactKind::kWasm             ? "application/wasm"
                                : kind == NativeArtifactKind::kWasmGuestAdapter ? "application/json"
                                : kind == NativeArtifactKind::kStack ? "application/x-reb-stack"
                                : kind == NativeArtifactKind::kBytecodeBuffer
                                    ? "application/octet-stream"
                                    : "text/plain";
  if (captured_url.empty() || captured_url.size() > kNativeArtifactMaxUrlBytes) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "generated_url_invalid", result_category);
    return 0;
  }

  // BigBuffer may be shared writable memory owned by the renderer. Copy once
  // in the browser before validation and transfer to avoid a TOCTOU race.
  const std::span<const std::uint8_t> received(content);
  auto transfer = std::make_unique<NativeArtifactTransfer>();
  transfer->header.kind = kind;
  transfer->header.session_id = capture_session_id;
  transfer->header.frame_id = frame_id;
  transfer->header.artifact_id = artifact_id;
  transfer->header.creator_event_id = creator_event_id;
  transfer->header.parent_artifact_id = parent_artifact_id;
  if (kind == NativeArtifactKind::kCanvasDataUrl) {
    transfer->header.flags |= kNativeArtifactFlagSensitive;
  }
  transfer->header.content_size = received.size();
  transfer->header.url_size = static_cast<std::uint32_t>(captured_url.size());
  transfer->header.mime_type_size = static_cast<std::uint32_t>(mime_type.size());
  transfer->header.execution_context_id = execution_context_id;
  transfer->header.capture_origin = capture_origin;
  transfer->url = captured_url;
  transfer->mime_type = mime_type;
  transfer->content.assign(received.begin(), received.end());
  if (!NativeArtifactSocketClient::Get().Enqueue(std::move(transfer))) {
    EmitResult(NativeProbeType::kArtifactCaptureFailed, artifact_id, 0, frame_id,
               "transfer_queue_full_or_disconnected", result_category);
    return 0;
  }
  pending_.emplace(artifact_id, PendingContext{.frame_id = frame_id,
                                               .session_id = capture_session_id,
                                               .generation = capture_generation,
                                               .result_category = result_category});
  return artifact_id;
}

void NativeArtifactCaptureSink::TrackResponseBody(const std::uint64_t artifact_id,
                                                  const std::uint64_t request_id,
                                                  const std::uint64_t frame_id,
                                                  const std::uint64_t creator_event_id) noexcept {
  pending_.emplace(artifact_id,
                   PendingContext{.request_id = request_id,
                                  .frame_id = frame_id,
                                  .session_id = session_id_.load(std::memory_order_relaxed),
                                  .generation = generation_.load(std::memory_order_acquire),
                                  .parent_event_id = creator_event_id,
                                  .response_body = true});
}

void NativeArtifactCaptureSink::TransferCompleted(
    const std::uint64_t artifact_id,
    const NativeArtifactReceiveStatus status) noexcept {
  Get().OnTransferCompleted(artifact_id, status);
}

void NativeArtifactCaptureSink::OnTransferCompleted(
    const std::uint64_t artifact_id,
    const NativeArtifactReceiveStatus status) noexcept {
  // A refusal while a tee still runs ends that stream here.
  response_streams_.erase(artifact_id);
  if (status != NativeArtifactReceiveStatus::kAccepted &&
      NativeResponseBodyCapture::Get().OnStreamRefused(artifact_id)) {
    return;
  }
  const auto found = pending_.find(artifact_id);
  if (found == pending_.end()) {
    return;
  }
  const PendingContext context = found->second;
  pending_.erase(found);
  if (!IsCurrentCapture(context.session_id, context.generation)) {
    return;
  }
  if (context.response_body) {
    NativeResponseBodyCapture::Get().OnTransferCompleted(
        artifact_id, status == NativeArtifactReceiveStatus::kAccepted);
  }
  if (auto receipt = guest_receipts_.find(artifact_id); receipt != guest_receipts_.end()) {
    receipt->second = status == NativeArtifactReceiveStatus::kAccepted ? GuestReceipt::kAccepted
                                                                       : GuestReceipt::kRejected;
    DrainGuestDependencies();
  }
  const bool accepted = status == NativeArtifactReceiveStatus::kAccepted;
  // The module map follows every receipt, including one whose observations
  // were already flushed as gaps, so later observations reuse or replace it.
  for (auto entry = wasm_dispatch_modules_.begin(); entry != wasm_dispatch_modules_.end();
       ++entry) {
    if (entry->second.first != artifact_id)
      continue;
    if (accepted)
      entry->second.second = true;
    else
      wasm_dispatch_modules_.erase(entry);
    break;
  }
  if (!context.wasm_observations.empty()) {
    if (!IsEnabledFor(NativeProbeCategory::kVm) || !IsEnabled())
      return;
    const auto emitter = emitter_.load(std::memory_order_acquire);
    for (const auto& [observation, is_current_document] : context.wasm_observations) {
      if (accepted && emitter && is_current_document && is_current_document())
        emitter(observation);
      else
        EmitRendererGap(observation, "native_wasm_dispatch_artifact_or_document_lost");
    }
  }
  EmitResult(status == NativeArtifactReceiveStatus::kAccepted
                 ? NativeProbeType::kArtifactCaptured
                 : NativeProbeType::kArtifactCaptureFailed,
             artifact_id, context.request_id, context.frame_id, StatusName(status),
             context.result_category, context.parent_event_id);
}

void NativeArtifactCaptureSink::EmitResult(const NativeProbeType type,
                                           const std::uint64_t artifact_id,
                                           const std::uint64_t request_id,
                                           const std::uint64_t frame_id,
                                           const std::string& detail,
                                           const NativeProbeCategory category,
                                           const std::uint64_t parent_event_id) noexcept {
  const NativeProbeEmitter emitter = emitter_.load(std::memory_order_acquire);
  if (!emitter) {
    return;
  }
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (now >= expires_at_monotonic_ns_.load(std::memory_order_relaxed)) {
    return;
  }
  NativeProbeEvent event;
  event.header.category = category;
  event.header.type = type;
  event.header.sequence_number = NativeProbeSession::Get().NextBrowserSequence();
  event.header.monotonic_time_ns = now;
  event.header.session_id = session_id_.load(std::memory_order_relaxed);
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.frame_id = frame_id;
  event.header.artifact_id = artifact_id;
  event.header.request_id = request_id;
  event.header.parent_event_id = parent_event_id;
  const std::size_t size = std::min(detail.size(), event.inline_payload.size());
  std::transform(detail.begin(), detail.begin() + static_cast<std::ptrdiff_t>(size),
                 event.inline_payload.begin(), [](const char value) {
                   return static_cast<std::byte>(static_cast<unsigned char>(value));
                 });
  event.header.payload_size = static_cast<std::uint32_t>(size);
  if (size != detail.size()) {
    event.header.flags |= static_cast<std::uint16_t>(NativeProbeFlag::kPayloadTruncated);
  }
  emitter(event);
}

bool NativeArtifactCaptureSink::IsCurrentCapture(const std::uint64_t session_id,
                                                 const std::uint64_t generation) const noexcept {
  return generation == generation_.load(std::memory_order_acquire) &&
         session_id == session_id_.load(std::memory_order_relaxed);
}

}  // namespace reb
