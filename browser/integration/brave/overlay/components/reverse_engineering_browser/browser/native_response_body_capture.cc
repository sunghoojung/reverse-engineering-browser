// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_response_body_capture.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "crypto/hash.h"
#include "net/http/http_response_headers.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "url/gurl.h"

namespace reb {
namespace {

constexpr std::uint64_t kSnapshotIntervalNs = 1'000'000'000;
// A body whose loader never reports completion is retained after this wait.
constexpr std::int64_t kCompletionWaitNs = 10'000'000'000;
constexpr std::size_t kDigestLimit = 16'384;
// net::ERR_ABORTED at the pin: the page or the browser stopped the request.
constexpr int kErrorAborted = -3;
constexpr int kStatusNotModified = 304;

std::uint64_t Now() {
  return static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
}

// Scheme, host, explicit port, path and query, never credentials or a
// fragment. Past the manifest's 8 KiB it is the origin.
std::string ArtifactUrl(const GURL& url) {
  const char* const scheme = url.SchemeIs("https")  ? "https://"
                             : url.SchemeIs("http") ? "http://"
                                                    : nullptr;
  if (!scheme || url.host().empty()) {
    return {};
  }
  std::string spec(scheme);
  spec.append(url.host());
  if (const int port = url.IntPort(); port > 0) {
    spec.append(":").append(std::to_string(port));
  }
  const std::size_t origin = spec.size();
  spec.append(url.path());
  if (url.has_query()) {
    spec.append("?").append(url.query());
  }
  if (spec.size() > kNativeArtifactMaxUrlBytes) {
    spec.resize(origin);
  }
  return spec;
}

}  // namespace

NativeResponseBodyCapture& NativeResponseBodyCapture::Get() {
  static base::NoDestructor<NativeResponseBodyCapture> capture;
  return *capture;
}

NativeResponseBodyCapture::NativeResponseBodyCapture() = default;
NativeResponseBodyCapture::~NativeResponseBodyCapture() = default;

void NativeResponseBodyCapture::Configure(const NativeProbeEmitter emitter,
                                          const std::uint64_t session_id,
                                          const std::uint64_t category_mask,
                                          const std::uint64_t expires_at_monotonic_ns,
                                          const NativeResponseBodyPolicy& policy) noexcept {
  constexpr auto kRequired = NativeProbeCategoryMask(NativeProbeCategory::kNetwork) |
                             NativeProbeCategoryMask(NativeProbeCategory::kArtifact);
  const bool enabled = emitter && policy.enabled && (category_mask & kRequired) == kRequired;
  enabled_.store(false, std::memory_order_relaxed);
  ++generation_;
  bodies_.clear();
  digests_.clear();
  queued_.clear();
  used_ = 0;
  last_response_started_ = {};
  emitter_ = enabled ? emitter : nullptr;
  session_id_ = enabled ? session_id : 0;
  expires_at_monotonic_ns_ = enabled ? expires_at_monotonic_ns : 0;
  media_ = enabled && policy.media;
  budget_ = enabled ? policy.budget : 0;
  enabled_.store(enabled, std::memory_order_relaxed);
}

void NativeResponseBodyCapture::NoteResponseStarted(const NativeProbeHeader& header) noexcept {
  if (IsEnabled()) {
    last_response_started_ = header;
  }
}

mojo::ScopedDataPipeConsumerHandle NativeResponseBodyCapture::MaybeCapture(
    const std::uint64_t creator_event_id,
    const network::ResourceRequest& request,
    const network::mojom::URLResponseHead& response_head,
    mojo::ScopedDataPipeConsumerHandle body) {
  // The proxy records response_started immediately before it offers the body.
  if (!IsEnabled() || creator_event_id == 0 ||
      last_response_started_.sequence_number != creator_event_id) {
    return body;
  }
  const NativeProbeHeader parent = last_response_started_;
  NativeResponseBodySummary summary;
  SetNativeResponseContentType(response_head.mime_type, summary);
  if (response_head.headers) {
    if (const auto codings = response_head.headers->GetNormalizedHeader("Content-Encoding")) {
      SetNativeResponseCodings(*codings, summary);
    }
  }
  if (response_head.was_fetched_via_cache) {
    summary.flags |= kNativeResponseBodyFromCache;
  }
  if (response_head.was_fetched_via_service_worker) {
    summary.flags |= kNativeResponseBodyServiceWorker;
  }
  if (!response_head.client_side_content_decoding_types.empty()) {
    summary.flags |= kNativeResponseBodyStillEncoded;
  }
  const std::string url = ArtifactUrl(request.url);
  std::optional<NativeResponseBodyState> refusal;
  if (response_head.headers && response_head.headers->response_code() == kStatusNotModified) {
    refusal = NativeResponseBodyState::kNotModified;
  } else if (!body.is_valid()) {
    // The loader delivered no body pipe at all.
    refusal = NativeResponseBodyState::kEmpty;
  } else if (!media_ && IsNativeResponseMedia(request.resource_type, response_head.mime_type)) {
    refusal = NativeResponseBodyState::kNotCapturedType;
  } else if (used_ >= budget_) {
    refusal = NativeResponseBodyState::kNotCapturedSessionBudget;
  } else if (url.empty()) {
    refusal = NativeResponseBodyState::kNotCapturedTransferRefused;
  }
  if (refusal) {
    summary.state = *refusal;
    Emit(parent, summary, 0);
    return body;
  }
  // A declared length is the encoded size; a decoded body grows past it.
  const std::size_t declared = response_head.content_length > 0
                                   ? static_cast<std::size_t>(std::min<std::uint64_t>(
                                         static_cast<std::uint64_t>(response_head.content_length),
                                         kNativeResponseBodyCaptureBytes))
                                   : 0;
  NativeArtifactCaptureBuffer captured(
      NativeArtifactReservation::Acquire(
          NativeArtifactCaptureSink::Get().memory_pool(),
          declared > 0 ? declared : kNativeArtifactInitialReservation),
      kNativeArtifactMaxContentBytes, /*keep_prefix=*/true);
  if (captured.status() != NativeArtifactCaptureStatus::kCapturing) {
    summary.state = NativeResponseBodyState::kNotCapturedTransferRefused;
    Emit(parent, summary, 0);
    return body;
  }
  const Key key{parent.request_id, parent.frame_id};
  if (const auto stale = bodies_.find(key); stale != bodies_.end()) {
    Finish(stale, /*synchronous=*/false);
  }
  const std::uint64_t capture_id = next_capture_id_++;
  Body& entry = bodies_[key];
  entry.capture_id = capture_id;
  entry.parent = parent;
  entry.url = url;
  entry.mime_type = response_head.mime_type.empty() ||
                            response_head.mime_type.size() > kNativeArtifactMaxMimeTypeBytes
                        ? "application/octet-stream"
                        : response_head.mime_type;
  entry.summary = summary;
  entry.captured = std::move(captured);
  entry.streaming = declared == 0;
  entry.snapshot_ns = Now();
  bool started = false;
  body = NativeArtifactBodyTee::Create(
      std::move(body), NativeArtifactCaptureBuffer(),
      base::BindOnce(&NativeResponseBodyCapture::OnEnd, base::Unretained(this), key, capture_id),
      started,
      base::BindRepeating(&NativeResponseBodyCapture::OnData, base::Unretained(this), key,
                          capture_id));
  if (!started) {
    bodies_.erase(key);
    summary.state = NativeResponseBodyState::kNotCapturedTransferRefused;
    Emit(parent, summary, 0);
  }
  return body;
}

void NativeResponseBodyCapture::OnData(const Key key,
                                       const std::uint64_t capture_id,
                                       const std::span<const std::uint8_t> chunk) {
  const auto found = bodies_.find(key);
  if (found == bodies_.end() || found->second.capture_id != capture_id) {
    return;
  }
  Body& body = found->second;
  body.captured.Append(chunk);
  // Streams without a declared length are retained as they arrive. Each
  // snapshot waits a second and half again the bytes, so their total stays
  // within three times the body.
  const std::size_t size = body.captured.size();
  if (!body.streaming || body.captured.status() == NativeArtifactCaptureStatus::kMemoryLimit ||
      body.partials + 1 >= kNativeResponseBodyPartialLimit ||
      Now() - body.snapshot_ns < kSnapshotIntervalNs ||
      size - body.snapshot_size < std::max<std::size_t>(body.snapshot_size / 2, 1)) {
    return;
  }
  Snapshot(found);
}

void NativeResponseBodyCapture::OnEnd(const Key key,
                                      const std::uint64_t capture_id,
                                      const NativeArtifactBodyEnd end,
                                      NativeArtifactCaptureBuffer) {
  const auto found = bodies_.find(key);
  if (found == bodies_.end() || found->second.capture_id != capture_id) {
    return;
  }
  found->second.tee_done = true;
  found->second.end = end;
  if (end == NativeArtifactBodyEnd::kTargetClosed || found->second.completion_known ||
      !base::SequencedTaskRunner::HasCurrentDefault()) {
    Finish(found, /*synchronous=*/false);
    return;
  }
  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce([](Key body, std::uint64_t id) { Get().OnCompletionTimeout(body, id); }, key,
                     capture_id),
      base::Nanoseconds(kCompletionWaitNs));
}

void NativeResponseBodyCapture::OnCompleted(const std::uint64_t request_id,
                                            const std::uint64_t frame_id,
                                            const int error_code) noexcept {
  if (!IsEnabled()) {
    return;
  }
  const auto found = bodies_.find({request_id, frame_id});
  if (found == bodies_.end()) {
    return;
  }
  found->second.completion_known = true;
  found->second.error_code = error_code;
  if (found->second.tee_done) {
    Finish(found, /*synchronous=*/false);
  }
}

void NativeResponseBodyCapture::OnCompletionTimeout(const Key key, const std::uint64_t capture_id) {
  const auto found = bodies_.find(key);
  if (found != bodies_.end() && found->second.capture_id == capture_id && found->second.tee_done) {
    Finish(found, /*synchronous=*/false);
  }
}

void NativeResponseBodyCapture::Finish(const std::map<Key, Body>::iterator found,
                                       const bool synchronous) {
  const Key key = found->first;
  Body body = std::move(found->second);
  bodies_.erase(found);
  NativeResponseBodySummary summary = body.summary;
  summary.body_length = body.captured.observed();
  const auto status = body.captured.status();
  const bool open = !body.tee_done;
  const bool cancelled =
      body.end == NativeArtifactBodyEnd::kTargetClosed || body.error_code == kErrorAborted;
  const bool aborted =
      !cancelled && (body.end == NativeArtifactBodyEnd::kSourceFailed || body.error_code != 0);
  if (status == NativeArtifactCaptureStatus::kMemoryLimit) {
    summary.state = NativeResponseBodyState::kNotCapturedTransferRefused;
  } else if (open) {
    summary.state = NativeResponseBodyState::kPartial;
    summary.partial_index = static_cast<std::uint16_t>(body.partials + 1);
  } else if (cancelled || aborted) {
    summary.state =
        cancelled ? NativeResponseBodyState::kCancelled : NativeResponseBodyState::kAborted;
  } else {
    if (!body.completion_known) {
      summary.flags |= kNativeResponseBodyCompletionUnobserved;
    }
    summary.state = summary.body_length == 0 ? NativeResponseBodyState::kEmpty
                    : status == NativeArtifactCaptureStatus::kTruncated
                        ? NativeResponseBodyState::kCapturedTruncated
                        : NativeResponseBodyState::kCaptured;
  }
  if (status == NativeArtifactCaptureStatus::kMemoryLimit || body.captured.size() == 0) {
    if (open && status != NativeArtifactCaptureStatus::kMemoryLimit) {
      // Capture ended before any byte arrived.
      Refuse(body.parent, summary, NativeResponseBodyState::kNotCapturedArtifactUnavailable);
      return;
    }
    summary.partial_index = 0;
    Emit(body.parent, summary, 0);
    return;
  }
  body.captured.Finish();
  auto retention = std::make_unique<Retention>();
  retention->key = key;
  retention->capture_id = body.capture_id;
  retention->generation = generation_;
  retention->parent = body.parent;
  retention->url = std::move(body.url);
  retention->mime_type = std::move(body.mime_type);
  retention->summary = summary;
  retention->summary.captured_length = body.captured.size();
  retention->bytes = body.captured.TakeContent();
  retention->reservation = body.captured.TakeReservation();
  Retain(std::move(retention), synchronous);
}

void NativeResponseBodyCapture::Snapshot(const std::map<Key, Body>::iterator found) {
  Body& body = found->second;
  const auto content = body.captured.content();
  auto reservation = NativeArtifactReservation::Acquire(
      NativeArtifactCaptureSink::Get().memory_pool(), content.size());
  if (!reservation.is_valid()) {
    return;
  }
  auto retention = std::make_unique<Retention>();
  retention->key = found->first;
  retention->capture_id = body.capture_id;
  retention->generation = generation_;
  retention->parent = body.parent;
  retention->url = body.url;
  retention->mime_type = body.mime_type;
  retention->summary = body.summary;
  retention->summary.state = NativeResponseBodyState::kPartial;
  retention->summary.partial_index = ++body.partials;
  retention->summary.body_length = body.captured.observed();
  retention->summary.captured_length = content.size();
  retention->live = true;
  retention->bytes.assign(content.begin(), content.end());
  retention->reservation = std::move(reservation);
  body.snapshot_ns = Now();
  body.snapshot_size = content.size();
  Retain(std::move(retention), /*synchronous=*/false);
}

void NativeResponseBodyCapture::Retain(std::unique_ptr<Retention> retention,
                                       const bool synchronous) {
  if (synchronous) {
    OnHashed(Hash(std::move(retention)));
    return;
  }
  const NativeProbeHeader parent = retention->parent;
  NativeResponseBodySummary summary = retention->summary;
  const bool live = retention->live;
  if (!base::ThreadPool::PostTaskAndReplyWithResult(
          FROM_HERE,
          {base::TaskPriority::USER_VISIBLE, base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
          base::BindOnce(&NativeResponseBodyCapture::Hash, std::move(retention)),
          base::BindOnce(&NativeResponseBodyCapture::OnHashed, base::Unretained(this))) &&
      !live) {
    Refuse(parent, summary, NativeResponseBodyState::kNotCapturedTransferRefused);
  }
}

std::unique_ptr<NativeResponseBodyCapture::Retention> NativeResponseBodyCapture::Hash(
    std::unique_ptr<Retention> retention) {
  retention->sha256 = crypto::hash::Sha256(retention->bytes);
  return retention;
}

void NativeResponseBodyCapture::OnHashed(std::unique_ptr<Retention> retention) {
  Retention& item = *retention;
  if (item.generation != generation_ || !IsEnabled()) {
    return;
  }
  NativeResponseBodySummary& summary = item.summary;
  if (item.live) {
    // A snapshot that settles after its body ended is superseded by it.
    const auto open = bodies_.find(item.key);
    if (open == bodies_.end() || open->second.capture_id != item.capture_id) {
      return;
    }
  }
  // A refused live snapshot is not a lost body: the end record reports it.
  const auto refuse = [&](const NativeResponseBodyState state) {
    if (!item.live) {
      Refuse(item.parent, summary, state);
    }
  };
  auto& artifacts = NativeArtifactCaptureSink::Get();
  if (!artifacts.IsEnabled()) {
    refuse(NativeResponseBodyState::kNotCapturedArtifactUnavailable);
    return;
  }
  summary.sha256 = item.sha256;
  // The receiver stores one blob per digest; a repeat names the first artifact.
  if (const auto shared = digests_.find(item.sha256); shared != digests_.end()) {
    summary.flags |= kNativeResponseBodyShared;
    Emit(item.parent, summary, shared->second);
    return;
  }
  const std::size_t size = item.bytes.size();
  if (size > budget_ - std::min(budget_, used_)) {
    refuse(NativeResponseBodyState::kNotCapturedSessionBudget);
    return;
  }
  auto transfer = std::make_unique<NativeArtifactTransfer>();
  NativeArtifactHeader& header = transfer->header;
  header.kind = NativeArtifactKind::kResponseBody;
  header.flags = kNativeArtifactFlagSensitive;
  header.session_id = session_id_;
  header.frame_id = item.parent.frame_id;
  header.artifact_id = artifacts.NextArtifactId();
  header.creator_event_id = item.parent.sequence_number;
  header.content_size = size;
  header.url_size = static_cast<std::uint32_t>(item.url.size());
  header.mime_type_size = static_cast<std::uint32_t>(item.mime_type.size());
  header.expected_sha256 = item.sha256;
  header.capture_origin = NativeArtifactCaptureOrigin::kNetworkResponse;
  transfer->url = std::move(item.url);
  transfer->mime_type = std::move(item.mime_type);
  transfer->content = std::move(item.bytes);
  transfer->reservation = std::move(item.reservation);
  const std::uint64_t artifact_id = header.artifact_id;
  if (!artifacts.QueueResponseBody(std::move(transfer), item.parent.request_id)) {
    refuse(NativeResponseBodyState::kNotCapturedTransferRefused);
    return;
  }
  used_ += size;
  queued_.emplace(artifact_id, std::make_pair(item.sha256, size));
  if (digests_.size() < kDigestLimit) {
    digests_.emplace(item.sha256, artifact_id);
  }
  Emit(item.parent, summary, artifact_id);
}

void NativeResponseBodyCapture::OnTransferCompleted(const std::uint64_t artifact_id,
                                                    const bool accepted) noexcept {
  const auto found = queued_.find(artifact_id);
  if (found == queued_.end()) {
    return;
  }
  const auto [digest, size] = found->second;
  queued_.erase(found);
  if (accepted) {
    return;
  }
  // Nothing was stored, so the bytes are refunded and a repeat is sent again.
  used_ -= std::min<std::uint64_t>(used_, size);
  if (const auto entry = digests_.find(digest);
      entry != digests_.end() && entry->second == artifact_id) {
    digests_.erase(entry);
  }
}

void NativeResponseBodyCapture::Flush() noexcept {
  if (!IsEnabled()) {
    return;
  }
  while (!bodies_.empty()) {
    Finish(bodies_.begin(), /*synchronous=*/true);
  }
}

void NativeResponseBodyCapture::Refuse(const NativeProbeHeader& parent,
                                       NativeResponseBodySummary summary,
                                       const NativeResponseBodyState state) noexcept {
  summary.state = state;
  summary.flags &= static_cast<std::uint8_t>(
      ~(kNativeResponseBodyCompletionUnobserved | kNativeResponseBodyShared));
  summary.captured_length = 0;
  summary.partial_index = 0;
  summary.sha256 = {};
  Emit(parent, summary, 0);
}

void NativeResponseBodyCapture::Emit(const NativeProbeHeader& parent,
                                     const NativeResponseBodySummary& summary,
                                     const std::uint64_t artifact_id) noexcept {
  const auto now = Now();
  if (!emitter_ || now >= expires_at_monotonic_ns_) {
    return;
  }
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kResponseBody;
  event.header.sequence_number = NativeProbeSession::Get().NextBrowserSequence();
  event.header.monotonic_time_ns = now;
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
  event.header.artifact_id = artifact_id;
  event.header.payload_size = static_cast<std::uint32_t>(kNativeRequestPayloadSize);
  event.inline_payload = EncodeNativeResponseBodyPayload(summary);
  emitter_(event);
}

}  // namespace reb
