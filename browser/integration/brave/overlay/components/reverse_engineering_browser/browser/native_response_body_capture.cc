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
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "net/http/http_response_headers.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "url/gurl.h"

namespace reb {
namespace {

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
  snapshot_used_ = 0;
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
  auto& artifacts = NativeArtifactCaptureSink::Get();
  NativeArtifactHeader header;
  header.kind = NativeArtifactKind::kResponseBody;
  header.flags = kNativeArtifactFlagSensitive;
  header.session_id = session_id_;
  header.frame_id = parent.frame_id;
  header.artifact_id = artifacts.NextArtifactId();
  header.creator_event_id = parent.sequence_number;
  header.capture_origin = NativeArtifactCaptureOrigin::kNetworkResponse;
  const std::string mime_type =
      response_head.mime_type.empty() ||
              response_head.mime_type.size() > kNativeArtifactMaxMimeTypeBytes
          ? "application/octet-stream"
          : response_head.mime_type;
  // The digest grows by at most one 64 KiB tee read per task.
  NativeArtifactStream stream(artifacts.memory_pool(), header, url, mime_type,
                              kNativeArtifactMaxContentBytes, /*keep_prefix=*/true,
                              /*digest=*/true);
  if (!stream.is_open()) {
    summary.state = NativeResponseBodyState::kNotCapturedTransferRefused;
    Emit(parent, summary, 0);
    return body;
  }
  const Key key{parent.request_id, parent.frame_id};
  if (const auto stale = bodies_.find(key); stale != bodies_.end()) {
    Finish(stale);
  }
  const std::uint64_t capture_id = next_capture_id_++;
  Body& entry = bodies_[key];
  entry.capture_id = capture_id;
  entry.parent = parent;
  entry.summary = summary;
  entry.stream = std::move(stream);
  entry.started_ns = Now();
  entry.snapshot_ns = entry.started_ns;
  bool started = false;
  body = NativeArtifactBodyTee::Create(
      std::move(body),
      base::BindOnce(&NativeResponseBodyCapture::OnEnd, base::Unretained(this), key, capture_id),
      base::BindRepeating(&NativeResponseBodyCapture::OnData, base::Unretained(this), key,
                          capture_id),
      started);
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
  NativeArtifactStream& stream = body.stream;
  const std::uint64_t now = Now();
  if (now >= expires_at_monotonic_ns_) {
    // Flush ran before expiry; a body opened since can no longer be recorded,
    // so neither its bytes nor a checkpoint reach the receiver past it.
    stream.Abort();
    bodies_.erase(found);
    return;
  }
  // The budget counts unique bytes, so it is charged once the digest is known.
  // A sealed or refused stream is no longer open, so Append only counts.
  stream.Append(chunk);
  if (body.sealed || body.refused) {
    return;
  }
  if (stream.state() == NativeArtifactStreamState::kMemoryLimit ||
      stream.state() == NativeArtifactStreamState::kRefused) {
    body.refused = NativeResponseBodyState::kNotCapturedTransferRefused;
    return;
  }
  if (!stream.is_open()) {
    return;
  }
  // Every open body is retained as it arrives, whether or not it declared a
  // length. At the capture limit its kept bytes are final, so it is sealed
  // instead of copied again.
  if (stream.kept() == kNativeResponseBodyCaptureBytes) {
    Seal(found);
  } else {
    TrySnapshot(found, now);
  }
}

void NativeResponseBodyCapture::TrySnapshot(const std::map<Key, Body>::iterator found,
                                            const std::uint64_t now) {
  Body& body = found->second;
  switch (SnapshotDue(body, body.stream.kept(), now)) {
    case SnapshotGate::kReady:
      Snapshot(found);
      return;
    case SnapshotGate::kWithheld:
      // Every later record of the body says a byte bound withheld one.
      body.summary.flags |= kNativeResponseBodySnapshotsWithheld;
      return;
    case SnapshotGate::kTooSoon:
      break;
    case SnapshotGate::kUnchanged:
      return;
  }
  // A burst followed by silence is still published once the spacing allows:
  // one delayed task per body, which finds the body by key and capture ID as
  // the completion wait does, so a body that ended or a new configuration
  // leaves it nothing to do.
  if (body.snapshot_timer || !base::SequencedTaskRunner::HasCurrentDefault()) {
    return;
  }
  body.snapshot_timer = true;
  const std::uint64_t due = NextSnapshotNs(body);
  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce([](Key key, std::uint64_t id) { Get().OnSnapshotTimer(key, id); },
                     found->first, body.capture_id),
      base::Nanoseconds(static_cast<std::int64_t>(due > now ? due - now : 0)));
}

void NativeResponseBodyCapture::OnSnapshotTimer(const Key key, const std::uint64_t capture_id) {
  const auto found = bodies_.find(key);
  if (found == bodies_.end() || found->second.capture_id != capture_id) {
    return;
  }
  Body& body = found->second;
  body.snapshot_timer = false;
  const std::uint64_t now = Now();
  // A body whose tee ended waits for its record; past expiry nothing is sent.
  if (body.tee_done || body.sealed || body.refused || !body.stream.is_open() ||
      now >= expires_at_monotonic_ns_) {
    return;
  }
  TrySnapshot(found, now);
}

std::uint64_t NativeResponseBodyCapture::NextSnapshotNs(const Body& body) noexcept {
  // The first t with t - last >= max(1 s, (t - start) / 32): at least a
  // second after the last, and (32 * (last - start)) / 31 after the start.
  const std::uint64_t last = body.snapshot_ns - body.started_ns;
  const std::uint64_t spaced =
      (last * kNativeResponseBodySnapshotAgeDivisor + kNativeResponseBodySnapshotAgeDivisor - 2) /
      (kNativeResponseBodySnapshotAgeDivisor - 1);
  return body.started_ns + std::max(last + kNativeResponseBodySnapshotFirstNs, spaced);
}

NativeResponseBodyCapture::SnapshotGate NativeResponseBodyCapture::SnapshotDue(
    const Body& body,
    const std::uint64_t size,
    const std::uint64_t now) const noexcept {
  // The partial index is 16 bits; the age spacing keeps a body far below it.
  if (size <= body.snapshot_size ||
      body.partials >= std::numeric_limits<std::uint16_t>::max() - 1) {
    return SnapshotGate::kUnchanged;
  }
  const std::uint64_t age = now - body.started_ns;
  if (now - body.snapshot_ns <
      std::max(kNativeResponseBodySnapshotFirstNs, age / kNativeResponseBodySnapshotAgeDivisor)) {
    return SnapshotGate::kTooSoon;
  }
  // A snapshot copies all `size` kept bytes. A body may spend a quarter of its
  // allowance at once, and the rest as the larger of the share of the session
  // left when it opened that has passed and the share of the capture limit it
  // has filled. The body opened and is still open before expiry, so the span
  // is not zero.
  const std::uint64_t allowance = budget_ / kNativeResponseBodySnapshotBodyDivisor;
  const std::uint64_t span = expires_at_monotonic_ns_ - body.started_ns;
  const double share =
      std::max(std::min(1.0, static_cast<double>(age) / static_cast<double>(span)),
               static_cast<double>(size) / static_cast<double>(kNativeResponseBodyCaptureBytes));
  const std::uint64_t paced =
      allowance / 4 +
      static_cast<std::uint64_t>(static_cast<double>(allowance - allowance / 4) * share);
  return body.copied + size <= paced &&
                 snapshot_used_ + size <= budget_ / kNativeResponseBodySnapshotSessionDivisor &&
                 size <= budget_ - std::min(budget_, used_)
             ? SnapshotGate::kReady
             : SnapshotGate::kWithheld;
}

void NativeResponseBodyCapture::OnEnd(const Key key,
                                      const std::uint64_t capture_id,
                                      const NativeArtifactBodyEnd end) {
  const auto found = bodies_.find(key);
  if (found == bodies_.end() || found->second.capture_id != capture_id) {
    return;
  }
  found->second.tee_done = true;
  found->second.end = end;
  if (end == NativeArtifactBodyEnd::kTargetClosed || found->second.completion_known ||
      !base::SequencedTaskRunner::HasCurrentDefault()) {
    Finish(found);
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
    Finish(found);
  }
}

void NativeResponseBodyCapture::OnCompletionTimeout(const Key key, const std::uint64_t capture_id) {
  const auto found = bodies_.find(key);
  if (found != bodies_.end() && found->second.capture_id == capture_id && found->second.tee_done) {
    Finish(found);
  }
}

void NativeResponseBodyCapture::Finish(const std::map<Key, Body>::iterator found) {
  Body body = std::move(found->second);
  bodies_.erase(found);
  NativeArtifactStream& stream = body.stream;
  NativeResponseBodySummary summary = body.summary;
  summary.body_length = stream.observed();
  const bool open = !body.tee_done;
  const bool cancelled =
      body.end == NativeArtifactBodyEnd::kTargetClosed || body.error_code == kErrorAborted;
  const bool aborted =
      !cancelled && (body.end == NativeArtifactBodyEnd::kSourceFailed || body.error_code != 0);
  if (body.refused) {
    stream.Abort();
    Refuse(body.parent, summary, *body.refused);
    return;
  }
  // A sealed stream holds the capture limit's prefix; later bytes were only
  // counted, so the observed length says whether the body was cut.
  const bool truncated = stream.observed() > stream.kept();
  if (open) {
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
                    : truncated              ? NativeResponseBodyState::kCapturedTruncated
                                             : NativeResponseBodyState::kCaptured;
  }
  const auto name = [&summary](const Retained& retained) {
    summary.sha256 = retained.digest;
    summary.captured_length = retained.size;
    if (retained.shared) {
      summary.flags |= kNativeResponseBodyShared;
    }
  };
  if (body.sealed) {
    name(*body.sealed);
    Emit(body.parent, summary, body.sealed->artifact_id);
    return;
  }
  if (stream.kept() == 0) {
    stream.Abort();
    if (open) {
      // Capture ended before any byte arrived.
      Refuse(body.parent, summary, NativeResponseBodyState::kNotCapturedArtifactUnavailable);
      return;
    }
    summary.partial_index = 0;
    Emit(body.parent, summary, 0);
    return;
  }
  const Retained retained = Retain(body.parent, stream);
  if (retained.refused) {
    Refuse(body.parent, summary, *retained.refused);
    return;
  }
  name(retained);
  Emit(body.parent, summary, retained.artifact_id);
}

NativeResponseBodyCapture::Retained NativeResponseBodyCapture::Retain(
    const NativeProbeHeader& parent,
    NativeArtifactStream& stream) {
  Retained retained;
  retained.digest = stream.Digest();
  retained.size = stream.kept();
  auto& artifacts = NativeArtifactCaptureSink::Get();
  if (!artifacts.IsEnabled()) {
    stream.Abort();
    retained.refused = NativeResponseBodyState::kNotCapturedArtifactUnavailable;
    return retained;
  }
  // The receiver stores one blob per digest; a repeat names the first artifact
  // and charges nothing. The receiver discards the aborted stream.
  if (const auto shared = digests_.find(retained.digest); shared != digests_.end()) {
    stream.Abort();
    retained.artifact_id = shared->second;
    retained.shared = true;
    return retained;
  }
  if (retained.size > budget_ - std::min(budget_, used_)) {
    stream.Abort();
    retained.refused = NativeResponseBodyState::kNotCapturedSessionBudget;
    return retained;
  }
  const std::uint64_t artifact_id = stream.artifact_id();
  if (!stream.End()) {
    retained.refused = NativeResponseBodyState::kNotCapturedTransferRefused;
    return retained;
  }
  used_ += retained.size;
  artifacts.TrackResponseBody(artifact_id, parent.request_id, parent.frame_id,
                              parent.sequence_number);
  queued_.emplace(artifact_id,
                  Queued{retained.digest, static_cast<std::size_t>(retained.size), false});
  if (digests_.size() < kDigestLimit) {
    digests_.emplace(retained.digest, artifact_id);
  }
  retained.artifact_id = artifact_id;
  return retained;
}

void NativeResponseBodyCapture::Seal(const std::map<Key, Body>::iterator found) {
  Body& body = found->second;
  Retained retained = Retain(body.parent, body.stream);
  if (retained.refused) {
    body.refused = retained.refused;
    return;
  }
  NativeResponseBodySummary summary = body.summary;
  summary.state = NativeResponseBodyState::kPartial;
  summary.partial_index = ++body.partials;
  summary.body_length = body.stream.observed();
  summary.captured_length = retained.size;
  summary.sha256 = retained.digest;
  if (retained.shared) {
    summary.flags |= kNativeResponseBodyShared;
  }
  body.snapshot_ns = Now();
  body.snapshot_size = retained.size;
  const std::uint64_t artifact_id = retained.artifact_id;
  body.sealed = std::move(retained);
  Emit(body.parent, summary, artifact_id);
}

void NativeResponseBodyCapture::Snapshot(const std::map<Key, Body>::iterator found) {
  Body& body = found->second;
  NativeArtifactStream& stream = body.stream;
  const std::uint64_t size = stream.kept();
  // The receiver copies what it already holds; the browser holds nothing new.
  auto& artifacts = NativeArtifactCaptureSink::Get();
  const std::uint64_t snapshot_id = artifacts.NextArtifactId();
  if (!stream.Checkpoint(snapshot_id)) {
    return;
  }
  used_ += size;
  snapshot_used_ += size;
  body.copied += size;
  NativeResponseBodySummary summary = body.summary;
  summary.state = NativeResponseBodyState::kPartial;
  summary.partial_index = ++body.partials;
  summary.body_length = stream.observed();
  summary.captured_length = size;
  summary.sha256 = stream.Digest();
  body.snapshot_ns = Now();
  body.snapshot_size = size;
  artifacts.TrackResponseBody(snapshot_id, body.parent.request_id, body.parent.frame_id,
                              body.parent.sequence_number);
  queued_.emplace(snapshot_id, Queued{summary.sha256, static_cast<std::size_t>(size), true});
  Emit(body.parent, summary, snapshot_id);
}

void NativeResponseBodyCapture::Refund(const std::uint64_t bytes) noexcept {
  used_ -= std::min(used_, bytes);
}

bool NativeResponseBodyCapture::OnStreamRefused(const std::uint64_t artifact_id) noexcept {
  for (auto& [key, body] : bodies_) {
    if (body.stream.artifact_id() == artifact_id && body.stream.is_open()) {
      body.stream.Abort();
      body.refused = NativeResponseBodyState::kNotCapturedTransferRefused;
      return true;
    }
  }
  return false;
}

void NativeResponseBodyCapture::OnTransferCompleted(const std::uint64_t artifact_id,
                                                    const bool accepted) noexcept {
  const auto found = queued_.find(artifact_id);
  if (found == queued_.end()) {
    return;
  }
  const Queued queued = found->second;
  queued_.erase(found);
  if (accepted) {
    return;
  }
  // Nothing was stored, so the bytes are refunded and a repeat is sent again.
  Refund(queued.size);
  if (queued.snapshot) {
    snapshot_used_ -= std::min<std::uint64_t>(snapshot_used_, queued.size);
  }
  const Digest& digest = queued.digest;
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
    Finish(bodies_.begin());
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
