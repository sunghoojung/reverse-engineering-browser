// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_stream.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"

namespace reb {
namespace {

constexpr std::size_t kChunk = kNativeArtifactStreamChunkBytes;

}  // namespace

NativeArtifactStream::NativeArtifactStream(NativeArtifactMemoryPool& pool,
                                           const NativeArtifactHeader& header,
                                           std::string url,
                                           std::string mime_type,
                                           const std::size_t limit,
                                           const bool keep_prefix,
                                           const bool digest)
    : pool_(&pool), limit_(limit), keep_prefix_(keep_prefix) {
  if (digest) {
    hasher_.emplace(crypto::hash::HashKind::kSha256);
  }
  auto transfer = std::make_unique<NativeArtifactTransfer>();
  transfer->op = NativeArtifactTransferOp::kOpen;
  transfer->header = header;
  transfer->header.protocol_version = kNativeArtifactStreamProtocolVersion;
  transfer->header.content_size = 0;
  transfer->header.expected_sha256 = {};
  transfer->header.url_size = static_cast<std::uint32_t>(url.size());
  transfer->header.mime_type_size = static_cast<std::uint32_t>(mime_type.size());
  transfer->url = std::move(url);
  transfer->mime_type = std::move(mime_type);
  state_ = NativeArtifactStreamState::kRefused;
  if (NativeArtifactSocketClient::Get().Enqueue(std::move(transfer))) {
    session_ = header.session_id;
    artifact_id_ = header.artifact_id;
    state_ = NativeArtifactStreamState::kOpen;
  }
}

NativeArtifactStream::NativeArtifactStream(NativeArtifactStream&& other) noexcept
    : pool_(other.pool_),
      session_(std::exchange(other.session_, 0)),
      artifact_id_(std::exchange(other.artifact_id_, 0)),
      limit_(other.limit_),
      keep_prefix_(other.keep_prefix_),
      truncated_(other.truncated_),
      state_(std::exchange(other.state_, NativeArtifactStreamState::kAborted)),
      observed_(other.observed_),
      kept_(other.kept_),
      pending_(std::move(other.pending_)),
      reservation_(std::move(other.reservation_)),
      hasher_(std::move(other.hasher_)) {}

NativeArtifactStream& NativeArtifactStream::operator=(NativeArtifactStream&& other) noexcept {
  if (this != &other) {
    Abort();
    pool_ = other.pool_;
    session_ = std::exchange(other.session_, 0);
    artifact_id_ = std::exchange(other.artifact_id_, 0);
    limit_ = other.limit_;
    keep_prefix_ = other.keep_prefix_;
    truncated_ = other.truncated_;
    state_ = std::exchange(other.state_, NativeArtifactStreamState::kAborted);
    observed_ = other.observed_;
    kept_ = other.kept_;
    pending_ = std::move(other.pending_);
    reservation_ = std::move(other.reservation_);
    hasher_ = std::move(other.hasher_);
  }
  return *this;
}

NativeArtifactStream::~NativeArtifactStream() {
  Abort();
}

void NativeArtifactStream::Append(const std::span<const std::uint8_t> data) {
  static_cast<void>(Take(data, false));
}

std::size_t NativeArtifactStream::Offer(const std::span<const std::uint8_t> data) {
  return Take(data, true);
}

bool NativeArtifactStream::Grow(const std::size_t bytes) noexcept {
  if (!reservation_.is_valid()) {
    reservation_ = NativeArtifactReservation::Acquire(*pool_, bytes);
    return reservation_.is_valid();
  }
  return reservation_.GrowTo(bytes);
}

std::size_t NativeArtifactStream::Take(const std::span<const std::uint8_t> data, const bool wait) {
  const auto skip = [&](const std::size_t consumed) {
    observed_ += data.size() - consumed;
    return data.size();
  };
  if (state_ != NativeArtifactStreamState::kOpen) {
    return skip(0);
  }
  if (data.size() > limit_ - kept_ && !keep_prefix_) {
    Fail(NativeArtifactStreamState::kTooLarge);
    return skip(0);
  }
  std::size_t consumed = 0;
  while (consumed < data.size()) {
    if (kept_ == limit_) {
      // Past the prefix, bytes are counted and not kept.
      truncated_ = true;
      return skip(consumed);
    }
    const std::size_t part = std::min({data.size() - consumed, kChunk - pending_.size(),
                                       static_cast<std::size_t>(limit_ - kept_)});
    const std::size_t needed = pending_.size() + part;
    if (needed > reservation_.bytes() &&
        !Grow(std::min(kChunk, std::max(needed, 2 * reservation_.bytes()))) && !Grow(needed)) {
      if (wait) {
        return consumed;
      }
      Fail(NativeArtifactStreamState::kMemoryLimit);
      return skip(consumed);
    }
    const auto piece = data.subspan(consumed, part);
    pending_.insert(pending_.end(), piece.begin(), piece.end());
    if (hasher_) {
      hasher_->Update(piece);
    }
    kept_ += part;
    observed_ += part;
    consumed += part;
    if (pending_.size() == kChunk && !Flush()) {
      return skip(consumed);
    }
  }
  return consumed;
}

bool NativeArtifactStream::Flush() {
  if (pending_.empty()) {
    return true;
  }
  reservation_.ShrinkTo(pending_.size());
  auto transfer = std::make_unique<NativeArtifactTransfer>();
  transfer->op = NativeArtifactTransferOp::kStream;
  transfer->frame.op = NativeArtifactStreamOp::kData;
  transfer->frame.data_size = static_cast<std::uint32_t>(pending_.size());
  transfer->frame.session_id = session_;
  transfer->frame.artifact_id = artifact_id_;
  transfer->content = std::move(pending_);
  transfer->reservation = std::move(reservation_);
  pending_ = {};
  if (!NativeArtifactSocketClient::Get().Enqueue(std::move(transfer))) {
    Fail(NativeArtifactStreamState::kRefused);
    return false;
  }
  return true;
}

bool NativeArtifactStream::Control(const NativeArtifactStreamOp op, const std::uint64_t value) {
  auto transfer = std::make_unique<NativeArtifactTransfer>();
  transfer->op = NativeArtifactTransferOp::kStream;
  transfer->frame.op = op;
  transfer->frame.session_id = session_;
  transfer->frame.artifact_id = artifact_id_;
  transfer->frame.value = value;
  if (op != NativeArtifactStreamOp::kAbort) {
    transfer->frame.content_size = kept_;
    transfer->frame.expected_sha256 = Digest();
  }
  return NativeArtifactSocketClient::Get().Enqueue(std::move(transfer));
}

bool NativeArtifactStream::Checkpoint(const std::uint64_t snapshot_id) {
  if (state_ != NativeArtifactStreamState::kOpen || !Flush()) {
    return false;
  }
  return Control(NativeArtifactStreamOp::kCheckpoint, snapshot_id);
}

bool NativeArtifactStream::End(const std::uint64_t creator_event_id) {
  if (state_ != NativeArtifactStreamState::kOpen || !Flush()) {
    return false;
  }
  if (!Control(NativeArtifactStreamOp::kEnd, creator_event_id)) {
    Fail(NativeArtifactStreamState::kRefused);
    return false;
  }
  state_ = NativeArtifactStreamState::kEnded;
  return true;
}

void NativeArtifactStream::Abort() {
  if (state_ == NativeArtifactStreamState::kOpen) {
    Fail(NativeArtifactStreamState::kAborted);
  }
}

void NativeArtifactStream::Fail(const NativeArtifactStreamState state) {
  pending_ = {};
  reservation_.Reset();
  if (state_ == NativeArtifactStreamState::kOpen) {
    static_cast<void>(Control(NativeArtifactStreamOp::kAbort, 0));
  }
  state_ = state;
}

std::array<std::uint8_t, 32> NativeArtifactStream::Digest() const {
  std::array<std::uint8_t, 32> digest{};
  if (hasher_) {
    crypto::hash::Hasher copy = *hasher_;
    copy.Finish(digest);
  }
  return digest;
}

}  // namespace reb
