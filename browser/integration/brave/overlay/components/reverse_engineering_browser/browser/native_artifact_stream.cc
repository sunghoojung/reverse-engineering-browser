// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_stream.h"

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include "base/location.h"
#include "base/memory/scoped_refptr.h"
#include "base/no_destructor.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/thread_annotations.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"

namespace reb {
namespace {

constexpr std::size_t kChunk = kNativeArtifactStreamChunkBytes;

// Streams waiting for pool space, from any sequence. The pool's hook wakes
// them all at once; a stream that still finds no room waits again.
struct SpaceWaiters final {
  base::Lock lock;
  std::vector<std::pair<scoped_refptr<base::SequencedTaskRunner>, base::OnceClosure>> waiting
      GUARDED_BY(lock);
};

SpaceWaiters& Waiters() {
  static base::NoDestructor<SpaceWaiters> waiters;
  return *waiters;
}

}  // namespace

NativeArtifactStream::NativeArtifactStream() = default;

NativeArtifactStream::NativeArtifactStream(NativeArtifactMemoryPool& pool,
                                           const NativeArtifactHeader& header,
                                           std::string url,
                                           std::string mime_type,
                                           const bool digest)
    : pool_(&pool) {
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
  // The metadata already exists, so it may use the whole-item headroom.
  transfer->reservation = NativeArtifactReservation::Acquire(pool, url.size() + mime_type.size(),
                                                             NativeArtifactPoolUse::kWhole);
  if (!transfer->reservation.is_valid()) {
    state_ = NativeArtifactStreamState::kMemoryLimit;
    return;
  }
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
      state_(std::exchange(other.state_, NativeArtifactStreamState::kAborted)),
      observed_(other.observed_),
      kept_(other.kept_),
      hasher_(std::move(other.hasher_)) {}

NativeArtifactStream& NativeArtifactStream::operator=(NativeArtifactStream&& other) noexcept {
  if (this != &other) {
    Abort();
    pool_ = other.pool_;
    session_ = std::exchange(other.session_, 0);
    artifact_id_ = std::exchange(other.artifact_id_, 0);
    state_ = std::exchange(other.state_, NativeArtifactStreamState::kAborted);
    observed_ = other.observed_;
    kept_ = other.kept_;
    hasher_ = std::move(other.hasher_);
  }
  return *this;
}

NativeArtifactStream::~NativeArtifactStream() {
  Abort();
}

std::size_t NativeArtifactStream::Offer(const std::span<const std::uint8_t> data) {
  if (state_ != NativeArtifactStreamState::kOpen) {
    observed_ += data.size();
    return data.size();
  }
  std::size_t taken = 0;
  while (taken < data.size()) {
    const auto piece = data.subspan(taken, std::min(kChunk, data.size() - taken));
    auto reservation =
        NativeArtifactReservation::Acquire(*pool_, piece.size(), NativeArtifactPoolUse::kStream);
    if (!reservation.is_valid()) {
      return taken;
    }
    auto transfer = std::make_unique<NativeArtifactTransfer>();
    transfer->op = NativeArtifactTransferOp::kStream;
    transfer->frame.op = NativeArtifactStreamOp::kData;
    transfer->frame.data_size = static_cast<std::uint32_t>(piece.size());
    transfer->frame.session_id = session_;
    transfer->frame.artifact_id = artifact_id_;
    transfer->content.assign(piece.begin(), piece.end());
    transfer->reservation = std::move(reservation);
    // The copy is hashed, not the source, which may be memory another
    // process can still write.
    if (hasher_) {
      hasher_->Update(transfer->content);
    }
    if (!NativeArtifactSocketClient::Get().Enqueue(std::move(transfer))) {
      Fail(NativeArtifactStreamState::kRefused);
      observed_ += data.size() - taken;
      return data.size();
    }
    kept_ += piece.size();
    observed_ += piece.size();
    taken += piece.size();
  }
  return taken;
}

void NativeArtifactStream::WaitForSpace(base::OnceClosure resume) {
  {
    SpaceWaiters& waiters = Waiters();
    base::AutoLock lock(waiters.lock);
    waiters.waiting.emplace_back(base::SequencedTaskRunner::GetCurrentDefault(), std::move(resume));
  }
  if (state_ != NativeArtifactStreamState::kOpen || !pool_->ArmSpaceHook()) {
    OnPoolSpace();
  }
}

void NativeArtifactStream::OnPoolSpace() noexcept {
  std::vector<std::pair<scoped_refptr<base::SequencedTaskRunner>, base::OnceClosure>> woken;
  {
    SpaceWaiters& waiters = Waiters();
    base::AutoLock lock(waiters.lock);
    woken.swap(waiters.waiting);
  }
  for (auto& [runner, resume] : woken) {
    runner->PostTask(FROM_HERE, std::move(resume));
  }
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
  if (state_ != NativeArtifactStreamState::kOpen) {
    return false;
  }
  return Control(NativeArtifactStreamOp::kCheckpoint, snapshot_id);
}

bool NativeArtifactStream::End(const std::uint64_t creator_event_id) {
  if (state_ != NativeArtifactStreamState::kOpen) {
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
