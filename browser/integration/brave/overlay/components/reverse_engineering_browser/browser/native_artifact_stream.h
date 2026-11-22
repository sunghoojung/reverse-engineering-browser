// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_STREAM_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_STREAM_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_memory_pool.h"
#include "crypto/hash.h"

namespace reb {

enum class NativeArtifactStreamState : std::uint8_t {
  kOpen,
  // The in-flight pool had no room for the open header's metadata.
  kMemoryLimit,
  // The queue refused a frame, or the open header: the channel is gone.
  kRefused,
  kEnded,
  kAborted,
};

// Producer half of one version 2 artifact stream
// (docs/architecture/artifact-transfer-channel.md). A stream has no size
// limit. Offered bytes are queued at once as data frames of at most 64 KiB;
// each frame holds its pool share until the writer drops it, so the pool
// bounds bytes in flight, not bodies, and every byte it holds is draining.
// One owner at a time; it may move between sequences.
class NativeArtifactStream final {
 public:
  NativeArtifactStream();
  // Queues the open header. `digest` keeps a SHA-256 of the bytes.
  NativeArtifactStream(NativeArtifactMemoryPool& pool,
                       const NativeArtifactHeader& header,
                       std::string url,
                       std::string mime_type,
                       bool digest);
  NativeArtifactStream(NativeArtifactStream&& other) noexcept;
  NativeArtifactStream& operator=(NativeArtifactStream&& other) noexcept;
  NativeArtifactStream(const NativeArtifactStream&) = delete;
  NativeArtifactStream& operator=(const NativeArtifactStream&) = delete;
  // An open stream is aborted.
  ~NativeArtifactStream();

  // Queues as many of `data`'s leading bytes as the in-flight pool has room
  // for and returns how many it took. Fewer than all means the pool is full:
  // the caller waits with WaitForSpace() and offers the rest, holding its
  // source rather than a copy. A stream that is not open takes every byte and
  // keeps none.
  [[nodiscard]] std::size_t Offer(std::span<const std::uint8_t> data);
  // Runs `resume` on the calling sequence once a stream may queue again: at
  // once when it already may, or when it is not open.
  void WaitForSpace(base::OnceClosure resume);
  // Publishes the bytes so far as `snapshot_id`; the stream stays open.
  [[nodiscard]] bool Checkpoint(std::uint64_t snapshot_id);
  // `creator_event_id` names a creator the open header left zero.
  [[nodiscard]] bool End(std::uint64_t creator_event_id = 0);
  void Abort();

  // The pool's space hook: posts every waiting stream's resume.
  static void OnPoolSpace() noexcept;

  [[nodiscard]] NativeArtifactStreamState state() const noexcept { return state_; }
  [[nodiscard]] bool is_open() const noexcept { return state_ == NativeArtifactStreamState::kOpen; }
  [[nodiscard]] std::uint64_t artifact_id() const noexcept { return session_ ? artifact_id_ : 0; }
  // Every offered byte, kept or not.
  [[nodiscard]] std::uint64_t observed() const noexcept { return observed_; }
  [[nodiscard]] std::uint64_t kept() const noexcept { return kept_; }
  // SHA-256 of the kept bytes so far; zero without `digest`.
  [[nodiscard]] std::array<std::uint8_t, 32> Digest() const;

 private:
  [[nodiscard]] bool Control(NativeArtifactStreamOp op, std::uint64_t value);
  void Fail(NativeArtifactStreamState state);

  raw_ptr<NativeArtifactMemoryPool> pool_ = nullptr;
  std::uint64_t session_ = 0;
  std::uint64_t artifact_id_ = 0;
  NativeArtifactStreamState state_ = NativeArtifactStreamState::kAborted;
  std::uint64_t observed_ = 0;
  std::uint64_t kept_ = 0;
  std::optional<crypto::hash::Hasher> hasher_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_STREAM_H_
