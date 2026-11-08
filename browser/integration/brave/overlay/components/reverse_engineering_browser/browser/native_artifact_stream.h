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
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_memory_pool.h"
#include "crypto/hash.h"

namespace reb {

enum class NativeArtifactStreamState : std::uint8_t {
  kOpen,
  // Past the limit without keep_prefix.
  kTooLarge,
  // The in-flight pool refused a data frame.
  kMemoryLimit,
  // The queue refused a frame, or the open header.
  kRefused,
  kEnded,
  kAborted,
};

// Producer half of one version 2 artifact stream
// (docs/architecture/artifact-transfer-channel.md). Bytes are coalesced into
// data frames of at most 64 KiB; each frame holds its pool share until the
// writer drops it, so the pool bounds bytes in flight, not bodies. One owner
// at a time; it may move between sequences.
class NativeArtifactStream final {
 public:
  NativeArtifactStream() = default;
  // Queues the open header. `digest` keeps a SHA-256 of the kept bytes.
  NativeArtifactStream(NativeArtifactMemoryPool& pool,
                       const NativeArtifactHeader& header,
                       std::string url,
                       std::string mime_type,
                       std::size_t limit,
                       bool keep_prefix,
                       bool digest);
  NativeArtifactStream(NativeArtifactStream&& other) noexcept;
  NativeArtifactStream& operator=(NativeArtifactStream&& other) noexcept;
  NativeArtifactStream(const NativeArtifactStream&) = delete;
  NativeArtifactStream& operator=(const NativeArtifactStream&) = delete;
  // An open stream is aborted.
  ~NativeArtifactStream();

  void Append(std::span<const std::uint8_t> data);
  // Like Append, but a full pool leaves the stream open: returns the bytes
  // taken, so a reader that may wait retries with the rest.
  [[nodiscard]] std::size_t Offer(std::span<const std::uint8_t> data);
  // Publishes the kept bytes so far as `snapshot_id`; the stream stays open.
  [[nodiscard]] bool Checkpoint(std::uint64_t snapshot_id);
  // `creator_event_id` names a creator the open header left zero.
  [[nodiscard]] bool End(std::uint64_t creator_event_id = 0);
  void Abort();

  [[nodiscard]] NativeArtifactStreamState state() const noexcept { return state_; }
  [[nodiscard]] bool is_open() const noexcept { return state_ == NativeArtifactStreamState::kOpen; }
  [[nodiscard]] std::uint64_t artifact_id() const noexcept { return session_ ? artifact_id_ : 0; }
  // Every appended byte, kept or not.
  [[nodiscard]] std::uint64_t observed() const noexcept { return observed_; }
  [[nodiscard]] std::uint64_t kept() const noexcept { return kept_; }
  [[nodiscard]] bool truncated() const noexcept { return truncated_; }
  // SHA-256 of the kept bytes so far; zero without `digest`.
  [[nodiscard]] std::array<std::uint8_t, 32> Digest() const;

 private:
  [[nodiscard]] std::size_t Take(std::span<const std::uint8_t> data, bool wait);
  [[nodiscard]] bool Grow(std::size_t bytes) noexcept;
  [[nodiscard]] bool Flush();
  [[nodiscard]] bool Control(NativeArtifactStreamOp op, std::uint64_t value);
  void Fail(NativeArtifactStreamState state);

  NativeArtifactMemoryPool* pool_ = nullptr;
  std::uint64_t session_ = 0;
  std::uint64_t artifact_id_ = 0;
  std::size_t limit_ = 0;
  bool keep_prefix_ = false;
  bool truncated_ = false;
  NativeArtifactStreamState state_ = NativeArtifactStreamState::kAborted;
  std::uint64_t observed_ = 0;
  std::uint64_t kept_ = 0;
  std::vector<std::uint8_t> pending_;
  NativeArtifactReservation reservation_;
  std::optional<crypto::hash::Hasher> hasher_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_STREAM_H_
