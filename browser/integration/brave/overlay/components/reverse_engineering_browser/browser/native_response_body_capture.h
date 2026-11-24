// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_RESPONSE_BODY_CAPTURE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_RESPONSE_BODY_CAPTURE_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "base/no_destructor.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_stream.h"
#include "brave/components/reverse_engineering_browser/common/native_network_response_body.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "mojo/public/cpp/system/data_pipe.h"

namespace network {
struct ResourceRequest;
namespace mojom {
class URLResponseHead;
}
}  // namespace network

namespace reb {

// Retains response bodies other than scripts and Wasm through the existing
// response tee (protocol/native-network-v3.md), streamed to the receiver as
// they arrive. It shares the artifact sink's in-flight pool, artifact IDs and
// ACK path. UI sequence only.
class NativeResponseBodyCapture final {
 public:
  static NativeResponseBodyCapture& Get();

  NativeResponseBodyCapture(const NativeResponseBodyCapture&) = delete;
  NativeResponseBodyCapture& operator=(const NativeResponseBodyCapture&) = delete;

  // Called by the artifact sink's SetEmitter after it flushed this capture.
  void Configure(NativeProbeEmitter emitter,
                 std::uint64_t session_id,
                 std::uint64_t category_mask,
                 std::uint64_t expires_at_monotonic_ns,
                 const NativeResponseBodyPolicy& policy) noexcept;
  [[nodiscard]] bool IsEnabled() const noexcept { return enabled_.load(std::memory_order_relaxed); }

  // The response_started record this response's body record is a child of.
  void NoteResponseStarted(const NativeProbeHeader& header) noexcept;
  [[nodiscard]] mojo::ScopedDataPipeConsumerHandle MaybeCapture(
      std::uint64_t creator_event_id,
      const network::ResourceRequest& request,
      const network::mojom::URLResponseHead& response_head,
      mojo::ScopedDataPipeConsumerHandle body);
  // The loader's completion status; the source pipe closing alone is not.
  void OnCompleted(std::uint64_t request_id, std::uint64_t frame_id, int error_code) noexcept;
  void OnTransferCompleted(std::uint64_t artifact_id, bool accepted) noexcept;
  // The receiver refused, or the channel lost, a stream whose body is still
  // open; it becomes not_captured_disk_reserve when the receiver's disk reserve
  // refused it, else not_captured_transfer_refused. False for any other ID.
  bool OnStreamRefused(std::uint64_t artifact_id, NativeArtifactReceiveStatus status) noexcept;
  // Capture end: open bodies become partial records while the session can
  // still record them; finished bodies waiting for completion are retained.
  void Flush() noexcept;

 private:
  friend class base::NoDestructor<NativeResponseBodyCapture>;
  using Key = std::pair<std::uint64_t, std::uint64_t>;
  using Digest = std::array<std::uint8_t, 32>;

  // Bytes the receiver will hold for a record: a queued stream, or the
  // earlier artifact with the same digest. `refused` says why there are none.
  struct Retained final {
    std::uint64_t artifact_id = 0;
    Digest digest{};
    std::uint64_t size = 0;
    bool shared = false;
    std::optional<NativeResponseBodyState> refused;
  };

  struct Body final {
    std::uint64_t capture_id = 0;
    NativeProbeHeader parent{};
    NativeResponseBodySummary summary;
    NativeArtifactStream stream;
    // Why the bytes stopped being retained, if they did.
    std::optional<NativeResponseBodyState> refused;
    std::uint16_t partials = 0;
    std::uint64_t started_ns = 0;
    std::uint64_t snapshot_ns = 0;
    std::uint64_t snapshot_size = 0;
    // A delayed task will retry a snapshot the spacing held back.
    bool snapshot_timer = false;
    // Bytes every snapshot of this body copied, against its snapshot bound.
    std::uint64_t copied = 0;
    bool tee_done = false;
    bool completion_known = false;
    NativeArtifactBodyEnd end = NativeArtifactBodyEnd::kSourceClosed;
    int error_code = 0;
  };

  NativeResponseBodyCapture();
  ~NativeResponseBodyCapture();

  // The tee's observer: takes what the pool has room for and waits for the rest.
  std::size_t OnData(Key key,
                     std::uint64_t capture_id,
                     std::span<const std::uint8_t> chunk,
                     base::OnceClosure resume);
  void OnEnd(Key key, std::uint64_t capture_id, NativeArtifactBodyEnd end);
  void OnCompletionTimeout(Key key, std::uint64_t capture_id);
  // Ends the stream and records the body; an open body becomes partial.
  void Finish(std::map<Key, Body>::iterator found);
  // Whether a snapshot of `size` kept bytes may be taken now.
  enum class SnapshotGate : std::uint8_t { kUnchanged, kTooSoon, kWithheld, kReady };
  [[nodiscard]] static SnapshotGate SnapshotDue(const Body& body,
                                                std::uint64_t size,
                                                std::uint64_t now) noexcept;
  // The earliest time the spacing allows the next snapshot.
  [[nodiscard]] static std::uint64_t NextSnapshotNs(const Body& body) noexcept;
  // Takes the snapshot, waits for the spacing, or marks it withheld.
  void TrySnapshot(std::map<Key, Body>::iterator found, std::uint64_t now);
  void OnSnapshotTimer(Key key, std::uint64_t capture_id);
  void Snapshot(std::map<Key, Body>::iterator found);
  // Ends `stream` as an artifact, or names an earlier one with its digest.
  [[nodiscard]] Retained Retain(const NativeProbeHeader& parent, NativeArtifactStream& stream);
  // Records why the bytes were not retained, keeping the body's metadata.
  void Refuse(const NativeProbeHeader& parent,
              NativeResponseBodySummary summary,
              NativeResponseBodyState state) noexcept;
  void Emit(const NativeProbeHeader& parent,
            const NativeResponseBodySummary& summary,
            std::uint64_t artifact_id) noexcept;

  std::atomic<bool> enabled_{false};
  NativeProbeEmitter emitter_ = nullptr;
  std::uint64_t session_id_ = 0;
  std::uint64_t expires_at_monotonic_ns_ = 0;
  std::uint64_t generation_ = 0;
  NativeProbeHeader last_response_started_{};
  std::uint64_t next_capture_id_ = 1;
  std::map<Key, Body> bodies_;
  // The artifact holding each retained digest; bounded, past it repeats are sent again.
  std::map<Digest, std::uint64_t> digests_;
  // Queued artifacts awaiting their ACK, by digest, so a refused one is sent again.
  std::map<std::uint64_t, Digest> queued_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_RESPONSE_BODY_CAPTURE_H_
