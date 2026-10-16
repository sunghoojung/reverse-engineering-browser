// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_RUNTIME_SNAPSHOT_QUEUE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_RUNTIME_SNAPSHOT_QUEUE_H_

#include <array>
#include <cstddef>
#include <optional>
#include <utility>

namespace reb {
// Owns at most sixteen payloads until the next native task checkpoint. Payloads
// own the original allocator identity and safe handles, never borrowed pointers.
// Retained bytes include both the buffer and source; this bound is independent
// from the renderer's admitted-snapshot session cap.
template <typename Payload>
class NativeRuntimeSnapshotQueue final {
 public:
  static constexpr std::size_t kMaxEntries = 16;
  static constexpr std::size_t kMaxBytes = 32U * 1024U * 1024U;
  bool CanRetain(std::size_t bytes) const noexcept {
    return count_ < kMaxEntries && bytes <= kMaxBytes - bytes_;
  }
  bool Push(Payload payload, std::size_t bytes) {
    if (!CanRetain(bytes))
      return false;
    for (auto& entry : entries_) {
      if (!entry.payload) {
        entry.payload.emplace(std::move(payload));
        entry.bytes = bytes;
        ++count_;
        bytes_ += bytes;
        return true;
      }
    }
    return false;
  }
  template <typename Visitor>
  void Drain(Visitor visitor) {
    for (auto& entry : entries_) {
      if (!entry.payload)
        continue;
      Payload payload = std::move(*entry.payload);
      entry.payload.reset();
      bytes_ -= entry.bytes;
      --count_;
      visitor(std::move(payload));
    }
  }
  std::size_t size() const noexcept { return count_; }
  std::size_t bytes() const noexcept { return bytes_; }

 private:
  struct Entry {
    std::optional<Payload> payload;
    std::size_t bytes = 0;
  };
  std::array<Entry, kMaxEntries> entries_{};
  std::size_t count_ = 0;
  std::size_t bytes_ = 0;
};
}  // namespace reb
#endif
