// Copyright 2026 The Reverse Engineering Browser Authors
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
// Owns at most sixteen payloads until the next native task checkpoint, whatever
// their size: each holds its buffer and source for one task, and the renderer's
// artifact credit bounds what is copied out. Payloads own the original
// allocator identity and safe handles, never borrowed pointers. This bound is
// independent from the renderer's admitted-snapshot session cap.
template <typename Payload>
class NativeRuntimeSnapshotQueue final {
 public:
  static constexpr std::size_t kMaxEntries = 16;
  bool CanRetain() const noexcept { return count_ < kMaxEntries; }
  bool Push(Payload payload) {
    if (!CanRetain())
      return false;
    for (auto& entry : entries_) {
      if (!entry) {
        entry.emplace(std::move(payload));
        ++count_;
        return true;
      }
    }
    return false;
  }
  template <typename Visitor>
  void Drain(Visitor visitor) {
    for (auto& entry : entries_) {
      if (!entry)
        continue;
      Payload payload = std::move(*entry);
      entry.reset();
      --count_;
      visitor(std::move(payload));
    }
  }
  std::size_t size() const noexcept { return count_; }

 private:
  std::array<std::optional<Payload>, kMaxEntries> entries_{};
  std::size_t count_ = 0;
};
}  // namespace reb
#endif
