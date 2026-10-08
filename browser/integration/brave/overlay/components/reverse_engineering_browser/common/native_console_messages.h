// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_MESSAGES_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_MESSAGES_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "native_console_protocol.h"

namespace reb {

// Renderer-thread only. Accepts complete JSON objects from the native serializer,
// never page-authored JSON. Charge encoded bytes so escaping cannot overflow a
// poll reply after its messages have already been removed from the queue.
class NativeConsoleMessages final {
 public:
  static constexpr std::size_t kCapacity = 32;
  static constexpr std::size_t kByteLimit = 32768;
  static constexpr std::uint32_t kDropLimit = 2147483647;

  NativeConsoleMessages() = default;
  NativeConsoleMessages(const NativeConsoleMessages&) = delete;
  NativeConsoleMessages& operator=(const NativeConsoleMessages&) = delete;
  NativeConsoleMessages(NativeConsoleMessages&&) = delete;
  NativeConsoleMessages& operator=(NativeConsoleMessages&&) = delete;

  void Drop(std::uint32_t count = 1) noexcept {
    dropped_ += count > kDropLimit - dropped_ ? kDropLimit - dropped_ : count;
  }

  void Push(std::string encoded) {
    if (encoded.empty() || encoded.size() > kByteLimit) {
      Drop();
      return;
    }
    while (count_ == kCapacity || bytes_ + encoded.size() > kByteLimit) {
      Pop();
      Drop();
    }
    bytes_ += encoded.size();
    messages_[(head_ + count_) % kCapacity] = std::move(encoded);
    ++count_;
  }

  [[nodiscard]] std::string Poll() {
    // Each record is serialized once on arrival. Poll needs one bounded output
    // allocation and byte copies, without rebuilding dictionaries or escaping.
    std::string result;
    result.reserve(bytes_ + kCapacity + kEnvelopeLimit);
    result += "{\"status\":\"ok\",\"messages\":[";
    for (std::size_t index = 0; index < count_; ++index) {
      if (index)
        result += ',';
      result += messages_[(head_ + index) % kCapacity];
    }
    result += "],\"dropped\":";
    result += std::to_string(dropped_);
    result += '}';
    Reset();
    return result;
  }

  void Reset() noexcept {
    while (count_)
      Pop();
    head_ = 0;
    dropped_ = 0;
  }

 private:
  // JSON envelope and the saturated ten-digit drop count fit within 64 bytes.
  static constexpr std::size_t kEnvelopeLimit = 64;
  static_assert(kByteLimit + kCapacity + kEnvelopeLimit <= kNativeConsolePayloadLimit);

  void Pop() noexcept {
    bytes_ -= messages_[head_].size();
    // Clear/eviction relinquishes storage instead of retaining peak capacities.
    std::string().swap(messages_[head_]);
    head_ = (head_ + 1) % kCapacity;
    --count_;
  }

  // Unlike a deque, the inactive queue allocates no backing nodes or map.
  std::array<std::string, kCapacity> messages_;
  std::size_t head_ = 0;
  std::size_t count_ = 0;
  std::size_t bytes_ = 0;
  std::uint32_t dropped_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_MESSAGES_H_
