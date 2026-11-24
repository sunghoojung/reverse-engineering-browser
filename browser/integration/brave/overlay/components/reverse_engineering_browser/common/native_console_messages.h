// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_MESSAGES_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_MESSAGES_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <utility>

#include "native_console_protocol.h"

namespace reb {

// Renderer-thread only. Accepts complete JSON objects from the native serializer,
// never page-authored JSON. Every message is kept whole, however long, until
// the Console owner polls for it.
class NativeConsoleMessages final {
 public:
  // What one document holds for an owner that is not polling. The Console
  // polls continuously while it is connected, so a connected owner is never
  // behind by this much; past it the oldest messages go, counted as dropped.
  // A renderer must stay bounded in memory: without this, a page logging in a
  // loop with no owner draining it would grow until the renderer is killed.
  // One message larger than this is still kept, alone.
  static constexpr std::size_t kRetainedBytes = 64 * 1024 * 1024;
  static constexpr std::uint32_t kDropLimit = 2147483647;

  NativeConsoleMessages() noexcept;
  ~NativeConsoleMessages() noexcept;
  NativeConsoleMessages(const NativeConsoleMessages&) = delete;
  NativeConsoleMessages& operator=(const NativeConsoleMessages&) = delete;
  NativeConsoleMessages(NativeConsoleMessages&&) = delete;
  NativeConsoleMessages& operator=(NativeConsoleMessages&&) = delete;

  void Drop(std::uint32_t count = 1) noexcept {
    dropped_ += count > kDropLimit - dropped_ ? kDropLimit - dropped_ : count;
  }

  void Push(std::string encoded) {
    if (encoded.empty()) {
      Drop();
      return;
    }
    while (!messages_.empty() && bytes_ + encoded.size() > kRetainedBytes) {
      Pop();
      Drop();
    }
    bytes_ += encoded.size();
    messages_.push_back(std::move(encoded));
  }

  // The oldest messages, whole: at least one, then more while the reply stays
  // within one page. `more` says that the owner should poll again at once.
  // The drop count travels with the first page after the drops, so it is
  // reported exactly once.
  [[nodiscard]] std::string Poll() {
    // Each record is serialized once on arrival. Poll needs one output
    // allocation and byte copies, without rebuilding dictionaries or escaping.
    std::size_t taken = 0;
    std::size_t size = 0;
    while (taken < messages_.size() &&
           (taken == 0 || size + messages_[taken].size() <= kNativeConsolePageBytes)) {
      size += messages_[taken].size() + 1;
      ++taken;
    }
    std::string result;
    result.reserve(size + kEnvelopeBytes);
    result += "{\"status\":\"ok\",\"messages\":[";
    for (std::size_t index = 0; index < taken; ++index) {
      if (index)
        result += ',';
      result += messages_.front();
      Pop();
    }
    result += "],\"dropped\":";
    result += std::to_string(dropped_);
    result += ",\"more\":";
    result += messages_.empty() ? "false" : "true";
    result += '}';
    dropped_ = 0;
    if (messages_.empty())
      std::deque<std::string>().swap(messages_);
    return result;
  }

  void Reset() noexcept {
    // Clear relinquishes storage instead of retaining peak capacities.
    std::deque<std::string>().swap(messages_);
    bytes_ = 0;
    dropped_ = 0;
  }

 private:
  // The JSON envelope with a saturated ten-digit drop count.
  static constexpr std::size_t kEnvelopeBytes = 80;

  void Pop() noexcept {
    bytes_ -= messages_.front().size();
    messages_.pop_front();
  }

  // libc++ allocates a deque's blocks on first use, so a document that never
  // logs holds no message storage.
  std::deque<std::string> messages_;
  std::size_t bytes_ = 0;
  std::uint32_t dropped_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_CONSOLE_MESSAGES_H_
