// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_RUNTIME_BUFFER_FRAME_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_RUNTIME_BUFFER_FRAME_H_

#include <cstddef>
#include <cstdint>
#include <span>

namespace reb {

// Stack frames visited while looking for the script that allocated a buffer.
// The V8 walk uses the same limit and the same per-frame order.
inline constexpr std::size_t kRuntimeBufferFrameLimit = 32;
inline constexpr std::size_t kRuntimeBufferFrameNone = static_cast<std::size_t>(-1);

// One summarized activation. Summaries that belong to one stack frame are
// ordered innermost first.
struct RuntimeBufferFrameFact {
  bool builtin = false;
  bool javascript = false;
  bool script = false;
  bool source_is_string = false;
  int script_id = 0;
};

struct RuntimeBufferFrameChoice {
  std::size_t frame = kRuntimeBufferFrameNone;
  std::size_t summary = kRuntimeBufferFrameNone;

  [[nodiscard]] bool found() const noexcept { return frame != kRuntimeBufferFrameNone; }
};

[[nodiscard]] inline bool RuntimeBufferFrameUsable(const RuntimeBufferFrameFact& fact) noexcept {
  return !fact.builtin && fact.javascript && fact.script && fact.source_is_string &&
         fact.script_id > 0;
}

// summaries_per_frame[i] is the number of innermost-first summaries in stack
// frame i. At most kRuntimeBufferFrameLimit stack frames are visited. Within a
// frame the innermost summaries are visited first. When a frame has more than
// that many summaries, its outermost summary is still visited, because that is
// the authored function that inlined the others.
[[nodiscard]] inline RuntimeBufferFrameChoice SelectRuntimeBufferFrame(
    const std::span<const RuntimeBufferFrameFact> summaries,
    const std::span<const std::uint8_t> summaries_per_frame) noexcept {
  std::size_t cursor = 0;
  const std::size_t frame_limit = summaries_per_frame.size() < kRuntimeBufferFrameLimit
                                      ? summaries_per_frame.size()
                                      : kRuntimeBufferFrameLimit;
  for (std::size_t frame = 0; frame < frame_limit; ++frame) {
    const std::size_t count = summaries_per_frame[frame];
    if (count > summaries.size() - cursor) {
      return {};
    }
    const std::size_t visit = count < kRuntimeBufferFrameLimit ? count : kRuntimeBufferFrameLimit;
    for (std::size_t summary = 0; summary < visit; ++summary) {
      if (RuntimeBufferFrameUsable(summaries[cursor + summary])) {
        return {frame, summary};
      }
    }
    if (count > kRuntimeBufferFrameLimit &&
        RuntimeBufferFrameUsable(summaries[cursor + count - 1U])) {
      return {frame, count - 1U};
    }
    cursor += count;
  }
  return {};
}

}  // namespace reb

#endif
