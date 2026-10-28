// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_QUEUE_LIMITS_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_QUEUE_LIMITS_H_
#include <cstddef>
namespace reb {
// 256 snapshots and 16 module/adapter pairs, still bounded by the same 32 MiB.
inline constexpr std::size_t kNativeArtifactMaxQueuedCount = 288;
inline constexpr std::size_t kNativeArtifactMaxQueuedBytes = 32U * 1024U * 1024U;
[[nodiscard]] constexpr bool CanQueueNativeArtifact(std::size_t count,
                                                    std::size_t bytes,
                                                    std::size_t incoming) noexcept {
  return count < kNativeArtifactMaxQueuedCount && bytes <= kNativeArtifactMaxQueuedBytes &&
         incoming <= kNativeArtifactMaxQueuedBytes - bytes;
}
}  // namespace reb
#endif
