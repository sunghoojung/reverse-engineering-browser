// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_QUEUE_LIMITS_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_ARTIFACT_QUEUE_LIMITS_H_
#include <cstddef>
namespace reb {
// One in-flight slot per guest sample (kNativeGuestSampleLimit) plus 16
// module/adapter pairs. Bytes cover those snapshots at kNativeGuestSnapshotLimit
// plus the 16 MiB the old 32 MiB cap left beside 256 full snapshots.
inline constexpr std::size_t kNativeArtifactMaxQueuedCount = 532;
inline constexpr std::size_t kNativeArtifactMaxQueuedBytes = 500U * 65536U + 16U * 1024U * 1024U;
[[nodiscard]] constexpr bool CanQueueNativeArtifact(std::size_t count,
                                                    std::size_t bytes,
                                                    std::size_t incoming) noexcept {
  return count < kNativeArtifactMaxQueuedCount && bytes <= kNativeArtifactMaxQueuedBytes &&
         incoming <= kNativeArtifactMaxQueuedBytes - bytes;
}
}  // namespace reb
#endif
