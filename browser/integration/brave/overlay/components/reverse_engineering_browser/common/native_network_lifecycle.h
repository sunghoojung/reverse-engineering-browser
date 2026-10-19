// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_LIFECYCLE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_LIFECYCLE_H_

#include <cstdint>

namespace reb {

// One UI-sequence-owned value per admitted proxy request. No registry, allocation,
// or retention beyond the actual loader lifetime. A disabled/midflight request
// cannot join a later session, even when the caller reuses a session identifier.
class NativeNetworkLifecycle final {
 public:
  explicit NativeNetworkLifecycle(std::uint64_t generation = 0) noexcept
      : generation_(generation) {}

  [[nodiscard]] bool IsCurrent(std::uint64_t generation) const noexcept {
    return generation_ != 0 && generation_ == generation && !terminal_;
  }

  [[nodiscard]] bool Finish(std::uint64_t generation) noexcept {
    const bool emit = IsCurrent(generation);
    terminal_ = true;
    return emit;
  }

 private:
  const std::uint64_t generation_;
  bool terminal_ = false;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_NETWORK_LIFECYCLE_H_
