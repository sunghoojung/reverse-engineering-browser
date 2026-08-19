// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "native_probe_queue.h"

namespace reb {

NativeProbeQueue::NativeProbeQueue() noexcept {
  for (std::uint64_t index = 0; index < kNativeProbeQueueCapacity; ++index) {
    slots_[static_cast<std::size_t>(index)].sequence.store(index, std::memory_order_relaxed);
  }
}

}  // namespace reb
