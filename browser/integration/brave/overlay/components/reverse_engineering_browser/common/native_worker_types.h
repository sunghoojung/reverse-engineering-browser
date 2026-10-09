// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_TYPES_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_TYPES_H_

#include <cstdint>

namespace reb {

struct NativeWorkerToken final {
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  [[nodiscard]] bool valid() const noexcept { return high != 0 || low != 0; }
  bool operator==(const NativeWorkerToken&) const = default;
};

enum class NativeWorkerKind : std::uint16_t { kDedicated = 1, kShared = 2, kService = 3 };
enum class NativeWorkerSourceKind : std::uint16_t { kClassic = 1, kModule = 2 };
enum class NativeWorkerCaptureStatus {
  kAccepted,
  kDisabled,
  kBusy,
  kExpired,
  kWrongWorker,
  kUnsupportedWorker,
  kStaleGeneration,
  kInvalid,
  kTooLarge,
  kFull,
  kEmpty,
  kOutputTooSmall,
  kAllocationFailed,
  kSourceUnavailable,
};

struct NativeWorkerCaptureTicket final {
  std::uint64_t session_id = 0;
  std::uint64_t generation = 0;
  NativeWorkerToken worker;
};

}  // namespace reb
#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WORKER_TYPES_H_
