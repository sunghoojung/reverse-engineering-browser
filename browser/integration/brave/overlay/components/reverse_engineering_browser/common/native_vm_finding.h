// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_FINDING_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_FINDING_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace reb {

inline constexpr std::uint16_t kNativeVmFindingProtocolVersion = 1;
inline constexpr std::size_t kNativeVmFindingLabelCapacity = 40;
inline constexpr std::size_t kNativeVmFindingReservedSize = 16;

enum class NativeVmFindingKind : std::uint8_t {
  kUnknown = 0,
  kInterpreter = 1,
  kGuestProgram = 2,
  kInvocation = 3,
  kHostBinding = 4,
  kHypothesis = 5,
  kCoverage = 6,
};

enum class NativeVmHostRuntime : std::uint8_t {
  kUnknown = 0,
  kJavaScript = 1,
  kWebAssembly = 2,
  kMixed = 3,
};

enum class NativeVmFindingConfidence : std::uint8_t {
  kUnknown = 0,
  kObserved = 1,
  kInferred = 2,
  kHeuristic = 3,
};

enum class NativeVmFindingFlag : std::uint8_t {
  kNone = 0,
  kHasSourceRange = 1U << 0U,
  kPartial = 1U << 1U,
  kDynamic = 1U << 2U,
  kNested = 1U << 3U,
};

// Fixed little-endian payload for NativeProbeCategory::kVm and
// NativeProbeType::kVmFinding. Emitters must zero all reserved bytes and label
// bytes beyond label_size.
struct NativeVmFindingPayload final {
  std::uint16_t protocol_version = kNativeVmFindingProtocolVersion;
  std::uint16_t payload_size = sizeof(NativeVmFindingPayload);
  NativeVmFindingKind kind = NativeVmFindingKind::kUnknown;
  NativeVmHostRuntime host_runtime = NativeVmHostRuntime::kUnknown;
  NativeVmFindingConfidence confidence = NativeVmFindingConfidence::kUnknown;
  std::uint8_t flags = 0;
  std::uint16_t label_size = 0;
  std::uint16_t reserved0 = 0;
  std::uint32_t observed_count = 0;
  std::uint32_t total_count = 0;
  std::uint32_t reserved1 = 0;
  std::uint64_t finding_id = 0;
  std::uint64_t investigation_id = 0;
  std::uint64_t subject_id = 0;
  std::uint64_t related_subject_id = 0;
  std::uint64_t source_offset = 0;
  std::uint64_t source_size = 0;
  std::array<char, kNativeVmFindingLabelCapacity> label{};
  std::array<std::byte, kNativeVmFindingReservedSize> reserved{};
};

static_assert(std::is_standard_layout_v<NativeVmFindingPayload>);
static_assert(std::is_trivially_copyable_v<NativeVmFindingPayload>);
static_assert(std::has_unique_object_representations_v<NativeVmFindingPayload>);
static_assert(sizeof(NativeVmFindingPayload) == 128);
static_assert(offsetof(NativeVmFindingPayload, finding_id) == 24);
static_assert(offsetof(NativeVmFindingPayload, label) == 72);
static_assert(offsetof(NativeVmFindingPayload, reserved) == 112);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_FINDING_H_
