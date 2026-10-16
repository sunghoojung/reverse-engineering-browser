// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_DISPATCH_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_DISPATCH_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace reb {

inline constexpr std::uint16_t kNativeVmDispatchSampleProtocolVersion = 1;
inline constexpr std::size_t kNativeVmDispatchReservedSize = 40;
inline constexpr std::size_t kNativeVmDispatchReservedTailSize = 16;

struct NativeVmDispatchSamplePayload final {
  std::uint16_t protocol_version = kNativeVmDispatchSampleProtocolVersion;
  std::uint16_t payload_size = sizeof(NativeVmDispatchSamplePayload);
  std::uint32_t instruction_pointer = 0;
  std::uint32_t opcode = 0;
  std::uint32_t handler_index = 0;
  std::uint32_t sample_index = 0;
  std::uint32_t reserved_alignment = 0;
  std::uint64_t finding_id = 0;
  std::uint64_t investigation_id = 0;
  std::uint64_t interpreter_artifact_id = 0;
  std::uint64_t bytecode_artifact_id = 0;
  std::uint8_t flags = 0;
  std::uint8_t operand_count = 0;
  std::uint16_t reserved0 = 0;
  std::uint32_t reserved1 = 0;
  std::uint64_t reserved2 = 0;
  std::array<std::byte, kNativeVmDispatchReservedSize> reserved{};
  std::array<std::byte, kNativeVmDispatchReservedTailSize> reserved_tail{};
};

static_assert(std::is_standard_layout_v<NativeVmDispatchSamplePayload>);
static_assert(std::is_trivially_copyable_v<NativeVmDispatchSamplePayload>);
static_assert(std::has_unique_object_representations_v<NativeVmDispatchSamplePayload>);
static_assert(sizeof(NativeVmDispatchSamplePayload) == 128);
#define REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(member, expected) \
  static_assert(offsetof(NativeVmDispatchSamplePayload, member) == expected)
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(protocol_version, 0);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(payload_size, 2);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(instruction_pointer, 4);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(opcode, 8);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(handler_index, 12);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(sample_index, 16);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(reserved_alignment, 20);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(finding_id, 24);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(investigation_id, 32);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(interpreter_artifact_id, 40);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(bytecode_artifact_id, 48);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(flags, 56);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(operand_count, 57);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(reserved0, 58);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(reserved1, 60);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(reserved2, 64);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(reserved, 72);
REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET(reserved_tail, 112);
#undef REB_ASSERT_NATIVE_VM_DISPATCH_OFFSET

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_VM_DISPATCH_H_
