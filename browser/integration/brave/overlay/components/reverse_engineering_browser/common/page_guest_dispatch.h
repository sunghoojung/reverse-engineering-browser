// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_PAGE_GUEST_DISPATCH_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_PAGE_GUEST_DISPATCH_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace reb {

// Both walks stop after this many committed steps. A non-halting program is
// incomplete: the caller counts one extra dispatch loss so the trace cannot
// look finished. This cap is separate from the 16-sample publish budget.
inline constexpr std::uint32_t kPageGuestStepCap = 32;
inline constexpr std::size_t kPageGuestProgramLimit = 1024;
inline constexpr std::size_t kPageGuestModuleLimit = 4096;

struct PageGuestStep final {
  std::uint32_t instruction_pointer = 0;
  std::uint32_t opcode = 0;
  std::uint8_t operand_count = 0;
};

struct PageGuestWalk final {
  std::uint32_t submitted = 0;
  bool halted = false;
  bool truncated = false;
  std::array<PageGuestStep, kPageGuestStepCap> steps{};
};

// javascript-switch-dispatch-v1. The program is the captured byte string, not
// JavaScript source. The program counter is the index of each opcode byte.
// Opcodes: 16 stores an immediate into one of eight registers (two operands),
// 17 adds two registers into the first (two operands, wrapping uint8), 18
// sets the byte index from a register (one operand), 19 halts (no operands).
// Any other opcode, a partial instruction, or a register outside 0..7 ends
// the walk. An empty or unsupported prefix submits nothing.
[[nodiscard]] inline PageGuestWalk WalkJavaScriptSwitchDispatch(
    const std::span<const std::uint8_t> program) noexcept {
  PageGuestWalk walk;
  if (program.empty() || program.size() > kPageGuestProgramLimit) {
    return walk;
  }
  std::array<std::uint8_t, 8> registers{};
  std::size_t ip = 0;
  while (walk.submitted < kPageGuestStepCap && ip < program.size()) {
    const auto instruction_pointer = static_cast<std::uint32_t>(ip);
    const std::uint8_t opcode = program[ip++];
    std::uint8_t operand_count = 0;
    if (opcode == 16 || opcode == 17) {
      if (ip + 1 >= program.size()) {
        break;
      }
      const std::uint8_t left = program[ip++];
      const std::uint8_t right = program[ip++];
      if (left >= registers.size() || (opcode == 17 && right >= registers.size())) {
        break;
      }
      if (opcode == 16) {
        registers[left] = right;
      } else {
        registers[left] = static_cast<std::uint8_t>(registers[left] + registers[right]);
      }
      operand_count = 2;
    } else if (opcode == 18) {
      if (ip >= program.size()) {
        break;
      }
      const std::uint8_t reg = program[ip++];
      if (reg >= registers.size()) {
        break;
      }
      ip = registers[reg];
      operand_count = 1;
    } else if (opcode == 19) {
      walk.steps[walk.submitted++] = {instruction_pointer, opcode, 0};
      walk.halted = true;
      return walk;
    } else {
      break;
    }
    walk.steps[walk.submitted++] = {instruction_pointer, opcode, operand_count};
  }
  walk.truncated = walk.submitted == kPageGuestStepCap && !walk.halted;
  if (!walk.truncated && walk.submitted > 0 && ip >= program.size()) {
    walk.halted = true;
  }
  if (walk.submitted > 0 && walk.steps[0].opcode != 16 && walk.steps[0].opcode != 17 &&
      walk.steps[0].opcode != 18 && walk.steps[0].opcode != 19) {
    return {};
  }
  return walk;
}

namespace page_guest_detail {

inline bool ReadUleb(const std::span<const std::uint8_t> bytes,
                     std::size_t& offset,
                     std::uint32_t& value) noexcept {
  value = 0;
  std::uint32_t shift = 0;
  for (int byte_index = 0; byte_index < 5; ++byte_index) {
    if (offset >= bytes.size()) {
      return false;
    }
    const std::uint8_t byte = bytes[offset++];
    if (byte_index == 4 && (byte & 0xF0U) != 0) {
      return false;
    }
    value |= static_cast<std::uint32_t>(byte & 0x7FU) << shift;
    if ((byte & 0x80U) == 0) {
      return true;
    }
    shift += 7;
  }
  return false;
}

inline bool ReadSleb32(const std::span<const std::uint8_t> bytes,
                       std::size_t& offset,
                       std::int32_t& value) noexcept {
  std::int32_t result = 0;
  std::uint32_t shift = 0;
  std::uint8_t byte = 0;
  for (int byte_index = 0; byte_index < 5; ++byte_index) {
    if (offset >= bytes.size()) {
      return false;
    }
    byte = bytes[offset++];
    result |= static_cast<std::int32_t>(byte & 0x7FU) << shift;
    shift += 7;
    if ((byte & 0x80U) == 0) {
      break;
    }
    if (byte_index == 4) {
      return false;
    }
  }
  if (shift < 32 && (byte & 0x40U) != 0) {
    result |= static_cast<std::int32_t>(~std::uint32_t{0} << shift);
  }
  value = result;
  return true;
}

struct WasmInsn {
  std::uint32_t instruction_pointer = 0;
  std::uint16_t opcode = 0;
  std::uint8_t operand_count = 0;
  std::int32_t immediate = 0;
  int frame = -1;
  std::uint8_t table_count = 0;
  std::array<int, 4> table_frames{};
};

struct WasmFrame {
  bool is_loop = false;
  int head = 0;
  int end = -1;
};

inline constexpr std::size_t kWasmInsnCap = 48;
inline constexpr std::size_t kWasmFrameCap = 8;
inline constexpr std::size_t kWasmLocalCap = 8;
inline constexpr std::size_t kWasmStackCap = 16;
inline constexpr std::size_t kWasmMemoryCap = 256;

}  // namespace page_guest_detail

// wasm-br-table-dispatch-v1. The input is one Wasm module. The walk executes
// the first function body when that body decodes with the opcode subset below
// and contains br_table. The program counter is the module byte offset of the
// opcode. Supported opcodes are nop, block, loop, end, br, br_if, br_table,
// drop, local.get, local.set, local.tee, i32.load8_u, i32.const, i32.eqz,
// i32.eq, and i32.add. Block types must be empty (0x40). Locals must be i32,
// at most eight. A body that does not decode, or that has no br_table, submits
// nothing. Branching to a block or the function lands after its end.
[[nodiscard]] inline PageGuestWalk WalkWasmBrTableDispatch(
    const std::span<const std::uint8_t> module) noexcept {
  using page_guest_detail::kWasmFrameCap;
  using page_guest_detail::kWasmInsnCap;
  using page_guest_detail::kWasmLocalCap;
  using page_guest_detail::kWasmMemoryCap;
  using page_guest_detail::kWasmStackCap;
  using page_guest_detail::ReadSleb32;
  using page_guest_detail::ReadUleb;
  using page_guest_detail::WasmFrame;
  using page_guest_detail::WasmInsn;
  PageGuestWalk walk;
  if (module.size() < 8 || module.size() > kPageGuestModuleLimit || module[0] != 0x00 ||
      module[1] != 0x61 || module[2] != 0x73 || module[3] != 0x6D || module[4] != 0x01 ||
      module[5] != 0x00 || module[6] != 0x00 || module[7] != 0x00) {
    return walk;
  }
  std::size_t cursor = 8;
  std::size_t code_at = 0;
  std::uint32_t code_size = 0;
  bool found_code = false;
  while (cursor < module.size()) {
    const std::uint8_t section = module[cursor++];
    std::uint32_t size = 0;
    if (!ReadUleb(module, cursor, size) || cursor + size > module.size()) {
      return walk;
    }
    if (section == 10) {
      code_at = cursor;
      code_size = size;
      found_code = true;
      break;
    }
    cursor += size;
  }
  if (!found_code || code_size == 0) {
    return walk;
  }
  const auto code = module.subspan(code_at, code_size);
  std::size_t at = 0;
  std::uint32_t function_count = 0;
  std::uint32_t body_size = 0;
  if (!ReadUleb(code, at, function_count) || function_count == 0 ||
      !ReadUleb(code, at, body_size) || at + body_size > code.size()) {
    return walk;
  }
  const auto body = code.subspan(at, body_size);
  const std::size_t body_base = code_at + at;
  std::size_t body_at = 0;
  std::uint32_t local_groups = 0;
  std::uint32_t local_count = 0;
  if (!ReadUleb(body, body_at, local_groups)) {
    return walk;
  }
  for (std::uint32_t group = 0; group < local_groups; ++group) {
    std::uint32_t count = 0;
    if (!ReadUleb(body, body_at, count) || body_at >= body.size()) {
      return walk;
    }
    if (body[body_at++] != 0x7F || count > kWasmLocalCap || local_count > kWasmLocalCap - count) {
      return walk;
    }
    local_count += count;
  }

  std::array<WasmInsn, kWasmInsnCap> insns{};
  std::array<WasmFrame, kWasmFrameCap> frames{};
  std::size_t insn_count = 0;
  std::size_t frame_count = 1;
  frames[0] = {false, 0, -1};
  bool saw_br_table = false;
  while (body_at < body.size()) {
    if (insn_count >= kWasmInsnCap) {
      return walk;
    }
    WasmInsn& insn = insns[insn_count];
    insn.instruction_pointer = static_cast<std::uint32_t>(body_base + body_at);
    if (body_at >= body.size()) {
      return walk;
    }
    const std::uint8_t opcode = body[body_at++];
    insn.opcode = opcode;
    auto push_frame = [&](const bool is_loop) -> bool {
      if (body_at >= body.size() || body[body_at++] != 0x40 || frame_count >= kWasmFrameCap) {
        return false;
      }
      frames[frame_count] = {is_loop, static_cast<int>(insn_count), -1};
      ++frame_count;
      return true;
    };
    auto resolve_label = [&](std::uint32_t label, int& frame_out) -> bool {
      if (label >= frame_count) {
        return false;
      }
      frame_out = static_cast<int>(frame_count - 1U - label);
      return true;
    };
    if (opcode == 0x01 || opcode == 0x1A || opcode == 0x6A || opcode == 0x45 || opcode == 0x46) {
      insn.operand_count = 0;
    } else if (opcode == 0x02 || opcode == 0x03) {
      if (!push_frame(opcode == 0x03)) {
        return walk;
      }
    } else if (opcode == 0x0B) {
      if (frame_count == 0) {
        return walk;
      }
      --frame_count;
      frames[frame_count].end = static_cast<int>(insn_count);
      insn.frame = static_cast<int>(frame_count);
    } else if (opcode == 0x0C || opcode == 0x0D) {
      std::uint32_t label = 0;
      if (!ReadUleb(body, body_at, label) || !resolve_label(label, insn.frame)) {
        return walk;
      }
      insn.operand_count = 1;
      insn.immediate = static_cast<std::int32_t>(label);
    } else if (opcode == 0x0E) {
      std::uint32_t targets = 0;
      if (!ReadUleb(body, body_at, targets) || targets > 3) {
        return walk;
      }
      insn.table_count = static_cast<std::uint8_t>(targets + 1U);
      insn.operand_count = insn.table_count;
      for (std::uint32_t index = 0; index < targets + 1U; ++index) {
        std::uint32_t label = 0;
        if (!ReadUleb(body, body_at, label) || !resolve_label(label, insn.table_frames[index])) {
          return walk;
        }
      }
      saw_br_table = true;
    } else if (opcode == 0x20 || opcode == 0x21 || opcode == 0x22) {
      std::uint32_t index = 0;
      if (!ReadUleb(body, body_at, index) || index >= local_count) {
        return walk;
      }
      insn.immediate = static_cast<std::int32_t>(index);
      insn.operand_count = 1;
    } else if (opcode == 0x2D) {
      std::uint32_t align = 0;
      std::uint32_t offset = 0;
      if (!ReadUleb(body, body_at, align) || !ReadUleb(body, body_at, offset)) {
        return walk;
      }
      insn.immediate = static_cast<std::int32_t>(offset);
      insn.operand_count = 2;
    } else if (opcode == 0x41) {
      std::int32_t immediate = 0;
      if (!ReadSleb32(body, body_at, immediate)) {
        return walk;
      }
      insn.immediate = immediate;
      insn.operand_count = 1;
    } else {
      return walk;
    }
    ++insn_count;
  }
  if (!saw_br_table || frame_count != 0 || frames[0].end < 0) {
    return walk;
  }

  std::array<std::uint32_t, kWasmLocalCap> locals{};
  std::array<std::uint32_t, kWasmStackCap> stack{};
  std::array<std::uint8_t, kWasmMemoryCap> memory{};
  std::size_t stack_size = 0;
  std::size_t ip = 0;
  auto push = [&](const std::uint32_t value) -> bool {
    if (stack_size >= stack.size()) {
      return false;
    }
    stack[stack_size++] = value;
    return true;
  };
  auto pop = [&](std::uint32_t& value) -> bool {
    if (stack_size == 0) {
      return false;
    }
    value = stack[--stack_size];
    return true;
  };
  auto take_branch = [&](const int frame_index) -> bool {
    if (frame_index < 0 || static_cast<std::size_t>(frame_index) >= frames.size()) {
      return false;
    }
    const WasmFrame& frame = frames[static_cast<std::size_t>(frame_index)];
    if (frame.is_loop) {
      ip = static_cast<std::size_t>(frame.head);
      return true;
    }
    if (frame.end < 0) {
      return false;
    }
    ip = static_cast<std::size_t>(frame.end) + 1U;
    return true;
  };

  while (walk.submitted < kPageGuestStepCap && ip < insn_count) {
    const WasmInsn& insn = insns[ip];
    walk.steps[walk.submitted++] = {insn.instruction_pointer, insn.opcode, insn.operand_count};
    bool trapped = false;
    switch (insn.opcode) {
      case 0x01:
      case 0x02:
      case 0x03:
        ++ip;
        break;
      case 0x0B:
        if (insn.frame == 0) {
          walk.halted = true;
          return walk;
        }
        ++ip;
        break;
      case 0x0C:
        if (!take_branch(insn.frame)) {
          trapped = true;
        }
        break;
      case 0x0D: {
        std::uint32_t condition = 0;
        if (!pop(condition)) {
          trapped = true;
          break;
        }
        if (condition != 0) {
          if (!take_branch(insn.frame)) {
            trapped = true;
          }
        } else {
          ++ip;
        }
        break;
      }
      case 0x0E: {
        std::uint32_t selector = 0;
        if (!pop(selector) || insn.table_count == 0) {
          trapped = true;
          break;
        }
        const std::uint32_t index = selector < static_cast<std::uint32_t>(insn.table_count - 1U)
                                        ? selector
                                        : static_cast<std::uint32_t>(insn.table_count - 1U);
        if (!take_branch(insn.table_frames[index])) {
          trapped = true;
        }
        break;
      }
      case 0x1A: {
        std::uint32_t ignored = 0;
        if (!pop(ignored)) {
          trapped = true;
        } else {
          ++ip;
        }
        break;
      }
      case 0x20:
        if (!push(locals[static_cast<std::size_t>(insn.immediate)])) {
          trapped = true;
        } else {
          ++ip;
        }
        break;
      case 0x21:
      case 0x22: {
        std::uint32_t value = 0;
        if (insn.opcode == 0x22) {
          if (stack_size == 0) {
            trapped = true;
            break;
          }
          value = stack[stack_size - 1];
        } else if (!pop(value)) {
          trapped = true;
          break;
        }
        locals[static_cast<std::size_t>(insn.immediate)] = value;
        ++ip;
        break;
      }
      case 0x2D: {
        std::uint32_t address = 0;
        if (!pop(address)) {
          trapped = true;
          break;
        }
        const std::uint64_t location =
            static_cast<std::uint64_t>(address) + static_cast<std::uint32_t>(insn.immediate);
        if (location >= memory.size()) {
          trapped = true;
          break;
        }
        if (!push(memory[static_cast<std::size_t>(location)])) {
          trapped = true;
        } else {
          ++ip;
        }
        break;
      }
      case 0x41:
        if (!push(static_cast<std::uint32_t>(insn.immediate))) {
          trapped = true;
        } else {
          ++ip;
        }
        break;
      case 0x45: {
        std::uint32_t value = 0;
        if (!pop(value) || !push(value == 0 ? 1U : 0U)) {
          trapped = true;
        } else {
          ++ip;
        }
        break;
      }
      case 0x46: {
        std::uint32_t right = 0;
        std::uint32_t left = 0;
        if (!pop(right) || !pop(left) || !push(left == right ? 1U : 0U)) {
          trapped = true;
        } else {
          ++ip;
        }
        break;
      }
      case 0x6A: {
        std::uint32_t right = 0;
        std::uint32_t left = 0;
        if (!pop(right) || !pop(left) || !push(left + right)) {
          trapped = true;
        } else {
          ++ip;
        }
        break;
      }
      default:
        trapped = true;
        break;
    }
    if (trapped) {
      walk.halted = true;
      return walk;
    }
  }
  walk.truncated = walk.submitted == kPageGuestStepCap && !walk.halted;
  if (!walk.truncated && ip >= insn_count) {
    walk.halted = true;
  }
  return walk;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_PAGE_GUEST_DISPATCH_H_
