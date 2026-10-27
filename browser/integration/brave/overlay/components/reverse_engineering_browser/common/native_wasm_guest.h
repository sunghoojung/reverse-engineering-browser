// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.
#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_GUEST_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_GUEST_H_
#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include "native_probe_event.h"
#include "native_wasm_guest_wire.h"
namespace reb {
inline constexpr std::size_t kNativeGuestSnapshotLimit = 65536;
inline constexpr std::size_t kNativeGuestSampleLimit = 256;
inline constexpr std::size_t kNativeGuestAdapterLimit = 8192;
struct NativeWasmGuestStateView final {
  std::uint64_t instance_id = 0, invocation_id = 0;
  std::uint32_t function_index = 0, module_byte_offset = 0, selector = 0, table_count = 0;
  void* accessor_context = nullptr;
  bool (*read_numeric_local)(void*, std::uint32_t, std::uint64_t*, std::uint8_t*) = nullptr;
  bool (*copy_memory)(void*, std::uint32_t, std::uint64_t, std::uint32_t, std::uint8_t*) = nullptr;
};
struct NativeWasmGuestContext final {
  std::uint64_t instance_id = 0, invocation_id = 0;
  std::uint32_t function_index = 0, module_byte_offset = 0;
  std::uint32_t import_function_index = 0, import_module_byte_offset = 0;
};
using NativeWasmGuestContextProvider = bool (*)(std::uint32_t, NativeWasmGuestContext*) noexcept;
using NativeWasmGuestReset = void (*)() noexcept;
struct NativeGuestValueSource final {
  bool is_local = false;
  std::uint8_t chain_count = 0;
  std::uint32_t memory_index = 0;
  std::array<std::uint32_t, 3> offsets{};
  std::uint8_t value_type = 32;
  std::uint32_t local_index = 0;
  std::uint64_t constant = 0;
};
struct NativeWasmGuestAdapter final {
  std::array<std::uint8_t, 32> module_sha256{}, recipe_sha256{};
  std::uint32_t function_index = 0, dispatch_module_offset = 0, pc_local_index = 0,
                sample_limit = 16;
  std::uint8_t pc_value_type = 32, opcode_width = 1;
  bool subtract_memory_base = false, opcode_big_endian = false;
  std::int64_t pc_adjustment = 0;
  std::uint32_t memory_index = 0;
  NativeGuestValueSource memory_base{}, memory_length{};
  std::array<std::uint32_t, 64> import_call_offsets{};
  std::size_t import_call_count = 0;
  std::string json;
};
namespace native_guest_detail {
constexpr std::array<std::uint32_t, 64> kSha256RoundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U,
};

class GuestSha256 final {
 public:
  void Update(const std::uint8_t* data, std::size_t size) noexcept {
    total_size_ += size;
    while (size > 0) {
      const std::size_t copied = std::min(size, block_.size() - block_size_);
      std::copy_n(data, copied, block_.begin() + static_cast<std::ptrdiff_t>(block_size_));
      block_size_ += copied;
      data += copied;
      size -= copied;
      if (block_size_ == block_.size()) {
        Transform();
        block_size_ = 0;
      }
    }
  }

  [[nodiscard]] std::array<std::uint8_t, 32> Final() noexcept {
    const std::uint64_t bit_size = static_cast<std::uint64_t>(total_size_) * 8U;
    block_[block_size_++] = 0x80U;
    if (block_size_ > 56) {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.end(), 0U);
      Transform();
      block_size_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.begin() + 56, 0U);
    for (std::size_t index = 0; index < 8; ++index) {
      block_[63 - index] = static_cast<std::uint8_t>(bit_size >> (index * 8U));
    }
    Transform();

    std::array<std::uint8_t, 32> digest{};
    for (std::size_t index = 0; index < state_.size(); ++index) {
      digest[index * 4] = static_cast<std::uint8_t>(state_[index] >> 24U);
      digest[index * 4 + 1] = static_cast<std::uint8_t>(state_[index] >> 16U);
      digest[index * 4 + 2] = static_cast<std::uint8_t>(state_[index] >> 8U);
      digest[index * 4 + 3] = static_cast<std::uint8_t>(state_[index]);
    }
    return digest;
  }

 private:
  void Transform() noexcept {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t index = 0; index < 16; ++index) {
      const std::size_t offset = index * 4;
      schedule[index] = (static_cast<std::uint32_t>(block_[offset]) << 24U) |
                        (static_cast<std::uint32_t>(block_[offset + 1]) << 16U) |
                        (static_cast<std::uint32_t>(block_[offset + 2]) << 8U) |
                        static_cast<std::uint32_t>(block_[offset + 3]);
    }
    for (std::size_t index = 16; index < schedule.size(); ++index) {
      const std::uint32_t s0 = std::rotr(schedule[index - 15], 7) ^
                               std::rotr(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3U);
      const std::uint32_t s1 = std::rotr(schedule[index - 2], 17) ^
                               std::rotr(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10U);
      schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];
    for (std::size_t index = 0; index < schedule.size(); ++index) {
      const std::uint32_t sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      const std::uint32_t choice = (e & f) ^ (~e & g);
      const std::uint32_t temporary1 =
          h + sum1 + choice + kSha256RoundConstants[index] + schedule[index];
      const std::uint32_t sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temporary2 = sum0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + temporary1;
      d = c;
      c = b;
      b = a;
      a = temporary1 + temporary2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_ = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  std::array<std::uint8_t, 64> block_{};
  std::size_t block_size_ = 0;
  std::size_t total_size_ = 0;
};

}  // namespace native_guest_detail
inline std::array<std::uint8_t, 32> NativeGuestDigest(
    std::span<const std::uint8_t> bytes) noexcept {
  native_guest_detail::GuestSha256 hash;
  hash.Update(bytes.data(), bytes.size());
  return hash.Final();
}
inline bool IsValidNativeGuestAdapterShape(const NativeWasmGuestAdapter& adapter) noexcept {
  if (adapter.json.empty() || adapter.json.size() > kNativeGuestAdapterLimit ||
      !adapter.sample_limit || adapter.sample_limit > kNativeGuestSampleLimit ||
      adapter.dispatch_module_offset < 8 ||
      (adapter.pc_value_type != 32 && adapter.pc_value_type != 64) ||
      (adapter.opcode_width != 1 && adapter.opcode_width != 2 && adapter.opcode_width != 4) ||
      adapter.import_call_count > adapter.import_call_offsets.size())
    return false;
  for (const auto* source : {&adapter.memory_base, &adapter.memory_length}) {
    if (source->chain_count > source->offsets.size() ||
        (!source->is_local && source->chain_count) ||
        (source->is_local && source->value_type != 32 && source->value_type != 64) ||
        (source->chain_count && source->value_type != 32))
      return false;
  }
  for (std::size_t i = 0; i < adapter.import_call_count; ++i)
    if (adapter.import_call_offsets[i] < 8 ||
        (i && adapter.import_call_offsets[i] <= adapter.import_call_offsets[i - 1]))
      return false;
  return adapter.recipe_sha256 ==
         NativeGuestDigest(std::span(reinterpret_cast<const std::uint8_t*>(adapter.json.data()),
                                     adapter.json.size()));
}
inline bool NativeGuestReadValue(const NativeWasmGuestStateView& view,
                                 const NativeGuestValueSource& source,
                                 std::uint64_t& out) noexcept {
  if (!source.is_local) {
    out = source.constant;
    return true;
  }
  std::uint8_t type = 0;
  if (!view.read_numeric_local ||
      !view.read_numeric_local(view.accessor_context, source.local_index, &out, &type) ||
      type != source.value_type || (type != 64 && (type != 32 || out > UINT32_MAX)) ||
      source.chain_count > 3)
    return false;
  for (std::size_t i = 0; i < source.chain_count; ++i) {
    if (type != 32 || !view.copy_memory || out > UINT32_MAX - source.offsets[i])
      return false;
    std::array<std::uint8_t, 4> bytes{};
    if (!view.copy_memory(view.accessor_context, source.memory_index, out + source.offsets[i], 4,
                          bytes.data()))
      return false;
    out = static_cast<std::uint64_t>(bytes[0]) | (static_cast<std::uint64_t>(bytes[1]) << 8U) |
          (static_cast<std::uint64_t>(bytes[2]) << 16U) |
          (static_cast<std::uint64_t>(bytes[3]) << 24U);
  }
  return true;
}
struct NativeGuestSnapshot final {
  std::uint64_t raw_pc = 0, pc = 0, memory_base = 0;
  std::uint32_t memory_length = 0, opcode = 0;
  std::array<std::uint8_t, kNativeGuestSnapshotLimit> bytes{};
};
inline bool ResolveNativeGuestSnapshot(const NativeWasmGuestAdapter& adapter,
                                       const NativeWasmGuestStateView& view,
                                       NativeGuestSnapshot& out) noexcept {
  if (!view.instance_id || !view.invocation_id || view.function_index != adapter.function_index ||
      view.module_byte_offset != adapter.dispatch_module_offset || !view.copy_memory ||
      (adapter.opcode_width != 1 && adapter.opcode_width != 2 && adapter.opcode_width != 4))
    return false;
  NativeGuestValueSource pc_source;
  pc_source.is_local = true;
  pc_source.value_type = adapter.pc_value_type;
  pc_source.local_index = adapter.pc_local_index;
  std::uint64_t length = 0;
  if (!NativeGuestReadValue(view, pc_source, out.raw_pc) ||
      !NativeGuestReadValue(view, adapter.memory_base, out.memory_base) ||
      !NativeGuestReadValue(view, adapter.memory_length, length) || !length ||
      length > kNativeGuestSnapshotLimit || out.memory_base > UINT64_MAX - length)
    return false;
  out.pc = out.raw_pc;
  if (adapter.pc_adjustment >= 0) {
    const auto delta = static_cast<std::uint64_t>(adapter.pc_adjustment);
    if (out.pc > UINT64_MAX - delta)
      return false;
    out.pc += delta;
  } else {
    const auto delta = static_cast<std::uint64_t>(-(adapter.pc_adjustment + 1)) + 1;
    if (out.pc < delta)
      return false;
    out.pc -= delta;
  }
  if (adapter.subtract_memory_base) {
    if (out.pc < out.memory_base)
      return false;
    out.pc -= out.memory_base;
  }
  if (length < adapter.opcode_width || out.pc > length - adapter.opcode_width)
    return false;
  out.memory_length = static_cast<std::uint32_t>(length);
  if (!view.copy_memory(view.accessor_context, adapter.memory_index, out.memory_base,
                        out.memory_length, out.bytes.data()))
    return false;
  out.opcode = 0;
  for (std::uint32_t i = 0; i < adapter.opcode_width; ++i) {
    const auto shift = adapter.opcode_big_endian ? 8U * (adapter.opcode_width - i - 1U) : 8U * i;
    out.opcode |= static_cast<std::uint32_t>(out.bytes[static_cast<std::size_t>(out.pc) + i])
                  << shift;
  }
  return true;
}
// Only designated artifact identifiers are filled by browser ACK publication.
inline void NativeGuestPut(std::array<std::byte, 128>& out,
                           std::size_t offset,
                           std::uint64_t value,
                           std::size_t width) noexcept {
  native_guest_wire_detail::Put(out, offset, value, width);
}
struct NativeGuestCapture final {
  NativeProbeEvent invocation{}, dispatch{};
  std::uint64_t execution_context_id = 0, document_token_high = 0, document_token_low = 0;
  std::string_view source_url, adapter_json;
  std::span<const std::uint8_t> module_bytes, bytecode_bytes;
};
using NativeGuestCaptureEmitter = bool (*)(const NativeGuestCapture&, std::uint64_t) noexcept;
using NativeGuestHostEmitter = bool (*)(const NativeProbeEvent&, std::uint64_t) noexcept;
}  // namespace reb
#endif
