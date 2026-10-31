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
#include "base/memory/raw_ptr_exclusion.h"
#include "crypto/hash.h"
#include "native_probe_event.h"
#include "native_wasm_guest_wire.h"
namespace reb {
inline constexpr std::size_t kNativeGuestSnapshotLimit = 65536;
inline constexpr std::size_t kNativeGuestSampleLimit = 256;
inline constexpr std::size_t kNativeGuestAdapterLimit = 8192;
// Dispatch sites per adapter. Every site draws on the one shared sample limit,
// so the snapshot budget (sample limit x snapshot limit, at most 16 MiB) and
// the 128 sampled activations are never multiplied per site.
inline constexpr std::size_t kNativeGuestSiteLimit = 8;
// Host events per capture configuration that may travel the parent-binding
// path. Later hosts stay on the ordinary bounded queue, unparented, after one
// explicit omission marker; the events themselves are never dropped here.
inline constexpr std::size_t kNativeGuestHostParentLimit = 256;
// Host events the browser holds while their parent dispatch awaits artifact
// receipts. Beyond this, a host is published at once without its parent link.
inline constexpr std::size_t kNativeGuestHeldHostLimit = 64;
// Module transfers per document binding. The renderer resends the module only
// after the browser reports that the previous transfer was not accepted.
inline constexpr std::uint8_t kNativeGuestModuleAttemptLimit = 3;
// The enclosing guest activation as the engine resolved it once, at this
// activation's first selected dispatch. kUnresolved never names a guess.
enum class NativeWasmGuestParent : std::uint8_t { kNone, kResolved, kUnresolved };
struct NativeWasmGuestStateView final {
  std::uint64_t instance_id = 0, invocation_id = 0;
  std::uint32_t function_index = 0, module_byte_offset = 0, selector = 0, table_count = 0;
  // V8's accessor for this synchronous dispatch only; never retained. It names
  // engine frame state, not PartitionAlloc memory, and is read on every sampled
  // dispatch, so raw_ptr would add per-call cost without any protection.
  RAW_PTR_EXCLUSION void* accessor_context = nullptr;
  bool (*read_numeric_local)(void*, std::uint32_t, std::uint64_t*, std::uint8_t*) = nullptr;
  bool (*copy_memory)(void*, std::uint32_t, std::uint64_t, std::uint32_t, std::uint8_t*) = nullptr;
  std::uint64_t parent_invocation_id = 0;
  NativeWasmGuestParent parent = NativeWasmGuestParent::kNone;
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
// One configured dispatch site. The sites of an adapter name distinct
// dispatcher functions, so an activation belongs to exactly one site and its
// parent walk and host attribution stay unambiguous.
struct NativeWasmGuestSite final {
  std::uint32_t function_index = 0, dispatch_module_offset = 0, pc_local_index = 0;
  std::uint8_t pc_value_type = 32, opcode_width = 1;
  bool subtract_memory_base = false, opcode_big_endian = false;
  std::int64_t pc_adjustment = 0;
  std::uint32_t memory_index = 0;
  NativeGuestValueSource memory_base{}, memory_length{};
  std::array<std::uint32_t, 64> import_call_offsets{};
  std::size_t import_call_count = 0;
};
// A version 1 recipe parses as one site; version 2 lists 1 to 8 sites in
// strictly increasing function index order. The array index is the site index
// that every invocation marker carries.
struct NativeWasmGuestAdapter final {
  std::array<std::uint8_t, 32> module_sha256{}, recipe_sha256{};
  std::uint32_t sample_limit = 16;
  std::array<NativeWasmGuestSite, kNativeGuestSiteLimit> sites{};
  std::size_t site_count = 0;
  std::string json;
};
// Module, recipe and adapter identities. Uses Chromium's BoringSSL-backed
// implementation; portable harnesses substitute a test-only reference.
inline std::array<std::uint8_t, 32> NativeGuestDigest(
    std::span<const std::uint8_t> bytes) noexcept {
  return crypto::hash::Sha256(bytes);
}
inline bool IsValidNativeGuestSiteShape(const NativeWasmGuestSite& site) noexcept {
  if (site.dispatch_module_offset < 8 || (site.pc_value_type != 32 && site.pc_value_type != 64) ||
      (site.opcode_width != 1 && site.opcode_width != 2 && site.opcode_width != 4) ||
      site.import_call_count > site.import_call_offsets.size())
    return false;
  for (const auto* source : {&site.memory_base, &site.memory_length}) {
    if (source->chain_count > source->offsets.size() ||
        (!source->is_local && source->chain_count) ||
        (source->is_local && source->value_type != 32 && source->value_type != 64) ||
        (source->chain_count && source->value_type != 32))
      return false;
  }
  for (std::size_t i = 0; i < site.import_call_count; ++i)
    if (site.import_call_offsets[i] < 8 ||
        (i && site.import_call_offsets[i] <= site.import_call_offsets[i - 1]))
      return false;
  return true;
}
inline bool IsValidNativeGuestAdapterShape(const NativeWasmGuestAdapter& adapter) noexcept {
  if (adapter.json.empty() || adapter.json.size() > kNativeGuestAdapterLimit ||
      !adapter.sample_limit || adapter.sample_limit > kNativeGuestSampleLimit ||
      !adapter.site_count || adapter.site_count > adapter.sites.size())
    return false;
  for (std::size_t i = 0; i < adapter.site_count; ++i)
    if (!IsValidNativeGuestSiteShape(adapter.sites[i]) ||
        (i && adapter.sites[i].function_index <= adapter.sites[i - 1].function_index))
      return false;
  return adapter.recipe_sha256 ==
         NativeGuestDigest(std::span(reinterpret_cast<const std::uint8_t*>(adapter.json.data()),
                                     adapter.json.size()));
}
// The site whose dispatcher function this is, or null. Sites are sorted by
// function index and there are at most eight, so this is a short scan.
inline const NativeWasmGuestSite* FindNativeGuestDispatcher(
    const NativeWasmGuestAdapter& adapter,
    std::uint32_t function_index,
    std::uint32_t* site_index = nullptr) noexcept {
  for (std::size_t i = 0; i < adapter.site_count && i < adapter.sites.size(); ++i)
    if (adapter.sites[i].function_index == function_index) {
      if (site_index)
        *site_index = static_cast<std::uint32_t>(i);
      return &adapter.sites[i];
    }
  return nullptr;
}
// The configured site at exactly this br_table, or null for a helper br_table.
inline const NativeWasmGuestSite* FindNativeGuestSite(
    const NativeWasmGuestAdapter& adapter,
    std::uint32_t function_index,
    std::uint32_t module_byte_offset,
    std::uint32_t* site_index = nullptr) noexcept {
  const auto* site = FindNativeGuestDispatcher(adapter, function_index, site_index);
  return site && site->dispatch_module_offset == module_byte_offset ? site : nullptr;
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
inline bool ResolveNativeGuestSnapshot(const NativeWasmGuestSite& site,
                                       const NativeWasmGuestStateView& view,
                                       NativeGuestSnapshot& out) noexcept {
  if (!view.instance_id || !view.invocation_id || view.function_index != site.function_index ||
      view.module_byte_offset != site.dispatch_module_offset || !view.copy_memory ||
      (site.opcode_width != 1 && site.opcode_width != 2 && site.opcode_width != 4))
    return false;
  NativeGuestValueSource pc_source;
  pc_source.is_local = true;
  pc_source.value_type = site.pc_value_type;
  pc_source.local_index = site.pc_local_index;
  std::uint64_t length = 0;
  if (!NativeGuestReadValue(view, pc_source, out.raw_pc) ||
      !NativeGuestReadValue(view, site.memory_base, out.memory_base) ||
      !NativeGuestReadValue(view, site.memory_length, length) || !length ||
      length > kNativeGuestSnapshotLimit || out.memory_base > UINT64_MAX - length)
    return false;
  out.pc = out.raw_pc;
  if (site.pc_adjustment >= 0) {
    const auto delta = static_cast<std::uint64_t>(site.pc_adjustment);
    if (out.pc > UINT64_MAX - delta)
      return false;
    out.pc += delta;
  } else {
    const auto delta = static_cast<std::uint64_t>(-(site.pc_adjustment + 1)) + 1;
    if (out.pc < delta)
      return false;
    out.pc -= delta;
  }
  if (site.subtract_memory_base) {
    if (out.pc < out.memory_base)
      return false;
    out.pc -= out.memory_base;
  }
  if (length < site.opcode_width || out.pc > length - site.opcode_width)
    return false;
  out.memory_length = static_cast<std::uint32_t>(length);
  if (!view.copy_memory(view.accessor_context, site.memory_index, out.memory_base,
                        out.memory_length, out.bytes.data()))
    return false;
  out.opcode = 0;
  for (std::uint32_t i = 0; i < site.opcode_width; ++i) {
    const auto shift = site.opcode_big_endian ? 8U * (site.opcode_width - i - 1U) : 8U * i;
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
