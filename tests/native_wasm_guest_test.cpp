#include "components/reverse_engineering_browser/common/native_wasm_guest.h"
#include <cassert>
#include <cstdio>
#include "components/reverse_engineering_browser/common/native_artifact_queue_limits.h"
#include "components/reverse_engineering_browser/common/native_wasm_guest_wire.h"
#include "reb/wasm_guest.hpp"

// The renderer encoder (overlay) and the core decoder each own a copy of the
// wire layout. Set one field at a time to a distinct value and require
// identical bytes and identical cross-decoding, so the copies cannot drift.
template <class Overlay, class Core, class Field>
void CheckGuestWireField(Field Overlay::*overlay_field, Field Core::*core_field, Field value) {
  Overlay overlay;
  Core core;
  overlay.*overlay_field = value;
  core.*core_field = value;
  std::array<std::byte, 128> overlay_bytes{}, core_bytes{};
  if constexpr (std::is_same_v<Overlay, reb::NativeWasmGuestDispatchPayload>) {
    overlay_bytes = reb::EncodeNativeWasmGuestDispatchPayload(overlay);
    core_bytes = reb::EncodeWasmGuestDispatchPayload(core);
    reb::WasmGuestDispatchPayload decoded_core;
    reb::NativeWasmGuestDispatchPayload decoded_overlay;
    assert(reb::DecodeWasmGuestDispatchPayload(overlay_bytes, decoded_core));
    assert(reb::DecodeNativeWasmGuestDispatchPayload(core_bytes, decoded_overlay));
    assert(decoded_core.*core_field == value && decoded_overlay.*overlay_field == value);
  } else {
    overlay_bytes = reb::EncodeNativeWasmGuestInvocationPayload(overlay);
    core_bytes = reb::EncodeWasmGuestInvocationPayload(core);
    reb::WasmGuestInvocationPayload decoded_core;
    reb::NativeWasmGuestInvocationPayload decoded_overlay;
    assert(reb::DecodeWasmGuestInvocationPayload(overlay_bytes, decoded_core));
    assert(reb::DecodeNativeWasmGuestInvocationPayload(core_bytes, decoded_overlay));
    assert(decoded_core.*core_field == value && decoded_overlay.*overlay_field == value);
  }
  assert(overlay_bytes == core_bytes);
}
void CheckGuestWireParity() {
  using O = reb::NativeWasmGuestDispatchPayload;
  using C = reb::WasmGuestDispatchPayload;
  CheckGuestWireField(&O::function_index, &C::function_index, std::uint32_t{0x01020304});
  CheckGuestWireField(&O::module_byte_offset, &C::module_byte_offset, std::uint32_t{0x05060708});
  CheckGuestWireField(&O::selector, &C::selector, std::uint32_t{0xfffffffe});
  CheckGuestWireField(&O::table_count, &C::table_count, std::uint32_t{0x0a0b0c0d});
  CheckGuestWireField(&O::sample_index, &C::sample_index, std::uint32_t{0x0e});
  CheckGuestWireField(&O::instance_id, &C::instance_id, std::uint64_t{0x1112131415161718});
  CheckGuestWireField(&O::invocation_id, &C::invocation_id, std::uint64_t{0x2122232425262728});
  CheckGuestWireField(&O::guest_pc, &C::guest_pc, std::uint64_t{0x31});
  CheckGuestWireField(&O::raw_pc_bits, &C::raw_pc_bits, std::uint64_t{0x4142434445464748});
  CheckGuestWireField(&O::bytecode_artifact_id, &C::bytecode_artifact_id,
                      std::uint64_t{0x5152535455565758});
  CheckGuestWireField(&O::memory_base, &C::memory_base, std::uint64_t{0x6162636465666768});
  CheckGuestWireField(&O::memory_length, &C::memory_length, std::uint32_t{0x10000});
  CheckGuestWireField(&O::pc_local_index, &C::pc_local_index, std::uint32_t{320});
  CheckGuestWireField(&O::pc_adjustment, &C::pc_adjustment, std::int64_t{-0x7172737475767778});
  CheckGuestWireField(&O::memory_index, &C::memory_index, std::uint32_t{0x81});
  CheckGuestWireField(&O::opcode, &C::opcode, std::uint32_t{0x91929394});
  std::array<std::byte, 32> digest{};
  for (std::size_t i = 0; i < digest.size(); ++i)
    digest[i] = static_cast<std::byte>(0xa0 + i);
  CheckGuestWireField(&O::recipe_sha256, &C::recipe_sha256, digest);
  using OI = reb::NativeWasmGuestInvocationPayload;
  using CI = reb::WasmGuestInvocationPayload;
  CheckGuestWireField(&OI::function_index, &CI::function_index, std::uint32_t{0x01020304});
  CheckGuestWireField(&OI::instance_id, &CI::instance_id, std::uint64_t{0x1112131415161718});
  CheckGuestWireField(&OI::invocation_id, &CI::invocation_id, std::uint64_t{0x2122232425262728});
  CheckGuestWireField(&OI::adapter_artifact_id, &CI::adapter_artifact_id,
                      std::uint64_t{0x3132333435363738});
  CheckGuestWireField(&OI::recipe_sha256, &CI::recipe_sha256, digest);
  CheckGuestWireField(&OI::parent_invocation_id, &CI::parent_invocation_id,
                      std::uint64_t{0x4142434445464748});
  CheckGuestWireField(&OI::parent_dispatch_sequence_number, &CI::parent_dispatch_sequence_number,
                      std::uint64_t{0x5152535455565758});
  // A version 1 record reserved bytes 72..128; it still decodes, with no
  // parent dispatch, and the new field occupies exactly bytes 72..80.
  OI legacy;
  legacy.protocol_version = 1;
  legacy.parent_invocation_id = 9;
  auto bytes = reb::EncodeNativeWasmGuestInvocationPayload(legacy);
  CI decoded;
  assert(reb::DecodeWasmGuestInvocationPayload(bytes, decoded) && decoded.protocol_version == 1 &&
         decoded.parent_invocation_id == 9 && decoded.parent_dispatch_sequence_number == 0);
  legacy.parent_dispatch_sequence_number = 0x0102030405060708;
  bytes = reb::EncodeNativeWasmGuestInvocationPayload(legacy);
  assert(bytes[72] == std::byte{8} && bytes[79] == std::byte{1} && bytes[80] == std::byte{0});
  std::puts("PASS overlay renderer encoder and core decoder agree byte-for-byte on every field");
}
struct Runtime {
  std::array<std::uint8_t, 256> memory{};
  std::array<std::uint64_t, 321> locals{};
  bool shared = false;
};
bool Read(void* opaque, std::uint32_t index, std::uint64_t* value, std::uint8_t* type) {
  auto& s = *static_cast<Runtime*>(opaque);
  if (index >= s.locals.size())
    return false;
  *value = s.locals[index];
  *type = 32;
  return true;
}
bool Copy(void* opaque,
          std::uint32_t index,
          std::uint64_t offset,
          std::uint32_t length,
          std::uint8_t* out) {
  auto& s = *static_cast<Runtime*>(opaque);
  if (s.shared || index || offset > s.memory.size() || length > s.memory.size() - offset)
    return false;
  std::copy_n(s.memory.data() + offset, length, out);
  return true;
}
void Put(Runtime& s, std::size_t offset, std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i)
    s.memory[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
}
int main() {
  static_assert(reb::CanQueueNativeArtifact(287, 0, 32U * 1024U * 1024U));
  static_assert(!reb::CanQueueNativeArtifact(288, 0, 1));
  static_assert(!reb::CanQueueNativeArtifact(0, 32U * 1024U * 1024U, 1));
  static_assert(!reb::CanQueueNativeArtifact(0, SIZE_MAX, 1));
  static_assert(!reb::CanQueueNativeArtifact(0, 1, SIZE_MAX));
  Runtime runtime;
  runtime.locals[10] = 8;
  Put(runtime, 12, 32);
  Put(runtime, 36, 100);
  Put(runtime, 40, 8);
  runtime.locals[320] = 103;
  runtime.memory[102] = 0x42;
  reb::NativeWasmGuestStateView view{1, 1, 414, 0x20677, 3, 244, &runtime, &Read, &Copy};
  reb::NativeWasmGuestAdapter adapter;
  adapter.function_index = 414;
  adapter.dispatch_module_offset = 0x20677;
  adapter.pc_local_index = 320;
  adapter.pc_adjustment = -1;
  adapter.subtract_memory_base = true;  // Authored preincrement case, not QuickJS recipe.
  adapter.memory_base.is_local = true;
  adapter.memory_base.local_index = 10;
  adapter.memory_base.chain_count = 2;
  adapter.memory_base.offsets = {4, 4, 0};
  adapter.memory_length = adapter.memory_base;
  adapter.memory_length.offsets = {4, 8, 0};
  reb::NativeGuestSnapshot out;
  assert(reb::ResolveNativeGuestSnapshot(adapter, view, out));
  assert(out.pc == 2 && out.raw_pc == 103 && out.opcode == 0x42 && out.memory_base == 100 &&
         out.memory_length == 8);
  runtime.locals[320] = 105;
  runtime.memory[104] = 0x9e;
  assert(reb::ResolveNativeGuestSnapshot(adapter, view, out) && out.pc == 4 && out.opcode == 0x9e);
  runtime.shared = true;
  assert(!reb::ResolveNativeGuestSnapshot(adapter, view, out));
  runtime.shared = false;
  runtime.locals[10] = UINT32_MAX;
  assert(!reb::ResolveNativeGuestSnapshot(adapter, view, out));
  runtime.locals[10] = 8;
  runtime.locals[320] = UINT64_MAX;
  assert(!reb::ResolveNativeGuestSnapshot(adapter, view, out));
  runtime.locals[320] = 0;
  assert(!reb::ResolveNativeGuestSnapshot(adapter, view, out));
  runtime.locals[320] = 103;
  adapter.pc_value_type = 64;
  assert(!reb::ResolveNativeGuestSnapshot(adapter, view, out));
  adapter.pc_value_type = 32;
  adapter.memory_base.chain_count = 4;
  assert(!reb::ResolveNativeGuestSnapshot(adapter, view, out));
  adapter.memory_base.chain_count = 2;
  Put(runtime, 40, 65537);
  assert(!reb::ResolveNativeGuestSnapshot(adapter, view, out));
  Put(runtime, 40, 8);
  adapter.opcode_width = 4;
  runtime.memory[102] = 1;
  runtime.memory[103] = 2;
  runtime.memory[104] = 3;
  runtime.memory[105] = 4;
  assert(reb::ResolveNativeGuestSnapshot(adapter, view, out) && out.opcode == 0x04030201);
  adapter.opcode_big_endian = true;
  assert(reb::ResolveNativeGuestSnapshot(adapter, view, out) && out.opcode == 0x01020304);
  view.instance_id = 0;
  assert(!reb::ResolveNativeGuestSnapshot(adapter, view, out));
  const std::array<std::uint8_t, 3> abc{'a', 'b', 'c'};
  const std::array<std::uint8_t, 32> expected{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                              0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                              0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                              0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  assert(reb::NativeGuestDigest(abc) == expected);
  CheckGuestWireParity();
  std::puts(
      "PASS actual borrowed local320/memory resolution, pointer chains, checked "
      "limits/type/shared/endian and digest");
}
