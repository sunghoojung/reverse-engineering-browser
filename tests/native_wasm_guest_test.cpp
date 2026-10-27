#include "components/reverse_engineering_browser/common/native_wasm_guest.h"
#include <cassert>
#include <cstdio>
#include "components/reverse_engineering_browser/common/native_artifact_queue_limits.h"
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
  std::puts(
      "PASS actual borrowed local320/memory resolution, pointer chains, checked "
      "limits/type/shared/endian and digest");
}
