// Actual overlay encoder -> core validator/JSON. Authored ABI fixture, not live capture.
#include <algorithm>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_wasm_guest_wire.h"
#include "reb/event.hpp"
#include "reb/wasm_guest.hpp"

int main(int argc, char** argv) {
  std::string_view mode = "default", recipe;
  bool host_fixture = false, quickjs_fixture = false;
  for (int i = 1; i < argc; ++i) {
    const std::string_view argument = argv[i];
    if (argument == "--quickjs-fixture") {
      quickjs_fixture = true;
      continue;
    }
    if (argument == "--host-fixture") {
      host_fixture = true;
      continue;
    }
    if ((argument == "--case" || argument == "--recipe-sha") && i + 1 < argc) {
      if (argument == "--case")
        mode = argv[++i];
      else
        recipe = argv[++i];
    } else
      return 2;
  }
  auto event =
      reb::MakeEvent(reb::EventCategory::kVm, reb::EventType::kWasmGuestInvocation, 104, 55, 101);
  event.header.process_id = 3;
  event.header.thread_id = 4;
  event.header.frame_id = 103;
  event.header.artifact_id = 107;
  reb::NativeWasmGuestInvocationPayload invocation;
  invocation.instance_id = 11;
  invocation.invocation_id = 12;
  invocation.adapter_artifact_id = 108;
  invocation.recipe_sha256.fill(std::byte{0x42});
  if (!recipe.empty()) {
    if (recipe.size() != 64)
      return 2;
    const auto digit = [](char c) -> int {
      return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
      const int high = digit(recipe[i * 2]), low = digit(recipe[i * 2 + 1]);
      if (high < 0 || low < 0)
        return 2;
      invocation.recipe_sha256[i] = static_cast<std::byte>((high << 4) | low);
    }
  }

  reb::NativeWasmGuestDispatchPayload sample;
  sample.module_byte_offset = 47;
  sample.selector = std::numeric_limits<std::uint32_t>::max();
  sample.table_count = 2;
  sample.instance_id = 11;
  sample.invocation_id = 12;
  sample.guest_pc = 1;
  sample.raw_pc_bits = 257;
  sample.bytecode_artifact_id = 109;
  sample.memory_base = 256;
  sample.memory_length = 4;
  sample.opcode = 0x42;
  sample.recipe_sha256 = invocation.recipe_sha256;
  if (host_fixture) {
    invocation.function_index = 1;
    sample.function_index = 1;
    sample.module_byte_offset = 58;
  }
  if (quickjs_fixture) {
    invocation.function_index = 414;
    sample.function_index = 414;
    sample.module_byte_offset = 0x20677;
    sample.table_count = 244;
    sample.selector = sample.opcode;
    sample.pc_local_index = 320;
    sample.raw_pc_bits = 4097;
    sample.memory_base = 4096;
  }
  bool valid_invocation = true, valid_sample = true;
  if (mode == "default") {
  } else if (mode == "version") {
    sample.protocol_version = 2;
    valid_sample = false;
  } else if (mode == "size") {
    sample.payload_size = 127;
    valid_sample = false;
  } else if (mode == "reserved") {
    invocation.reserved[0] = std::byte{1};
    valid_invocation = false;
  } else if (mode == "pc-range") {
    sample.guest_pc = 4;
    valid_sample = false;
  } else if (mode == "snapshot-limit") {
    sample.memory_length = 65537;
    valid_sample = false;
  } else if (mode == "memory-overflow") {
    sample.memory_base = std::numeric_limits<std::uint64_t>::max();
    valid_sample = false;
  } else if (mode == "sample-limit") {
    sample.sample_index = 256;
    valid_sample = false;
  } else if (mode == "digest") {
    sample.recipe_sha256.fill(std::byte{0});
    valid_sample = false;
  } else if (mode == "signed-adjustment") {
    sample.pc_adjustment = std::numeric_limits<std::int64_t>::min();
  } else if (mode == "wide-identities") {
    invocation.instance_id = sample.instance_id = std::numeric_limits<std::uint64_t>::max();
  } else if (mode == "legacy-invocation") {
    invocation.protocol_version = 1;
  } else if (mode == "parent-dispatch") {
    invocation.parent_invocation_id = 10;
    invocation.parent_dispatch_sequence_number = 103;
  } else if (mode == "parent-dispatch-order") {
    invocation.parent_invocation_id = 10;
    invocation.parent_dispatch_sequence_number = 104;
    valid_invocation = false;
  } else if (mode == "parent-dispatch-orphan") {
    invocation.parent_dispatch_sequence_number = 103;
    valid_invocation = false;
  } else if (mode == "legacy-reserved") {
    // Version 1 reserved the parent dispatch bytes.
    invocation.protocol_version = 1;
    invocation.parent_invocation_id = 10;
    invocation.parent_dispatch_sequence_number = 103;
    valid_invocation = false;
  } else if (mode == "parent" || mode == "truncated" || mode == "big-endian") {
    valid_sample = false;
  } else
    return 2;
  auto inv_bytes = reb::EncodeNativeWasmGuestInvocationPayload(invocation);
  reb::WasmGuestInvocationPayload decoded_inv;
  assert(reb::DecodeWasmGuestInvocationPayload(inv_bytes, decoded_inv));
  assert(reb::EncodeWasmGuestInvocationPayload(decoded_inv) == inv_bytes);
  assert(reb::SetInlinePayload(event, inv_bytes));
  assert(reb::IsValidEvent(event) == valid_invocation);
  std::string json;
  reb::WriteEventJson(event, json);
  std::cout << json << '\n';
  event.header.type = reb::EventType::kWasmGuestDispatch;
  event.header.sequence_number = 105;
  event.header.parent_event_id = 104;
  auto bytes = reb::EncodeNativeWasmGuestDispatchPayload(sample);
  reb::WasmGuestDispatchPayload decoded;
  assert(reb::DecodeWasmGuestDispatchPayload(bytes, decoded));
  assert(reb::EncodeWasmGuestDispatchPayload(decoded) == bytes);
  assert(decoded.pc_adjustment == sample.pc_adjustment);
  if (mode == "big-endian") {
    bytes[0] = std::byte{0};
    bytes[1] = std::byte{1};
  }
  assert(reb::SetInlinePayload(event, bytes));
  if (mode == "parent")
    event.header.parent_event_id = 0;
  if (mode == "truncated")
    event.header.payload_size = 127;
  assert(reb::IsValidEvent(event) == valid_sample);
  reb::WriteEventJson(event, json);
  std::cout << json << '\n';
  return 0;
}
