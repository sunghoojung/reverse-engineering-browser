// Emits the real native payload encoder through the production core JSON writer.
// Authored test observations, not evidence of a running Brave/V8 build.
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>

#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_wasm_dispatch.h"
#include "reb/event.hpp"
#include "reb/wasm_dispatch.hpp"

int main(int argc, char** argv) {
  std::string_view mode = "default";
  if (argc == 3 && std::string_view(argv[1]) == "--case")
    mode = argv[2];
  else if (argc != 1)
    return 2;
  reb::NativeProbeEvent native;
  native.header.category = reb::NativeProbeCategory::kVm;
  native.header.type = reb::NativeProbeType::kWasmDispatchObservation;
  native.header.payload_size = 128;
  native.header.session_id = 101;
  native.header.frame_id = 103;
  native.header.sequence_number = 104;
  native.header.artifact_id = 107;
  native.header.process_id = 3;
  native.header.thread_id = 4;
  native.header.monotonic_time_ns = 55;
  reb::NativeWasmDispatchObservationPayload payload;
  payload.module_byte_offset = 47;
  payload.selector = std::numeric_limits<std::uint32_t>::max();
  payload.table_count = 2;
  bool syntactically_valid = true;
  if (mode == "default") {
  } else if (mode == "arm")
    payload.selector = 0;
  else if (mode == "wide-identities") {
    native.header.session_id = native.header.sequence_number = native.header.monotonic_time_ns =
        native.header.frame_id = native.header.artifact_id =
            std::numeric_limits<std::uint64_t>::max();
    native.header.process_id = native.header.thread_id = std::numeric_limits<std::uint32_t>::max();
  } else if (mode == "function")
    payload.function_index = 1;
  else if (mode == "count")
    payload.table_count = 3;
  else if (mode == "offset")
    payload.module_byte_offset = 46;
  else if (mode == "reserved") {
    payload.reserved[0] = std::byte{1};
    syntactically_valid = false;
  } else if (mode == "version") {
    payload.protocol_version = 2;
    syntactically_valid = false;
  } else if (mode == "size") {
    payload.payload_size = 127;
    syntactically_valid = false;
  } else if (mode == "truncated") {
    native.header.payload_size = 127;
    syntactically_valid = false;
  } else if (mode == "sample-index") {
    payload.sample_index = 16;
    syntactically_valid = false;
  } else if (mode == "flags") {
    native.header.flags = 1;
    syntactically_valid = false;
  } else if (mode == "parent") {
    native.header.parent_event_id = 9;
    syntactically_valid = false;
  } else if (mode == "identity") {
    native.header.artifact_id = 0;
    syntactically_valid = false;
  } else if (mode == "envelope-version") {
    native.header.protocol_version = 2;
    syntactically_valid = false;
  } else if (mode == "big-endian")
    syntactically_valid = false;
  else
    return 2;
  native.inline_payload = reb::EncodeNativeWasmDispatchObservationPayload(payload);
  if (mode == "big-endian") {
    native.inline_payload[0] = std::byte{0};
    native.inline_payload[1] = std::byte{1};
  }
  static_assert(sizeof(reb::NativeProbeEvent) == sizeof(reb::EventRecord));
  static_assert(alignof(reb::NativeProbeEvent) == alignof(reb::EventRecord));
  static_assert(offsetof(reb::NativeProbeEvent, inline_payload) ==
                offsetof(reb::EventRecord, inline_payload));
  static_assert(offsetof(reb::NativeProbeEvent, reserved) == offsetof(reb::EventRecord, reserved));
#define CHECK_FIELD(field) \
  static_assert(offsetof(reb::NativeProbeHeader, field) == offsetof(reb::EventHeader, field))
  CHECK_FIELD(protocol_version);
  CHECK_FIELD(header_size);
  CHECK_FIELD(category);
  CHECK_FIELD(type);
  CHECK_FIELD(payload_size);
  CHECK_FIELD(tab_id);
  CHECK_FIELD(sequence_number);
  CHECK_FIELD(monotonic_time_ns);
  CHECK_FIELD(session_id);
  CHECK_FIELD(process_id);
  CHECK_FIELD(thread_id);
  CHECK_FIELD(navigation_id);
  CHECK_FIELD(frame_id);
  CHECK_FIELD(artifact_id);
  CHECK_FIELD(parent_event_id);
  CHECK_FIELD(request_id);
  CHECK_FIELD(browser_context_id_high);
  CHECK_FIELD(browser_context_id_low);
  CHECK_FIELD(encoded_data_length);
  CHECK_FIELD(decoded_body_length);
  CHECK_FIELD(status_code);
  CHECK_FIELD(error_code);
  CHECK_FIELD(resource_type);
  CHECK_FIELD(flags);
  CHECK_FIELD(initiator_request_id);
  CHECK_FIELD(initiator_process_id);
  CHECK_FIELD(reserved1);
#undef CHECK_FIELD
  const auto event = std::bit_cast<reb::EventRecord>(native);
  assert(reb::IsValidEvent(event) == syntactically_valid);
  reb::WasmDispatchObservationPayload decoded;
  assert(reb::DecodeWasmDispatchObservationPayload(event.inline_payload, decoded));
  assert(reb::EncodeWasmDispatchObservationPayload(decoded) == native.inline_payload);
  std::cout << reb::EventToJson(event) << '\n';
}
