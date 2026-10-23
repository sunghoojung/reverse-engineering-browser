#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>

#include "reb/event.hpp"

namespace {

bool CheckJsonReuse() {
  reb::EventRecord event =
      reb::MakeEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 1, 2, 3);
  constexpr std::string_view expected =
      "{\"protocol_version\":3,\"session_id\":\"3\",\"sequence_number\":\"1\","
      "\"monotonic_time_ns\":\"2\",\"process_id\":0,\"thread_id\":0,\"tab_id\":0,"
      "\"navigation_id\":\"0\",\"frame_id\":\"0\",\"artifact_id\":\"0\","
      "\"parent_event_id\":\"0\",\"request_id\":\"0\",\"browser_context_id_high\":\"0\","
      "\"browser_context_id_low\":\"0\",\"encoded_data_length\":\"0\","
      "\"decoded_body_length\":\"0\",\"status_code\":0,\"error_code\":0,\"resource_type\":0,"
      "\"flags\":0,\"initiator_request_id\":0,\"initiator_process_id\":0,"
      "\"payload_truncated\":false,\"category\":\"canvas\",\"type\":\"api_call\","
      "\"payload_size\":0,\"payload_encoding\":\"hex\",\"payload\":\"\"}";
  std::string output("previous content must not survive");
  reb::WriteEventJson(event, output);
  if (output != expected || reb::EventToJson(event) != expected) {
    std::cerr << "Event JSON bytes changed\n";
    return false;
  }
  const char* const storage = output.data();
  const std::size_t capacity = output.capacity();

  // Include quotes, backslashes, controls, and malformed UTF-8. All payload
  // bytes remain inert lowercase hex, never string content needing escaping.
  constexpr std::string_view hex = "0123456789abcdef";
  std::string expected_payload_suffix;
  for (const unsigned first : {0U, 128U}) {
    std::array<std::byte, reb::kInlinePayloadSize> bytes;
    std::string expected_hex;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
      const auto value = static_cast<unsigned>(index) + first;
      bytes[index] = static_cast<std::byte>(value);
      expected_hex.push_back(hex[value >> 4U]);
      expected_hex.push_back(hex[value & 15U]);
    }
    if (!reb::SetInlinePayload(event, bytes)) {
      return false;
    }
    expected_payload_suffix = "\"payload\":\"" + expected_hex + "\"}";
    reb::WriteEventJson(event, output);
    if (!output.ends_with(expected_payload_suffix) || output != reb::EventToJson(event)) {
      std::cerr << "Payload byte encoding changed\n";
      return false;
    }
  }

  // Widest numeric representations and longest known enum labels must fit
  // the one-record budget even with a malformed advertised payload length.
  auto& header = event.header;
  header.protocol_version = std::numeric_limits<std::uint16_t>::max();
  header.category = reb::EventCategory::kPermissions;
  header.type = reb::EventType::kArtifactCaptureFailed;
  header.payload_size = std::numeric_limits<std::uint32_t>::max();
  header.tab_id = std::numeric_limits<std::uint32_t>::max();
  header.sequence_number = std::numeric_limits<std::uint64_t>::max();
  header.monotonic_time_ns = std::numeric_limits<std::uint64_t>::max();
  header.session_id = std::numeric_limits<std::uint64_t>::max();
  header.process_id = std::numeric_limits<std::uint32_t>::max();
  header.thread_id = std::numeric_limits<std::uint32_t>::max();
  header.navigation_id = std::numeric_limits<std::uint64_t>::max();
  header.frame_id = std::numeric_limits<std::uint64_t>::max();
  header.artifact_id = std::numeric_limits<std::uint64_t>::max();
  header.parent_event_id = std::numeric_limits<std::uint64_t>::max();
  header.request_id = std::numeric_limits<std::uint64_t>::max();
  header.browser_context_id_high = std::numeric_limits<std::uint64_t>::max();
  header.browser_context_id_low = std::numeric_limits<std::uint64_t>::max();
  header.encoded_data_length = std::numeric_limits<std::int64_t>::min();
  header.decoded_body_length = std::numeric_limits<std::int64_t>::min();
  header.status_code = std::numeric_limits<std::int32_t>::min();
  header.error_code = std::numeric_limits<std::int32_t>::min();
  header.resource_type = std::numeric_limits<std::uint16_t>::max();
  header.flags = std::numeric_limits<std::uint16_t>::max() - 1;
  header.initiator_request_id = std::numeric_limits<std::uint32_t>::max();
  header.initiator_process_id = std::numeric_limits<std::uint32_t>::max();
  reb::WriteEventJson(event, output);
  if (output != reb::EventToJson(event) || output.size() > reb::kMaxEventJsonBytes ||
      output.capacity() != capacity || output.data() != storage || reb::IsValidEvent(event) ||
      !output.ends_with(expected_payload_suffix) ||
      output.find("\"payload_size\":4294967295,") == std::string::npos ||
      output.find("\"encoded_data_length\":\"-9223372036854775808\"") == std::string::npos) {
    std::cerr << "Event JSON budget, reuse, or malformed-input contract failed\n";
    return false;
  }
  event = reb::MakeEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 1, 2, 3);
  for (unsigned iteration = 0; iteration < 10000; ++iteration) {
    reb::WriteEventJson(event, output);
    if (output != expected || output.data() != storage || output.capacity() != capacity) {
      std::cerr << "Empty record retained preceding bytes or replaced its buffer\n";
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
  const reb::EventRecord event =
      reb::MakeEvent(reb::EventCategory::kVm, reb::EventType::kVmDispatchSample, 1, 2, 3);
  if (!reb::IsValidEvent(event) ||
      reb::EventTypeName(reb::EventType::kVmDispatchSample) != "vm_dispatch_sample") {
    std::cerr << "VM dispatch event type contract failed\n";
    return 1;
  }
  return CheckJsonReuse() ? 0 : 1;
}
