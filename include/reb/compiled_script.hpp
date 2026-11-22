#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "reb/event.hpp"

// Wire contract: protocol/native-compiled-scripts-v2.md.
namespace reb {

// Version 2 hashes every source, with no source budget or size limit.
inline constexpr std::uint16_t kCompiledScriptPayloadVersion = 2;
// Version 1 only: a longer source was not hashed.
inline constexpr std::uint64_t kCompiledScriptMaxSourceBytes = 16ULL * 1024ULL * 1024ULL;

enum class CompiledScriptKind : std::uint8_t {
  kScript = 1,
  kModule = 2,
  kFunction = 3,
  kEval = 4,
  kFunctionConstructor = 5,
};

enum class CompiledScriptRetention : std::uint8_t {
  kQueued = 1,
  kDuplicate = 2,
  kNetworkFetched = 3,
  kNotPermitted = 4,
  // Version 1 only: the renderer's 64 MiB source budget was spent.
  kBudgetSpent = 5,
  // Version 1 only: over 16 MiB, so not hashed.
  kTooLarge = 6,
  kUnavailable = 7,
  // Version 2: the renderer's 256 MiB of content waiting for the browser was
  // in use, so the source was hashed and not sent.
  kTransferBacklog = 8,
};

struct CompiledScriptPayload final {
  std::uint16_t protocol_version = kCompiledScriptPayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint8_t kind = 0;
  std::uint8_t retention = 0;
  std::uint16_t reserved_after_retention = 0;
  std::uint32_t script_id = 0;
  std::uint32_t start_line = 0;
  std::uint32_t start_column = 0;
  std::uint32_t creator_script_id = 0;
  std::uint64_t execution_context_id = 0;
  std::uint64_t source_length = 0;
  std::array<std::byte, 32> source_sha256{};
  std::uint32_t creator_position = 0;
  std::array<std::byte, 52> reserved{};
};

[[nodiscard]] inline std::array<std::byte, 128> EncodeCompiledScriptPayload(
    const CompiledScriptPayload& value) noexcept {
  std::array<std::byte, 128> out{};
  const auto put = [&out](std::size_t offset, std::uint64_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
      out[offset + i] = static_cast<std::byte>((v >> (8U * i)) & 255U);
  };
  put(0, value.protocol_version, 2);
  put(2, value.payload_size, 2);
  put(4, value.kind, 1);
  put(5, value.retention, 1);
  put(6, value.reserved_after_retention, 2);
  put(8, value.script_id, 4);
  put(12, value.start_line, 4);
  put(16, value.start_column, 4);
  put(20, value.creator_script_id, 4);
  put(24, value.execution_context_id, 8);
  put(32, value.source_length, 8);
  std::copy(value.source_sha256.begin(), value.source_sha256.end(), out.begin() + 40);
  put(72, value.creator_position, 4);
  std::copy(value.reserved.begin(), value.reserved.end(), out.begin() + 76);
  return out;
}

[[nodiscard]] inline bool DecodeCompiledScriptPayload(std::span<const std::byte> bytes,
                                                      CompiledScriptPayload& value) noexcept {
  if (bytes.size() != 128)
    return false;
  const auto get = [bytes](std::size_t offset, std::size_t width) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < width; ++i)
      v |= std::to_integer<std::uint64_t>(bytes[offset + i]) << (8U * i);
    return v;
  };
  value.protocol_version = static_cast<std::uint16_t>(get(0, 2));
  value.payload_size = static_cast<std::uint16_t>(get(2, 2));
  value.kind = static_cast<std::uint8_t>(get(4, 1));
  value.retention = static_cast<std::uint8_t>(get(5, 1));
  value.reserved_after_retention = static_cast<std::uint16_t>(get(6, 2));
  value.script_id = static_cast<std::uint32_t>(get(8, 4));
  value.start_line = static_cast<std::uint32_t>(get(12, 4));
  value.start_column = static_cast<std::uint32_t>(get(16, 4));
  value.creator_script_id = static_cast<std::uint32_t>(get(20, 4));
  value.execution_context_id = get(24, 8);
  value.source_length = get(32, 8);
  std::copy(bytes.begin() + 40, bytes.begin() + 72, value.source_sha256.begin());
  value.creator_position = static_cast<std::uint32_t>(get(72, 4));
  std::copy(bytes.begin() + 76, bytes.end(), value.reserved.begin());
  return true;
}

[[nodiscard]] inline bool IsValidCompiledScriptPayload(
    const CompiledScriptPayload& value) noexcept {
  const auto zero = [](std::byte b) { return b == std::byte{0}; };
  const bool generated =
      value.kind == static_cast<std::uint8_t>(CompiledScriptKind::kEval) ||
      value.kind == static_cast<std::uint8_t>(CompiledScriptKind::kFunctionConstructor);
  const bool too_large =
      value.retention == static_cast<std::uint8_t>(CompiledScriptRetention::kTooLarge);
  const bool unavailable =
      value.retention == static_cast<std::uint8_t>(CompiledScriptRetention::kUnavailable);
  const bool digest_is_zero =
      std::all_of(value.source_sha256.begin(), value.source_sha256.end(), zero);
  const bool limited = value.protocol_version == 1;
  const bool retention_known =
      limited ? value.retention >= 1 && value.retention <= 7
              : value.retention >= 1 && value.retention <= 8 &&
                    value.retention !=
                        static_cast<std::uint8_t>(CompiledScriptRetention::kBudgetSpent) &&
                    !too_large;
  const bool source_is_hashed = value.source_length != 0 && !digest_is_zero &&
                                (!limited || value.source_length <= kCompiledScriptMaxSourceBytes);
  return (value.protocol_version == 1 || value.protocol_version == kCompiledScriptPayloadVersion) &&
         value.payload_size == 128 && value.kind >= 1 && value.kind <= 5 && retention_known &&
         value.reserved_after_retention == 0 && value.script_id != 0 &&
         value.execution_context_id != 0 &&
         (generated || (value.creator_script_id == 0 && value.creator_position == 0)) &&
         (value.creator_script_id != 0 || value.creator_position == 0) &&
         (too_large     ? value.source_length > kCompiledScriptMaxSourceBytes && digest_is_zero
          : unavailable ? digest_is_zero
                        : source_is_hashed) &&
         std::all_of(value.reserved.begin(), value.reserved.end(), zero);
}

[[nodiscard]] inline bool IsValidScriptCompiled(const EventRecord& event) noexcept {
  CompiledScriptPayload value;
  return event.header.protocol_version == kEventProtocolVersion &&
         event.header.category == EventCategory::kArtifact &&
         event.header.type == EventType::kScriptCompiled && event.header.payload_size == 128 &&
         event.header.flags == 0 && event.header.session_id != 0 &&
         event.header.sequence_number != 0 && event.header.process_id != 0 &&
         event.header.thread_id != 0 && event.header.monotonic_time_ns != 0 &&
         event.header.artifact_id == 0 && event.header.parent_event_id == 0 &&
         event.header.request_id == 0 && DecodeCompiledScriptPayload(event.inline_payload, value) &&
         IsValidCompiledScriptPayload(value);
}

}  // namespace reb
