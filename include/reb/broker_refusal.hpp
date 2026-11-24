#ifndef REB_BROKER_REFUSAL_HPP_
#define REB_BROKER_REFUSAL_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "reb/event.hpp"

namespace reb {

// A broker_refusal record (type 53) stands in the store for a record the
// broker refused at validation, so the loss is evidence rather than a count on
// the broker's stop line. Only the broker writes it, and IsValidEvent refuses
// it from a producer. See protocol/broker-refusal-v1.md.
inline constexpr std::uint16_t kBrokerRefusalPayloadVersion = 1;
inline constexpr std::size_t kBrokerRefusalPayloadSize = 128;
// The process ID of the broker's own stream. It is reserved: a producer record
// claiming it is refused, so a refusal on that stream can never share an
// event identity with an observation.
inline constexpr std::uint32_t kBrokerProcessId = 0xffffffffU;

// The first check a refused record failed, in the order IsValidEvent applies
// them. kNone is a valid record.
enum class EventRefusal : std::uint16_t {
  kNone = 0,
  kProtocolVersion = 1,
  kHeaderSize = 2,
  kProcessId = 3,
  kPayloadSize = 4,
  kReserved = 5,
  kCategory = 6,
  kType = 7,
  kFlags = 8,
  kNetworkClass = 9,
  kTypedPayload = 10,
};
inline constexpr std::uint16_t kEventRefusalLast = 10;

// Whose identity the refusal's header carries. After an envelope refusal the
// refused record's place cannot be used: its header's layout is unknown
// (protocol version, header size) or it claims the broker's own stream
// (process ID). The record then takes that stream instead: kBrokerProcessId,
// thread 0 and the broker's next sequence number on it.
enum class BrokerRefusalIdentity : std::uint16_t {
  kRefused = 1,
  kBroker = 2,
};

// Version 1, 128 bytes, little-endian. Every refused field is copied as read
// at its version 3 offset and was not validated. No payload byte of the
// refused record is kept: validation is part of the capture contract, so the
// bytes it refused are never stored.
struct BrokerRefusalPayload final {
  std::uint16_t version = kBrokerRefusalPayloadVersion;
  std::uint16_t size = kBrokerRefusalPayloadSize;
  EventRefusal reason = EventRefusal::kNone;
  BrokerRefusalIdentity identity = BrokerRefusalIdentity::kRefused;
  std::uint16_t protocol_version = 0;
  std::uint16_t header_size = 0;
  std::uint16_t category = 0;
  std::uint16_t type = 0;
  std::uint32_t payload_size = 0;
  std::uint16_t flags = 0;
  std::uint8_t scheme_class = 0;
  std::uint8_t loader_kind = 0;
  // The broker's monotonic clock when the record arrived.
  std::uint64_t received_monotonic_time_ns = 0;
  std::uint64_t sequence_number = 0;
  std::uint64_t monotonic_time_ns = 0;
  std::uint32_t process_id = 0;
  std::uint32_t thread_id = 0;
};

namespace broker_refusal_detail {
inline void Put(std::span<std::byte> out,
                const std::size_t offset,
                const std::uint64_t value,
                const std::size_t size) noexcept {
  for (std::size_t index = 0; index < size; ++index)
    out[offset + index] = static_cast<std::byte>((value >> (8U * index)) & 0xffU);
}
inline std::uint64_t Get(std::span<const std::byte> bytes,
                         const std::size_t offset,
                         const std::size_t size) noexcept {
  std::uint64_t result = 0;
  for (std::size_t index = 0; index < size; ++index)
    result |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[offset + index]))
              << (8U * index);
  return result;
}
}  // namespace broker_refusal_detail

[[nodiscard]] inline std::array<std::byte, kBrokerRefusalPayloadSize> EncodeBrokerRefusalPayload(
    const BrokerRefusalPayload& value) noexcept {
  using broker_refusal_detail::Put;
  std::array<std::byte, kBrokerRefusalPayloadSize> out{};
  Put(out, 0, value.version, 2);
  Put(out, 2, value.size, 2);
  Put(out, 4, static_cast<std::uint16_t>(value.reason), 2);
  Put(out, 6, static_cast<std::uint16_t>(value.identity), 2);
  Put(out, 8, value.protocol_version, 2);
  Put(out, 10, value.header_size, 2);
  Put(out, 12, value.category, 2);
  Put(out, 14, value.type, 2);
  Put(out, 16, value.payload_size, 4);
  Put(out, 20, value.flags, 2);
  Put(out, 22, value.scheme_class, 1);
  Put(out, 23, value.loader_kind, 1);
  Put(out, 24, value.received_monotonic_time_ns, 8);
  Put(out, 32, value.sequence_number, 8);
  Put(out, 40, value.monotonic_time_ns, 8);
  Put(out, 48, value.process_id, 4);
  Put(out, 52, value.thread_id, 4);
  return out;
}

// Decodes the fields; bytes 56 to 128 must be zero.
[[nodiscard]] inline bool DecodeBrokerRefusalPayload(std::span<const std::byte> bytes,
                                                     BrokerRefusalPayload& value) noexcept {
  using broker_refusal_detail::Get;
  if (bytes.size() != kBrokerRefusalPayloadSize)
    return false;
  for (std::size_t index = 56; index < bytes.size(); ++index)
    if (bytes[index] != std::byte{0})
      return false;
  value.version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.reason = static_cast<EventRefusal>(Get(bytes, 4, 2));
  value.identity = static_cast<BrokerRefusalIdentity>(Get(bytes, 6, 2));
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 8, 2));
  value.header_size = static_cast<std::uint16_t>(Get(bytes, 10, 2));
  value.category = static_cast<std::uint16_t>(Get(bytes, 12, 2));
  value.type = static_cast<std::uint16_t>(Get(bytes, 14, 2));
  value.payload_size = static_cast<std::uint32_t>(Get(bytes, 16, 4));
  value.flags = static_cast<std::uint16_t>(Get(bytes, 20, 2));
  value.scheme_class = static_cast<std::uint8_t>(Get(bytes, 22, 1));
  value.loader_kind = static_cast<std::uint8_t>(Get(bytes, 23, 1));
  value.received_monotonic_time_ns = Get(bytes, 24, 8);
  value.sequence_number = Get(bytes, 32, 8);
  value.monotonic_time_ns = Get(bytes, 40, 8);
  value.process_id = static_cast<std::uint32_t>(Get(bytes, 48, 4));
  value.thread_id = static_cast<std::uint32_t>(Get(bytes, 52, 4));
  return true;
}

// Why IsValidEvent refuses `event`, or kNone when it accepts it.
[[nodiscard]] EventRefusal EventRefusalOf(const EventRecord& event) noexcept;
[[nodiscard]] std::string_view EventRefusalName(EventRefusal reason) noexcept;
// The category a refusal of a record with this raw category files under: that
// category when it is a known one, else kUnknown.
[[nodiscard]] EventCategory BrokerRefusalCategory(std::uint16_t refused_category) noexcept;
// Whether a refusal for `reason` takes the broker's stream (identity kBroker).
[[nodiscard]] constexpr bool IsEnvelopeRefusal(const EventRefusal reason) noexcept {
  return reason == EventRefusal::kProtocolVersion || reason == EventRefusal::kHeaderSize ||
         reason == EventRefusal::kProcessId;
}
// The record the broker stores in place of `refused`, which `reason` refused.
// `broker_sequence` numbers the broker's own stream and is used only after an
// envelope refusal (IsEnvelopeRefusal).
[[nodiscard]] EventRecord MakeBrokerRefusal(const EventRecord& refused,
                                            EventRefusal reason,
                                            std::uint64_t received_monotonic_time_ns,
                                            std::uint64_t broker_sequence) noexcept;
// A record MakeBrokerRefusal can write. A store reader applies this; the wire
// never carries one.
[[nodiscard]] bool IsValidBrokerRefusal(const EventRecord& event) noexcept;

}  // namespace reb

#endif  // REB_BROKER_REFUSAL_HPP_
