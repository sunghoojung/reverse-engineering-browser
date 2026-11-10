#ifndef REB_NETWORK_HEADERS_HPP_
#define REB_NETWORK_HEADERS_HPP_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include "reb/event.hpp"
#include "reb/network_request.hpp"
namespace reb {
// Header block records, see protocol/native-network-v3.md. The Brave overlay's
// common/native_network_headers.h is the producer half of this ABI.
inline constexpr std::uint16_t kHeaderPayloadVersion = 1;
inline constexpr std::uint32_t kHeaderBlockLimitBytes = 320U * 1024U;

enum class HeaderSource : std::uint8_t {
  kBrowser = 1,
  kNetwork = 2,
  kEarlyHints = 3,
};

enum class HeaderState : std::uint8_t {
  kCaptured = 1,
  kCapturedShared = 2,
  kEmpty = 3,
  kNotCapturedBlockLimit = 4,
  kNotCapturedArtifactUnavailable = 5,
  kNotCapturedTransferRefused = 6,
  kNotCapturedSessionBudget = 7,
  kNotCapturedUrl = 8,
};

struct HeaderBlockPayload final {
  std::uint16_t protocol_version = kHeaderPayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint8_t source = 0;
  std::uint8_t state = 0;
  std::uint8_t referrer_policy = 0;
  std::uint8_t address_family = 0;
  std::uint32_t header_count = 0;
  std::uint32_t block_length = 0;
  std::uint32_t hop = 0;
  std::uint16_t status_code = 0;
  std::uint16_t remote_port = 0;
  std::array<std::uint8_t, 16> remote_address{};
  std::uint32_t unattributed_blocks = 0;
  std::uint32_t reserved0 = 0;
  std::array<std::uint8_t, 32> sha256{};
  std::array<std::uint8_t, 48> reserved1{};
};
static_assert(sizeof(HeaderBlockPayload) == 128);
static_assert(std::is_standard_layout_v<HeaderBlockPayload>);
static_assert(std::is_trivially_copyable_v<HeaderBlockPayload>);
static_assert(offsetof(HeaderBlockPayload, source) == 4);
static_assert(offsetof(HeaderBlockPayload, header_count) == 8);
static_assert(offsetof(HeaderBlockPayload, hop) == 16);
static_assert(offsetof(HeaderBlockPayload, status_code) == 20);
static_assert(offsetof(HeaderBlockPayload, remote_address) == 24);
static_assert(offsetof(HeaderBlockPayload, unattributed_blocks) == 40);
static_assert(offsetof(HeaderBlockPayload, sha256) == 48);
static_assert(offsetof(HeaderBlockPayload, reserved1) == 80);

[[nodiscard]] inline bool DecodeHeaderBlockPayload(std::span<const std::byte> bytes,
                                                   HeaderBlockPayload& value) noexcept {
  using request_detail::Get;
  if (bytes.size() != 128) {
    return false;
  }
  const auto copy = [&bytes](const std::size_t offset, auto& out) {
    std::transform(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                   bytes.begin() + static_cast<std::ptrdiff_t>(offset + out.size()), out.begin(),
                   [](std::byte b) { return std::to_integer<std::uint8_t>(b); });
  };
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.source = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  value.state = static_cast<std::uint8_t>(Get(bytes, 5, 1));
  value.referrer_policy = static_cast<std::uint8_t>(Get(bytes, 6, 1));
  value.address_family = static_cast<std::uint8_t>(Get(bytes, 7, 1));
  value.header_count = static_cast<std::uint32_t>(Get(bytes, 8, 4));
  value.block_length = static_cast<std::uint32_t>(Get(bytes, 12, 4));
  value.hop = static_cast<std::uint32_t>(Get(bytes, 16, 4));
  value.status_code = static_cast<std::uint16_t>(Get(bytes, 20, 2));
  value.remote_port = static_cast<std::uint16_t>(Get(bytes, 22, 2));
  copy(24, value.remote_address);
  value.unattributed_blocks = static_cast<std::uint32_t>(Get(bytes, 40, 4));
  value.reserved0 = static_cast<std::uint32_t>(Get(bytes, 44, 4));
  copy(48, value.sha256);
  copy(80, value.reserved1);
  return true;
}

// Payload rules from protocol/native-network-v3.md. has_artifact is whether the
// envelope names a header artifact.
[[nodiscard]] inline bool IsValidHeaderBlockPayload(const HeaderBlockPayload& value,
                                                    const bool response,
                                                    const bool has_artifact) noexcept {
  using enum HeaderState;
  const auto zero = [](const auto& bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
  };
  const auto source = static_cast<HeaderSource>(value.source);
  const auto state = static_cast<HeaderState>(value.state);
  if (value.protocol_version != kHeaderPayloadVersion || value.payload_size != 128 ||
      value.reserved0 != 0 || !zero(value.reserved1) ||
      value.state < static_cast<std::uint8_t>(kCaptured) ||
      value.state > static_cast<std::uint8_t>(kNotCapturedUrl)) {
    return false;
  }
  const bool addressed = value.address_family != 0;
  if (response) {
    if (value.referrer_policy != 0 ||
        (source == HeaderSource::kBrowser
             ? value.status_code > 999 || (value.status_code != 0 && value.status_code < 100)
             : source != HeaderSource::kEarlyHints || value.status_code != 103 || addressed)) {
      return false;
    }
  } else if (value.status_code != 0 || addressed ||
             (source == HeaderSource::kBrowser
                  ? value.referrer_policy < 1 || value.referrer_policy > 8
                  : source != HeaderSource::kNetwork || value.referrer_policy != 0)) {
    return false;
  }
  const std::span<const std::uint8_t> address(value.remote_address);
  if ((value.address_family != 0 && value.address_family != 4 && value.address_family != 6) ||
      (!addressed && (value.remote_port != 0 || !zero(address))) ||
      (value.address_family == 4 && !zero(address.subspan(4)))) {
    return false;
  }
  const bool empty = state == kEmpty;
  const bool limited = state == kNotCapturedBlockLimit;
  if ((value.header_count == 0) != empty || (value.block_length == 0) != empty ||
      static_cast<std::uint64_t>(value.block_length) < 5ULL * value.header_count ||
      limited != (value.block_length > kHeaderBlockLimitBytes) || zero(value.sha256) != limited) {
    return false;
  }
  return has_artifact == (state == kCaptured || state == kCapturedShared);
}

[[nodiscard]] inline bool IsValidHeaderBlockEvent(const EventRecord& event) noexcept {
  const bool response = event.header.type == EventType::kResponseHeaders;
  HeaderBlockPayload value;
  return (response || event.header.type == EventType::kRequestHeaders) &&
         request_detail::IsRequestChildEnvelope(event, event.header.type) &&
         DecodeHeaderBlockPayload(event.inline_payload, value) &&
         IsValidHeaderBlockPayload(value, response, event.header.artifact_id != 0);
}
}  // namespace reb
#endif
