#ifndef REB_NETWORK_COOKIES_HPP_
#define REB_NETWORK_COOKIES_HPP_
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include "reb/event.hpp"
#include "reb/network_headers.hpp"
#include "reb/network_request.hpp"
namespace reb {
// Cookie records, see "Cookies" in protocol/native-network-v3.md. The overlay's
// common/native_network_cookies.h is the producer half of this ABI.
inline constexpr std::uint16_t kCookiePayloadVersion = 1;
inline constexpr std::uint32_t kCookieListLimitBytes = 2U * 1024U * 1024U;
inline constexpr std::uint32_t kCookieListHeaderBytes = 16;
inline constexpr std::uint32_t kCookieEntryBytes = 64;
inline constexpr std::uint32_t kScriptCookieNamePrefixBytes = 24;

enum class CookieDirection : std::uint8_t {
  kSent = 1,
  kReceived = 2,
};

enum class ScriptCookieApi : std::uint8_t {
  kDocumentCookieSet = 1,
  kDocumentCookieGet = 2,
  kCookieStoreSet = 3,
  kCookieStoreGet = 4,
  kCookieStoreGetAll = 5,
  kCookieStoreDelete = 6,
};

inline constexpr std::uint8_t kScriptCookieNameTruncated = 1U << 0U;
inline constexpr std::uint8_t kScriptCookieFrameRecorded = 1U << 1U;
inline constexpr std::uint8_t kScriptCookieStackRecorded = 1U << 2U;
inline constexpr std::uint8_t kScriptCookieTableFull = 1U << 3U;

struct CookieListPayload final {
  std::uint16_t protocol_version = kCookiePayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint8_t direction = 0;
  std::uint8_t state = 0;
  std::uint16_t reserved0 = 0;
  std::uint32_t cookie_count = 0;
  std::uint32_t blocked_count = 0;
  std::uint32_t list_length = 0;
  std::uint32_t hop = 0;
  std::uint32_t unattributed_lists = 0;
  std::uint32_t reserved1 = 0;
  std::array<std::uint8_t, 32> sha256{};
  std::array<std::uint8_t, 64> reserved2{};
};
static_assert(sizeof(CookieListPayload) == 128);
static_assert(std::is_trivially_copyable_v<CookieListPayload>);
static_assert(offsetof(CookieListPayload, cookie_count) == 8);
static_assert(offsetof(CookieListPayload, hop) == 20);
static_assert(offsetof(CookieListPayload, sha256) == 32);
static_assert(offsetof(CookieListPayload, reserved2) == 64);

// The request_initiator_stack frame layout: kind, flags, combinator, script ID,
// position and function start.
struct ScriptFrame final {
  std::uint8_t kind = 0;
  std::uint8_t flags = 0;
  std::uint16_t combinator = 0;
  std::uint32_t script_id = 0;
  std::uint32_t position = 0;
  std::uint32_t function_start = 0;
};
static_assert(sizeof(ScriptFrame) == 16);

struct ScriptCookiePayload final {
  std::uint16_t protocol_version = kCookiePayloadVersion;
  std::uint16_t payload_size = 128;
  std::uint8_t api = 0;
  std::uint8_t flags = 0;
  std::uint16_t reserved0 = 0;
  std::uint32_t count = 0;
  std::uint32_t name_length = 0;
  std::uint32_t value_length = 0;
  std::uint32_t string_length = 0;
  ScriptFrame frame;
  std::array<std::uint8_t, 32> stack_digest{};
  std::array<std::uint8_t, 32> value_sha256{};
  std::array<std::uint8_t, kScriptCookieNamePrefixBytes> name_prefix{};
};
static_assert(sizeof(ScriptCookiePayload) == 128);
static_assert(std::is_trivially_copyable_v<ScriptCookiePayload>);
static_assert(offsetof(ScriptCookiePayload, frame) == 24);
static_assert(offsetof(ScriptCookiePayload, stack_digest) == 40);
static_assert(offsetof(ScriptCookiePayload, value_sha256) == 72);
static_assert(offsetof(ScriptCookiePayload, name_prefix) == 104);

namespace cookie_detail {
template <std::size_t N>
void Copy(std::span<const std::byte> bytes,
          const std::size_t offset,
          std::array<std::uint8_t, N>& out) noexcept {
  std::transform(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                 bytes.begin() + static_cast<std::ptrdiff_t>(offset + N), out.begin(),
                 [](std::byte b) { return std::to_integer<std::uint8_t>(b); });
}
template <class Bytes>
[[nodiscard]] bool Zero(const Bytes& bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
}
}  // namespace cookie_detail

[[nodiscard]] inline bool DecodeCookieListPayload(std::span<const std::byte> bytes,
                                                  CookieListPayload& value) noexcept {
  using request_detail::Get;
  if (bytes.size() != 128) {
    return false;
  }
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.direction = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  value.state = static_cast<std::uint8_t>(Get(bytes, 5, 1));
  value.reserved0 = static_cast<std::uint16_t>(Get(bytes, 6, 2));
  value.cookie_count = static_cast<std::uint32_t>(Get(bytes, 8, 4));
  value.blocked_count = static_cast<std::uint32_t>(Get(bytes, 12, 4));
  value.list_length = static_cast<std::uint32_t>(Get(bytes, 16, 4));
  value.hop = static_cast<std::uint32_t>(Get(bytes, 20, 4));
  value.unattributed_lists = static_cast<std::uint32_t>(Get(bytes, 24, 4));
  value.reserved1 = static_cast<std::uint32_t>(Get(bytes, 28, 4));
  cookie_detail::Copy(bytes, 32, value.sha256);
  cookie_detail::Copy(bytes, 64, value.reserved2);
  return true;
}

[[nodiscard]] inline bool IsValidCookieListPayload(const CookieListPayload& value,
                                                   const bool has_artifact) noexcept {
  using enum HeaderState;
  using cookie_detail::Zero;
  const auto state = static_cast<HeaderState>(value.state);
  if (value.protocol_version != kCookiePayloadVersion || value.payload_size != 128 ||
      value.reserved0 != 0 || value.reserved1 != 0 || !Zero(value.reserved2) ||
      (value.direction != static_cast<std::uint8_t>(CookieDirection::kSent) &&
       value.direction != static_cast<std::uint8_t>(CookieDirection::kReceived)) ||
      value.state < static_cast<std::uint8_t>(kCaptured) ||
      value.state > static_cast<std::uint8_t>(kNotCapturedUrl) ||
      value.blocked_count > value.cookie_count) {
    return false;
  }
  const bool empty = state == kEmpty;
  const bool limited = state == kNotCapturedBlockLimit;
  if ((value.cookie_count == 0) != empty || (value.list_length == 0) != empty ||
      (!empty && static_cast<std::uint64_t>(value.list_length) <
                     kCookieListHeaderBytes +
                         static_cast<std::uint64_t>(kCookieEntryBytes) * value.cookie_count) ||
      limited != (value.list_length > kCookieListLimitBytes) || Zero(value.sha256) != limited) {
    return false;
  }
  return has_artifact == (state == kCaptured || state == kCapturedShared);
}

[[nodiscard]] inline bool IsValidCookieListEvent(const EventRecord& event) noexcept {
  CookieListPayload value;
  return request_detail::IsRequestChildEnvelope(event, EventType::kCookieList) &&
         DecodeCookieListPayload(event.inline_payload, value) &&
         IsValidCookieListPayload(value, event.header.artifact_id != 0);
}

[[nodiscard]] inline bool DecodeScriptCookiePayload(std::span<const std::byte> bytes,
                                                    ScriptCookiePayload& value) noexcept {
  using request_detail::Get;
  if (bytes.size() != 128) {
    return false;
  }
  value.protocol_version = static_cast<std::uint16_t>(Get(bytes, 0, 2));
  value.payload_size = static_cast<std::uint16_t>(Get(bytes, 2, 2));
  value.api = static_cast<std::uint8_t>(Get(bytes, 4, 1));
  value.flags = static_cast<std::uint8_t>(Get(bytes, 5, 1));
  value.reserved0 = static_cast<std::uint16_t>(Get(bytes, 6, 2));
  value.count = static_cast<std::uint32_t>(Get(bytes, 8, 4));
  value.name_length = static_cast<std::uint32_t>(Get(bytes, 12, 4));
  value.value_length = static_cast<std::uint32_t>(Get(bytes, 16, 4));
  value.string_length = static_cast<std::uint32_t>(Get(bytes, 20, 4));
  value.frame.kind = static_cast<std::uint8_t>(Get(bytes, 24, 1));
  value.frame.flags = static_cast<std::uint8_t>(Get(bytes, 25, 1));
  value.frame.combinator = static_cast<std::uint16_t>(Get(bytes, 26, 2));
  value.frame.script_id = static_cast<std::uint32_t>(Get(bytes, 28, 4));
  value.frame.position = static_cast<std::uint32_t>(Get(bytes, 32, 4));
  value.frame.function_start = static_cast<std::uint32_t>(Get(bytes, 36, 4));
  cookie_detail::Copy(bytes, 40, value.stack_digest);
  cookie_detail::Copy(bytes, 72, value.value_sha256);
  cookie_detail::Copy(bytes, 104, value.name_prefix);
  return true;
}

[[nodiscard]] inline bool IsValidScriptCookiePayload(const ScriptCookiePayload& value) noexcept {
  using cookie_detail::Zero;
  if (value.protocol_version != kCookiePayloadVersion || value.payload_size != 128 ||
      value.reserved0 != 0 || value.api < 1 || value.api > 6 || value.count == 0 ||
      (value.flags & ~0x0fU) != 0) {
    return false;
  }
  const auto api = static_cast<ScriptCookieApi>(value.api);
  const bool write = api == ScriptCookieApi::kDocumentCookieSet ||
                     api == ScriptCookieApi::kCookieStoreSet ||
                     api == ScriptCookieApi::kCookieStoreDelete;
  const bool truncated = value.name_length > kScriptCookieNamePrefixBytes;
  const std::span<const std::uint8_t> prefix(value.name_prefix);
  if (truncated != ((value.flags & kScriptCookieNameTruncated) != 0) ||
      (!truncated && !Zero(prefix.subspan(value.name_length)))) {
    return false;
  }
  if (write ? value.count != 1 || Zero(value.value_sha256) ||
                  (value.flags & kScriptCookieTableFull) != 0
            : value.value_length != 0 || !Zero(value.value_sha256)) {
    return false;
  }
  if (api == ScriptCookieApi::kDocumentCookieSet
          ? static_cast<std::uint64_t>(value.string_length) <
                static_cast<std::uint64_t>(value.name_length) + value.value_length
          : api != ScriptCookieApi::kDocumentCookieGet && value.string_length != 0) {
    return false;
  }
  const ScriptFrame& frame = value.frame;
  const bool framed = (frame.kind == 1 || frame.kind == 2) && frame.script_id != 0 &&
                      frame.combinator == 0 && (frame.flags & ~0x03U) == 0;
  const bool frame_zero = frame.kind == 0 && frame.flags == 0 && frame.combinator == 0 &&
                          frame.script_id == 0 && frame.position == 0 && frame.function_start == 0;
  const bool recorded = (value.flags & kScriptCookieFrameRecorded) != 0;
  const bool stacked = (value.flags & kScriptCookieStackRecorded) != 0;
  return (recorded ? framed : frame_zero) && stacked == !Zero(value.stack_digest) &&
         (!stacked || recorded);
}

[[nodiscard]] inline bool IsValidScriptCookieEvent(const EventRecord& event) noexcept {
  const auto& h = event.header;
  ScriptCookiePayload value;
  return h.protocol_version == kEventProtocolVersion && h.category == EventCategory::kNetwork &&
         h.type == EventType::kScriptCookie && h.payload_size == 128 && h.flags == 0 &&
         h.session_id != 0 && h.sequence_number != 0 && h.process_id != 0 &&
         h.parent_event_id == 0 && h.request_id == 0 && h.artifact_id == 0 &&
         h.navigation_id == 0 && h.status_code == 0 && h.error_code == 0 &&
         h.encoded_data_length == 0 && h.decoded_body_length == 0 && h.resource_type == 0 &&
         DecodeScriptCookiePayload(event.inline_payload, value) &&
         IsValidScriptCookiePayload(value);
}
}  // namespace reb
#endif
