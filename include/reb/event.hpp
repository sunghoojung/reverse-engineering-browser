#ifndef REB_EVENT_HPP_
#define REB_EVENT_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace reb {

inline constexpr std::uint16_t kEventProtocolVersion = 1;
inline constexpr std::size_t kInlinePayloadSize = 48;

enum class EventCategory : std::uint16_t {
  kUnknown = 0,
  kCanvas,
  kWebGl,
  kWebAudio,
  kNavigator,
  kPermissions,
  kStorage,
  kWebRtc,
  kWasm,
  kNetwork,
};

enum class EventType : std::uint16_t {
  kUnknown = 0,
  kApiCall,
  kPropertyRead,
  kModuleCompiled,
  kModuleInstantiated,
  kRequestStarted,
  kResponseCompleted,
  kGap,
};

struct EventHeader final {
  std::uint16_t protocol_version = kEventProtocolVersion;
  std::uint16_t header_size = sizeof(EventHeader);
  EventCategory category = EventCategory::kUnknown;
  EventType type = EventType::kUnknown;
  std::uint32_t payload_size = 0;
  std::uint64_t sequence_number = 0;
  std::uint64_t monotonic_time_ns = 0;
  std::uint64_t session_id = 0;
  std::uint32_t process_id = 0;
  std::uint32_t thread_id = 0;
  std::uint64_t navigation_id = 0;
  std::uint64_t frame_id = 0;
  std::uint64_t artifact_id = 0;
  std::uint64_t parent_event_id = 0;
};

struct alignas(64) EventRecord final {
  EventHeader header{};
  std::array<std::byte, kInlinePayloadSize> inline_payload{};
};

static_assert(std::is_standard_layout_v<EventHeader>);
static_assert(std::is_trivially_copyable_v<EventHeader>);
static_assert(std::is_standard_layout_v<EventRecord>);
static_assert(std::is_trivially_copyable_v<EventRecord>);
static_assert(sizeof(EventHeader) == 80);
static_assert(sizeof(EventRecord) == 128);

[[nodiscard]] EventRecord MakeEvent(EventCategory category,
                                    EventType type,
                                    std::uint64_t sequence_number,
                                    std::uint64_t monotonic_time_ns,
                                    std::uint64_t session_id) noexcept;

[[nodiscard]] std::string_view EventCategoryName(EventCategory category) noexcept;
[[nodiscard]] std::string_view EventTypeName(EventType type) noexcept;

}  // namespace reb

#endif  // REB_EVENT_HPP_
