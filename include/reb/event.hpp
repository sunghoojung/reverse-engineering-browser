#ifndef REB_EVENT_HPP_
#define REB_EVENT_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace reb {

inline constexpr std::uint16_t kEventProtocolVersion = 2;
inline constexpr std::size_t kInlinePayloadSize = 128;
inline constexpr std::size_t kEventRecordReservedSize = 48;

enum class EventCategory : std::uint16_t {
  kUnknown = 0,
  kCanvas = 1,
  kWebGl = 2,
  kWebAudio = 3,
  kNavigator = 4,
  kPermissions = 5,
  kStorage = 6,
  kWebRtc = 7,
  kWasm = 8,
  kNetwork = 9,
};

enum class EventType : std::uint16_t {
  kUnknown = 0,
  kApiCall = 1,
  kPropertyRead = 2,
  kModuleCompiled = 3,
  kModuleInstantiated = 4,
  kRequestStarted = 5,
  kResponseCompleted = 6,
  kGap = 7,
  kRequestInitiated = 8,
  kRequestRedirected = 9,
  kResponseStarted = 10,
  kRequestCompleted = 11,
  kRequestFailed = 12,
};

enum class EventFlag : std::uint16_t {
  kNone = 0,
  kPayloadTruncated = 1U << 0U,
  kFromCache = 1U << 1U,
  kFromServiceWorker = 1U << 2U,
};

struct EventHeader final {
  std::uint16_t protocol_version = kEventProtocolVersion;
  std::uint16_t header_size = sizeof(EventHeader);
  EventCategory category = EventCategory::kUnknown;
  EventType type = EventType::kUnknown;
  std::uint32_t payload_size = 0;
  std::uint32_t reserved0 = 0;
  std::uint64_t sequence_number = 0;
  std::uint64_t monotonic_time_ns = 0;
  std::uint64_t session_id = 0;
  std::uint32_t process_id = 0;
  std::uint32_t thread_id = 0;
  std::uint64_t navigation_id = 0;
  std::uint64_t frame_id = 0;
  std::uint64_t artifact_id = 0;
  std::uint64_t parent_event_id = 0;
  std::uint64_t request_id = 0;
  std::uint64_t browser_context_id_high = 0;
  std::uint64_t browser_context_id_low = 0;
  std::int64_t encoded_data_length = 0;
  std::int64_t decoded_body_length = 0;
  std::int32_t status_code = 0;
  std::int32_t error_code = 0;
  std::uint16_t resource_type = 0;
  std::uint16_t flags = 0;
  std::uint32_t initiator_request_id = 0;
  std::uint32_t initiator_process_id = 0;
  std::uint32_t reserved1 = 0;
};

struct alignas(64) EventRecord final {
  EventHeader header{};
  std::array<std::byte, kInlinePayloadSize> inline_payload{};
  std::array<std::byte, kEventRecordReservedSize> reserved{};
};

static_assert(std::is_standard_layout_v<EventHeader>);
static_assert(std::is_trivially_copyable_v<EventHeader>);
static_assert(std::is_standard_layout_v<EventRecord>);
static_assert(std::is_trivially_copyable_v<EventRecord>);
static_assert(std::has_unique_object_representations_v<EventHeader>);
static_assert(std::has_unique_object_representations_v<EventRecord>);
#define REB_ASSERT_EVENT_HEADER_OFFSET(member, expected) \
  static_assert(offsetof(EventHeader, member) == expected)
REB_ASSERT_EVENT_HEADER_OFFSET(protocol_version, 0);
REB_ASSERT_EVENT_HEADER_OFFSET(header_size, 2);
REB_ASSERT_EVENT_HEADER_OFFSET(category, 4);
REB_ASSERT_EVENT_HEADER_OFFSET(type, 6);
REB_ASSERT_EVENT_HEADER_OFFSET(payload_size, 8);
REB_ASSERT_EVENT_HEADER_OFFSET(reserved0, 12);
REB_ASSERT_EVENT_HEADER_OFFSET(sequence_number, 16);
REB_ASSERT_EVENT_HEADER_OFFSET(monotonic_time_ns, 24);
REB_ASSERT_EVENT_HEADER_OFFSET(session_id, 32);
REB_ASSERT_EVENT_HEADER_OFFSET(process_id, 40);
REB_ASSERT_EVENT_HEADER_OFFSET(thread_id, 44);
REB_ASSERT_EVENT_HEADER_OFFSET(navigation_id, 48);
REB_ASSERT_EVENT_HEADER_OFFSET(frame_id, 56);
REB_ASSERT_EVENT_HEADER_OFFSET(artifact_id, 64);
REB_ASSERT_EVENT_HEADER_OFFSET(parent_event_id, 72);
REB_ASSERT_EVENT_HEADER_OFFSET(request_id, 80);
REB_ASSERT_EVENT_HEADER_OFFSET(browser_context_id_high, 88);
REB_ASSERT_EVENT_HEADER_OFFSET(browser_context_id_low, 96);
REB_ASSERT_EVENT_HEADER_OFFSET(encoded_data_length, 104);
REB_ASSERT_EVENT_HEADER_OFFSET(decoded_body_length, 112);
REB_ASSERT_EVENT_HEADER_OFFSET(status_code, 120);
REB_ASSERT_EVENT_HEADER_OFFSET(error_code, 124);
REB_ASSERT_EVENT_HEADER_OFFSET(resource_type, 128);
REB_ASSERT_EVENT_HEADER_OFFSET(flags, 130);
REB_ASSERT_EVENT_HEADER_OFFSET(initiator_request_id, 132);
REB_ASSERT_EVENT_HEADER_OFFSET(initiator_process_id, 136);
REB_ASSERT_EVENT_HEADER_OFFSET(reserved1, 140);
#undef REB_ASSERT_EVENT_HEADER_OFFSET
static_assert(sizeof(EventHeader) == 144);
static_assert(sizeof(EventRecord) == 320);
static_assert(alignof(EventRecord) == 64);
static_assert(offsetof(EventRecord, inline_payload) == 144);
static_assert(offsetof(EventRecord, reserved) == 272);

[[nodiscard]] EventRecord MakeEvent(EventCategory category,
                                    EventType type,
                                    std::uint64_t sequence_number,
                                    std::uint64_t monotonic_time_ns,
                                    std::uint64_t session_id) noexcept;

[[nodiscard]] bool SetInlinePayload(EventRecord& event,
                                    std::span<const std::byte> payload) noexcept;
[[nodiscard]] bool SetInlinePayload(EventRecord& event, std::string_view payload) noexcept;
void SetInlinePayloadPrefix(EventRecord& event, std::string_view payload) noexcept;

[[nodiscard]] std::span<const std::byte> InlinePayload(const EventRecord& event) noexcept;

[[nodiscard]] bool IsValidEvent(const EventRecord& event) noexcept;
[[nodiscard]] std::string EventToJson(const EventRecord& event);

[[nodiscard]] std::string_view EventCategoryName(EventCategory category) noexcept;
[[nodiscard]] std::string_view EventTypeName(EventType type) noexcept;

}  // namespace reb

#endif  // REB_EVENT_HPP_
