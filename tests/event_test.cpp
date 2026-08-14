#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <locale>
#include <string>
#include <type_traits>

#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_event.h"
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_ipc.h"
#include "reb/event.hpp"
#include "reb/local_ipc.hpp"

#define CHECK(condition)                                                                   \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " << #condition \
                << '\n';                                                                   \
      return 1;                                                                            \
    }                                                                                      \
  } while (false)

#define CHECK_WIRE_OFFSET(field) \
  static_assert(offsetof(reb::EventHeader, field) == offsetof(reb::NativeProbeHeader, field))

CHECK_WIRE_OFFSET(protocol_version);
CHECK_WIRE_OFFSET(header_size);
CHECK_WIRE_OFFSET(category);
CHECK_WIRE_OFFSET(type);
CHECK_WIRE_OFFSET(payload_size);
CHECK_WIRE_OFFSET(reserved0);
CHECK_WIRE_OFFSET(sequence_number);
CHECK_WIRE_OFFSET(monotonic_time_ns);
CHECK_WIRE_OFFSET(session_id);
CHECK_WIRE_OFFSET(process_id);
CHECK_WIRE_OFFSET(thread_id);
CHECK_WIRE_OFFSET(navigation_id);
CHECK_WIRE_OFFSET(frame_id);
CHECK_WIRE_OFFSET(artifact_id);
CHECK_WIRE_OFFSET(parent_event_id);
CHECK_WIRE_OFFSET(request_id);
CHECK_WIRE_OFFSET(browser_context_id_high);
CHECK_WIRE_OFFSET(browser_context_id_low);
CHECK_WIRE_OFFSET(encoded_data_length);
CHECK_WIRE_OFFSET(decoded_body_length);
CHECK_WIRE_OFFSET(status_code);
CHECK_WIRE_OFFSET(error_code);
CHECK_WIRE_OFFSET(resource_type);
CHECK_WIRE_OFFSET(flags);
CHECK_WIRE_OFFSET(initiator_request_id);
CHECK_WIRE_OFFSET(initiator_process_id);
CHECK_WIRE_OFFSET(reserved1);

#undef CHECK_WIRE_OFFSET

static_assert(reb::kEventProtocolVersion == reb::kNativeProbeProtocolVersion);
static_assert(reb::kInlinePayloadSize == reb::kNativeProbeInlinePayloadSize);
static_assert(reb::kEventRecordReservedSize == reb::kNativeProbeRecordReservedSize);
static_assert(sizeof(reb::EventHeader) == sizeof(reb::NativeProbeHeader));
static_assert(sizeof(reb::EventRecord) == sizeof(reb::NativeProbeEvent));
static_assert(alignof(reb::EventRecord) == alignof(reb::NativeProbeEvent));
static_assert(reb::kLocalIpcMagic == reb::kNativeProbeLocalIpcMagic);
static_assert(reb::kLocalIpcVersion == reb::kNativeProbeLocalIpcVersion);
static_assert(reb::kLocalIpcTokenSize == reb::kNativeProbeLocalIpcTokenSize);
static_assert(sizeof(reb::LocalIpcHello) == sizeof(reb::NativeProbeLocalIpcHello));
static_assert(alignof(reb::LocalIpcHello) == alignof(reb::NativeProbeLocalIpcHello));
static_assert(offsetof(reb::LocalIpcHello, magic) ==
              offsetof(reb::NativeProbeLocalIpcHello, magic));
static_assert(offsetof(reb::LocalIpcHello, session_id) ==
              offsetof(reb::NativeProbeLocalIpcHello, session_id));
static_assert(offsetof(reb::LocalIpcHello, token) ==
              offsetof(reb::NativeProbeLocalIpcHello, token));
#define CHECK_WIRE_ENUM_VALUE(core_enum, native_enum, value)    \
  static_assert(static_cast<std::uint16_t>(core_enum::value) == \
                static_cast<std::uint16_t>(native_enum::value))

CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kUnknown);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kCanvas);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kWebGl);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kWebAudio);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kNavigator);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kPermissions);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kStorage);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kWebRtc);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kWasm);
CHECK_WIRE_ENUM_VALUE(reb::EventCategory, reb::NativeProbeCategory, kNetwork);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kUnknown);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kApiCall);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kPropertyRead);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kModuleCompiled);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kModuleInstantiated);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kRequestStarted);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kResponseCompleted);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kGap);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kRequestInitiated);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kRequestRedirected);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kResponseStarted);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kRequestCompleted);
CHECK_WIRE_ENUM_VALUE(reb::EventType, reb::NativeProbeType, kRequestFailed);
CHECK_WIRE_ENUM_VALUE(reb::EventFlag, reb::NativeProbeFlag, kNone);
CHECK_WIRE_ENUM_VALUE(reb::EventFlag, reb::NativeProbeFlag, kPayloadTruncated);
CHECK_WIRE_ENUM_VALUE(reb::EventFlag, reb::NativeProbeFlag, kFromCache);
CHECK_WIRE_ENUM_VALUE(reb::EventFlag, reb::NativeProbeFlag, kFromServiceWorker);

#undef CHECK_WIRE_ENUM_VALUE

namespace {

class GroupedNumbers final : public std::numpunct<char> {
 private:
  char do_thousands_sep() const override { return '_'; }
  std::string do_grouping() const override { return "\3"; }
};

}  // namespace

int main() {
  CHECK(sizeof(reb::EventHeader) == 144);
  CHECK(sizeof(reb::EventRecord) == 320);
  CHECK(alignof(reb::EventRecord) == 64);
  CHECK(std::is_trivially_copyable_v<reb::EventRecord>);

  const reb::EventRecord event =
      reb::MakeEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 42, 123456, 7);

  CHECK(event.header.protocol_version == reb::kEventProtocolVersion);
  CHECK(event.header.header_size == sizeof(reb::EventHeader));
  CHECK(event.header.category == reb::EventCategory::kCanvas);
  CHECK(event.header.type == reb::EventType::kApiCall);
  CHECK(event.header.sequence_number == 42);
  CHECK(event.header.monotonic_time_ns == 123456);
  CHECK(event.header.session_id == 7);
  CHECK(event.header.payload_size == 0);
  CHECK(event.header.reserved0 == 0);
  CHECK(event.header.reserved1 == 0);
  CHECK(reb::EventCategoryName(event.header.category) == "canvas");
  CHECK(reb::EventTypeName(event.header.type) == "api_call");
  CHECK(reb::IsValidEvent(event));

  reb::EventRecord truncated = event;
  const std::string oversized(reb::kInlinePayloadSize + 1, 'x');
  reb::SetInlinePayloadPrefix(truncated, oversized);
  CHECK(truncated.header.payload_size == reb::kInlinePayloadSize);
  CHECK((truncated.header.flags & static_cast<std::uint16_t>(reb::EventFlag::kPayloadTruncated)) !=
        0);
  reb::SetInlinePayloadPrefix(truncated, "short");
  CHECK(truncated.header.payload_size == 5);
  CHECK((truncated.header.flags & static_cast<std::uint16_t>(reb::EventFlag::kPayloadTruncated)) ==
        0);

  truncated.header.flags |= static_cast<std::uint16_t>(reb::EventFlag::kPayloadTruncated) |
                            static_cast<std::uint16_t>(reb::EventFlag::kFromCache);
  CHECK(reb::SetInlinePayload(truncated, "exact"));
  CHECK((truncated.header.flags & static_cast<std::uint16_t>(reb::EventFlag::kPayloadTruncated)) ==
        0);
  CHECK((truncated.header.flags & static_cast<std::uint16_t>(reb::EventFlag::kFromCache)) != 0);

  reb::EventRecord malformed = event;
  malformed.header.category = reb::EventCategory::kUnknown;
  CHECK(!reb::IsValidEvent(malformed));
  malformed = event;
  malformed.header.type = static_cast<reb::EventType>(65535);
  CHECK(!reb::IsValidEvent(malformed));
  malformed = event;
  malformed.header.flags = 1U << 15U;
  CHECK(!reb::IsValidEvent(malformed));
  malformed = event;
  malformed.header.reserved0 = 1;
  CHECK(!reb::IsValidEvent(malformed));
  malformed = event;
  malformed.header.reserved1 = 1;
  CHECK(!reb::IsValidEvent(malformed));
  malformed = event;
  malformed.reserved[0] = std::byte{1};
  CHECK(!reb::IsValidEvent(malformed));

  reb::EventRecord large_identifiers = event;
  large_identifiers.header.session_id = std::numeric_limits<std::uint64_t>::max();
  large_identifiers.header.sequence_number = 9'007'199'254'740'993ULL;
  large_identifiers.header.monotonic_time_ns = 9'007'199'254'740'994ULL;
  large_identifiers.header.navigation_id = 9'007'199'254'740'995ULL;
  large_identifiers.header.frame_id = 9'007'199'254'740'996ULL;
  large_identifiers.header.artifact_id = 9'007'199'254'740'997ULL;
  large_identifiers.header.parent_event_id = 9'007'199'254'740'998ULL;
  large_identifiers.header.request_id = 9'007'199'254'740'999ULL;
  large_identifiers.header.browser_context_id_high = 9'007'199'254'741'000ULL;
  large_identifiers.header.browser_context_id_low = 9'007'199'254'741'001ULL;
  large_identifiers.header.encoded_data_length = -1;
  large_identifiers.header.decoded_body_length = std::numeric_limits<std::int64_t>::max();
  const std::string json = reb::EventToJson(large_identifiers);
  CHECK(json.find("\"session_id\":\"18446744073709551615\"") != std::string::npos);
  CHECK(json.find("\"sequence_number\":\"9007199254740993\"") != std::string::npos);
  CHECK(json.find("\"monotonic_time_ns\":\"9007199254740994\"") != std::string::npos);
  CHECK(json.find("\"navigation_id\":\"9007199254740995\"") != std::string::npos);
  CHECK(json.find("\"frame_id\":\"9007199254740996\"") != std::string::npos);
  CHECK(json.find("\"artifact_id\":\"9007199254740997\"") != std::string::npos);
  CHECK(json.find("\"parent_event_id\":\"9007199254740998\"") != std::string::npos);
  CHECK(json.find("\"request_id\":\"9007199254740999\"") != std::string::npos);
  CHECK(json.find("\"browser_context_id_high\":\"9007199254741000\"") != std::string::npos);
  CHECK(json.find("\"browser_context_id_low\":\"9007199254741001\"") != std::string::npos);
  CHECK(json.find("\"encoded_data_length\":\"-1\"") != std::string::npos);
  CHECK(json.find("\"decoded_body_length\":\"9223372036854775807\"") != std::string::npos);

  const std::locale original_locale = std::locale();
  std::locale::global(std::locale(std::locale::classic(), new GroupedNumbers));
  const std::string locale_independent_json = reb::EventToJson(large_identifiers);
  std::locale::global(original_locale);
  CHECK(locale_independent_json == json);

  std::cout << "event_test passed\n";
  return 0;
}
