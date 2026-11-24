#include "reb/event.hpp"
#include "reb/broker_refusal.hpp"
#include "reb/compiled_script.hpp"
#include "reb/debugger_observation.hpp"
#include "reb/debugger_pause.hpp"
#include "reb/js_dispatch.hpp"
#include "reb/js_invocation.hpp"
#include "reb/network_cookies.hpp"
#include "reb/network_headers.hpp"
#include "reb/network_request.hpp"
#include "reb/network_response_body.hpp"
#include "reb/network_scope.hpp"
#include "reb/request_stack.hpp"
#include "reb/tab_link.hpp"
#include "reb/wasm_dispatch.hpp"
#include "reb/wasm_guest.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>

namespace reb {

namespace {

constexpr std::uint16_t kKnownEventFlags =
    static_cast<std::uint16_t>(EventFlag::kPayloadTruncated) |
    static_cast<std::uint16_t>(EventFlag::kFromCache) |
    static_cast<std::uint16_t>(EventFlag::kFromServiceWorker);

constexpr std::uint16_t ClearEventFlag(const std::uint16_t flags, const EventFlag flag) noexcept {
  const auto flag_mask = static_cast<std::uint16_t>(flag);
  return static_cast<std::uint16_t>(flags & static_cast<std::uint16_t>(~flag_mask));
}

bool IsKnownCategory(const EventCategory category) noexcept {
  switch (category) {
    case EventCategory::kCanvas:
    case EventCategory::kWebGl:
    case EventCategory::kWebAudio:
    case EventCategory::kNavigator:
    case EventCategory::kPermissions:
    case EventCategory::kStorage:
    case EventCategory::kWebRtc:
    case EventCategory::kWasm:
    case EventCategory::kNetwork:
    case EventCategory::kVm:
    case EventCategory::kArtifact:
    case EventCategory::kRuntime:
      return true;
    case EventCategory::kUnknown:
      return false;
  }
  return false;
}

bool IsKnownType(const EventType type) noexcept {
  switch (type) {
    case EventType::kApiCall:
    case EventType::kPropertyRead:
    case EventType::kModuleCompiled:
    case EventType::kModuleInstantiated:
    case EventType::kRequestStarted:
    case EventType::kResponseCompleted:
    case EventType::kGap:
    case EventType::kRequestInitiated:
    case EventType::kRequestRedirected:
    case EventType::kResponseStarted:
    case EventType::kRequestCompleted:
    case EventType::kRequestFailed:
    case EventType::kVmFinding:
    case EventType::kArtifactCaptured:
    case EventType::kArtifactCaptureFailed:
    case EventType::kVmDispatchSample:
    case EventType::kWasmDispatchObservation:
    case EventType::kWasmGuestDispatch:
    case EventType::kWasmGuestInvocation:
    case EventType::kWasmIndirectObservation:
    case EventType::kJsDispatchObservation:
    case EventType::kRequestBody:
    case EventType::kRequestTarget:
    case EventType::kJsInvocationStart:
    case EventType::kJsInvocationSettle:
    case EventType::kJsInvocationRequest:
    case EventType::kWasmExecutionOutcome:
    case EventType::kWasmDispatchOverflow:
    case EventType::kWasmIndirectOverflow:
    case EventType::kRequestHeaders:
    case EventType::kResponseHeaders:
    case EventType::kCookieList:
    case EventType::kScriptCookie:
    case EventType::kResponseBody:
    case EventType::kCaptureExclusion:
    case EventType::kTabSet:
    case EventType::kRequestTabLink:
    case EventType::kRequestExtensionLink:
    case EventType::kRequestInitiatorStack:
    case EventType::kScriptIdentity:
    case EventType::kRequestWatchMatch:
    case EventType::kListenerDispatch:
    case EventType::kTimerObservation:
    case EventType::kCspViolation:
    case EventType::kExceptionObservation:
    case EventType::kDomMutation:
    case EventType::kNavigationInitiatorStack:
    case EventType::kNavigationInitiatorLink:
    case EventType::kAsyncTaskStack:
    case EventType::kScriptCompiled:
    case EventType::kMemoryCacheReuse:
    case EventType::kBrokerRefusal:
    case EventType::kDebuggerAttached:
    case EventType::kDebuggerPaused:
    case EventType::kDebuggerResumed:
    case EventType::kDebuggerBreakpoint:
      return true;
    case EventType::kUnknown:
      return false;
  }
  return false;
}

template <typename Integer>
void AppendInteger(std::string& output, const Integer value) {
  std::array<char, std::numeric_limits<Integer>::digits10 + 3> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  output.append(buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data()));
}

}  // namespace

EventRecord MakeEvent(const EventCategory category,
                      const EventType type,
                      const std::uint64_t sequence_number,
                      const std::uint64_t monotonic_time_ns,
                      const std::uint64_t session_id) noexcept {
  EventRecord event{};
  event.header.category = category;
  event.header.type = type;
  event.header.sequence_number = sequence_number;
  event.header.monotonic_time_ns = monotonic_time_ns;
  event.header.session_id = session_id;
  return event;
}

bool SetInlinePayload(EventRecord& event, const std::span<const std::byte> payload) noexcept {
  if (payload.size() > event.inline_payload.size()) {
    return false;
  }

  std::fill(event.inline_payload.begin(), event.inline_payload.end(), std::byte{0});
  std::copy(payload.begin(), payload.end(), event.inline_payload.begin());
  event.header.payload_size = static_cast<std::uint32_t>(payload.size());
  event.header.flags = ClearEventFlag(event.header.flags, EventFlag::kPayloadTruncated);
  return true;
}

bool SetInlinePayload(EventRecord& event, const std::string_view payload) noexcept {
  const auto* data = reinterpret_cast<const std::byte*>(payload.data());
  return SetInlinePayload(event, std::span<const std::byte>(data, payload.size()));
}

void SetInlinePayloadPrefix(EventRecord& event, const std::string_view payload) noexcept {
  event.header.flags = ClearEventFlag(event.header.flags, EventFlag::kPayloadTruncated);
  const std::size_t size = std::min(payload.size(), event.inline_payload.size());
  const auto* data = reinterpret_cast<const std::byte*>(payload.data());
  static_cast<void>(SetInlinePayload(event, std::span<const std::byte>(data, size)));
  if (size != payload.size()) {
    event.header.flags |= static_cast<std::uint16_t>(EventFlag::kPayloadTruncated);
  }
}

std::span<const std::byte> InlinePayload(const EventRecord& event) noexcept {
  const std::size_t size =
      std::min<std::size_t>(event.header.payload_size, event.inline_payload.size());
  return std::span<const std::byte>(event.inline_payload.data(), size);
}

namespace {

// The type-specific payload validators. Each type without one is valid here.
bool TypedPayloadValid(const EventRecord& event) noexcept {
  if (event.header.type == EventType::kWasmGuestDispatch && !IsValidWasmGuestDispatch(event))
    return false;
  if (event.header.type == EventType::kWasmGuestInvocation && !IsValidWasmGuestInvocation(event))
    return false;
  if (event.header.type == EventType::kWasmDispatchObservation &&
      !IsValidWasmDispatchObservation(event))
    return false;
  if (event.header.type == EventType::kWasmIndirectObservation &&
      !IsValidWasmIndirectObservation(event))
    return false;
  if (event.header.type == EventType::kJsDispatchObservation &&
      !IsValidJsDispatchObservation(event))
    return false;
  if (event.header.type == EventType::kRequestBody && !IsValidRequestBodyEvent(event))
    return false;
  if (event.header.type == EventType::kRequestTarget && !IsValidRequestTargetEvent(event))
    return false;
  if (event.header.type == EventType::kJsInvocationStart && !IsValidJsInvocationStart(event))
    return false;
  if (event.header.type == EventType::kJsInvocationSettle && !IsValidJsInvocationSettle(event))
    return false;
  if (event.header.type == EventType::kJsInvocationRequest && !IsValidJsInvocationRequest(event))
    return false;
  if (event.header.type == EventType::kWasmExecutionOutcome && !IsValidWasmExecutionOutcome(event))
    return false;
  if (event.header.type == EventType::kWasmDispatchOverflow && !IsValidWasmDispatchOverflow(event))
    return false;
  if (event.header.type == EventType::kWasmIndirectOverflow && !IsValidWasmIndirectOverflow(event))
    return false;
  if (event.header.type == EventType::kRequestInitiatorStack && !IsValidRequestStackEvent(event))
    return false;
  if (event.header.type == EventType::kScriptIdentity && !IsValidScriptIdentityEvent(event))
    return false;
  if (event.header.type == EventType::kNavigationInitiatorStack &&
      !IsValidNavigationStackEvent(event))
    return false;
  if (event.header.type == EventType::kNavigationInitiatorLink &&
      !IsValidNavigationLinkEvent(event))
    return false;
  if (event.header.type == EventType::kAsyncTaskStack && !IsValidAsyncTaskStackEvent(event))
    return false;
  if (event.header.type >= EventType::kRequestWatchMatch &&
      event.header.type <= EventType::kDomMutation && !IsValidObservationEvent(event))
    return false;
  if (event.header.type >= EventType::kDebuggerAttached &&
      event.header.type <= EventType::kDebuggerBreakpoint && !IsValidDebuggerPauseEvent(event))
    return false;
  if ((event.header.type == EventType::kRequestHeaders ||
       event.header.type == EventType::kResponseHeaders) &&
      !IsValidHeaderBlockEvent(event))
    return false;
  if (event.header.type == EventType::kCookieList && !IsValidCookieListEvent(event))
    return false;
  if (event.header.type == EventType::kScriptCookie && !IsValidScriptCookieEvent(event))
    return false;
  if (event.header.type == EventType::kResponseBody && !IsValidResponseBodyEvent(event))
    return false;
  if (event.header.type == EventType::kCaptureExclusion && !IsValidCaptureExclusionEvent(event))
    return false;
  if (event.header.type == EventType::kTabSet && !IsValidTabSetEvent(event))
    return false;
  if (event.header.type == EventType::kRequestTabLink && !IsValidRequestTabLinkEvent(event))
    return false;
  if (event.header.type == EventType::kRequestExtensionLink &&
      !IsValidRequestExtensionLinkEvent(event))
    return false;
  if (event.header.type == EventType::kScriptCompiled && !IsValidScriptCompiled(event))
    return false;
  if (event.header.type == EventType::kMemoryCacheReuse && !IsValidMemoryCacheReuseEvent(event))
    return false;
  return true;
}

}  // namespace

EventRefusal EventRefusalOf(const EventRecord& event) noexcept {
  const EventHeader& header = event.header;
  if (header.protocol_version != kEventProtocolVersion)
    return EventRefusal::kProtocolVersion;
  if (header.header_size != sizeof(EventHeader))
    return EventRefusal::kHeaderSize;
  if (header.process_id == kBrokerProcessId)
    return EventRefusal::kProcessId;
  if (header.payload_size > event.inline_payload.size())
    return EventRefusal::kPayloadSize;
  if (header.reserved2 != 0 || !std::ranges::all_of(event.reserved, [](const std::byte value) {
        return value == std::byte{0};
      }))
    return EventRefusal::kReserved;
  if (!IsKnownCategory(header.category))
    return EventRefusal::kCategory;
  // Only the broker writes a refusal, so a producer's is refused.
  if (!IsKnownType(header.type) || header.type == EventType::kBrokerRefusal)
    return EventRefusal::kType;
  if ((header.flags & static_cast<std::uint16_t>(~kKnownEventFlags)) != 0)
    return EventRefusal::kFlags;
  if (!IsKnownSchemeClass(header.scheme_class) ||
      (header.scheme_class != 0 && !CarriesSchemeClass(header)) || !IsValidLoaderKind(header))
    return EventRefusal::kNetworkClass;
  if (!TypedPayloadValid(event))
    return EventRefusal::kTypedPayload;
  return EventRefusal::kNone;
}

bool IsValidEvent(const EventRecord& event) noexcept {
  return EventRefusalOf(event) == EventRefusal::kNone;
}

std::string_view EventRefusalName(const EventRefusal reason) noexcept {
  switch (reason) {
    case EventRefusal::kNone:
      return "none";
    case EventRefusal::kProtocolVersion:
      return "protocol_version";
    case EventRefusal::kHeaderSize:
      return "header_size";
    case EventRefusal::kProcessId:
      return "process_id";
    case EventRefusal::kPayloadSize:
      return "payload_size";
    case EventRefusal::kReserved:
      return "reserved";
    case EventRefusal::kCategory:
      return "category";
    case EventRefusal::kType:
      return "type";
    case EventRefusal::kFlags:
      return "flags";
    case EventRefusal::kNetworkClass:
      return "network_class";
    case EventRefusal::kTypedPayload:
      return "typed_payload";
  }
  return "unknown";
}

EventCategory BrokerRefusalCategory(const std::uint16_t refused_category) noexcept {
  const auto category = static_cast<EventCategory>(refused_category);
  return IsKnownCategory(category) ? category : EventCategory::kUnknown;
}

EventRecord MakeBrokerRefusal(const EventRecord& refused,
                              const EventRefusal reason,
                              const std::uint64_t received_monotonic_time_ns,
                              const std::uint64_t broker_sequence) noexcept {
  const EventHeader& from = refused.header;
  const bool envelope = IsEnvelopeRefusal(reason);
  const BrokerRefusalPayload payload{
      .reason = reason,
      .identity = envelope ? BrokerRefusalIdentity::kBroker : BrokerRefusalIdentity::kRefused,
      .protocol_version = from.protocol_version,
      .header_size = from.header_size,
      .category = static_cast<std::uint16_t>(from.category),
      .type = static_cast<std::uint16_t>(from.type),
      .payload_size = from.payload_size,
      .flags = from.flags,
      .scheme_class = from.scheme_class,
      .loader_kind = from.loader_kind,
      .received_monotonic_time_ns = received_monotonic_time_ns,
      .sequence_number = from.sequence_number,
      .monotonic_time_ns = from.monotonic_time_ns,
      .process_id = from.process_id,
      .thread_id = from.thread_id,
  };
  EventRecord event = MakeEvent(BrokerRefusalCategory(payload.category), EventType::kBrokerRefusal,
                                broker_sequence, received_monotonic_time_ns, from.session_id);
  EventHeader& to = event.header;
  if (envelope) {
    to.process_id = kBrokerProcessId;
  } else {
    // The refused record's place in its own stream, as read.
    to.sequence_number = from.sequence_number;
    to.monotonic_time_ns = from.monotonic_time_ns;
    to.process_id = from.process_id;
    to.thread_id = from.thread_id;
    to.tab_id = from.tab_id;
    to.navigation_id = from.navigation_id;
    to.frame_id = from.frame_id;
    to.artifact_id = from.artifact_id;
    to.parent_event_id = from.parent_event_id;
    to.request_id = from.request_id;
  }
  static_cast<void>(SetInlinePayload(event, EncodeBrokerRefusalPayload(payload)));
  return event;
}

bool IsValidBrokerRefusal(const EventRecord& event) noexcept {
  const EventHeader& h = event.header;
  BrokerRefusalPayload p;
  if (h.protocol_version != kEventProtocolVersion || h.header_size != sizeof(EventHeader) ||
      h.type != EventType::kBrokerRefusal || h.payload_size != kBrokerRefusalPayloadSize ||
      h.flags != 0 || h.reserved2 != 0 || h.scheme_class != 0 || h.loader_kind != 0 ||
      h.browser_context_id_high != 0 || h.browser_context_id_low != 0 ||
      h.encoded_data_length != 0 || h.decoded_body_length != 0 || h.status_code != 0 ||
      h.error_code != 0 || h.resource_type != 0 || h.initiator_request_id != 0 ||
      h.initiator_process_id != 0 ||
      !std::ranges::all_of(event.reserved,
                           [](const std::byte value) { return value == std::byte{0}; }) ||
      !DecodeBrokerRefusalPayload(InlinePayload(event), p) ||
      p.version != kBrokerRefusalPayloadVersion || p.size != kBrokerRefusalPayloadSize ||
      p.reason == EventRefusal::kNone || static_cast<std::uint16_t>(p.reason) > kEventRefusalLast ||
      h.category != BrokerRefusalCategory(p.category))
    return false;
  // The reason is the first check the refused fields fail, so they agree.
  // Each earlier check passed, and the named one failed.
  const auto reason = static_cast<std::uint16_t>(p.reason);
  const auto past = [reason](const EventRefusal check) {
    return reason > static_cast<std::uint16_t>(check);
  };
  const auto at = [&p](const EventRefusal check) { return p.reason == check; };
  const auto holds = [&](const EventRefusal check, const bool passed) {
    return at(check) ? !passed : !past(check) || passed;
  };
  if (!holds(EventRefusal::kProtocolVersion, p.protocol_version == kEventProtocolVersion) ||
      !holds(EventRefusal::kHeaderSize, p.header_size == sizeof(EventHeader)) ||
      !holds(EventRefusal::kProcessId, p.process_id != kBrokerProcessId) ||
      !holds(EventRefusal::kPayloadSize, p.payload_size <= kInlinePayloadSize) ||
      !holds(EventRefusal::kCategory, h.category != EventCategory::kUnknown))
    return false;
  if (IsEnvelopeRefusal(p.reason))
    return p.identity == BrokerRefusalIdentity::kBroker && h.process_id == kBrokerProcessId &&
           h.thread_id == 0 && h.tab_id == 0 && h.navigation_id == 0 && h.frame_id == 0 &&
           h.artifact_id == 0 && h.parent_event_id == 0 && h.request_id == 0 &&
           h.sequence_number != 0 && h.monotonic_time_ns == p.received_monotonic_time_ns;
  return p.identity == BrokerRefusalIdentity::kRefused && h.process_id == p.process_id &&
         h.thread_id == p.thread_id && h.sequence_number == p.sequence_number &&
         h.monotonic_time_ns == p.monotonic_time_ns;
}

void WriteEventJson(const EventRecord& event, std::string& output) {
  constexpr std::array<char, 16> kHex = {'0', '1', '2', '3', '4', '5', '6', '7',
                                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  const std::span<const std::byte> payload = InlinePayload(event);
  output.clear();
  output.reserve(kMaxEventJsonBytes);
  output.append("{\"protocol_version\":");
  AppendInteger(output, event.header.protocol_version);
  output.append(",\"session_id\":\"");
  AppendInteger(output, event.header.session_id);
  output.append("\",\"sequence_number\":\"");
  AppendInteger(output, event.header.sequence_number);
  output.append("\",\"monotonic_time_ns\":\"");
  AppendInteger(output, event.header.monotonic_time_ns);
  output.append("\",\"process_id\":");
  AppendInteger(output, event.header.process_id);
  output.append(",\"thread_id\":");
  AppendInteger(output, event.header.thread_id);
  output.append(",\"tab_id\":");
  AppendInteger(output, event.header.tab_id);
  output.append(",\"navigation_id\":\"");
  AppendInteger(output, event.header.navigation_id);
  output.append("\",\"frame_id\":\"");
  AppendInteger(output, event.header.frame_id);
  output.append("\",\"artifact_id\":\"");
  AppendInteger(output, event.header.artifact_id);
  output.append("\",\"parent_event_id\":\"");
  AppendInteger(output, event.header.parent_event_id);
  output.append("\",\"request_id\":\"");
  AppendInteger(output, event.header.request_id);
  output.append("\",\"browser_context_id_high\":\"");
  AppendInteger(output, event.header.browser_context_id_high);
  output.append("\",\"browser_context_id_low\":\"");
  AppendInteger(output, event.header.browser_context_id_low);
  output.append("\",\"encoded_data_length\":\"");
  AppendInteger(output, event.header.encoded_data_length);
  output.append("\",\"decoded_body_length\":\"");
  AppendInteger(output, event.header.decoded_body_length);
  output.append("\",\"status_code\":");
  AppendInteger(output, event.header.status_code);
  output.append(",\"error_code\":");
  AppendInteger(output, event.header.error_code);
  output.append(",\"resource_type\":");
  AppendInteger(output, event.header.resource_type);
  output.append(",\"flags\":");
  AppendInteger(output, event.header.flags);
  output.append(",\"initiator_request_id\":");
  AppendInteger(output, event.header.initiator_request_id);
  output.append(",\"initiator_process_id\":");
  AppendInteger(output, event.header.initiator_process_id);
  // Absent means 0, so records without a scheme keep their earlier JSON.
  if (event.header.scheme_class != 0) {
    output.append(",\"scheme_class\":");
    AppendInteger(output, event.header.scheme_class);
  }
  if (event.header.loader_kind != 0) {
    output.append(",\"loader_kind\":");
    AppendInteger(output, event.header.loader_kind);
  }
  output.append(",\"payload_truncated\":");
  output.append((event.header.flags & static_cast<std::uint16_t>(EventFlag::kPayloadTruncated)) != 0
                    ? "true"
                    : "false");
  output.append(",\"category\":\"");
  output.append(EventCategoryName(event.header.category));
  output.append("\",\"type\":\"");
  output.append(EventTypeName(event.header.type));
  output.append("\",\"payload_size\":");
  AppendInteger(output, event.header.payload_size);
  output.append(",\"payload_encoding\":\"hex\",\"payload\":\"");
  // InlinePayload bounds the extra space even for a malformed advertised size.
  const std::size_t payload_start = output.size();
  output.resize(payload_start + payload.size() * 2);
  for (std::size_t index = 0; index < payload.size(); ++index) {
    const auto byte_value =
        static_cast<unsigned int>(std::to_integer<unsigned char>(payload[index]));
    output[payload_start + index * 2] = kHex[(byte_value >> 4U) & 0x0fU];
    output[payload_start + index * 2 + 1] = kHex[byte_value & 0x0fU];
  }
  output.append("\"}");
}

std::string EventToJson(const EventRecord& event) {
  std::string output;
  WriteEventJson(event, output);
  return output;
}

std::string_view EventCategoryName(const EventCategory category) noexcept {
  switch (category) {
    case EventCategory::kCanvas:
      return "canvas";
    case EventCategory::kWebGl:
      return "webgl";
    case EventCategory::kWebAudio:
      return "web_audio";
    case EventCategory::kNavigator:
      return "navigator";
    case EventCategory::kPermissions:
      return "permissions";
    case EventCategory::kStorage:
      return "storage";
    case EventCategory::kWebRtc:
      return "webrtc";
    case EventCategory::kWasm:
      return "wasm";
    case EventCategory::kNetwork:
      return "network";
    case EventCategory::kVm:
      return "vm";
    case EventCategory::kArtifact:
      return "artifact";
    case EventCategory::kRuntime:
      return "runtime";
    case EventCategory::kUnknown:
      return "unknown";
  }
  return "unknown";
}

std::string_view EventTypeName(const EventType type) noexcept {
  switch (type) {
    case EventType::kApiCall:
      return "api_call";
    case EventType::kPropertyRead:
      return "property_read";
    case EventType::kModuleCompiled:
      return "module_compiled";
    case EventType::kModuleInstantiated:
      return "module_instantiated";
    case EventType::kRequestStarted:
      return "request_started";
    case EventType::kResponseCompleted:
      return "response_completed";
    case EventType::kGap:
      return "gap";
    case EventType::kRequestInitiated:
      return "request_initiated";
    case EventType::kRequestRedirected:
      return "request_redirected";
    case EventType::kResponseStarted:
      return "response_started";
    case EventType::kRequestCompleted:
      return "request_completed";
    case EventType::kRequestFailed:
      return "request_failed";
    case EventType::kVmFinding:
      return "vm_finding";
    case EventType::kArtifactCaptured:
      return "artifact_captured";
    case EventType::kArtifactCaptureFailed:
      return "artifact_capture_failed";
    case EventType::kVmDispatchSample:
      return "vm_dispatch_sample";
    case EventType::kWasmDispatchObservation:
      return "wasm_dispatch_observation";
    case EventType::kWasmGuestDispatch:
      return "wasm_guest_dispatch";
    case EventType::kWasmGuestInvocation:
      return "wasm_guest_invocation";
    case EventType::kWasmIndirectObservation:
      return "wasm_indirect_observation";
    case EventType::kJsDispatchObservation:
      return "js_dispatch_observation";
    case EventType::kRequestBody:
      return "request_body";
    case EventType::kRequestTarget:
      return "request_target";
    case EventType::kJsInvocationStart:
      return "js_invocation_start";
    case EventType::kJsInvocationSettle:
      return "js_invocation_settle";
    case EventType::kJsInvocationRequest:
      return "js_invocation_request";
    case EventType::kWasmExecutionOutcome:
      return "wasm_execution_outcome";
    case EventType::kWasmDispatchOverflow:
      return "wasm_dispatch_overflow";
    case EventType::kWasmIndirectOverflow:
      return "wasm_indirect_overflow";
    case EventType::kRequestHeaders:
      return "request_headers";
    case EventType::kResponseHeaders:
      return "response_headers";
    case EventType::kCookieList:
      return "cookie_list";
    case EventType::kScriptCookie:
      return "script_cookie";
    case EventType::kResponseBody:
      return "response_body";
    case EventType::kCaptureExclusion:
      return "capture_exclusion";
    case EventType::kTabSet:
      return "tab_set";
    case EventType::kRequestTabLink:
      return "request_tab_link";
    case EventType::kRequestExtensionLink:
      return "request_extension_link";
    case EventType::kRequestInitiatorStack:
      return "request_initiator_stack";
    case EventType::kScriptIdentity:
      return "script_identity";
    case EventType::kRequestWatchMatch:
      return "request_watch_match";
    case EventType::kListenerDispatch:
      return "listener_dispatch";
    case EventType::kTimerObservation:
      return "timer_observation";
    case EventType::kCspViolation:
      return "csp_violation";
    case EventType::kExceptionObservation:
      return "exception_observation";
    case EventType::kDomMutation:
      return "dom_mutation";
    case EventType::kNavigationInitiatorStack:
      return "navigation_initiator_stack";
    case EventType::kNavigationInitiatorLink:
      return "navigation_initiator_link";
    case EventType::kAsyncTaskStack:
      return "async_task_stack";
    case EventType::kScriptCompiled:
      return "script_compiled";
    case EventType::kMemoryCacheReuse:
      return "memory_cache_reuse";
    case EventType::kBrokerRefusal:
      return "broker_refusal";
    case EventType::kDebuggerAttached:
      return "debugger_attached";
    case EventType::kDebuggerPaused:
      return "debugger_paused";
    case EventType::kDebuggerResumed:
      return "debugger_resumed";
    case EventType::kDebuggerBreakpoint:
      return "debugger_breakpoint";
    case EventType::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace reb
