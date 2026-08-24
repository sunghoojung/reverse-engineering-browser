#ifndef REB_REQUEST_SIGNAL_PROFILE_HPP_
#define REB_REQUEST_SIGNAL_PROFILE_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>

#include "reb/event.hpp"

namespace reb {

inline constexpr std::uint16_t kRequestSignalProfileProtocolVersion = 1;
inline constexpr std::size_t kRequestSignalProfileCategoryCount = 7;
inline constexpr std::size_t kRequestSignalProfileParentDepthLimit = 32;

enum class RequestSignalRelation : std::uint16_t {
  kUnknown = 0,
  kParentChain = 1,
  kSameContext = 2,
};

struct RequestSignalEventReference final {
  std::uint64_t session_id = 0;
  std::uint64_t sequence_number = 0;
  std::uint32_t process_id = 0;
  std::uint32_t reserved = 0;

  bool operator==(const RequestSignalEventReference&) const = default;
};

struct RequestSignalEvidence final {
  EventCategory category = EventCategory::kUnknown;
  RequestSignalRelation relation = RequestSignalRelation::kUnknown;
  std::uint64_t event_count = 0;
  RequestSignalEventReference first_event{};
  RequestSignalEventReference last_event{};
};

struct RequestSignalProfile final {
  std::uint16_t protocol_version = kRequestSignalProfileProtocolVersion;
  std::uint16_t reserved = 0;
  std::uint32_t parent_depth = 0;
  RequestSignalEventReference root_event{};
  RequestSignalEventReference initiator_event{};
  std::uint64_t request_id = 0;
  std::uint64_t navigation_id = 0;
  std::uint64_t frame_id = 0;
  bool copied_from_initiator = false;
  bool retention_truncated = false;
  bool parent_depth_limited = false;
  bool count_saturated = false;
  std::array<RequestSignalEvidence, kRequestSignalProfileCategoryCount> signals{};
  std::size_t signal_count = 0;
};

static_assert(std::is_standard_layout_v<RequestSignalEventReference>);
static_assert(std::is_trivially_copyable_v<RequestSignalEventReference>);
static_assert(std::is_standard_layout_v<RequestSignalEvidence>);
static_assert(std::is_trivially_copyable_v<RequestSignalEvidence>);
static_assert(std::is_standard_layout_v<RequestSignalProfile>);
static_assert(std::is_trivially_copyable_v<RequestSignalProfile>);
static_assert(sizeof(RequestSignalEventReference) == 24);
static_assert(sizeof(RequestSignalEvidence) == 64);
static_assert(sizeof(RequestSignalProfile) == 544);
static_assert(offsetof(RequestSignalProfile, root_event) == 8);
static_assert(offsetof(RequestSignalProfile, signals) == 88);
static_assert(offsetof(RequestSignalProfile, signal_count) == 536);

struct RequestSignalProfileIndexStats final {
  std::uint64_t indexed_events = 0;
  std::uint64_t emitted_profiles = 0;
  std::uint64_t duplicate_events = 0;
  std::uint64_t evicted_events = 0;
  std::uint64_t evicted_contexts = 0;
  std::uint64_t evicted_profiles = 0;
  std::uint64_t copied_profiles = 0;
};

// Builds a bounded request-first summary of fingerprint-relevant API evidence.
// Explicit parent chains are observed. Events that merely share the same
// session, process, navigation, and frame are labeled correlated in JSON.
// This broker cold-path index never reads captured values or participates in
// renderer capture.
class RequestSignalProfileIndex final {
 public:
  explicit RequestSignalProfileIndex(std::size_t capacity);

  RequestSignalProfileIndex(const RequestSignalProfileIndex&) = delete;
  RequestSignalProfileIndex& operator=(const RequestSignalProfileIndex&) = delete;

  [[nodiscard]] std::optional<RequestSignalProfile> Ingest(const EventRecord& event);
  [[nodiscard]] RequestSignalProfileIndexStats Stats() const noexcept;
  [[nodiscard]] std::size_t Size() const noexcept;

 private:
  struct EventReferenceHash final {
    [[nodiscard]] std::size_t operator()(const RequestSignalEventReference& value) const noexcept;
  };

  struct EventState final {
    RequestSignalEventReference reference{};
    std::uint64_t parent_event_id = 0;
    EventCategory category = EventCategory::kUnknown;
  };

  struct ContextKey final {
    std::uint64_t session_id = 0;
    std::uint64_t navigation_id = 0;
    std::uint64_t frame_id = 0;
    std::uint32_t process_id = 0;

    bool operator==(const ContextKey&) const = default;
  };

  struct ContextKeyHash final {
    [[nodiscard]] std::size_t operator()(const ContextKey& value) const noexcept;
  };

  struct ContextSignalState final {
    std::uint64_t event_count = 0;
    RequestSignalEventReference first_event{};
    RequestSignalEventReference last_event{};
    bool count_saturated = false;
  };

  struct ContextState final {
    std::array<ContextSignalState, kRequestSignalProfileCategoryCount> signals{};
  };

  struct RequestKey final {
    std::uint64_t session_id = 0;
    std::uint64_t request_id = 0;
    std::uint32_t process_id = 0;

    bool operator==(const RequestKey&) const = default;
  };

  struct RequestKeyHash final {
    [[nodiscard]] std::size_t operator()(const RequestKey& value) const noexcept;
  };

  [[nodiscard]] bool Contains(const RequestSignalEventReference& reference) const;
  [[nodiscard]] RequestSignalProfile BuildProfile(const EventRecord& event) const;
  [[nodiscard]] std::optional<RequestSignalProfile> FindInitiatorProfile(
      const EventRecord& event) const;
  void AddParentSignals(const EventRecord& event, RequestSignalProfile& profile) const;
  void AddContextSignals(const EventRecord& event, RequestSignalProfile& profile) const;
  void RememberEvent(const EventRecord& event);
  void RememberContextSignal(const EventRecord& event);
  void RememberRequestProfile(const EventRecord& event, const RequestSignalProfile& profile);

  const std::size_t capacity_;
  std::unordered_map<RequestSignalEventReference, EventState, EventReferenceHash> events_;
  std::deque<RequestSignalEventReference> event_order_;
  std::unordered_map<ContextKey, ContextState, ContextKeyHash> contexts_;
  std::deque<ContextKey> context_order_;
  std::unordered_map<RequestKey, RequestSignalProfile, RequestKeyHash> request_profiles_;
  std::deque<RequestKey> request_profile_order_;
  RequestSignalProfileIndexStats stats_;
};

[[nodiscard]] bool IsFingerprintSignalCategory(EventCategory category) noexcept;
[[nodiscard]] bool IsValidRequestSignalProfile(const RequestSignalProfile& profile) noexcept;
[[nodiscard]] std::string RequestSignalProfileToJson(const RequestSignalProfile& profile);
[[nodiscard]] std::string_view RequestSignalRelationName(RequestSignalRelation relation) noexcept;

}  // namespace reb

#endif  // REB_REQUEST_SIGNAL_PROFILE_HPP_
