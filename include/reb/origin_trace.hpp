#ifndef REB_ORIGIN_TRACE_HPP_
#define REB_ORIGIN_TRACE_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

#include "reb/event.hpp"

namespace reb {

inline constexpr std::uint16_t kOriginTraceProtocolVersion = 1;
inline constexpr std::size_t kMaxOriginTraceEdgesPerEvent = 3;

enum class OriginTraceRelation : std::uint16_t {
  kUnknown = 0,
  kParentEvent = 1,
  kRequestInitiator = 2,
  kRequestLifecycle = 3,
  kArtifactRequest = 4,
};

enum class OriginTraceConfidence : std::uint16_t {
  kUnknown = 0,
  kObserved = 1,
  kCorrelated = 2,
};

struct OriginTraceEventReference final {
  std::uint64_t session_id = 0;
  std::uint64_t sequence_number = 0;
  std::uint32_t process_id = 0;
  std::uint32_t reserved = 0;

  bool operator==(const OriginTraceEventReference&) const = default;
};

struct OriginTraceEdge final {
  std::uint16_t protocol_version = kOriginTraceProtocolVersion;
  OriginTraceRelation relation = OriginTraceRelation::kUnknown;
  OriginTraceConfidence confidence = OriginTraceConfidence::kUnknown;
  std::uint16_t reserved = 0;
  OriginTraceEventReference from{};
  OriginTraceEventReference to{};
  std::uint64_t request_id = 0;
  std::uint64_t artifact_id = 0;
};

static_assert(std::is_standard_layout_v<OriginTraceEventReference>);
static_assert(std::is_trivially_copyable_v<OriginTraceEventReference>);
static_assert(std::is_standard_layout_v<OriginTraceEdge>);
static_assert(std::is_trivially_copyable_v<OriginTraceEdge>);
static_assert(sizeof(OriginTraceEventReference) == 24);
static_assert(sizeof(OriginTraceEdge) == 72);
static_assert(offsetof(OriginTraceEdge, from) == 8);
static_assert(offsetof(OriginTraceEdge, to) == 32);
static_assert(offsetof(OriginTraceEdge, request_id) == 56);

struct OriginTraceEdgeBatch final {
  std::array<OriginTraceEdge, kMaxOriginTraceEdgesPerEvent> edges{};
  std::size_t count = 0;
};

struct OriginTraceIndexStats final {
  std::uint64_t indexed_events = 0;
  std::uint64_t emitted_edges = 0;
  std::uint64_t duplicate_events = 0;
  std::uint64_t evicted_events = 0;
};

// Builds bounded, deterministic relationships from identifiers already
// present in normalized evidence. It never infers value flow. The index is a
// broker cold-path component and does not participate in renderer capture.
class OriginTraceIndex final {
 public:
  explicit OriginTraceIndex(std::size_t capacity);

  OriginTraceIndex(const OriginTraceIndex&) = delete;
  OriginTraceIndex& operator=(const OriginTraceIndex&) = delete;

  [[nodiscard]] OriginTraceEdgeBatch Ingest(const EventRecord& event);
  [[nodiscard]] OriginTraceIndexStats Stats() const noexcept;
  [[nodiscard]] std::size_t Size() const noexcept;

 private:
  struct EventReferenceHash final {
    [[nodiscard]] std::size_t operator()(const OriginTraceEventReference& value) const noexcept;
  };

  struct RequestKey final {
    std::uint64_t session_id = 0;
    std::uint64_t request_id = 0;
    std::uint64_t browser_context_id_high = 0;
    std::uint64_t browser_context_id_low = 0;
    std::uint32_t process_id = 0;

    bool operator==(const RequestKey&) const = default;
  };

  struct RequestKeyHash final {
    [[nodiscard]] std::size_t operator()(const RequestKey& value) const noexcept;
  };

  struct LegacyRequestKey final {
    std::uint64_t session_id = 0;
    std::uint64_t request_id = 0;
    std::uint32_t process_id = 0;

    bool operator==(const LegacyRequestKey&) const = default;
  };

  struct LegacyRequestKeyHash final {
    [[nodiscard]] std::size_t operator()(const LegacyRequestKey& value) const noexcept;
  };

  struct LegacyRequestState final {
    OriginTraceEventReference event{};
    std::uint64_t browser_context_id_high = 0;
    std::uint64_t browser_context_id_low = 0;
    bool ambiguous = false;
  };

  [[nodiscard]] bool Contains(const OriginTraceEventReference& event) const;
  [[nodiscard]] OriginTraceEventReference FindRequest(const EventRecord& event) const;
  [[nodiscard]] OriginTraceEventReference FindLegacyRequest(const LegacyRequestKey& key) const;
  void RememberEvent(const OriginTraceEventReference& event);
  void RememberRequest(const EventRecord& event, const OriginTraceEventReference& reference);
  void AddEdge(OriginTraceEdgeBatch& batch,
               const EventRecord& event,
               const OriginTraceEventReference& target,
               OriginTraceRelation relation,
               OriginTraceConfidence confidence);

  const std::size_t capacity_;
  std::unordered_set<OriginTraceEventReference, EventReferenceHash> events_;
  std::deque<OriginTraceEventReference> event_order_;
  std::unordered_map<RequestKey, OriginTraceEventReference, RequestKeyHash> requests_;
  std::deque<RequestKey> request_order_;
  std::unordered_map<LegacyRequestKey, LegacyRequestState, LegacyRequestKeyHash> legacy_requests_;
  std::deque<LegacyRequestKey> legacy_request_order_;
  OriginTraceIndexStats stats_;
};

[[nodiscard]] bool IsValidOriginTraceEdge(const OriginTraceEdge& edge) noexcept;
[[nodiscard]] std::string OriginTraceEdgeToJson(const OriginTraceEdge& edge);
[[nodiscard]] std::string_view OriginTraceRelationName(OriginTraceRelation relation) noexcept;
[[nodiscard]] std::string_view OriginTraceConfidenceName(OriginTraceConfidence confidence) noexcept;

}  // namespace reb

#endif  // REB_ORIGIN_TRACE_HPP_
