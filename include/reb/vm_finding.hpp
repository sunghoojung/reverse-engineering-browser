#ifndef REB_VM_FINDING_HPP_
#define REB_VM_FINDING_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

#include "reb/event.hpp"

namespace reb {

inline constexpr std::uint16_t kVmFindingProtocolVersion = 1;
inline constexpr std::size_t kVmFindingLabelCapacity = 40;
inline constexpr std::size_t kVmFindingReservedSize = 16;

enum class VmFindingKind : std::uint8_t {
  kUnknown = 0,
  kInterpreter = 1,
  kGuestProgram = 2,
  kInvocation = 3,
  kHostBinding = 4,
  kHypothesis = 5,
  kCoverage = 6,
};

enum class VmHostRuntime : std::uint8_t {
  kUnknown = 0,
  kJavaScript = 1,
  kWebAssembly = 2,
  kMixed = 3,
};

enum class VmFindingConfidence : std::uint8_t {
  kUnknown = 0,
  kObserved = 1,
  kInferred = 2,
  kHeuristic = 3,
};

enum class VmFindingFlag : std::uint8_t {
  kNone = 0,
  kHasSourceRange = 1U << 0U,
  kPartial = 1U << 1U,
  kDynamic = 1U << 2U,
  kNested = 1U << 3U,
};

// This local wire record occupies one complete EventRecord inline payload.
// All numeric fields use the host's little-endian representation. The event's
// artifact_id identifies the source artifact for an optional byte range.
struct VmFindingPayload final {
  std::uint16_t protocol_version = kVmFindingProtocolVersion;
  std::uint16_t payload_size = sizeof(VmFindingPayload);
  VmFindingKind kind = VmFindingKind::kUnknown;
  VmHostRuntime host_runtime = VmHostRuntime::kUnknown;
  VmFindingConfidence confidence = VmFindingConfidence::kUnknown;
  std::uint8_t flags = 0;
  std::uint16_t label_size = 0;
  std::uint16_t reserved0 = 0;
  std::uint32_t observed_count = 0;
  std::uint32_t total_count = 0;
  std::uint32_t reserved1 = 0;
  std::uint64_t finding_id = 0;
  std::uint64_t investigation_id = 0;
  std::uint64_t subject_id = 0;
  std::uint64_t related_subject_id = 0;
  std::uint64_t source_offset = 0;
  std::uint64_t source_size = 0;
  std::array<char, kVmFindingLabelCapacity> label{};
  std::array<std::byte, kVmFindingReservedSize> reserved{};
};

static_assert(std::is_standard_layout_v<VmFindingPayload>);
static_assert(std::is_trivially_copyable_v<VmFindingPayload>);
static_assert(std::has_unique_object_representations_v<VmFindingPayload>);
static_assert(sizeof(VmFindingPayload) == kInlinePayloadSize);
static_assert(offsetof(VmFindingPayload, finding_id) == 24);
static_assert(offsetof(VmFindingPayload, label) == 72);
static_assert(offsetof(VmFindingPayload, reserved) == 112);

[[nodiscard]] VmFindingPayload MakeVmFinding(VmFindingKind kind,
                                             VmHostRuntime host_runtime,
                                             VmFindingConfidence confidence,
                                             std::uint64_t finding_id,
                                             std::uint64_t investigation_id,
                                             std::string_view label) noexcept;

[[nodiscard]] bool SetVmFindingLabel(VmFindingPayload& finding, std::string_view label) noexcept;
[[nodiscard]] std::string_view VmFindingLabel(const VmFindingPayload& finding) noexcept;
[[nodiscard]] bool IsValidVmFinding(const VmFindingPayload& finding) noexcept;
[[nodiscard]] bool SetVmFindingPayload(EventRecord& event,
                                       const VmFindingPayload& finding) noexcept;
[[nodiscard]] bool DecodeVmFinding(const EventRecord& event, VmFindingPayload& finding) noexcept;

[[nodiscard]] std::string_view VmFindingKindName(VmFindingKind kind) noexcept;
[[nodiscard]] std::string_view VmHostRuntimeName(VmHostRuntime runtime) noexcept;
[[nodiscard]] std::string_view VmFindingConfidenceName(VmFindingConfidence confidence) noexcept;

}  // namespace reb

#endif  // REB_VM_FINDING_HPP_
