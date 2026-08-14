#include "reb/vm_finding.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <span>

namespace reb {

namespace {

static_assert(std::endian::native == std::endian::little);

constexpr std::uint8_t kKnownFlags = static_cast<std::uint8_t>(VmFindingFlag::kHasSourceRange) |
                                     static_cast<std::uint8_t>(VmFindingFlag::kPartial) |
                                     static_cast<std::uint8_t>(VmFindingFlag::kDynamic) |
                                     static_cast<std::uint8_t>(VmFindingFlag::kNested);

bool IsKnownKind(const VmFindingKind kind) noexcept {
  return kind >= VmFindingKind::kInterpreter && kind <= VmFindingKind::kCoverage;
}

bool IsKnownRuntime(const VmHostRuntime runtime) noexcept {
  return runtime >= VmHostRuntime::kUnknown && runtime <= VmHostRuntime::kMixed;
}

bool IsKnownConfidence(const VmFindingConfidence confidence) noexcept {
  return confidence >= VmFindingConfidence::kUnknown &&
         confidence <= VmFindingConfidence::kHeuristic;
}

bool IsLabelCharacter(const char value) noexcept {
  const auto byte = static_cast<unsigned char>(value);
  return byte >= 0x20U && byte <= 0x7eU;
}

}  // namespace

VmFindingPayload MakeVmFinding(const VmFindingKind kind,
                               const VmHostRuntime host_runtime,
                               const VmFindingConfidence confidence,
                               const std::uint64_t finding_id,
                               const std::uint64_t investigation_id,
                               const std::string_view label) noexcept {
  VmFindingPayload finding{};
  finding.kind = kind;
  finding.host_runtime = host_runtime;
  finding.confidence = confidence;
  finding.finding_id = finding_id;
  finding.investigation_id = investigation_id;
  static_cast<void>(SetVmFindingLabel(finding, label));
  return finding;
}

bool SetVmFindingLabel(VmFindingPayload& finding, const std::string_view label) noexcept {
  if (label.empty() || label.size() > finding.label.size() ||
      !std::ranges::all_of(label, IsLabelCharacter)) {
    return false;
  }
  std::fill(finding.label.begin(), finding.label.end(), '\0');
  std::copy(label.begin(), label.end(), finding.label.begin());
  finding.label_size = static_cast<std::uint16_t>(label.size());
  return true;
}

std::string_view VmFindingLabel(const VmFindingPayload& finding) noexcept {
  const std::size_t size = std::min<std::size_t>(finding.label_size, finding.label.size());
  return std::string_view(finding.label.data(), size);
}

bool IsValidVmFinding(const VmFindingPayload& finding) noexcept {
  const bool has_source_range =
      (finding.flags & static_cast<std::uint8_t>(VmFindingFlag::kHasSourceRange)) != 0;
  const bool valid_counts =
      finding.kind == VmFindingKind::kCoverage
          ? finding.total_count > 0 && finding.observed_count <= finding.total_count
          : finding.observed_count == 0 && finding.total_count == 0;
  const bool valid_range =
      has_source_range ? finding.source_size > 0 &&
                             finding.source_offset <=
                                 std::numeric_limits<std::uint64_t>::max() - finding.source_size
                       : finding.source_offset == 0 && finding.source_size == 0;
  const std::size_t label_size = finding.label_size;
  const bool clean_label_tail = label_size <= finding.label.size() &&
                                std::ranges::all_of(std::span(finding.label).subspan(label_size),
                                                    [](const char value) { return value == '\0'; });
  const bool valid_label =
      label_size <= finding.label.size() &&
      std::ranges::all_of(std::span(finding.label).first(label_size), IsLabelCharacter);
  return finding.protocol_version == kVmFindingProtocolVersion &&
         finding.payload_size == sizeof(VmFindingPayload) && IsKnownKind(finding.kind) &&
         IsKnownRuntime(finding.host_runtime) && IsKnownConfidence(finding.confidence) &&
         (finding.flags & static_cast<std::uint8_t>(~kKnownFlags)) == 0 && finding.label_size > 0 &&
         finding.label_size <= finding.label.size() && valid_label && clean_label_tail &&
         finding.reserved0 == 0 && finding.reserved1 == 0 && finding.finding_id != 0 &&
         finding.investigation_id != 0 && valid_counts && valid_range &&
         std::ranges::all_of(finding.reserved,
                             [](const std::byte value) { return value == std::byte{0}; });
}

bool SetVmFindingPayload(EventRecord& event, const VmFindingPayload& finding) noexcept {
  const bool has_source_range =
      (finding.flags & static_cast<std::uint8_t>(VmFindingFlag::kHasSourceRange)) != 0;
  if (!IsValidVmFinding(finding) || (has_source_range && event.header.artifact_id == 0)) {
    return false;
  }
  event.header.category = EventCategory::kVm;
  event.header.type = EventType::kVmFinding;
  const auto* bytes = reinterpret_cast<const std::byte*>(&finding);
  return SetInlinePayload(event, std::span<const std::byte>(bytes, sizeof(finding)));
}

bool DecodeVmFinding(const EventRecord& event, VmFindingPayload& finding) noexcept {
  const bool payload_truncated =
      (event.header.flags & static_cast<std::uint16_t>(EventFlag::kPayloadTruncated)) != 0;
  if (!IsValidEvent(event) || payload_truncated || event.header.category != EventCategory::kVm ||
      event.header.type != EventType::kVmFinding ||
      event.header.payload_size != sizeof(VmFindingPayload)) {
    return false;
  }
  VmFindingPayload decoded{};
  std::memcpy(&decoded, event.inline_payload.data(), sizeof(decoded));
  if (!IsValidVmFinding(decoded)) {
    return false;
  }
  if ((decoded.flags & static_cast<std::uint8_t>(VmFindingFlag::kHasSourceRange)) != 0 &&
      event.header.artifact_id == 0) {
    return false;
  }
  finding = decoded;
  return true;
}

std::string_view VmFindingKindName(const VmFindingKind kind) noexcept {
  switch (kind) {
    case VmFindingKind::kInterpreter:
      return "interpreter";
    case VmFindingKind::kGuestProgram:
      return "guest_program";
    case VmFindingKind::kInvocation:
      return "invocation";
    case VmFindingKind::kHostBinding:
      return "host_binding";
    case VmFindingKind::kHypothesis:
      return "hypothesis";
    case VmFindingKind::kCoverage:
      return "coverage";
    case VmFindingKind::kUnknown:
      return "unknown";
  }
  return "unknown";
}

std::string_view VmHostRuntimeName(const VmHostRuntime runtime) noexcept {
  switch (runtime) {
    case VmHostRuntime::kJavaScript:
      return "javascript";
    case VmHostRuntime::kWebAssembly:
      return "webassembly";
    case VmHostRuntime::kMixed:
      return "mixed";
    case VmHostRuntime::kUnknown:
      return "unknown";
  }
  return "unknown";
}

std::string_view VmFindingConfidenceName(const VmFindingConfidence confidence) noexcept {
  switch (confidence) {
    case VmFindingConfidence::kObserved:
      return "observed";
    case VmFindingConfidence::kInferred:
      return "inferred";
    case VmFindingConfidence::kHeuristic:
      return "heuristic";
    case VmFindingConfidence::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace reb
