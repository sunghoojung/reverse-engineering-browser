#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <type_traits>

#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_vm_finding.h"
#include "reb/event.hpp"
#include "reb/vm_finding.hpp"

#define CHECK(condition)                                                                   \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " << #condition \
                << '\n';                                                                   \
      return 1;                                                                            \
    }                                                                                      \
  } while (false)

int main() {
  static_assert(sizeof(reb::VmFindingPayload) == reb::kInlinePayloadSize);
  static_assert(std::is_trivially_copyable_v<reb::VmFindingPayload>);
  static_assert(reb::kVmFindingProtocolVersion == reb::kNativeVmFindingProtocolVersion);
  static_assert(sizeof(reb::VmFindingPayload) == sizeof(reb::NativeVmFindingPayload));
  static_assert(alignof(reb::VmFindingPayload) == alignof(reb::NativeVmFindingPayload));
#define CHECK_VM_OFFSET(field)                            \
  static_assert(offsetof(reb::VmFindingPayload, field) == \
                offsetof(reb::NativeVmFindingPayload, field))
  CHECK_VM_OFFSET(protocol_version);
  CHECK_VM_OFFSET(payload_size);
  CHECK_VM_OFFSET(kind);
  CHECK_VM_OFFSET(host_runtime);
  CHECK_VM_OFFSET(confidence);
  CHECK_VM_OFFSET(flags);
  CHECK_VM_OFFSET(label_size);
  CHECK_VM_OFFSET(observed_count);
  CHECK_VM_OFFSET(total_count);
  CHECK_VM_OFFSET(finding_id);
  CHECK_VM_OFFSET(investigation_id);
  CHECK_VM_OFFSET(subject_id);
  CHECK_VM_OFFSET(related_subject_id);
  CHECK_VM_OFFSET(source_offset);
  CHECK_VM_OFFSET(source_size);
  CHECK_VM_OFFSET(label);
  CHECK_VM_OFFSET(reserved);
#undef CHECK_VM_OFFSET
#define CHECK_VM_ENUM(core_enum, native_enum, value)           \
  static_assert(static_cast<std::uint8_t>(core_enum::value) == \
                static_cast<std::uint8_t>(native_enum::value))
  CHECK_VM_ENUM(reb::VmFindingKind, reb::NativeVmFindingKind, kUnknown);
  CHECK_VM_ENUM(reb::VmFindingKind, reb::NativeVmFindingKind, kInterpreter);
  CHECK_VM_ENUM(reb::VmFindingKind, reb::NativeVmFindingKind, kGuestProgram);
  CHECK_VM_ENUM(reb::VmFindingKind, reb::NativeVmFindingKind, kInvocation);
  CHECK_VM_ENUM(reb::VmFindingKind, reb::NativeVmFindingKind, kHostBinding);
  CHECK_VM_ENUM(reb::VmFindingKind, reb::NativeVmFindingKind, kHypothesis);
  CHECK_VM_ENUM(reb::VmFindingKind, reb::NativeVmFindingKind, kCoverage);
  CHECK_VM_ENUM(reb::VmHostRuntime, reb::NativeVmHostRuntime, kUnknown);
  CHECK_VM_ENUM(reb::VmHostRuntime, reb::NativeVmHostRuntime, kJavaScript);
  CHECK_VM_ENUM(reb::VmHostRuntime, reb::NativeVmHostRuntime, kWebAssembly);
  CHECK_VM_ENUM(reb::VmHostRuntime, reb::NativeVmHostRuntime, kMixed);
  CHECK_VM_ENUM(reb::VmFindingConfidence, reb::NativeVmFindingConfidence, kUnknown);
  CHECK_VM_ENUM(reb::VmFindingConfidence, reb::NativeVmFindingConfidence, kObserved);
  CHECK_VM_ENUM(reb::VmFindingConfidence, reb::NativeVmFindingConfidence, kInferred);
  CHECK_VM_ENUM(reb::VmFindingConfidence, reb::NativeVmFindingConfidence, kHeuristic);
  CHECK_VM_ENUM(reb::VmFindingFlag, reb::NativeVmFindingFlag, kNone);
  CHECK_VM_ENUM(reb::VmFindingFlag, reb::NativeVmFindingFlag, kHasSourceRange);
  CHECK_VM_ENUM(reb::VmFindingFlag, reb::NativeVmFindingFlag, kPartial);
  CHECK_VM_ENUM(reb::VmFindingFlag, reb::NativeVmFindingFlag, kDynamic);
  CHECK_VM_ENUM(reb::VmFindingFlag, reb::NativeVmFindingFlag, kNested);
#undef CHECK_VM_ENUM

  reb::VmFindingPayload finding =
      reb::MakeVmFinding(reb::VmFindingKind::kInterpreter, reb::VmHostRuntime::kJavaScript,
                         reb::VmFindingConfidence::kHeuristic, 101, 7, "dispatcher loop candidate");
  finding.subject_id = 1001;
  finding.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kPartial) |
                  static_cast<std::uint8_t>(reb::VmFindingFlag::kDynamic);
  CHECK(reb::IsValidVmFinding(finding));
  CHECK(reb::VmFindingLabel(finding) == "dispatcher loop candidate");
  CHECK(reb::VmFindingKindName(finding.kind) == "interpreter");
  CHECK(reb::VmHostRuntimeName(finding.host_runtime) == "javascript");
  CHECK(reb::VmFindingConfidenceName(finding.confidence) == "heuristic");

  reb::EventRecord event =
      reb::MakeEvent(reb::EventCategory::kCanvas, reb::EventType::kApiCall, 4, 500, 1);
  CHECK(reb::SetVmFindingPayload(event, finding));
  CHECK(event.header.category == reb::EventCategory::kVm);
  CHECK(event.header.type == reb::EventType::kVmFinding);
  CHECK(event.header.payload_size == sizeof(reb::VmFindingPayload));
  CHECK(reb::IsValidEvent(event));

  reb::VmFindingPayload decoded{};
  CHECK(reb::DecodeVmFinding(event, decoded));
  CHECK(decoded.finding_id == 101);
  CHECK(decoded.investigation_id == 7);
  CHECK(decoded.subject_id == 1001);
  CHECK(decoded.flags == finding.flags);
  CHECK(reb::VmFindingLabel(decoded) == "dispatcher loop candidate");

  reb::VmFindingPayload range =
      reb::MakeVmFinding(reb::VmFindingKind::kGuestProgram, reb::VmHostRuntime::kWebAssembly,
                         reb::VmFindingConfidence::kObserved, 102, 7, "nested guest program");
  range.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kHasSourceRange) |
                static_cast<std::uint8_t>(reb::VmFindingFlag::kNested);
  range.source_offset = 4096;
  range.source_size = 2048;
  CHECK(reb::IsValidVmFinding(range));
  reb::EventRecord range_event =
      reb::MakeEvent(reb::EventCategory::kVm, reb::EventType::kVmFinding, 5, 600, 1);
  CHECK(!reb::SetVmFindingPayload(range_event, range));
  range_event.header.artifact_id = 300;
  CHECK(reb::SetVmFindingPayload(range_event, range));

  reb::VmFindingPayload coverage =
      reb::MakeVmFinding(reb::VmFindingKind::kCoverage, reb::VmHostRuntime::kMixed,
                         reb::VmFindingConfidence::kObserved, 103, 7, "handler characterization");
  coverage.flags = static_cast<std::uint8_t>(reb::VmFindingFlag::kPartial);
  coverage.observed_count = 42;
  coverage.total_count = 60;
  CHECK(reb::IsValidVmFinding(coverage));
  coverage.observed_count = 61;
  CHECK(!reb::IsValidVmFinding(coverage));
  coverage.observed_count = 42;
  coverage.total_count = 0;
  CHECK(!reb::IsValidVmFinding(coverage));

  reb::VmFindingPayload malformed = finding;
  malformed.protocol_version = 2;
  CHECK(!reb::IsValidVmFinding(malformed));
  malformed = finding;
  malformed.kind = reb::VmFindingKind::kUnknown;
  CHECK(!reb::IsValidVmFinding(malformed));
  malformed = finding;
  malformed.flags = 1U << 7U;
  CHECK(!reb::IsValidVmFinding(malformed));
  malformed = finding;
  malformed.source_offset = 1;
  CHECK(!reb::IsValidVmFinding(malformed));
  malformed = finding;
  malformed.label[finding.label_size] = 'x';
  CHECK(!reb::IsValidVmFinding(malformed));
  malformed = finding;
  malformed.reserved[0] = std::byte{1};
  CHECK(!reb::IsValidVmFinding(malformed));

  const std::string oversized(reb::kVmFindingLabelCapacity + 1, 'x');
  CHECK(!reb::SetVmFindingLabel(finding, oversized));
  CHECK(reb::VmFindingLabel(finding) == "dispatcher loop candidate");
  CHECK(!reb::SetVmFindingLabel(finding, "line\nbreak"));
  CHECK(reb::VmFindingLabel(finding) == "dispatcher loop candidate");

  reb::EventRecord malformed_event = event;
  malformed_event.header.payload_size -= 1;
  reb::VmFindingPayload retained = range;
  CHECK(!reb::DecodeVmFinding(malformed_event, retained));
  CHECK(retained.finding_id == range.finding_id);
  malformed_event = event;
  malformed_event.inline_payload[4] = std::byte{0};
  CHECK(!reb::DecodeVmFinding(malformed_event, retained));
  CHECK(retained.finding_id == range.finding_id);

  std::cout << "vm_finding_test passed\n";
  return 0;
}
