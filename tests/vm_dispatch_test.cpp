#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_event.h"
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_vm_dispatch.h"
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_vm_dispatch_emit.h"
#include "reb/artifact.hpp"
#include "reb/event.hpp"
#include "reb/vm_dispatch.hpp"

namespace {

bool Check(const bool condition, const char* const message) {
  if (!condition) {
    std::cerr << message << '\n';
  }
  return condition;
}

}  // namespace

int main() {
  static_assert(sizeof(reb::VmDispatchSamplePayload) == 128);
  static_assert(offsetof(reb::VmDispatchSamplePayload, instruction_pointer) == 4);
  static_assert(offsetof(reb::VmDispatchSamplePayload, finding_id) == 24);
  static_assert(offsetof(reb::VmDispatchSamplePayload, flags) == 56);
  static_assert(offsetof(reb::VmDispatchSamplePayload, reserved_tail) == 112);
  static_assert(sizeof(reb::NativeVmDispatchSamplePayload) == sizeof(reb::VmDispatchSamplePayload));
  static_assert(offsetof(reb::NativeVmDispatchSamplePayload, finding_id) ==
                offsetof(reb::VmDispatchSamplePayload, finding_id));
  static_assert(offsetof(reb::NativeVmDispatchSamplePayload, reserved_tail) ==
                offsetof(reb::VmDispatchSamplePayload, reserved_tail));
  static_assert(static_cast<std::uint16_t>(reb::NativeProbeType::kVmDispatchSample) ==
                static_cast<std::uint16_t>(reb::EventType::kVmDispatchSample));
  static_assert(static_cast<std::uint16_t>(reb::NativeArtifactKind::kBytecodeBuffer) ==
                static_cast<std::uint16_t>(reb::ArtifactKind::kBytecodeBuffer));
  static_assert(static_cast<std::uint16_t>(reb::NativeArtifactCaptureOrigin::kRuntimeTypedArray) ==
                static_cast<std::uint16_t>(reb::ArtifactCaptureOrigin::kRuntimeTypedArray));

  const reb::VmDispatchSamplePayload sample =
      reb::MakeVmDispatchSample(17, 41, 3, 9, 101, 202, 303, 404, 2);
  if (!Check(reb::IsValidVmDispatchSample(sample), "valid sample rejected")) {
    return 1;
  }

  reb::EventRecord event =
      reb::MakeEvent(reb::EventCategory::kRuntime, reb::EventType::kApiCall, 1, 2, 3);
  if (!Check(reb::SetVmDispatchSamplePayload(event, sample), "sample encoding failed") ||
      !Check(event.header.category == reb::EventCategory::kVm,
             "sample category was not normalized") ||
      !Check(event.header.type == reb::EventType::kVmDispatchSample,
             "sample event type was not normalized")) {
    return 1;
  }

  reb::VmDispatchSamplePayload decoded{};
  if (!Check(reb::DecodeVmDispatchSample(event, decoded), "sample decoding failed") ||
      !Check(std::memcmp(&sample, &decoded, sizeof(sample)) == 0,
             "sample round trip changed bytes")) {
    return 1;
  }

  reb::VmDispatchSamplePayload invalid = sample;
  invalid.payload_size = 127;
  if (!Check(!reb::IsValidVmDispatchSample(invalid), "payload size mismatch accepted")) {
    return 1;
  }
  invalid = sample;
  invalid.flags = 1;
  if (!Check(!reb::IsValidVmDispatchSample(invalid), "unknown flags accepted")) {
    return 1;
  }
  invalid = sample;
  invalid.reserved_alignment = 1;
  if (!Check(!reb::IsValidVmDispatchSample(invalid), "dirty alignment reserve accepted")) {
    return 1;
  }
  invalid = sample;
  invalid.reserved0 = 1;
  if (!Check(!reb::IsValidVmDispatchSample(invalid), "dirty reserved0 accepted")) {
    return 1;
  }
  invalid = sample;
  invalid.reserved1 = 1;
  if (!Check(!reb::IsValidVmDispatchSample(invalid), "dirty reserved1 accepted")) {
    return 1;
  }
  invalid = sample;
  invalid.reserved2 = 1;
  if (!Check(!reb::IsValidVmDispatchSample(invalid), "dirty reserved2 accepted")) {
    return 1;
  }
  invalid = sample;
  invalid.reserved[13] = std::byte{1};
  if (!Check(!reb::IsValidVmDispatchSample(invalid), "dirty reserved bytes accepted")) {
    return 1;
  }
  invalid = sample;
  invalid.reserved_tail[15] = std::byte{1};
  if (!Check(!reb::IsValidVmDispatchSample(invalid), "dirty reserved tail accepted")) {
    return 1;
  }
  event.inline_payload.back() = std::byte{1};
  if (!Check(!reb::DecodeVmDispatchSample(event, decoded),
             "encoded dirty reserved tail accepted")) {
    return 1;
  }
  if (!Check(reb::SetVmDispatchSamplePayload(event, sample), "sample restore failed")) {
    return 1;
  }
  event.header.payload_size = 127;
  if (!Check(!reb::DecodeVmDispatchSample(event, decoded), "short sample accepted")) {
    return 1;
  }

  reb::NativeVmDispatchSamplePayload native{};
  std::memcpy(&native, &sample, sizeof(native));
  reb::NativeProbeEvent probe;
  if (!Check(reb::PrepareVmDispatchProbeEvent(native, 0, 8, 9, 10, 11, 12, 13, probe) ==
                 reb::NativeVmDispatchPrepareStatus::kReady,
             "observed sample was not prepared") ||
      !Check(probe.header.category == reb::NativeProbeCategory::kVm, "probe category") ||
      !Check(probe.header.type == reb::NativeProbeType::kVmDispatchSample, "probe type") ||
      !Check(probe.header.payload_size == sizeof(native), "probe payload size") ||
      !Check(probe.header.artifact_id == native.interpreter_artifact_id, "probe artifact id") ||
      !Check(probe.header.sequence_number == 8 && probe.header.frame_id == 13, "probe identity") ||
      !Check(std::memcmp(probe.inline_payload.data(), &native, sizeof(native)) == 0,
             "probe payload bytes")) {
    return 1;
  }
  native.interpreter_artifact_id = 0;
  if (!Check(!reb::IsEmittableVmDispatchSample(native), "missing interpreter artifact accepted") ||
      !Check(reb::PrepareVmDispatchProbeEvent(native, 0, 1, 1, 1, 1, 1, 1, probe) ==
                 reb::NativeVmDispatchPrepareStatus::kMalformed,
             "missing interpreter artifact prepared")) {
    return 1;
  }
  native.interpreter_artifact_id = sample.interpreter_artifact_id;
  native.finding_id = 0;
  if (!Check(reb::PrepareVmDispatchProbeEvent(native, 0, 1, 1, 1, 1, 1, 1, probe) ==
                 reb::NativeVmDispatchPrepareStatus::kMalformed,
             "missing finding id prepared")) {
    return 1;
  }
  native.finding_id = sample.finding_id;
  if (!Check(reb::PrepareVmDispatchProbeEvent(native, reb::kNativeVmDispatchSampleBudget, 1, 1, 1,
                                              1, 1, 1, probe) ==
                 reb::NativeVmDispatchPrepareStatus::kBudgetExhausted,
             "sample past the budget was prepared") ||
      !Check(reb::kNativeVmDispatchSampleBudget == 16, "dispatch budget drifted")) {
    return 1;
  }
  return 0;
}
