#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <latch>
#include <thread>

#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_probe_event.h"
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_vm_dispatch.h"
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_vm_dispatch_emit.h"
#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_wasm_dispatch.h"
#include "reb/artifact.hpp"
#include "reb/event.hpp"
#include "reb/vm_dispatch.hpp"
#include "reb/wasm_dispatch.hpp"

namespace {

bool Check(const bool condition, const char* const message) {
  if (!condition) {
    std::cerr << message << '\n';
  }
  return condition;
}

}  // namespace

int main() {
  {
    static_assert(static_cast<std::uint16_t>(reb::EventType::kWasmDispatchObservation) ==
                  static_cast<std::uint16_t>(reb::NativeProbeType::kWasmDispatchObservation));
    reb::NativeWasmDispatchObservationPayload wasm;
    wasm.function_index = 0x00010203;
    wasm.module_byte_offset = 0x04050607;
    wasm.selector = UINT32_MAX;
    wasm.table_count = 0x08090a0b;
    const auto encoded = reb::EncodeNativeWasmDispatchObservationPayload(wasm);
    reb::WasmDispatchObservationPayload decoded;
    if (!Check(encoded[4] == std::byte{3} && encoded[7] == std::byte{0} &&
                   encoded[8] == std::byte{7} && encoded[16] == std::byte{11},
               "native payload is not LE") ||
        !Check(reb::DecodeWasmDispatchObservationPayload(encoded, decoded),
               "native bytes decode") ||
        !Check(decoded.function_index == wasm.function_index &&
                   decoded.module_byte_offset == wasm.module_byte_offset &&
                   decoded.selector == UINT32_MAX && decoded.table_count == wasm.table_count,
               "payload field parity") ||
        !Check(reb::EncodeWasmDispatchObservationPayload(decoded) == encoded,
               "core/native encoder parity"))
      return 1;
    for (std::size_t size : {std::size_t{0}, std::size_t{24}, std::size_t{127}}) {
      if (!Check(
              !reb::DecodeWasmDispatchObservationPayload(std::span(encoded).first(size), decoded),
              "truncation accepted"))
        return 1;
    }
  }
  {
    static_assert(static_cast<std::uint16_t>(reb::EventType::kWasmIndirectObservation) ==
                  static_cast<std::uint16_t>(reb::NativeProbeType::kWasmIndirectObservation));
    reb::NativeWasmIndirectObservationPayload wasm;
    wasm.function_index = 0x00010203;
    wasm.module_byte_offset = 0x04050607;
    wasm.table_index = 0x08090a0b;
    wasm.slot = UINT32_MAX;
    wasm.callee_function_index = 0x0c0d0e0f;
    wasm.resolution = static_cast<std::uint32_t>(reb::NativeWasmIndirectResolution::kForeign);
    wasm.sample_index = 15;
    const auto encoded = reb::EncodeNativeWasmIndirectObservationPayload(wasm);
    reb::WasmIndirectObservationPayload decoded;
    if (!Check(encoded[4] == std::byte{3} && encoded[8] == std::byte{7} &&
                   encoded[12] == std::byte{11} && encoded[20] == std::byte{15} &&
                   encoded[24] == std::byte{3} && encoded[28] == std::byte{15},
               "native call_indirect payload is not LE") ||
        !Check(reb::DecodeWasmIndirectObservationPayload(encoded, decoded),
               "native call_indirect bytes decode") ||
        !Check(decoded.function_index == wasm.function_index &&
                   decoded.module_byte_offset == wasm.module_byte_offset &&
                   decoded.table_index == wasm.table_index && decoded.slot == UINT32_MAX &&
                   decoded.callee_function_index == wasm.callee_function_index &&
                   decoded.resolution == wasm.resolution && decoded.sample_index == 15,
               "call_indirect payload field parity") ||
        !Check(reb::EncodeWasmIndirectObservationPayload(decoded) == encoded,
               "call_indirect core/native encoder parity"))
      return 1;
    for (std::size_t size : {std::size_t{0}, std::size_t{32}, std::size_t{127}}) {
      if (!Check(
              !reb::DecodeWasmIndirectObservationPayload(std::span(encoded).first(size), decoded),
              "call_indirect truncation accepted"))
        return 1;
    }
  }
  // Model a reader paused after policy validation, then a replacement config.
  // This is the same reservation state used by NativeProbeSink, not a copy of
  // its algorithm. No timing sleeps or native browser are required.
  reb::NativeVmDispatchBudget budget;
  std::latch validated(1);
  std::latch resume(1);
  std::thread stale([&] {
    validated.count_down();
    resume.wait();
    static_cast<void>(budget.TryReserve(2));
  });
  validated.wait();
  const auto first_new = budget.TryReserve(4);
  resume.count_down();
  stale.join();
  if (!Check(first_new == 0, "new configuration lost its first reservation")) {
    return 1;
  }
  for (std::uint32_t slot = 1; slot < reb::kNativeVmDispatchSampleBudget; ++slot) {
    if (!Check(budget.TryReserve(4) == slot, "stale reader consumed new configuration budget")) {
      return 1;
    }
  }
  if (!Check(budget.TryReserve(4) == reb::kNativeVmDispatchSampleBudget,
             "configuration exceeded its budget") ||
      !Check(budget.TryReserve(2) == reb::kNativeVmDispatchSampleBudget,
             "stale generation overwrote newer claims") ||
      !Check(budget.TryReserve(0) == reb::kNativeVmDispatchSampleBudget,
             "inactive generation reserved budget") ||
      !Check(budget.TryReserve(5) == reb::kNativeVmDispatchSampleBudget,
             "unstable generation reserved budget")) {
    return 1;
  }
  for (std::uint32_t slot = 0; slot < reb::kNativeVmDispatchSampleBudget; ++slot) {
    if (!Check(budget.TryReserve(6) == slot, "next configuration did not reclaim budget")) {
      return 1;
    }
  }

  reb::NativeVmDispatchBudget concurrent_budget;
  std::array<std::thread, 32> contenders;
  std::atomic<std::uint32_t> accepted{0};
  std::latch start(1);
  for (auto& contender : contenders) {
    contender = std::thread([&] {
      start.wait();
      if (concurrent_budget.TryReserve(2) < reb::kNativeVmDispatchSampleBudget) {
        accepted.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }
  start.count_down();
  for (auto& contender : contenders) {
    contender.join();
  }
  if (!Check(accepted.load() == reb::kNativeVmDispatchSampleBudget,
             "concurrent callers violated a stable configuration budget")) {
    return 1;
  }

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
  invalid = sample;
  invalid.interpreter_artifact_id = 0;
  if (!Check(!reb::IsValidVmDispatchSample(invalid),
             "missing interpreter artifact accepted by harness validator") ||
      !Check(!reb::SetVmDispatchSamplePayload(event, invalid),
             "missing interpreter artifact was encoded")) {
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

  auto native = std::bit_cast<reb::NativeVmDispatchSamplePayload>(sample);
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

  reb::NativeVmDispatchBudget releasable;
  for (std::uint32_t slot = 0; slot < reb::kNativeVmDispatchSampleBudget; ++slot) {
    if (!Check(releasable.TryReserve(4) == slot, "release fixture did not reserve")) {
      return 1;
    }
  }
  releasable.Release(0, 4);
  if (!Check(releasable.TryReserve(2) == reb::kNativeVmDispatchSampleBudget,
             "stale generation reclaimed a released slot") ||
      !Check(releasable.TryReserve(4) == 0, "failed emit did not return the budget slot")) {
    return 1;
  }
  releasable.Release(0, 4);
  if (!Check(releasable.TryReserve(6) == 0, "newer generation did not reclaim a released slot")) {
    return 1;
  }
  return 0;
}
