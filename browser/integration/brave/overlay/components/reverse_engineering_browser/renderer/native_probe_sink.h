// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include "brave/components/reverse_engineering_browser/common/native_wasm_guest.h"

#include "base/component_export.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_vm_dispatch_emit.h"
#include "brave/components/reverse_engineering_browser/common/native_vm_finding.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_dispatch.h"

namespace reb {

// Maximum allocating-script source prefix scanned to admit a runtime buffer.
// The same bound is the renderer classifier's window.
inline constexpr std::size_t kRuntimeScriptNoteBytes = 256U * 1024U;
inline constexpr std::size_t kRuntimeTypedArrayMaxSnapshots = 16;

// kAdmitted is in the renderer ring, not delivered to the browser or store.
// kQueueFull already contributes its drop weight to the ring's DroppedCount;
// kRejected never reached the ring. Keep this boundary independent of Mojo.
enum class NativeProbeEmitStatus : std::uint8_t {
  kAdmitted = 0,
  kRejected = 1,
  kQueueFull = 2,
};

// The generation identifies the captured policy. Emitters must remain
// non-blocking and non-throwing, including when called from another component.
using NativeRendererProbeEmitter =
    NativeProbeEmitStatus (*)(const NativeProbeEvent& event,
                              std::uint64_t config_generation) noexcept;

using NativeProbeFrameIdProvider = std::uint64_t (*)() noexcept;

// Trusted native detector output only. Registration is not exposed to page JS.
enum class NativeRuntimeScriptObservation : std::uint8_t {
  kCapturedVmCandidate,
  kCapturedLikelyVm,
  kStaticDispatchLoop,
};

// Identities for one opt-in guest shape. Zero is rejected. These are
// researcher-selected reference claims, not proof that a page supplied them.
struct PageGuestSamplePolicy final {
  std::uint64_t finding_id = 0;
  std::uint64_t investigation_id = 0;
  std::uint64_t interpreter_artifact_id = 0;
  std::uint64_t bytecode_artifact_id = 0;
};

// Identities for the owned-register opt-in. Zero is rejected. These are
// researcher-selected reference claims, not proof that a page supplied them.
struct OwnedRegisterSamplePolicy final {
  std::uint64_t finding_id = 0;
  std::uint64_t investigation_id = 0;
  std::uint64_t interpreter_artifact_id = 0;
  std::uint64_t bytecode_artifact_id = 0;
};

enum class NativeWasmGuestModuleDecision : std::uint8_t {
  kNotDispatcher,
  kAdmit,
  kRejectModule,
};

class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeProbeSink final {
 public:
  static NativeProbeSink& Get();

  NativeProbeSink(const NativeProbeSink&) = delete;
  NativeProbeSink& operator=(const NativeProbeSink&) = delete;

  // Must be called from one serialized control sequence.
  void SetEmitters(NativeRendererProbeEmitter emitter,
                   NativeGeneratedArtifactEmitter artifact_emitter,
                   std::uint64_t session_id,
                   std::uint64_t category_mask,
                   std::uint64_t expires_at_monotonic_ns,
                   bool capture_canvas_images = false,
                   NativeProbeFrameIdProvider frame_id_provider = nullptr) noexcept;
  // Called after acquiring the transport queue pointer. A successful check
  // authorizes an in-flight insertion into that retained mapping; Disable does
  // not wait for producers already past this admission check.
  [[nodiscard]] bool CanAdmitEvent(const NativeProbeEvent& event,
                                   std::uint64_t config_generation) const noexcept;
  [[nodiscard]] bool IsArtifactCaptureEnabled() const noexcept;
  [[nodiscard]] bool IsVmCaptureEnabled() const noexcept;
  [[nodiscard]] bool IsCanvasImageCaptureEnabled() const noexcept;
  [[nodiscard]] bool RuntimeScriptSourceNeeded(std::uint64_t execution_context_id,
                                               std::uint64_t script_id) const noexcept;
  [[nodiscard]] std::uint64_t RuntimeCaptureGeneration() const noexcept;
  // Caller must preserve the generation at observation time. No URL matching,
  // cross-thread transfer, or inference of VM classification occurs here.
  [[nodiscard]] bool RegisterRuntimeScriptObservation(
      std::uint64_t generation,
      std::uint64_t execution_context_id,
      std::uint64_t script_id,
      NativeRuntimeScriptObservation observation) noexcept;
  // True while this script's source attempt is remembered in this generation,
  // including a negative classification or an unavailable conversion.
  [[nodiscard]] bool RuntimeScriptSourceNoted(std::uint64_t generation,
                                              std::uint64_t execution_context_id,
                                              std::uint64_t script_id) const noexcept;
  // Check before UTF-8 conversion. Positive observations stay pinned; negative
  // entries rotate within 64 slots. At most 256 attempts (including conversion
  // misses and scan allocation failures) run per generation and thread.
  [[nodiscard]] bool RuntimeScriptNoteAccepts(std::uint64_t generation,
                                              std::uint64_t execution_context_id,
                                              std::uint64_t script_id) const noexcept;
  // Records a bounded structural classification, returning whether it found a
  // signal. Cached entries are not rescanned. Evicted negatives can be retried
  // only within the total attempt budget. Allocation failure is retryable within
  // that budget; a full positive table or exhausted budget refuses the scan.
  // source_truncated is true when source is a prefix of a longer script.
  [[nodiscard]] bool NoteRuntimeScriptSource(std::uint64_t generation,
                                             std::uint64_t execution_context_id,
                                             std::uint64_t script_id,
                                             std::span<const std::uint8_t> source,
                                             bool source_truncated = false) noexcept;
  // Remembers a conversion that produced no bytes, so the caller does not
  // allocate the prefix again. Returns false.
  [[nodiscard]] bool RememberRuntimeScriptMiss(std::uint64_t generation,
                                               std::uint64_t execution_context_id,
                                               std::uint64_t script_id) noexcept;
  [[nodiscard]] bool RuntimeBufferHasSignal(std::uint64_t generation,
                                            std::uint64_t execution_context_id,
                                            std::uint64_t frame_id,
                                            std::size_t bytes,
                                            std::uint64_t script_id,
                                            bool is_eval) noexcept;
  void RecordRuntimeBufferOmission(std::uint64_t generation,
                                   std::uint64_t frame_id,
                                   std::string_view reason) noexcept;
  void CaptureRuntimeTypedArray(std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::span<const std::uint8_t> content,
                                const NativeRuntimeScript& script) noexcept;
  void CaptureGeneratedArtifact(NativeArtifactKind kind,
                                NativeArtifactCaptureOrigin capture_origin,
                                std::uint64_t creator_event_id,
                                std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::span<const std::uint8_t> content) noexcept;
  void CaptureGeneratedArtifact(NativeArtifactKind kind,
                                NativeArtifactCaptureOrigin capture_origin,
                                std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::span<const std::uint8_t> content) noexcept {
    CaptureGeneratedArtifact(kind, capture_origin, 0, execution_context_id, frame_id, source_url,
                             content);
  }
  void ConfigureNativeWasmGuest(std::shared_ptr<const NativeWasmGuestAdapter> adapter,
                                NativeGuestCaptureEmitter capture,
                                NativeGuestHostEmitter host) noexcept;
  void SetNativeWasmGuestRuntime(NativeWasmGuestContextProvider context,
                                 NativeWasmGuestReset reset) noexcept;
  // Records the browser's verdict for the module bytes sent with the guest
  // dispatch whose sequence number is module_token. Lock-free; may be called
  // from the transport sequence while Wasm runs on another thread.
  void NoteNativeGuestModuleStatus(std::uint64_t module_token, bool accepted) noexcept;
  [[nodiscard]] bool IsNativeWasmGuestEnabled() const noexcept;
  [[nodiscard]] bool IsNativeWasmGuestDispatchSite(std::uint32_t function_index,
                                                   std::uint32_t module_byte_offset) const noexcept;
  void InvalidateNativeWasmGuest(const NativeWasmGuestStateView& view) noexcept;
  // kNotDispatcher defers to a later function entry (or a later enabled
  // interval). kRejectModule is final for these exact module bytes under the
  // immutable adapter, so the engine may stop asking (and hashing) for them.
  [[nodiscard]] NativeWasmGuestModuleDecision AdmitNativeWasmGuestModule(
      std::span<const std::uint8_t> module,
      std::uint32_t function_index) const noexcept;
  void RecordNativeWasmGuest(std::uint64_t execution_context_id,
                             std::uint64_t frame_id,
                             std::string_view source_url,
                             std::span<const std::uint8_t> module_bytes,
                             const NativeWasmGuestStateView& view,
                             std::uint64_t document_token_high,
                             std::uint64_t document_token_low) noexcept;
  // Native-only runtime callback; no page JS registration and no inferred guest PC.
  void SetNativeWasmDispatchEmitter(NativeWasmDispatchEmitter emitter) noexcept;
  [[nodiscard]] bool IsNativeWasmDispatchEnabled() const noexcept;
  void RecordNativeWasmDispatch(std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::span<const std::uint8_t> module_bytes,
                                std::uint32_t function_index,
                                std::uint32_t module_byte_offset,
                                std::uint32_t selector,
                                std::uint32_t table_count,
                                std::uint64_t document_token_high,
                                std::uint64_t document_token_low) noexcept;
  // Physical call_indirect observations share the br_table admission rules
  // with their own emitter, 16-record budget and coalesced omission gaps. The
  // caller fills identity, site, slot and resolution; the sink fills the rest.
  void SetNativeWasmIndirectEmitter(NativeWasmIndirectEmitter emitter) noexcept;
  [[nodiscard]] bool IsNativeWasmIndirectEnabled() const noexcept;
  void RecordNativeWasmIndirect(NativeWasmIndirectObservation observation) noexcept;
  void RecordApiCall(NativeProbeCategory category, std::string_view operation) noexcept;
  void RecordPropertyRead(NativeProbeCategory category, std::string_view operation) noexcept;
  // Call-site state is an opaque, monotonically ordered configuration claim,
  // not a session ID. Zero initializes an unobserved site. Failed admission
  // leaves generation - 1 so stale callers cannot reclaim a newer generation.
  void RecordApiCallOnce(NativeProbeCategory category,
                         std::string_view operation,
                         std::atomic<std::uint64_t>& observed_generation) noexcept;
  void RecordPropertyReadOnce(NativeProbeCategory category,
                              std::string_view operation,
                              std::atomic<std::uint64_t>& observed_generation) noexcept;
  void RecordCanvasToDataUrl() noexcept;
  void RecordCanvasToDataUrl(std::string_view data_url) noexcept;
  void RecordWebAudioCall(std::string_view operation) noexcept;
  void RecordRequestInitiated(std::int32_t request_id,
                              std::string_view method,
                              std::string_view url) noexcept;
  // Copies one guest step the caller already observed. The instruction
  // pointer, opcode, and handler index are not read from V8, Wasm, canvas,
  // or a static handler table. At most kNativeVmDispatchSampleBudget samples
  // are admitted for one capture configuration. Overflow and rejected emits
  // stay on a generation-scoped counter until PublishVmDispatchBudgetGap
  // writes one vm gap whose decimal payload is the exact unreported count.
  void RecordVmDispatchSample(const NativeVmDispatchSamplePayload& sample) noexcept;
  // Emits one coalesced vm gap for dispatch observations that were not
  // retained. A full probe queue already counts its own drops, so this gap
  // covers budget overflow and emits rejected before the queue. Safe to call
  // when capture is inactive or the counter is caught up.
  void PublishVmDispatchBudgetGap() noexcept;
  // Owned-register sampler. Disabled until EnableOwnedRegisterSampling accepts
  // a VM capture session and nonzero identities. The sample policy is one
  // invocation finding plus every committed instruction of owned-register-v1.
  // Program counters are that fixture's instruction indices. Handler index
  // copies the fixture opcode. The 16-sample budget and a full probe queue
  // both stay visible through the existing dispatch-loss and drop counters.
  // Reconfigure clears the opt-in. This path does not read V8 or Wasm.
  [[nodiscard]] bool EnableOwnedRegisterSampling(const OwnedRegisterSamplePolicy& policy) noexcept;
  void DisableOwnedRegisterSampling() noexcept;
  void IngestOwnedRegisterInvocation(std::uint64_t invocation_id) noexcept;
  void IngestOwnedRegisterStep(std::uint32_t instruction_pointer,
                               std::uint32_t opcode,
                               std::uint8_t operand_count,
                               std::uint32_t sample_index) noexcept;
  // Page guest shapes. Disabled until the matching Enable accepts a VM capture
  // session and nonzero identities. Reconfigure clears both. javascript-switch-
  // dispatch-v1 steps a captured byte program (opcodes 16-19); its program
  // counter is the opcode's byte index. wasm-br-table-dispatch-v1 steps the
  // first function of a captured Wasm module when that body contains br_table
  // and stays inside the supported opcode subset; its program counter is the
  // module byte offset. Neither shape reads Ignition, Liftoff, or TurboFan.
  // The handler index copies the opcode. The 16-sample budget, a full probe
  // queue, and the 32-step walk cap all stay visible.
  [[nodiscard]] bool EnableJavaScriptSwitchSampling(const PageGuestSamplePolicy& policy) noexcept;
  [[nodiscard]] bool EnableWasmBrTableSampling(const PageGuestSamplePolicy& policy) noexcept;
  void DisablePageGuestSampling() noexcept;
  void ObserveCapturedJavaScriptSwitchProgram(std::span<const std::uint8_t> program) noexcept;
  void ObserveCapturedWasmModule(std::span<const std::uint8_t> module) noexcept;

 private:
  NativeProbeSink() noexcept;

  [[nodiscard]] NativeProbeEmitStatus EmitStatus(const NativeProbeEvent& event,
                                                 std::uint64_t generation) const noexcept;

  std::uint64_t RecordRuntimeBufferEvent(NativeProbeType type,
                                         std::uint64_t frame_id,
                                         std::string_view reason,
                                         std::uint64_t generation) noexcept;

  [[nodiscard]] std::uint64_t RecordSurfaceOperation(
      NativeProbeCategory category,
      NativeProbeType type,
      std::string_view operation,
      std::atomic<std::uint64_t>* observed_generation = nullptr) noexcept;

  struct VmAdmission final {
    std::uint64_t generation = 0;
    std::uint64_t session_id = 0;
    std::uint64_t monotonic_time_ns = 0;
    std::uint64_t frame_id = 0;
    std::uint32_t process_id = 0;
    std::uint32_t thread_id = 0;
  };
  [[nodiscard]] bool SnapshotVmAdmission(VmAdmission& admission) const noexcept;

  void NoteVmDispatchLoss(std::uint64_t generation,
                          std::uint64_t session_id,
                          std::uint64_t monotonic_time_ns,
                          std::uint64_t frame_id,
                          std::uint32_t process_id,
                          std::uint32_t thread_id,
                          std::uint64_t interpreter_artifact_id) noexcept;

  enum class NativeWasmOmission : std::size_t { kInput, kTransport, kBudget };
  bool NoteNativeWasmDispatchOmission(const VmAdmission& admission,
                                      NativeWasmOmission reason) noexcept;
  std::atomic<NativeWasmDispatchEmitter> native_wasm_emitter_{nullptr};
  std::array<std::atomic<std::uint64_t>, kNativeWasmDispatchSampleBudget> native_wasm_slots_{};
  std::array<std::atomic<std::uint64_t>, 3> native_wasm_gap_generations_{};
  std::atomic<std::uint64_t> native_wasm_capped_generation_{0};
  bool NoteNativeWasmIndirectOmission(const VmAdmission& admission,
                                      NativeWasmOmission reason) noexcept;
  std::atomic<NativeWasmIndirectEmitter> native_wasm_indirect_emitter_{nullptr};
  std::array<std::atomic<std::uint64_t>, kNativeWasmIndirectSampleBudget>
      native_wasm_indirect_slots_{};
  std::array<std::atomic<std::uint64_t>, 3> native_wasm_indirect_gap_generations_{};
  std::atomic<std::uint64_t> native_wasm_indirect_capped_generation_{0};
  std::atomic<NativeRendererProbeEmitter> emitter_{nullptr};
  std::atomic<NativeProbeFrameIdProvider> frame_id_provider_{nullptr};
  std::atomic<NativeGeneratedArtifactEmitter> artifact_emitter_{nullptr};
  std::atomic<std::uint64_t> next_sequence_{1};
  // Even generations are stable. SetEmitters transitions through the next odd
  // generation while replacing the independently atomic policy fields.
  std::atomic<std::uint64_t> config_generation_{0};
  std::atomic<std::uint64_t> session_id_{0};
  std::atomic<std::uint64_t> category_mask_{0};
  std::atomic<std::uint64_t> expires_at_monotonic_ns_{0};
  std::atomic<bool> capture_canvas_images_{false};
  // Monotonic generation claims are never reset: an old capture cannot spend
  // or release a replacement configuration's snapshot quota.
  std::array<std::atomic<std::uint64_t>, kRuntimeTypedArrayMaxSnapshots>
      runtime_snapshot_generations_{};
  NativeVmDispatchBudget dispatch_sample_budget_;
  // Cumulative dispatch losses for the active capture. reported_ trails
  // dropped_ until a vm gap is admitted. Identity fields describe the losses
  // still waiting to be published. The counters are not reset: a generation
  // bump publishes the remainder first, then new losses append.
  std::atomic<std::uint64_t> dispatch_loss_generation_{0};
  std::atomic<std::uint64_t> dispatch_loss_dropped_{0};
  std::atomic<std::uint64_t> dispatch_loss_reported_{0};
  std::atomic<std::uint64_t> dispatch_loss_artifact_id_{0};
  std::atomic<std::uint64_t> dispatch_loss_session_id_{0};
  std::atomic<std::uint64_t> dispatch_loss_time_ns_{0};
  std::atomic<std::uint64_t> dispatch_loss_frame_id_{0};
  std::atomic<std::uint32_t> dispatch_loss_process_id_{0};
  std::atomic<std::uint32_t> dispatch_loss_thread_id_{0};
  // Release-published with the enabled flag. Inactive reads return before
  // these fields are consulted.
  std::atomic<std::uint8_t> owned_register_sampling_{0};
  std::atomic<std::uint64_t> owned_register_finding_id_{0};
  std::atomic<std::uint64_t> owned_register_investigation_id_{0};
  std::atomic<std::uint64_t> owned_register_interpreter_id_{0};
  std::atomic<std::uint64_t> owned_register_bytecode_id_{0};
  // Release-published with each shape's enabled flag. Inactive reads return
  // before the identity fields are consulted. The invocation counter is not a
  // guest program counter.
  std::atomic<std::uint8_t> javascript_switch_sampling_{0};
  std::atomic<std::uint64_t> javascript_switch_finding_id_{0};
  std::atomic<std::uint64_t> javascript_switch_investigation_id_{0};
  std::atomic<std::uint64_t> javascript_switch_interpreter_id_{0};
  std::atomic<std::uint64_t> javascript_switch_bytecode_id_{0};
  std::atomic<std::uint8_t> wasm_br_table_sampling_{0};
  std::atomic<std::uint64_t> wasm_br_table_finding_id_{0};
  std::atomic<std::uint64_t> wasm_br_table_investigation_id_{0};
  std::atomic<std::uint64_t> wasm_br_table_interpreter_id_{0};
  std::atomic<std::uint64_t> wasm_br_table_bytecode_id_{0};
  std::atomic<std::uint64_t> page_guest_invocation_{1};
  const NativeWasmGuestAdapter* native_guest_retained_adapter_ = nullptr;
  std::atomic<const NativeWasmGuestAdapter*> native_guest_adapter_{nullptr};
  std::atomic<NativeGuestCaptureEmitter> native_guest_capture_{nullptr};
  std::atomic<NativeGuestHostEmitter> native_guest_host_{nullptr};
  std::atomic<NativeWasmGuestContextProvider> native_guest_context_{nullptr};
  std::atomic<NativeWasmGuestReset> native_guest_reset_{nullptr};
  std::array<std::atomic<std::uint64_t>, kNativeGuestSampleLimit> native_guest_slots_{};
  std::atomic<std::uint64_t> native_guest_capped_generation_{0};
  std::array<std::atomic<std::uint64_t>, 10> native_guest_gap_generations_{};
  // Parent-binding host routes claimed per configuration (see
  // kNativeGuestHostParentLimit). Same generation-tag scheme as samples.
  std::array<std::atomic<std::uint64_t>, kNativeGuestHostParentLimit> native_guest_host_slots_{};
  std::atomic<std::uint64_t> native_guest_host_capped_generation_{0};
  // Recent module verdicts, (token << 1) | accepted. Tokens are process-unique
  // renderer sequence numbers, so a stale verdict can never match a new send.
  std::array<std::atomic<std::uint64_t>, 64> native_guest_module_status_{};
  std::atomic<std::uint32_t> native_guest_module_status_next_{0};
  enum class GuestModuleVerdict : std::uint8_t { kPending, kAccepted, kRejected };
  [[nodiscard]] GuestModuleVerdict NativeGuestModuleVerdict(std::uint64_t token) const noexcept;
  [[nodiscard]] bool ClaimNativeGuestHostRoute(std::uint64_t generation) noexcept;
  void NoteNativeGuestOmission(std::uint64_t generation,
                               std::uint64_t frame,
                               std::size_t kind,
                               std::string_view reason) noexcept;
  bool TryRecordNativeGuestHost(NativeProbeEvent& event, std::uint64_t generation) noexcept;

  struct PageGuestIds final {
    std::uint64_t finding_id = 0;
    std::uint64_t investigation_id = 0;
    std::uint64_t interpreter_artifact_id = 0;
    std::uint64_t bytecode_artifact_id = 0;
  };
  void EmitPageGuestInvocation(std::string_view label,
                               NativeVmHostRuntime host_runtime,
                               PageGuestIds ids,
                               std::uint64_t invocation_id,
                               const VmAdmission& admission) noexcept;
  void EmitPageGuestStep(PageGuestIds ids,
                         std::uint32_t instruction_pointer,
                         std::uint32_t opcode,
                         std::uint8_t operand_count,
                         std::uint32_t sample_index) noexcept;
  void ObservePageGuest(bool javascript, std::span<const std::uint8_t> bytes) noexcept;
};

// Function-pointer entries for the owned-register runner. They call the sink
// methods above and do not invent a program counter.
void IngestOwnedRegisterInvocationThunk(std::uint64_t invocation_id, void* sink) noexcept;
void IngestOwnedRegisterStepThunk(std::uint32_t instruction_pointer,
                                  std::uint32_t opcode,
                                  std::uint8_t operand_count,
                                  std::uint32_t sample_index,
                                  void* sink) noexcept;

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_SINK_H_
