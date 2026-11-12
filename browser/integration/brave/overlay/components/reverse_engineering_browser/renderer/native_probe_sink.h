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
#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "brave/components/reverse_engineering_browser/common/native_compiled_script.h"
#include "brave/components/reverse_engineering_browser/common/native_js_dispatch.h"
#include "brave/components/reverse_engineering_browser/common/native_js_invocation.h"
#include "brave/components/reverse_engineering_browser/common/native_network_scope.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_vm_dispatch_emit.h"
#include "brave/components/reverse_engineering_browser/common/native_vm_finding.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_dispatch.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_sample_budget.h"
#include "brave/components/reverse_engineering_browser/renderer/native_fetch_owner.h"
#include "brave/components/reverse_engineering_browser/renderer/native_renderer_request.h"

namespace reb {

class NativeDebuggerWatch;
class NativeRequestStackWalk;
class NativeScriptCookieSink;

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

// Counts one request or memory-cache reuse the configuration did not record:
// a browser-internal scheme class, or kNativeMemoryCacheReuseExclusion.
using NativeProbeExclusionCounter = void (*)(std::uint8_t exclusion_class,
                                             std::uint64_t session_id,
                                             std::uint64_t config_generation) noexcept;

// Network gates of one configuration, published by SetEmitters.
struct NativeNetworkScope final {
  // --reb-capture-request-content: renderer request targets follow it.
  bool capture_request_content = false;
  // --reb-capture-browser-internal: record internal schemes instead of counting.
  bool capture_browser_internal = false;
  NativeProbeExclusionCounter exclusion_counter = nullptr;
};

// One ResourceFetcher::DidLoadResourceFromMemoryCache, as Blink reports it.
// Every view is borrowed for the call; see protocol/native-network-v3.md.
struct NativeMemoryCacheReuse final {
  // A fresh renderer request ID, so the reuse is a Traffic row of its own.
  std::int32_t request_id = 0;
  NativeFetchOwner owner;
  std::string_view scheme;
  std::string_view host;
  // The URL's path and query: a prefix of target_length bytes.
  std::string_view target;
  std::size_t target_length = 0;
  int port = -1;
  // Blink ResourceType, 1 to 15 at the pin.
  std::uint8_t resource_type = 0;
  bool static_data = false;
  std::int32_t status_code = 0;
  std::int64_t decoded_body_length = 0;
};

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
                   NativeProbeFrameIdProvider frame_id_provider = nullptr,
                   NativeNetworkScope network_scope = {}) noexcept;
  // Called after acquiring the transport queue pointer. A successful check
  // authorizes an in-flight insertion into that retained mapping; Disable does
  // not wait for producers already past this admission check.
  [[nodiscard]] bool CanAdmitEvent(const NativeProbeEvent& event,
                                   std::uint64_t config_generation) const noexcept;
  [[nodiscard]] bool IsArtifactCaptureEnabled() const noexcept;
  // Whether this session opted in to retaining request and script content.
  [[nodiscard]] bool IsContentCaptureEnabled() const noexcept {
    return capture_request_content_.load(std::memory_order_relaxed);
  }
  [[nodiscard]] bool IsVmCaptureEnabled() const noexcept;
  [[nodiscard]] bool IsCanvasImageCaptureEnabled() const noexcept;
  // One atomic load while inactive, for loaders that must convert before
  // they can record.
  [[nodiscard]] bool IsCaptureArmed() const noexcept;
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
  // False once this thread has recorded the script in this configuration, so
  // an eval compilation cache hit costs one lookup and no string conversion.
  [[nodiscard]] bool CompiledScriptNeedsRecord(std::uint64_t execution_context_id,
                                               std::uint32_t script_id) const noexcept;
  void RecordCompiledScript(const NativeCompiledScript& script) noexcept;
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
  // Whether a function is the dispatcher of any configured site. V8's parent
  // walk treats an enclosing frame of such a function without identity as a
  // possible parent, so it reports an unresolved parent instead of none.
  [[nodiscard]] bool IsNativeWasmGuestDispatcherFunction(
      std::uint32_t function_index) const noexcept;
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
  // caller_observed is true only when the runtime walked this activation.
  // kind 0 with a nonzero index is refused rather than stored as a function.
  void RecordNativeWasmDispatch(std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::span<const std::uint8_t> module_bytes,
                                std::uint32_t function_index,
                                std::uint32_t module_byte_offset,
                                std::uint32_t selector,
                                std::uint32_t table_count,
                                std::uint64_t document_token_high,
                                std::uint64_t document_token_low,
                                std::uint8_t caller_kind = kWasmDirectCallerUnknown,
                                std::uint32_t caller_function_index = 0,
                                bool caller_observed = false) noexcept;
  // Physical call_indirect observations share the br_table admission rules
  // with their own emitter, 16-record budget and coalesced omission gaps. The
  // caller fills identity, site, slot and resolution; the sink fills the rest.
  void SetNativeWasmIndirectEmitter(NativeWasmIndirectEmitter emitter) noexcept;
  [[nodiscard]] bool IsNativeWasmIndirectEnabled() const noexcept;
  void RecordNativeWasmIndirect(NativeWasmIndirectObservation observation) noexcept;
  // Published by the next SetEmitters. Empty lists and zero caps keep the
  // historical 16-record stream budgets. Invalid policies are ignored.
  void SetNativeWasmSampleBudgetPolicy(const NativeWasmSampleBudgetPolicy& policy) noexcept;
  // Restarts both sample-index ranges and both overflow rings in this
  // configuration. It first publishes each stream's pending omitted count for
  // the epoch being closed, the same snapshot a configuration retirement
  // publishes. The next retained sample of each stream is index 0, and the
  // next overflow identity may reuse ring index 0. It does not change the
  // session, the emitters, the policy, or the capture generation, and it does
  // not invent a sample, a caller, or a parent edge.
  void ResetNativeWasmSampleBudgets() noexcept;
  // Coalesced once per configuration. A notice that arrives is kept after
  // sample budgets are exhausted. The admission predicate stays true past the
  // 16-record stream cap so a later execution can be named; it turns false
  // when the omitted counter saturates or the budget epoch is resetting. Not
  // an observation: no selector, offset, or function index is stored. False
  // means it was not retained and was not already retained, so the caller can
  // retry.
  bool NoteNativeWasmDispatchScope(NativeWasmScopeGap gap) noexcept;
  bool NoteNativeWasmIndirectScope(NativeWasmScopeGap gap) noexcept;
  // Host-visible Wasm call ledger. Entry and exit stay paired after the
  // 16-record outcome budget is spent; that budget only refuses records.
  // These never call the frame-id provider or allocate V8 handles.
  void SetNativeWasmExecutionEmitter(NativeWasmExecutionEmitter emitter) noexcept;
  [[nodiscard]] bool IsNativeWasmExecutionEnabled() const noexcept;
  // True when this call opened a new host-visible ledger entry. A nested
  // frame or an outermost tail callee returns false.
  bool NoteWasmHostCallEntered(bool outermost,
                               bool function_known,
                               std::uint32_t function_index) noexcept;
  void NoteWasmHostCallReturned() noexcept;
  void NoteWasmTailCall() noexcept;
  [[nodiscard]] NativeWasmExecutionHeartbeat PollWasmExecutionHeartbeat() noexcept;
  // Nanoseconds until this thread's open call should be forced into a stack
  // check, or kNativeWasmExecutionNoNudge when it has nothing pending.
  // A due deadline returns 50ms so a check that did not poll can try again.
  // No V8 handles.
  [[nodiscard]] std::uint64_t WasmExecutionNudgeDelayNs() const noexcept;
  // Asks V8 to enter the stack-guard runtime on the main isolate. Null
  // until the renderer installs it. The callback must not terminate the
  // isolate; the stack guard throws only when the poll returns interrupt.
  void SetNativeWasmExecutionNudge(NativeWasmExecutionNudge nudge) noexcept;
  // Any thread may set this for the current even configuration. The nudge,
  // when installed, runs after the store. A stack check with no open host
  // call leaves the request for a thread that has one. Replacing the
  // configuration clears it.
  void RequestWasmExecutionInterrupt() noexcept;
  // Closes the open host call. Unknown function or offset must be passed
  // with the known flag clear and the integer 0; a nonzero unknown is refused.
  void ReportWasmTrap(NativeWasmExecutionReason reason,
                      NativeWasmExecutionBounds bounds,
                      bool function_known,
                      std::uint32_t function_index,
                      bool offset_known,
                      std::uint32_t module_byte_offset,
                      std::uint64_t execution_context_id,
                      std::uint64_t frame_id,
                      std::string_view source_url,
                      std::uint64_t document_token_high,
                      std::uint64_t document_token_low,
                      std::span<const std::uint8_t> module_bytes) noexcept;
  // Native JavaScript dispatch at armed static sites. The browser keeps the
  // site list immutable for its lifetime; a different list is refused with an
  // input gap. Configure after SetEmitters, which disarms the previous list.
  void ConfigureNativeJsDispatch(std::span<const NativeJsDispatchSite> sites) noexcept;
  // The configuration generation while JS dispatch is configured for it and
  // the session is active with the VM category and unexpired; otherwise 0.
  // V8 pulls it and must not be re-entered: these never call the frame-id
  // provider, allocate or block.
  [[nodiscard]] std::uint64_t NativeJsDispatchEpoch() const noexcept;
  // Copies the armed sites for a still-current epoch; returns 0 otherwise.
  [[nodiscard]] std::size_t CopyNativeJsDispatchSites(
      std::uint64_t epoch,
      std::span<NativeJsDispatchSite> out) const noexcept;
  // False once the configuration's 256 samples or the slot's 64 are spent.
  [[nodiscard]] bool IsNativeJsDispatchEnabled(std::uint64_t epoch,
                                               std::uint32_t slot) const noexcept;
  // Assigns both sample indices and emits through the ordinary ring. The
  // payload must name the configured site of its slot exactly.
  void RecordNativeJsDispatch(std::uint64_t epoch,
                              std::uint64_t frame_id,
                              NativeJsDispatchObservationPayload payload) noexcept;
  void NoteNativeJsDispatchStatus(std::uint64_t epoch,
                                  std::uint32_t slot,
                                  NativeJsDispatchSiteStatus status) noexcept;
  void NoteNativeJsDispatchInputUnavailable(std::uint64_t epoch, std::uint64_t frame_id) noexcept;
  // Native JavaScript invocation identity, protocol/native-js-invocation-v1.md.
  // The site list follows the dispatch rules: immutable for the browser
  // lifetime, configured after SetEmitters, disarmed by the next one.
  // digests is the session's sensitive value-digest opt-in.
  void ConfigureNativeJsInvocation(std::span<const NativeJsInvocationSite> sites,
                                   bool digests) noexcept;
  // V8 pulls these on the isolate thread; none of them calls back into V8,
  // allocates or blocks.
  [[nodiscard]] std::uint64_t NativeJsInvocationEpoch() const noexcept;
  [[nodiscard]] std::size_t CopyNativeJsInvocationSites(
      std::uint64_t epoch,
      std::span<NativeJsInvocationSite> out) const noexcept;
  // False once the configuration's 256 starts or the slot's 64 are spent,
  // counting starts the renderer refused, so V8 stops wrapping calls there.
  [[nodiscard]] bool IsNativeJsInvocationEnabled(std::uint64_t epoch,
                                                 std::uint32_t slot) const noexcept;
  [[nodiscard]] bool NativeJsInvocationDigests(std::uint64_t epoch) const noexcept;
  // Assign sample indices and emit through the ordinary ring. A start must
  // name the configured site of its slot exactly; a settle carries a digest
  // only when the configuration enables digests. Only the settle of an
  // admitted start is recorded, and it closes that start even when its own
  // record is refused or dropped.
  void RecordNativeJsInvocationStart(std::uint64_t epoch,
                                     std::uint64_t frame_id,
                                     NativeJsInvocationStartPayload payload) noexcept;
  void RecordNativeJsInvocationSettle(std::uint64_t epoch,
                                      std::uint64_t frame_id,
                                      NativeJsInvocationSettlePayload payload) noexcept;
  void NoteNativeJsInvocationStatus(std::uint64_t epoch,
                                    std::uint32_t slot,
                                    NativeJsInvocationSiteStatus status) noexcept;
  // Blink refused a start V8 reported because its context is not a live
  // document; like any refused start it spends one of the 256.
  void NoteNativeJsInvocationInputUnavailable(std::uint64_t epoch, std::uint64_t frame_id) noexcept;
  // The settle of invocation_id could not be read because its document went
  // away; it still closes an admitted start.
  void NoteNativeJsInvocationSettleUnavailable(std::uint64_t epoch,
                                               std::uint64_t frame_id,
                                               std::uint32_t invocation_id) noexcept;
  // Blink's reader of the current V8 invocation, set once per renderer.
  void SetNativeJsInvocationContextProvider(NativeJsInvocationContextProvider provider) noexcept;
  // The context for a Wasm or guest record: state 0 (not observed) unless
  // invocation capture is active for the current configuration.
  [[nodiscard]] NativeJsInvocationContext CurrentNativeJsInvocation() const noexcept;
  // Called by the loader right after RecordRequestInitiated. Records only a
  // request started inside an invocation, or one started outside script while
  // an admitted invocation has not settled (unknown).
  void RecordNativeJsInvocationRequest(std::int32_t request_id) noexcept;
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
  // A browser-internal scheme is counted instead of recorded unless the
  // configuration opts in. The result is what the loader keeps to finish a
  // request the browser proxy never sees; see protocol/native-network-v3.md.
  [[nodiscard]] NativeRendererRequest RecordRequestInitiated(std::int32_t request_id,
                                                             std::string_view method,
                                                             std::string_view scheme,
                                                             std::string_view host) noexcept;
  // Only for AnsweredInRenderer() requests of the configuration that recorded
  // them: a content-mode request_target child, then request_completed or
  // request_failed. target starts the URL's path and query of target_length.
  void RecordRendererRequestComplete(const NativeRendererRequest& request,
                                     std::string_view target,
                                     std::size_t target_length,
                                     int port,
                                     std::int32_t error_code,
                                     std::int64_t encoded_data_length,
                                     std::int64_t decoded_body_length) noexcept;
  // A request content::ServiceWorkerSubresourceLoader ended itself
  // (NativeServiceWorkerEndsRequest): the renderer completion, with
  // from_service_worker, of the http(s) start this process recorded under
  // request_id; or a service_worker_end_lost gap naming that request when
  // another start of the same configuration took its slot. One atomic load
  // while inactive.
  void RecordServiceWorkerRequestEnd(std::int32_t request_id,
                                     std::string_view target,
                                     std::size_t target_length,
                                     int port,
                                     std::int32_t error_code) noexcept;
  // Charges one memory-cache reuse to the configuration's budget, after the
  // Network category, expiry and page checks, so the caller converts nothing
  // for a reuse it will not record. A reuse in a page that is not ordinary, or
  // past kNativeMemoryCacheReuseBudget, is counted as exclusion class 70
  // instead. Callers check IsCaptureArmed first.
  [[nodiscard]] NativeMemoryCacheAdmission AdmitMemoryCacheReuse(bool ordinary_page) noexcept;
  // One memory_cache_reuse record and, in content sessions, its target, into
  // the configuration that admitted it. A browser-internal URL is counted per
  // scheme class instead and returns its budget charge.
  void RecordMemoryCacheReuse(const NativeMemoryCacheAdmission& admission,
                              const NativeMemoryCacheReuse& reuse) noexcept;
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
  friend class base::NoDestructor<NativeProbeSink>;
  friend class NativeDebuggerWatch;
  friend class NativeRequestStackWalk;
  friend class NativeScriptCookieSink;
  NativeProbeSink() noexcept;

  [[nodiscard]] NativeProbeEmitStatus EmitStatus(const NativeProbeEvent& event,
                                                 std::uint64_t generation) const noexcept;
  // The fetch's own document or worker, or the running script's frame
  // (loader kind script_context) when no owner reached the loader.
  void NameRequestOwner(NativeProbeHeader& header, const NativeFetchOwner& owner) const noexcept;
  // The content-mode request_target child of a renderer row's start record.
  void EmitRendererTarget(const NativeRendererRequest& start,
                          std::string_view target_prefix,
                          std::size_t target_length,
                          int port,
                          std::uint64_t config_generation,
                          NativeRendererProbeEmitter emitter) noexcept;

  // Writes a gap into the renderer sequence slot a record already took but
  // could not deliver, so the broker sees an explicit omission there. A full
  // ring counts it as a drop like any other record.
  void FillSequenceGap(const NativeProbeHeader& source,
                       std::string_view reason,
                       std::uint64_t generation) noexcept;

  [[nodiscard]] bool ReserveCompiledScriptSource(std::uint64_t bytes) noexcept;
  std::uint64_t RecordRuntimeBufferEvent(
      NativeProbeType type,
      std::uint64_t frame_id,
      std::string_view reason,
      std::uint64_t generation,
      NativeProbeCategory category = NativeProbeCategory::kVm) noexcept;

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

  // Coalesced per budget epoch. A refused transport emit is not: it fills
  // the sequence slot its record took. A filter, per-function cap, per-site
  // cap, or the 16-record stream cap records an overflow identity and does
  // not stop the rest of the stream. The hook stays enabled until the omitted
  // counter saturates.
  enum class NativeWasmOmission : std::size_t {
    kInput,
    kBudget,
    kFiltered,
    kFunctionBudget,
    kSiteBudget
  };
  // kRecorded: this epoch's gap is already in the queue, or this call just
  // enqueued it. kBusy: another thread holds the in-flight claim. kRefused:
  // the emit was refused, or a newer budget epoch already owns the slot.
  // A refused emit already took one sequence, so the caller must not also
  // push an overflow identity for that execution.
  enum class NativeWasmGapClaim : std::uint8_t { kRecorded, kBusy, kRefused };
  NativeWasmGapClaim NoteNativeWasmDispatchOmission(const VmAdmission& admission,
                                                    NativeWasmOmission reason,
                                                    std::uint64_t budget_epoch) noexcept;
  // One admission's scope, not a mix of frames or threads. writing is 1 while
  // a thread owns the snapshot. scope_sequence is a seqlock: odd while fields
  // are changing, even once generation, budget epoch and the fields are one
  // snapshot. omitted is one word: the high 32 bits are the low 32 bits of
  // that admission's budget epoch, and the low 32 bits are the count. An
  // increment commits to that epoch. Installing a later scope stores a new
  // tag and count 0, so a late increment cannot join the next epoch. The tag
  // repeats only after 2^31 budget-epoch steps.
  struct NativeWasmOverflowAccount {
    std::atomic<std::uint64_t> writing{0};
    std::atomic<std::uint64_t> scope_sequence{0};
    std::atomic<std::uint64_t> generation{0};
    std::atomic<std::uint64_t> epoch{0};
    std::atomic<std::uint64_t> session_id{0};
    std::atomic<std::uint64_t> monotonic_time_ns{0};
    std::atomic<std::uint64_t> frame_id{0};
    std::atomic<std::uint32_t> process_id{0};
    std::atomic<std::uint32_t> thread_id{0};
    std::atomic<std::uint64_t> omitted{0};
  };
  enum class WasmOverflowStore : std::uint8_t { kStored, kRingFull, kRejected };
  void RememberNativeWasmOverflowScope(NativeWasmOverflowAccount& account,
                                       const VmAdmission& admission,
                                       std::uint64_t budget_epoch) noexcept;
  void NoteNativeWasmOverflowOmitted(NativeWasmOverflowAccount& account,
                                     const VmAdmission& admission,
                                     std::uint64_t budget_epoch,
                                     std::atomic<std::uint64_t>& capped) noexcept;
  void PublishNativeWasmOverflow(NativeWasmOverflowAccount& account, NativeProbeType type) noexcept;
  [[nodiscard]] WasmOverflowStore StoreNativeWasmDispatchOverflow(
      const VmAdmission& admission,
      std::uint64_t budget_epoch,
      const NativeWasmDispatchObservation& observation) noexcept;
  [[nodiscard]] WasmOverflowStore StoreNativeWasmIndirectOverflow(
      const VmAdmission& admission,
      std::uint64_t budget_epoch,
      const NativeWasmIndirectObservation& observation) noexcept;
  void RecordDispatchBudgetOverflow(const VmAdmission& admission,
                                    std::uint64_t budget_epoch,
                                    NativeWasmOmission reason,
                                    const NativeWasmDispatchObservation& observation) noexcept;
  void RecordIndirectBudgetOverflow(const VmAdmission& admission,
                                    std::uint64_t budget_epoch,
                                    NativeWasmOmission reason,
                                    const NativeWasmIndirectObservation& observation) noexcept;
  // Coalesced JS dispatch gaps: budget, site budget, transport, input, then
  // one compiled-before-arming reason per site slot.
  static constexpr std::size_t kNativeJsBudgetGap = 0, kNativeJsSiteBudgetGap = 1,
                               kNativeJsTransportGap = 2, kNativeJsInputGap = 3,
                               kNativeJsCompiledBeforeArmingGap = 4;
  [[nodiscard]] bool NativeJsDispatchActive(std::uint64_t generation) const noexcept;
  bool NoteNativeJsDispatchOmission(std::uint64_t generation,
                                    std::uint64_t frame_id,
                                    std::size_t gap) noexcept;
  // Written once before native_js_site_count_ is release-published and never
  // rewritten, so V8-thread readers need no lock.
  std::array<NativeJsDispatchSite, kNativeJsDispatchSiteLimit> native_js_sites_{};
  std::atomic<std::size_t> native_js_site_count_{0};
  std::atomic<std::uint64_t> native_js_generation_{0};
  // Generation-tagged claims, as for Wasm dispatch: a slot holding an older
  // generation is free for the current one.
  std::array<std::atomic<std::uint64_t>, kNativeJsDispatchSampleBudget> native_js_slots_{};
  std::array<std::array<std::atomic<std::uint64_t>, kNativeJsDispatchSiteSampleBudget>,
             kNativeJsDispatchSiteLimit>
      native_js_site_slots_{};
  std::atomic<std::uint64_t> native_js_capped_generation_{0};
  std::array<std::atomic<std::uint64_t>, kNativeJsDispatchSiteLimit>
      native_js_site_capped_generations_{};
  std::array<std::atomic<std::uint64_t>,
             kNativeJsCompiledBeforeArmingGap + kNativeJsDispatchSiteLimit>
      native_js_gap_generations_{};
  // Coalesced invocation gaps: budget, site budget, request budget,
  // transport, input, settle unavailable, then compiled-before-arming and
  // unsupported-function reasons per site slot.
  static constexpr std::size_t kInvocationBudgetGap = 0, kInvocationSiteBudgetGap = 1,
                               kInvocationRequestBudgetGap = 2, kInvocationTransportGap = 3,
                               kInvocationInputGap = 4, kInvocationSettleGap = 5,
                               kInvocationCompiledGap = 6,
                               kInvocationUnsupportedGap =
                                   kInvocationCompiledGap + kNativeJsInvocationSiteLimit,
                               kInvocationGapCount =
                                   kInvocationUnsupportedGap + kNativeJsInvocationSiteLimit;
  [[nodiscard]] bool NativeJsInvocationActive(std::uint64_t generation) const noexcept;
  // Returns whether the gap is retained. One the ring cannot take is held
  // until PublishNativeJsInvocationGaps retains it.
  bool NoteNativeJsInvocationOmission(std::uint64_t generation,
                                      std::uint64_t frame_id,
                                      std::size_t gap) noexcept;
  // Writes the held gaps of generation. Called before an invocation record
  // takes its sequence and before the configuration changes; one load while
  // nothing is held.
  void PublishNativeJsInvocationGaps(std::uint64_t generation) noexcept;
  // Closes the admitted start of invocation_id and returns its site slot;
  // false when no admitted start of this generation is open under that ID.
  bool CloseNativeJsInvocation(std::uint64_t generation,
                               std::uint32_t invocation_id,
                               std::uint8_t& site_slot) noexcept;
  // Written once before native_invocation_site_count_ is release-published
  // and never rewritten, as for dispatch sites.
  std::array<NativeJsInvocationSite, kNativeJsInvocationSiteLimit> native_invocation_sites_{};
  std::atomic<std::size_t> native_invocation_site_count_{0};
  std::atomic<std::uint64_t> native_invocation_generation_{0};
  std::atomic<std::uint64_t> native_invocation_digest_generation_{0};
  std::array<std::atomic<std::uint64_t>, kNativeJsInvocationSampleBudget>
      native_invocation_slots_{};
  std::array<std::array<std::atomic<std::uint64_t>, kNativeJsInvocationSiteSampleBudget>,
             kNativeJsInvocationSiteLimit>
      native_invocation_site_slots_{};
  std::array<std::atomic<std::uint64_t>, kNativeJsInvocationRequestBudget>
      native_invocation_request_slots_{};
  std::atomic<std::uint64_t> native_invocation_capped_generation_{0};
  std::array<std::atomic<std::uint64_t>, kNativeJsInvocationSiteLimit>
      native_invocation_site_capped_generations_{};
  std::atomic<std::uint64_t> native_invocation_request_capped_generation_{0};
  std::array<std::atomic<std::uint64_t>, kInvocationGapCount> native_invocation_gap_generations_{};
  // A cap stops admission whether or not its gap was retained, so a gap the
  // full ring refused is held: the latest generation that needs each gap, and
  // the generation with at least one held gap (generation - 1 once
  // published).
  std::array<std::atomic<std::uint64_t>, kInvocationGapCount> native_invocation_gap_wanted_{};
  std::atomic<std::uint64_t> native_invocation_gap_held_{0};
  // The admitted start holding each claimed sample index, as
  // (invocation ID << 8) | site slot, or 0 once settled. An entry counts only
  // while native_invocation_slots_ at its index holds the same generation, so
  // a replacement configuration never sees an older one's starts. The fixed
  // table bounds both the state and a settle's lookup to the 256 starts.
  std::array<std::atomic<std::uint64_t>, kNativeJsInvocationSampleBudget>
      native_invocation_open_starts_{};
  // The number of open entries above for the current configuration, so an
  // unattributable loader start is reported only while one may be open.
  std::atomic<std::uint64_t> native_invocation_open_generation_{0};
  std::atomic<std::int64_t> native_invocation_open_{0};
  std::atomic<NativeJsInvocationContextProvider> native_invocation_context_provider_{nullptr};
  std::atomic<NativeWasmDispatchEmitter> native_wasm_emitter_{nullptr};
  std::array<std::atomic<std::uint64_t>, kNativeWasmDispatchSampleBudget> native_wasm_slots_{};
  std::array<std::atomic<std::uint64_t>, 5> native_wasm_gap_epochs_{};
  // Saturation of the overflow omitted count, not the 16-observation cap and
  // not a per-function, per-module, or per-site refusal. The hook stays
  // enabled after those refusals so later executions can be named. A reset
  // advances the budget epoch, so a saturated epoch does not keep the next
  // one disabled.
  std::atomic<std::uint64_t> native_wasm_capped_epoch_{0};
  // Even values are stable. SetEmitters and Reset each advance it by two so
  // the next claimed sample slot and the next overflow ring slot start empty.
  // Odd is the in-flight reset.
  std::atomic<std::uint64_t> native_wasm_budget_epoch_{2};
  NativeWasmSampleBudgetPolicy native_wasm_budget_policy_{};
  NativeWasmSampleBudgetPolicy native_wasm_budget_policy_pending_{};
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots> native_wasm_function_keys_{};
  std::array<std::atomic<std::uint64_t>, kNativeWasmOverflowRingLimit>
      native_wasm_overflow_slots_{};
  NativeWasmOverflowAccount native_wasm_overflow_{};
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots>
      native_wasm_indirect_function_keys_{};
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots> native_wasm_indirect_site_keys_{};
  bool NoteNativeWasmScopeGap(bool call_indirect, NativeWasmScopeGap gap) noexcept;
  static constexpr std::size_t kNativeWasmScopeGapCount = 4;
  std::array<std::atomic<std::uint64_t>, kNativeWasmScopeGapCount>
      native_wasm_scope_gap_generations_{};
  std::array<std::atomic<std::uint64_t>, kNativeWasmScopeGapCount>
      native_wasm_indirect_scope_gap_generations_{};
  NativeWasmGapClaim NoteNativeWasmIndirectOmission(const VmAdmission& admission,
                                                    NativeWasmOmission reason,
                                                    std::uint64_t budget_epoch) noexcept;
  std::atomic<NativeWasmIndirectEmitter> native_wasm_indirect_emitter_{nullptr};
  std::array<std::atomic<std::uint64_t>, kNativeWasmIndirectSampleBudget>
      native_wasm_indirect_slots_{};
  std::array<std::atomic<std::uint64_t>, 5> native_wasm_indirect_gap_epochs_{};
  // Same saturation rule as native_wasm_capped_epoch_.
  std::atomic<std::uint64_t> native_wasm_indirect_capped_epoch_{0};
  std::array<std::atomic<std::uint64_t>, kNativeWasmOverflowRingLimit>
      native_wasm_indirect_overflow_slots_{};
  NativeWasmOverflowAccount native_wasm_indirect_overflow_{};
  [[nodiscard]] bool SnapshotWasmExecutionAdmission(VmAdmission& admission) const noexcept;
  bool NoteNativeWasmExecutionOmission(const VmAdmission& admission, std::size_t reason) noexcept;
  void NoteWasmInstrumentedSite(std::uint64_t generation,
                                std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                std::string_view source_url,
                                std::uint64_t document_token_high,
                                std::uint64_t document_token_low,
                                std::uint32_t function_index,
                                std::uint32_t module_byte_offset,
                                std::uint32_t sample_index,
                                NativeWasmExecutionStream stream,
                                std::uint8_t js_state,
                                std::uint32_t js_id) noexcept;
  bool EmitWasmExecution(NativeWasmExecutionKind kind,
                         NativeWasmExecutionReason reason,
                         NativeWasmExecutionBounds bounds,
                         bool function_known,
                         std::uint32_t function_index,
                         bool offset_known,
                         std::uint32_t module_byte_offset,
                         NativeWasmExecutionStream stream,
                         std::uint32_t related_sample,
                         std::uint64_t execution_context_id,
                         std::uint64_t frame_id,
                         std::string_view source_url,
                         std::uint64_t document_token_high,
                         std::uint64_t document_token_low,
                         std::uint8_t js_state,
                         std::uint32_t js_id,
                         std::span<const std::uint8_t> module_bytes) noexcept;
  std::atomic<NativeWasmExecutionEmitter> native_wasm_execution_emitter_{nullptr};
  std::atomic<NativeWasmExecutionNudge> native_wasm_execution_nudge_{nullptr};
  std::array<std::atomic<std::uint64_t>, kNativeWasmExecutionBudget> native_wasm_execution_slots_{};
  std::array<std::atomic<std::uint64_t>, 2> native_wasm_execution_gap_generations_{};
  std::atomic<std::uint64_t> native_wasm_execution_capped_generation_{0};
  // Configuration generation to interrupt, or 0 when no request is waiting.
  // A stack check consumes it only when that thread has an open host call
  // for the same generation.
  std::atomic<std::uint64_t> wasm_execution_interrupt_generation_{0};
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
  // The session's --reb-capture-request-content opt-in. It also decides
  // whether compiled script source no response body carries is retained.
  std::atomic<bool> capture_request_content_{false};
  std::atomic<bool> capture_browser_internal_{false};
  std::atomic<NativeProbeExclusionCounter> exclusion_counter_{nullptr};
  // memory_cache_reuse records admitted in this configuration, at most
  // kNativeMemoryCacheReuseBudget.
  std::atomic<std::uint32_t> memory_cache_reuses_{0};
  // Source bytes queued in this configuration, across every thread.
  std::atomic<std::uint64_t> compiled_script_source_bytes_{0};
  // Monotonic generation claims are never reset: an old capture cannot spend
  // or release a replacement configuration's snapshot quota.
  std::array<std::atomic<std::uint64_t>, kRuntimeTypedArrayMaxSnapshots>
      runtime_snapshot_generations_{};
  NativeVmDispatchBudget dispatch_sample_budget_;
  // Cumulative dispatch losses for the active capture. reported_ trails
  // dropped_ until a vm gap is admitted. Identity fields describe the losses
  // still waiting to be published. The counters are not reset: a generation
  // bump publishes the remainder first, then new losses append.
  // Known limitation: these are independent atomics, not one snapshot, so a
  // loss racing a publish can pair a count with another loss's identity. No
  // production probe records dispatch samples today.
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
  // these fields are consulted. Known limitation: like the page guest
  // opt-ins below, the flag is cleared by SetEmitters but not tagged with a
  // generation, so an Enable racing a reconfiguration can survive into it.
  // No production caller enables these samplers today.
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
  raw_ptr<const NativeWasmGuestAdapter> native_guest_retained_adapter_ = nullptr;
  std::atomic<const NativeWasmGuestAdapter*> native_guest_adapter_{nullptr};
  std::atomic<NativeGuestCaptureEmitter> native_guest_capture_{nullptr};
  std::atomic<NativeGuestHostEmitter> native_guest_host_{nullptr};
  std::atomic<NativeWasmGuestContextProvider> native_guest_context_{nullptr};
  std::atomic<NativeWasmGuestReset> native_guest_reset_{nullptr};
  std::array<std::atomic<std::uint64_t>, kNativeGuestSampleLimit> native_guest_slots_{};
  std::atomic<std::uint64_t> native_guest_capped_generation_{0};
  // Coalesced guest gaps, at most one of each per configuration.
  // A refused capture emit is not coalesced: it fills its own slots.
  static constexpr std::size_t kGuestSampleLimitGap = 0, kGuestInvocationLimitGap = 1,
                               kGuestSnapshotGap = 2, kGuestHostTransportGap = 3,
                               kGuestAdapterRestartGap = 4, kGuestRuntimeIdentityGap = 5,
                               kGuestModuleUnavailableGap = 6, kGuestHostParentBudgetGap = 7,
                               kGuestParentUnresolvedGap = 8, kGuestGapCount = 9;
  std::array<std::atomic<std::uint64_t>, kGuestGapCount> native_guest_gap_generations_{};
  // Parent-binding host routes claimed per configuration (see
  // kNativeGuestHostParentLimit). Same generation-tag scheme as samples.
  std::array<std::atomic<std::uint64_t>, kNativeGuestHostParentLimit> native_guest_host_slots_{};
  std::atomic<std::uint64_t> native_guest_host_capped_generation_{0};
  // Recent module verdicts, (token << 1) | accepted. Tokens are process-unique
  // renderer sequence numbers, so a stale verdict can never match a new send.
  // Each verdict answers one delivered capture and a configuration delivers
  // at most kNativeGuestSampleLimit, so its own verdicts all fit. next_ counts
  // writes: a binding that finds no verdict after a full ring of writes since
  // its send reads kLost, because its verdict may have been overwritten.
  std::array<std::atomic<std::uint64_t>, kNativeGuestSampleLimit> native_guest_module_status_{};
  std::atomic<std::uint64_t> native_guest_module_status_next_{0};
  enum class GuestModuleVerdict : std::uint8_t { kPending, kAccepted, kRejected, kLost };
  // writes_before_send is native_guest_module_status_next_ read before the
  // capture carrying token was sent.
  [[nodiscard]] GuestModuleVerdict NativeGuestModuleVerdict(
      std::uint64_t token,
      std::uint64_t writes_before_send) const noexcept;
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
