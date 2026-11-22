// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_wasm_sample_budget.h"

#include "base/memory/raw_ptr.h"
#include "base/memory/raw_ref.h"
#include "base/memory/shared_memory_mapping.h"
#include "base/memory/unsafe_shared_memory_region.h"
#include "base/memory/weak_ptr.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/common/native_network_scope.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver.h"

namespace reb {

class NativeProbeQueue;
class NativeProbeSession;

class NativeProbeHost final : public mojom::NativeProbeHost {
 public:
  NativeProbeHost(NativeProbeSession& session, int renderer_process_id);
  NativeProbeHost(const NativeProbeHost&) = delete;
  NativeProbeHost& operator=(const NativeProbeHost&) = delete;
  ~NativeProbeHost() override;

  // The client the session requested on this renderer's IPC channel at
  // launch. Configures the renderer at once while a session is active.
  void BindClient(mojo::PendingAssociatedRemote<mojom::NativeProbeClient> client);
  // The renderer's own connection, which it opens once it runs.
  void BindReceiver(mojo::PendingReceiver<mojom::NativeProbeHost> receiver);

  // mojom::NativeProbeHost:
  void EventsAvailable() override;
  void CaptureWasmDispatch(std::uint64_t capture_epoch,
                           std::uint64_t session_id,
                           std::uint64_t sequence_number,
                           std::uint64_t monotonic_time_ns,
                           std::uint32_t process_id,
                           std::uint32_t thread_id,
                           std::uint64_t frame_id,
                           std::uint64_t execution_context_id,
                           std::uint64_t document_token_high,
                           std::uint64_t document_token_low,
                           std::uint32_t function_index,
                           std::uint32_t module_byte_offset,
                           std::uint32_t selector,
                           std::uint32_t table_count,
                           bool caller_observed,
                           std::uint8_t caller_kind,
                           std::uint32_t caller_function_index,
                           std::uint32_t sample_index,
                           std::uint8_t js_invocation_state,
                           std::uint32_t js_invocation_id,
                           const std::string& source_url,
                           std::uint64_t module_token,
                           mojo_base::BigBuffer content) override;
  void CaptureWasmIndirect(std::uint64_t capture_epoch,
                           std::uint64_t session_id,
                           std::uint64_t sequence_number,
                           std::uint64_t monotonic_time_ns,
                           std::uint32_t process_id,
                           std::uint32_t thread_id,
                           std::uint64_t frame_id,
                           std::uint64_t execution_context_id,
                           std::uint64_t document_token_high,
                           std::uint64_t document_token_low,
                           std::uint32_t function_index,
                           std::uint32_t module_byte_offset,
                           std::uint32_t table_index,
                           std::uint32_t slot,
                           std::uint32_t callee_function_index,
                           std::uint32_t resolution,
                           std::uint32_t sample_index,
                           std::uint8_t js_invocation_state,
                           std::uint32_t js_invocation_id,
                           const std::string& source_url,
                           std::uint64_t module_token,
                           mojo_base::BigBuffer content) override;
  void CaptureWasmExecution(std::uint64_t capture_epoch,
                            std::uint64_t session_id,
                            std::uint64_t sequence_number,
                            std::uint64_t monotonic_time_ns,
                            std::uint32_t process_id,
                            std::uint32_t thread_id,
                            std::uint64_t frame_id,
                            std::uint64_t execution_context_id,
                            std::uint64_t document_token_high,
                            std::uint64_t document_token_low,
                            std::uint32_t invocation_id,
                            std::uint32_t function_index,
                            std::uint32_t module_byte_offset,
                            std::uint32_t related_sample_index,
                            std::uint8_t kind,
                            std::uint8_t reason,
                            std::uint8_t bounds,
                            std::uint8_t known,
                            std::uint8_t related_stream,
                            std::uint8_t js_invocation_state,
                            std::uint32_t js_invocation_id,
                            const std::string& source_url,
                            std::uint64_t module_token,
                            mojo_base::BigBuffer content) override;
  void CaptureNativeGuest(std::uint64_t capture_epoch,
                          const std::vector<std::uint8_t>& invocation_record,
                          const std::vector<std::uint8_t>& dispatch_record,
                          std::uint64_t execution_context_id,
                          std::uint64_t document_token_high,
                          std::uint64_t document_token_low,
                          const std::string& source_url,
                          const std::string& adapter_json,
                          mojo_base::BigBuffer wasm_module,
                          mojo_base::BigBuffer bytecode) override;
  void CaptureNativeGuestHost(std::uint64_t capture_epoch,
                              const std::vector<std::uint8_t>& event_record) override;
  void CaptureRendererTarget(const std::vector<std::uint8_t>& event_record,
                             const std::string& origin,
                             const std::string& target) override;
  void CaptureGeneratedArtifact(std::uint16_t kind,
                                std::uint16_t capture_origin,
                                std::uint64_t creator_event_id,
                                std::uint64_t execution_context_id,
                                std::uint64_t frame_id,
                                const std::string& source_url,
                                mojo_base::BigBuffer content,
                                std::uint64_t allocating_script_id,
                                bool allocating_script_is_eval,
                                mojo_base::BigBuffer allocating_script_source,
                                std::uint64_t allocating_script_session_id,
                                std::uint64_t credit_bytes) override;

  void Configure(std::uint64_t session_id,
                 std::uint64_t category_mask,
                 std::uint64_t expires_at_monotonic_ns,
                 bool capture_canvas_images,
                 bool capture_request_content);
  void Disable();
  // Zeros this renderer's window counts and asks the renderer to start a new
  // sample window. The queue, capture epoch and module bindings stay.
  void ResetWasmSampleBudgets();
  // A revision of the session's invocation site records, for a configured
  // renderer; one configured later receives it in Configure.
  void UpdateJsInvocationSites(const std::vector<std::uint8_t>& records);
  // Sends the session's kept debugger watch scope, or its absence.
  void SendDebuggerWatchScope();

 private:
  void Drain();
  // WebUI bindings can be granted after the renderer bound.
  [[nodiscard]] std::uint32_t RendererOsPid();
  [[nodiscard]] bool IsBrowserInternal();
  void ReportExclusions();
  [[nodiscard]] std::uint32_t FrameTab(const std::unordered_map<std::uint64_t, std::uint32_t>& live,
                                       std::uint64_t frame_id) const;
  [[nodiscard]] static bool IsWorkerRequestStart(const NativeProbeEvent& event);
  void ReportUnsharedDecisions();
  [[nodiscard]] bool IsExcludedRequestRecord(const NativeProbeEvent& event) const;
  void EmitWorkerRequest(NativeProbeEvent& event);
  // Reports the browser verdict for module bytes sent with the guest dispatch
  // whose sequence number is module_token, if that configuration is current.
  void SendNativeStackArtifactRefused(std::uint64_t creator_event_id);
  void SendReleaseArtifactCredit(std::uint64_t bytes);
  void SendNativeGuestModuleStatus(std::uint64_t capture_epoch,
                                   std::uint64_t module_token,
                                   bool accepted);
  // Starts this host's next window once the current one is
  // kNativeWasmSampleWindowNs old.
  void AdvanceWasmWindow(std::uint64_t now);
  // A record's module: a private copy of the bytes it carried, the module an
  // earlier record of the same document bound to module_token, or unknown
  // for an empty record without a token. Nullopt refuses the record.
  [[nodiscard]] std::optional<NativeWasmModuleTransfer> ResolveWasmModule(
      std::uint64_t module_token,
      mojo_base::BigBuffer& content,
      std::uint64_t frame_id,
      std::uint64_t execution_context_id,
      std::uint64_t document_token_high,
      std::uint64_t document_token_low) const;
  // Lets this renderer's later records name the bytes this accepted record
  // carried by its sequence number.
  void BindWasmModule(std::uint64_t token,
                      const NativeWasmModuleTransfer& module,
                      std::uint64_t frame_id,
                      std::uint64_t execution_context_id,
                      std::uint64_t document_token_high,
                      std::uint64_t document_token_low);

  const raw_ref<NativeProbeSession> session_;
  const int renderer_process_id_;
  mojo::AssociatedRemote<mojom::NativeProbeClient> client_;
  mojo::Receiver<mojom::NativeProbeHost> receiver_{this};
  base::UnsafeSharedMemoryRegion queue_region_;
  base::WritableSharedMemoryMapping queue_mapping_;
  raw_ptr<NativeProbeQueue> queue_ = nullptr;
  std::uint64_t reported_dropped_events_ = 0;
  std::array<std::uint64_t, kNativeRendererExclusionSlots> reported_exclusions_{};
  std::uint32_t renderer_os_pid_ = 0;
  // Requests of extension workers and of service workers no page used; their
  // later renderer records are dropped too.
  std::array<std::uint64_t, 64> excluded_requests_{};
  std::size_t excluded_next_ = 0;
  std::uint64_t extension_requests_excluded_ = 0;
  std::uint64_t no_page_requests_excluded_ = 0;
  bool browser_internal_ = false;
  bool disabling_ = false;
  std::uint64_t wasm_capture_epoch_ = 0;
  // Records of each Wasm stream this renderer delivered in the host's current
  // window. The renderer paces itself; this bound only stops one that does
  // not. Host windows are not the renderer's, so one overlaps at most two of
  // them, and the limit is twice the renderer's budget.
  static constexpr std::uint32_t kWasmBrowserWindowLimit = 2 * kNativeWasmDispatchSampleBudget;
  static_assert(kNativeWasmIndirectSampleBudget == kNativeWasmDispatchSampleBudget &&
                kNativeWasmExecutionBudget == kNativeWasmDispatchSampleBudget);
  std::uint64_t wasm_window_started_ns_ = 0;
  std::uint32_t wasm_capture_count_ = 0;
  std::uint32_t wasm_indirect_capture_count_ = 0;
  std::uint32_t wasm_execution_capture_count_ = 0;
  // The modules this renderer's accepted records carried, by token, so a later
  // record of the same document can name one. The newest
  // kWasmModuleBindingLimit stay; a renderer thread sends each module again
  // every window.
  struct WasmModuleBinding final {
    std::uint64_t frame_id = 0;
    std::uint64_t execution_context_id = 0;
    std::uint64_t document_token_high = 0;
    std::uint64_t document_token_low = 0;
    std::size_t size = 0;
    std::array<std::uint8_t, 32> digest{};
  };
  static constexpr std::size_t kWasmModuleBindingLimit = 256;
  std::map<std::uint64_t, WasmModuleBinding> wasm_modules_;
  std::uint32_t guest_capture_count_ = 0;
  // One marker for host records naming another identity, whose sequence
  // slots are not this renderer's to fill. Every other refusal fills its own.
  bool guest_host_malformed_gap_emitted_ = false;
  std::shared_ptr<const std::uint64_t> wasm_epoch_lifetime_;
  base::WeakPtrFactory<NativeProbeHost> weak_factory_{this};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_
