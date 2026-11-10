// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "brave/components/reverse_engineering_browser/common/native_wasm_sample_budget.h"

#include "base/memory/raw_ptr.h"
#include "base/memory/raw_ref.h"
#include "base/memory/shared_memory_mapping.h"
#include "base/memory/unsafe_shared_memory_region.h"
#include "base/memory/weak_ptr.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "mojo/public/cpp/bindings/remote.h"

namespace reb {

class NativeProbeQueue;
class NativeProbeSession;

class NativeProbeHost final : public mojom::NativeProbeHost {
 public:
  NativeProbeHost(NativeProbeSession& session, int renderer_process_id);
  NativeProbeHost(const NativeProbeHost&) = delete;
  NativeProbeHost& operator=(const NativeProbeHost&) = delete;
  ~NativeProbeHost() override;

  // mojom::NativeProbeHost:
  void BindClient(mojo::PendingRemote<mojom::NativeProbeClient> client) override;
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
                                std::uint64_t allocating_script_session_id) override;

  void Configure(std::uint64_t session_id,
                 std::uint64_t category_mask,
                 std::uint64_t expires_at_monotonic_ns,
                 bool capture_canvas_images,
                 bool capture_request_content);
  void Disable();
  // Zeros this renderer's stream counters and asks the renderer to restart
  // sample indexes. The queue and capture epoch stay.
  void ResetWasmSampleBudgets();

 private:
  void Drain();
  // Reports the browser verdict for module bytes sent with the guest dispatch
  // whose sequence number is module_token, if that configuration is current.
  void SendNativeGuestModuleStatus(std::uint64_t capture_epoch,
                                   std::uint64_t module_token,
                                   bool accepted);

  const raw_ref<NativeProbeSession> session_;
  const int renderer_process_id_;
  mojo::Remote<mojom::NativeProbeClient> client_;
  base::UnsafeSharedMemoryRegion queue_region_;
  base::WritableSharedMemoryMapping queue_mapping_;
  raw_ptr<NativeProbeQueue> queue_ = nullptr;
  std::uint64_t reported_dropped_events_ = 0;
  std::uint64_t wasm_capture_epoch_ = 0;
  std::uint32_t wasm_capture_count_ = 0;
  std::uint32_t wasm_indirect_capture_count_ = 0;
  std::uint64_t wasm_budget_epoch_ = 2;
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots> wasm_dispatch_function_keys_{};
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots> wasm_indirect_function_keys_{};
  std::array<NativeWasmBudgetKeySlot, kNativeWasmBudgetKeySlots> wasm_indirect_site_keys_{};
  std::uint32_t wasm_execution_capture_count_ = 0;
  std::uint32_t guest_capture_count_ = 0;
  // One marker for host records naming another identity, whose sequence
  // slots are not this renderer's to fill. Every other refusal fills its own.
  bool guest_host_malformed_gap_emitted_ = false;
  std::shared_ptr<const std::uint64_t> wasm_epoch_lifetime_;
  base::WeakPtrFactory<NativeProbeHost> weak_factory_{this};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_HOST_H_
