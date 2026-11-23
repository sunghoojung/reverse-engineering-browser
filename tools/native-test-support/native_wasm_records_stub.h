// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-ins for the Wasm record structs and union that
// CaptureWasmRecords carries (native_probe_transport.mojom), shared by the
// renderer transport and browser host harnesses under tools/. Include it after
// the harness's mojo_base::BigBuffer.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_NATIVE_WASM_RECORDS_STUB_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_NATIVE_WASM_RECORDS_STUB_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace reb::mojom {
// The record structs and union of native_probe_transport.mojom, shaped as
// the generated bindings shape them: New takes each field by its type.
struct NativeWasmDispatchRecord {
  static std::unique_ptr<NativeWasmDispatchRecord> New(std::uint64_t session_id,
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
                                                       std::string source_url,
                                                       std::uint64_t module_token,
                                                       mojo_base::BigBuffer content) {
    return std::unique_ptr<NativeWasmDispatchRecord>(
        new NativeWasmDispatchRecord{session_id,
                                     sequence_number,
                                     monotonic_time_ns,
                                     process_id,
                                     thread_id,
                                     frame_id,
                                     execution_context_id,
                                     document_token_high,
                                     document_token_low,
                                     function_index,
                                     module_byte_offset,
                                     selector,
                                     table_count,
                                     caller_observed,
                                     caller_kind,
                                     caller_function_index,
                                     sample_index,
                                     js_invocation_state,
                                     js_invocation_id,
                                     std::move(source_url),
                                     module_token,
                                     std::move(content)});
  }
  std::uint64_t session_id;
  std::uint64_t sequence_number;
  std::uint64_t monotonic_time_ns;
  std::uint32_t process_id;
  std::uint32_t thread_id;
  std::uint64_t frame_id;
  std::uint64_t execution_context_id;
  std::uint64_t document_token_high;
  std::uint64_t document_token_low;
  std::uint32_t function_index;
  std::uint32_t module_byte_offset;
  std::uint32_t selector;
  std::uint32_t table_count;
  bool caller_observed;
  std::uint8_t caller_kind;
  std::uint32_t caller_function_index;
  std::uint32_t sample_index;
  std::uint8_t js_invocation_state;
  std::uint32_t js_invocation_id;
  std::string source_url;
  std::uint64_t module_token;
  mojo_base::BigBuffer content;
};
struct NativeWasmIndirectRecord {
  static std::unique_ptr<NativeWasmIndirectRecord> New(std::uint64_t session_id,
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
                                                       std::string source_url,
                                                       std::uint64_t module_token,
                                                       mojo_base::BigBuffer content) {
    return std::unique_ptr<NativeWasmIndirectRecord>(
        new NativeWasmIndirectRecord{session_id,
                                     sequence_number,
                                     monotonic_time_ns,
                                     process_id,
                                     thread_id,
                                     frame_id,
                                     execution_context_id,
                                     document_token_high,
                                     document_token_low,
                                     function_index,
                                     module_byte_offset,
                                     table_index,
                                     slot,
                                     callee_function_index,
                                     resolution,
                                     sample_index,
                                     js_invocation_state,
                                     js_invocation_id,
                                     std::move(source_url),
                                     module_token,
                                     std::move(content)});
  }
  std::uint64_t session_id;
  std::uint64_t sequence_number;
  std::uint64_t monotonic_time_ns;
  std::uint32_t process_id;
  std::uint32_t thread_id;
  std::uint64_t frame_id;
  std::uint64_t execution_context_id;
  std::uint64_t document_token_high;
  std::uint64_t document_token_low;
  std::uint32_t function_index;
  std::uint32_t module_byte_offset;
  std::uint32_t table_index;
  std::uint32_t slot;
  std::uint32_t callee_function_index;
  std::uint32_t resolution;
  std::uint32_t sample_index;
  std::uint8_t js_invocation_state;
  std::uint32_t js_invocation_id;
  std::string source_url;
  std::uint64_t module_token;
  mojo_base::BigBuffer content;
};
struct NativeWasmExecutionRecord {
  static std::unique_ptr<NativeWasmExecutionRecord> New(std::uint64_t session_id,
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
                                                        std::string source_url,
                                                        std::uint64_t module_token,
                                                        mojo_base::BigBuffer content) {
    return std::unique_ptr<NativeWasmExecutionRecord>(
        new NativeWasmExecutionRecord{session_id,
                                      sequence_number,
                                      monotonic_time_ns,
                                      process_id,
                                      thread_id,
                                      frame_id,
                                      execution_context_id,
                                      document_token_high,
                                      document_token_low,
                                      invocation_id,
                                      function_index,
                                      module_byte_offset,
                                      related_sample_index,
                                      kind,
                                      reason,
                                      bounds,
                                      known,
                                      related_stream,
                                      js_invocation_state,
                                      js_invocation_id,
                                      std::move(source_url),
                                      module_token,
                                      std::move(content)});
  }
  std::uint64_t session_id;
  std::uint64_t sequence_number;
  std::uint64_t monotonic_time_ns;
  std::uint32_t process_id;
  std::uint32_t thread_id;
  std::uint64_t frame_id;
  std::uint64_t execution_context_id;
  std::uint64_t document_token_high;
  std::uint64_t document_token_low;
  std::uint32_t invocation_id;
  std::uint32_t function_index;
  std::uint32_t module_byte_offset;
  std::uint32_t related_sample_index;
  std::uint8_t kind;
  std::uint8_t reason;
  std::uint8_t bounds;
  std::uint8_t known;
  std::uint8_t related_stream;
  std::uint8_t js_invocation_state;
  std::uint32_t js_invocation_id;
  std::string source_url;
  std::uint64_t module_token;
  mojo_base::BigBuffer content;
};
class NativeWasmRecord {
 public:
  enum class Tag { kDispatch, kIndirect, kExecution };
  static std::unique_ptr<NativeWasmRecord> NewDispatch(
      std::unique_ptr<NativeWasmDispatchRecord> value) {
    auto record = std::make_unique<NativeWasmRecord>();
    record->tag_ = Tag::kDispatch;
    record->dispatch_ = std::move(value);
    return record;
  }
  static std::unique_ptr<NativeWasmRecord> NewIndirect(
      std::unique_ptr<NativeWasmIndirectRecord> value) {
    auto record = std::make_unique<NativeWasmRecord>();
    record->tag_ = Tag::kIndirect;
    record->indirect_ = std::move(value);
    return record;
  }
  static std::unique_ptr<NativeWasmRecord> NewExecution(
      std::unique_ptr<NativeWasmExecutionRecord> value) {
    auto record = std::make_unique<NativeWasmRecord>();
    record->tag_ = Tag::kExecution;
    record->execution_ = std::move(value);
    return record;
  }
  Tag which() const { return tag_; }
  std::unique_ptr<NativeWasmDispatchRecord>& get_dispatch() { return dispatch_; }
  std::unique_ptr<NativeWasmIndirectRecord>& get_indirect() { return indirect_; }
  std::unique_ptr<NativeWasmExecutionRecord>& get_execution() { return execution_; }

 private:
  Tag tag_ = Tag::kDispatch;
  std::unique_ptr<NativeWasmDispatchRecord> dispatch_;
  std::unique_ptr<NativeWasmIndirectRecord> indirect_;
  std::unique_ptr<NativeWasmExecutionRecord> execution_;
};
using NativeWasmRecordPtr = std::unique_ptr<NativeWasmRecord>;
}  // namespace reb::mojom

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_NATIVE_WASM_RECORDS_STUB_H_
