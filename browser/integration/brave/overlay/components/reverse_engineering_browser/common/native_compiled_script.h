// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_COMPILED_SCRIPT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_COMPILED_SCRIPT_H_
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
namespace reb {

// Values match v8::CompiledScriptKind.
enum class NativeCompiledScriptKind : std::uint8_t {
  kScript = 1,
  kModule = 2,
  kFunction = 3,
  kEval = 4,
  kFunctionConstructor = 5,
};

// What happened to the source. Every compiled script gets exactly one.
enum class NativeCompiledScriptRetention : std::uint8_t {
  kQueued = 1,
  kDuplicate = 2,
  kNetworkFetched = 3,
  kNotPermitted = 4,
  kBudgetSpent = 5,
  kTooLarge = 6,
  kUnavailable = 7,
};

// Unique source bytes one renderer may queue in one configuration. Identical
// sources count once, so this bounds distinct generated code.
inline constexpr std::uint64_t kNativeCompiledScriptSourceBudget = 64ULL * 1024ULL * 1024ULL;

// Transient views: the sink copies what it keeps before returning.
struct NativeCompiledScript final {
  NativeCompiledScriptKind kind = NativeCompiledScriptKind::kScript;
  std::uint32_t script_id = 0;
  std::uint32_t start_line = 0;
  std::uint32_t start_column = 0;
  std::uint32_t creator_script_id = 0;
  std::uint32_t creator_position = 0;
  std::uint64_t execution_context_id = 0;
  std::uint64_t frame_id = 0;
  // Empty when V8 has no name for the script.
  std::string_view script_url;
  std::string_view context_url;
  bool is_document = false;
  // UTF-8 length. source is empty when the text is over the artifact limit or
  // could not be converted.
  std::uint64_t source_length = 0;
  std::span<const std::uint8_t> source;
};

// True when no response body carries this source, so nothing else can retain
// it. A document's inline scripts carry the document's URL. A worker's entry
// script also carries its context's URL, but it was fetched.
[[nodiscard]] inline bool NativeCompiledScriptSkipsNetwork(
    const NativeCompiledScript& script) noexcept {
  if (script.kind == NativeCompiledScriptKind::kEval ||
      script.kind == NativeCompiledScriptKind::kFunctionConstructor || script.script_url.empty() ||
      (script.is_document && script.script_url == script.context_url)) {
    return true;
  }
  return script.script_url.starts_with("blob:") || script.script_url.starts_with("data:") ||
         script.script_url.starts_with("about:");
}

struct NativeCompiledScriptPayload final {
  NativeCompiledScriptKind kind = NativeCompiledScriptKind::kScript;
  NativeCompiledScriptRetention retention = NativeCompiledScriptRetention::kUnavailable;
  std::uint32_t script_id = 0;
  std::uint32_t start_line = 0;
  std::uint32_t start_column = 0;
  std::uint32_t creator_script_id = 0;
  std::uint64_t execution_context_id = 0;
  std::uint64_t source_length = 0;
  std::array<std::uint8_t, 32> source_sha256{};
  std::uint32_t creator_position = 0;
};

[[nodiscard]] inline std::array<std::byte, 128> EncodeNativeCompiledScriptPayload(
    const NativeCompiledScriptPayload& value) noexcept {
  std::array<std::byte, 128> out{};
  const auto put = [&out](std::size_t offset, std::uint64_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
      out[offset + i] = static_cast<std::byte>((v >> (8U * i)) & 255U);
  };
  put(0, 1, 2);
  put(2, 128, 2);
  put(4, static_cast<std::uint8_t>(value.kind), 1);
  put(5, static_cast<std::uint8_t>(value.retention), 1);
  put(8, value.script_id, 4);
  put(12, value.start_line, 4);
  put(16, value.start_column, 4);
  put(20, value.creator_script_id, 4);
  put(24, value.execution_context_id, 8);
  put(32, value.source_length, 8);
  for (std::size_t i = 0; i < value.source_sha256.size(); ++i)
    out[40 + i] = static_cast<std::byte>(value.source_sha256[i]);
  put(72, value.creator_position, 4);
  return out;
}

}  // namespace reb
#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_COMPILED_SCRIPT_H_
