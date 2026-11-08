// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_OBSERVATION_BLINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_OBSERVATION_BLINK_H_

#include <cstdint>
#include <string_view>

#include "brave/components/reverse_engineering_browser/renderer/native_debugger_observation.h"
#include "brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "v8/include/v8-function.h"

// Blink-side helpers for protocol/native-debugger-observation-v1.md hooks.
namespace reb::debugger_observation {

// A document's frame id; 0 for a worker or worklet, which never matches.
inline std::uint64_t FrameId(const blink::ExecutionContext* context) {
  if (!context) {
    return 0;
  }
  const blink::ExecutionContextToken token = context->GetExecutionContextToken();
  if (!token.Is<blink::LocalFrameToken>()) {
    return 0;
  }
  const base::UnguessableToken& value = token.GetAs<blink::LocalFrameToken>().value();
  return NativeFrameIdOf(value.GetHighForSerialization(), value.GetLowForSerialization());
}

// Empty for a null or 16-bit string, which no ASCII rule names.
inline std::string_view Latin1(const blink::StringView& text) {
  if (text.IsNull() || !text.Is8Bit()) {
    return {};
  }
  const auto bytes = text.Span8();
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// Reads no property, so an object listener's handleEvent getter never runs.
inline NativeStackFrame FunctionFrame(const v8::Local<v8::Value> value) {
  if (value.IsEmpty() || !value->IsFunction()) {
    return {};
  }
  v8::Local<v8::Function> function = value.As<v8::Function>();
  for (int depth = 0; depth < 8; ++depth) {
    const v8::Local<v8::Value> target = function->GetBoundFunction();
    if (!target->IsFunction()) {
      break;
    }
    function = target.As<v8::Function>();
  }
  return NativeDebuggerWatch::FunctionFrame(function->ScriptId(),
                                            function->GetScriptStartPosition());
}

}  // namespace reb::debugger_observation

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_OBSERVATION_BLINK_H_
