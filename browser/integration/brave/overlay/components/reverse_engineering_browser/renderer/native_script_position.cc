// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_script_position.h"

#include "v8/include/v8-debug.h"
#include "v8/include/v8-isolate.h"
#include "v8/include/v8-local-handle.h"

namespace reb {

bool CurrentNativeScriptFrame(NativeScriptFrame& frame) noexcept {
  v8::Isolate* const isolate = v8::Isolate::TryGetCurrent();
  if (!isolate || !isolate->InContext()) {
    return false;
  }
  v8::HandleScope scope(isolate);
  const v8::Local<v8::StackTrace> trace = v8::StackTrace::CurrentStackTrace(
      isolate, 1,
      static_cast<v8::StackTrace::StackTraceOptions>(v8::StackTrace::kScriptId |
                                                     v8::StackTrace::kIsConstructor));
  if (trace.IsEmpty() || trace->GetFrameCount() < 1) {
    return false;
  }
  const v8::Local<v8::StackFrame> top = trace->GetFrame(isolate, 0);
  const int script_id = top->GetScriptId();
  const int position = top->GetSourcePosition();
  if (script_id <= 0 || position < 0) {
    return false;
  }
  frame.kind = top->IsWasm() ? 2 : 1;
  frame.flags = top->IsConstructor() ? 1 : 0;
  frame.script_id = static_cast<std::uint32_t>(script_id);
  frame.position = static_cast<std::uint32_t>(position);
  frame.function_start = 0;
  return true;
}

}  // namespace reb
