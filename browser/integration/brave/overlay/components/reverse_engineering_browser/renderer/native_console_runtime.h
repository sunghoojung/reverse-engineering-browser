// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_RUNTIME_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_RUNTIME_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "base/functional/callback_helpers.h"
#include "base/timer/timer.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/common/native_console_messages.h"
#include "third_party/blink/public/web/web_element.h"
#include "v8/include/v8.h"

namespace blink {
class WebLocalFrame;
}

namespace reb {

// Renderer-thread only. Each slot holds one value for at most 60 seconds.
// Monotonic handles never alias an evicted value or a replacement document.
class NativeConsoleRuntime final {
 public:
  NativeConsoleRuntime();
  ~NativeConsoleRuntime();
  void Reset();
  void Message(const std::string& text,
               const std::string& source,
               const std::string& stack,
               unsigned line,
               int level,
               bool truncated = false);
  std::string Run(v8::Isolate* isolate,
                  v8::Local<v8::Context> context,
                  blink::WebLocalFrame* frame,
                  const std::string& command);

 private:
  struct Slot {
    std::uint64_t id = 0;
    std::int64_t expires_us = 0;
    v8::Global<v8::Value> value;
  };
  void Expire();
  struct Monitor {
    blink::WebElement element;
    std::int64_t expires_us;
    std::vector<base::ScopedClosureRunner> removals;
  };
  std::vector<Monitor> monitors_;
  base::RepeatingTimer expiration_;
  std::uint64_t Retain(v8::Isolate* isolate, v8::Local<v8::Value> value);
  v8::Local<v8::Value> Lookup(v8::Isolate* isolate, const std::string& handle);
  base::DictValue Value(v8::Isolate* isolate,
                        v8::Local<v8::Context> context,
                        v8::Local<v8::Value> value);
  base::DictValue Properties(v8::Isolate* isolate,
                             v8::Local<v8::Context> context,
                             v8::Local<v8::Value> value,
                             int offset);
  base::DictValue Complete(v8::Isolate* isolate,
                           v8::Local<v8::Context> context,
                           const base::DictValue& command);
  std::array<Slot, 128> slots_;
  std::size_t next_slot_ = 0;
  std::uint64_t next_handle_ = 1;
  std::uint64_t last_ = 0;
  unsigned next_temp_ = 1;
  NativeConsoleMessages messages_;
};

}  // namespace reb
#endif
