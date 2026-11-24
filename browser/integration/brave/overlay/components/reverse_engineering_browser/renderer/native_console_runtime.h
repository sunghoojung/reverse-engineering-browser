// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_RUNTIME_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_RUNTIME_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "base/functional/callback_helpers.h"
#include "base/unguessable_token.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/common/native_console_messages.h"
#include "third_party/blink/public/web/web_element.h"
#include "v8/include/v8.h"

namespace blink {
class WebLocalFrame;
}

namespace reb {

// Renderer-thread only. A retained value stays until it is released, the
// transcript is cleared, or its document's main-world context goes away, as a
// DevTools object group does; event monitors stay until unmonitorEvents or
// that same document change. Monotonic handles never alias a released value
// or a replacement document.
class NativeConsoleRuntime final {
 public:
  NativeConsoleRuntime();
  ~NativeConsoleRuntime();
  void Reset();
  // Queues one page message, every field whole.
  void Message(std::string text, std::string source, std::string stack, unsigned line, int level);
  std::string Run(v8::Isolate* isolate,
                  v8::Local<v8::Context> context,
                  blink::WebLocalFrame* frame,
                  const std::string& command);
  // Disarms the rules the Console armed on this document,
  // protocol/native-debugger-observation-v1.md.
  void Unwatch();
  // The frame's main-world context exists for a new document, before any of
  // its own scripts: arms the kept watch scope when it names this document's
  // origin and frame kind. Without a kept scope this reads two tokens and
  // stores them.
  void DocumentStarted(v8::Isolate* isolate, blink::WebLocalFrame* frame);
  // Blink cleared the window object. When the commit kept the existing context
  // for a new document, that document starts here instead.
  void WindowCleared(v8::Isolate* isolate, blink::WebLocalFrame* frame);
  // The document's main-world context is going away: nothing stays armed on it.
  void DocumentEnded();

 private:
  struct Retained {
    bool repl = false;
    v8::Global<v8::Value> value;
  };
  struct Monitor {
    blink::WebElement element;
    std::vector<base::ScopedClosureRunner> removals;
  };
  std::vector<Monitor> monitors_;
  std::uint64_t Retain(v8::Isolate* isolate, v8::Local<v8::Value> value, bool repl = false);
  v8::Local<v8::Value> Lookup(v8::Isolate* isolate,
                              const std::string& handle,
                              bool* repl = nullptr);
  base::DictValue Value(v8::Isolate* isolate,
                        v8::Local<v8::Context> context,
                        v8::Local<v8::Value> value,
                        bool repl = false);
  base::DictValue Properties(v8::Isolate* isolate,
                             v8::Local<v8::Context> context,
                             v8::Local<v8::Value> value,
                             std::uint64_t offset);
  base::DictValue Complete(v8::Isolate* isolate,
                           v8::Local<v8::Context> context,
                           const base::DictValue& command);
  base::DictValue Watch(v8::Isolate* isolate,
                        blink::WebLocalFrame* frame,
                        const base::DictValue& command);
  // The frame the Console's own watch arm holds, or 0.
  std::uint64_t watch_frame_ = 0;
  // The frame and document whose start was last decided.
  std::uint64_t frame_id_ = 0;
  base::UnguessableToken document_;
  // Keyed by handle. Handles only grow, so lookups never see a reused one.
  std::map<std::uint64_t, Retained> retained_;
  std::uint64_t next_handle_ = 1;
  std::uint64_t last_ = 0;
  std::uint64_t next_temp_ = 1;
  NativeConsoleMessages messages_;
};

}  // namespace reb
#endif
