// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_EXECUTION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_EXECUTION_H_

#include <cstdint>

#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "base/synchronization/lock.h"
#include "brave/components/reverse_engineering_browser/common/native_console.mojom.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "v8/include/v8.h"

namespace reb {

// The page JavaScript the Console runs on the renderer main thread, so a Stop
// that arrives on the IO thread can end it. Nothing here has a time budget: an
// explicit command and a document-start injection both run until they return
// or their owner sends Stop.
//
// The lock ensures a late Stop can never terminate a later page task or touch
// an isolate after this execution released it. No V8 handles cross threads,
// and TerminateExecution is explicitly safe to call from another thread.
//
// Executions nest only synchronously, when a command or an injection creates a
// frame whose new document runs an injection. The outermost execution names
// what Stop ends; terminating it unwinds the whole stack, nested ones included.
class NativeConsoleExecution final {
 public:
  enum class End { kReturned, kStopped };

  static NativeConsoleExecution& Get();

  NativeConsoleExecution(const NativeConsoleExecution&) = delete;
  NativeConsoleExecution& operator=(const NativeConsoleExecution&) = delete;

  // Renderer main thread. `stop_id` is a command's request id, or an
  // injection's script id with kNativeConsoleDocumentStartStopBit set; it is
  // ignored for a nested execution. Every Begin is paired with one Finish.
  void Begin(v8::Isolate* isolate, std::uint64_t stop_id);
  // Any thread. Terminates the outermost execution only when `stop_id` names
  // it (NativeConsoleStopNames).
  void Stop(std::uint64_t stop_id);
  // Renderer main thread. How the execution ended. The outermost Finish after
  // kStopped cancels termination for the next task; a nested one leaves it, so
  // the enclosing execution keeps unwinding.
  [[nodiscard]] End Finish();

 private:
  friend class base::NoDestructor<NativeConsoleExecution>;
  NativeConsoleExecution();
  ~NativeConsoleExecution();

  base::Lock lock_;
  raw_ptr<v8::Isolate> isolate_ = nullptr;
  std::uint64_t stop_id_ = 0;
  std::uint32_t depth_ = 0;
  bool stopped_ = false;
};

// Binds a Stop pipe on the renderer IO thread, which stays responsive while
// page JavaScript holds the main thread.
void BindNativeConsoleControl(mojo::PendingReceiver<mojom::NativeConsoleControl> receiver);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_EXECUTION_H_
