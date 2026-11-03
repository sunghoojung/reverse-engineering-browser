// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DEADLINE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DEADLINE_H_

#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/time/time.h"
#include "v8/include/v8.h"

namespace reb {

// Only the watchdog thread and the renderer execution thread share this state.
// The lock ensures a late watchdog can never terminate a subsequent page task
// or touch an isolate after this execution released it. No V8 handles cross
// threads. TerminateExecution is explicitly safe to call from another thread.
//
// One slot is enough: every caller runs synchronously on the renderer main
// thread, so an explicit console command and a document-start injection can
// never hold the deadline at the same time. A second Begin fails closed.
class NativeConsoleDeadline final {
 public:
  static NativeConsoleDeadline& Get();

  NativeConsoleDeadline(const NativeConsoleDeadline&) = delete;
  NativeConsoleDeadline& operator=(const NativeConsoleDeadline&) = delete;

  // False when the slot is taken or the watchdog thread is unavailable. A
  // caller that cannot be interrupted must not run page JavaScript at all.
  [[nodiscard]] bool Begin(v8::Isolate* isolate, int budget_millis);
  // True when the budget expired and execution was terminated.
  [[nodiscard]] bool Finish();

 private:
  friend class base::NoDestructor<NativeConsoleDeadline>;
  NativeConsoleDeadline();
  ~NativeConsoleDeadline();
  void Watch();

  base::Lock lock_;
  base::ConditionVariable changed_{&lock_};
  raw_ptr<v8::Isolate> isolate_ = nullptr;
  base::TimeTicks expires_;
  bool expired_ = false;
  bool worker_running_ = false;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DEADLINE_H_
