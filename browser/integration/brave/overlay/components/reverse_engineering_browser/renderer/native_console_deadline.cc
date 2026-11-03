// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_console_deadline.h"

#include <algorithm>

#include "base/functional/bind.h"
#include "base/task/thread_pool.h"

namespace reb {

NativeConsoleDeadline& NativeConsoleDeadline::Get() {
  static base::NoDestructor<NativeConsoleDeadline> deadline;
  return *deadline;
}

NativeConsoleDeadline::NativeConsoleDeadline() = default;
NativeConsoleDeadline::~NativeConsoleDeadline() = default;

bool NativeConsoleDeadline::Begin(v8::Isolate* isolate, int budget_millis) {
  base::AutoLock lock(lock_);
  if (isolate_ || !isolate || budget_millis <= 0)
    return false;
  isolate_ = isolate;
  expires_ = base::TimeTicks::Now() + base::Milliseconds(budget_millis);
  expired_ = false;
  if (!worker_running_) {
    worker_running_ = base::ThreadPool::PostTask(
        FROM_HERE, {base::WithBaseSyncPrimitives(), base::TaskPriority::USER_BLOCKING},
        base::BindOnce(&NativeConsoleDeadline::Watch, base::Unretained(this)));
    if (!worker_running_) {
      isolate_ = nullptr;
      return false;
    }
  }
  changed_.Signal();
  return true;
}

bool NativeConsoleDeadline::Finish() {
  base::AutoLock lock(lock_);
  if (expired_)
    isolate_->CancelTerminateExecution();
  isolate_ = nullptr;
  changed_.Signal();
  return expired_;
}

void NativeConsoleDeadline::Watch() {
  base::AutoLock lock(lock_);
  for (;;) {
    if (!isolate_) {
      const auto idle_until = base::TimeTicks::Now() + base::Milliseconds(500);
      while (!isolate_ && base::TimeTicks::Now() < idle_until)
        changed_.TimedWait(std::max(base::TimeDelta(), idle_until - base::TimeTicks::Now()));
      if (!isolate_) {
        worker_running_ = false;
        return;
      }
    }
    if (!expired_ && base::TimeTicks::Now() >= expires_) {
      expired_ = true;
      isolate_->TerminateExecution();
    }
    if (expired_)
      changed_.Wait();
    else
      changed_.TimedWait(std::max(base::TimeDelta(), expires_ - base::TimeTicks::Now()));
  }
}

}  // namespace reb
