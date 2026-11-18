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

bool NativeConsoleDeadline::Begin(v8::Isolate* isolate,
                                  std::uint64_t request_id,
                                  int budget_millis) {
  base::AutoLock lock(lock_);
  if (isolate_ || !isolate || budget_millis < 0)
    return false;
  isolate_ = isolate;
  request_id_ = request_id;
  expires_ = budget_millis ? base::TimeTicks::Now() + base::Milliseconds(budget_millis)
                           : base::TimeTicks::Max();
  end_ = End::kReturned;
  if (!worker_running_) {
    worker_running_ = base::ThreadPool::PostTask(
        FROM_HERE, {base::WithBaseSyncPrimitives(), base::TaskPriority::USER_BLOCKING},
        base::BindOnce(&NativeConsoleDeadline::Watch, base::Unretained(this)));
    if (!worker_running_) {
      isolate_ = nullptr;
      request_id_ = 0;
      return false;
    }
  }
  changed_.Signal();
  return true;
}

void NativeConsoleDeadline::Stop(std::uint64_t request_id) {
  base::AutoLock lock(lock_);
  if (!isolate_ || request_id == 0 || request_id != request_id_ || end_ != End::kReturned)
    return;
  end_ = End::kStopped;
  isolate_->TerminateExecution();
  changed_.Signal();
}

NativeConsoleDeadline::End NativeConsoleDeadline::Finish() {
  base::AutoLock lock(lock_);
  if (end_ != End::kReturned)
    isolate_->CancelTerminateExecution();
  isolate_ = nullptr;
  request_id_ = 0;
  changed_.Signal();
  return end_;
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
    if (end_ == End::kReturned && base::TimeTicks::Now() >= expires_) {
      end_ = End::kExpired;
      isolate_->TerminateExecution();
    }
    // A command without a budget waits for Stop or Finish, both of which signal.
    if (end_ != End::kReturned || expires_.is_max())
      changed_.Wait();
    else
      changed_.TimedWait(std::max(base::TimeDelta(), expires_ - base::TimeTicks::Now()));
  }
}

}  // namespace reb
