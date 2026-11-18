// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_console_execution.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/task/sequenced_task_runner.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "third_party/blink/public/platform/platform.h"

namespace reb {
namespace {

class NativeConsoleControl final : public mojom::NativeConsoleControl {
 public:
  void Stop(std::uint64_t request_id) override { NativeConsoleExecution::Get().Stop(request_id); }
};

}  // namespace

NativeConsoleExecution& NativeConsoleExecution::Get() {
  static base::NoDestructor<NativeConsoleExecution> execution;
  return *execution;
}

NativeConsoleExecution::NativeConsoleExecution() = default;
NativeConsoleExecution::~NativeConsoleExecution() = default;

void NativeConsoleExecution::Begin(v8::Isolate* isolate, std::uint64_t stop_id) {
  base::AutoLock lock(lock_);
  if (depth_++)
    return;
  isolate_ = isolate;
  stop_id_ = stop_id;
  stopped_ = false;
}

void NativeConsoleExecution::Stop(std::uint64_t stop_id) {
  base::AutoLock lock(lock_);
  if (!isolate_ || stop_id == 0 || stop_id != stop_id_ || stopped_)
    return;
  stopped_ = true;
  isolate_->TerminateExecution();
}

NativeConsoleExecution::End NativeConsoleExecution::Finish() {
  base::AutoLock lock(lock_);
  const auto end = stopped_ ? End::kStopped : End::kReturned;
  if (!depth_ || --depth_)
    return end;
  if (stopped_)
    isolate_->CancelTerminateExecution();
  isolate_ = nullptr;
  stop_id_ = 0;
  stopped_ = false;
  return end;
}

void BindNativeConsoleControl(mojo::PendingReceiver<mojom::NativeConsoleControl> receiver) {
  blink::Platform::Current()->GetIOTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(
                     [](mojo::PendingReceiver<mojom::NativeConsoleControl> pending) {
                       mojo::MakeSelfOwnedReceiver(std::make_unique<NativeConsoleControl>(),
                                                   std::move(pending));
                     },
                     std::move(receiver)));
}

}  // namespace reb
