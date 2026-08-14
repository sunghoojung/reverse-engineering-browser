// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SOCKET_CLIENT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SOCKET_CLIENT_H_

#include <atomic>
#include <cstdint>

#include "base/memory/scoped_refptr.h"
#include "base/no_destructor.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"

namespace base {
class SequencedTaskRunner;
}

namespace reb {

class NativeProbeSocketClient final {
 public:
  static NativeProbeSocketClient& Get();

  NativeProbeSocketClient(const NativeProbeSocketClient&) = delete;
  NativeProbeSocketClient& operator=(const NativeProbeSocketClient&) = delete;

  // Does nothing and returns false when no broker switches are present. A
  // partial or invalid configuration also returns false and leaves probes off.
  [[nodiscard]] bool StartFromCommandLine();

 private:
  friend class base::NoDestructor<NativeProbeSocketClient>;

  NativeProbeSocketClient();
  ~NativeProbeSocketClient();

  static void Emit(const NativeProbeEvent& event) noexcept;
  void Enqueue(const NativeProbeEvent& event) noexcept;
  void Run();
  void HandleDisconnect();

  NativeProbeQueue queue_;
  base::WaitableEvent wakeup_{base::WaitableEvent::ResetPolicy::AUTOMATIC,
                              base::WaitableEvent::InitialState::NOT_SIGNALED};
  base::Thread writer_thread_{"REB broker writer"};
  scoped_refptr<base::SequencedTaskRunner> browser_task_runner_;
  std::atomic<bool> connected_{false};
  int socket_descriptor_ = -1;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_PROBE_SOCKET_CLIENT_H_
