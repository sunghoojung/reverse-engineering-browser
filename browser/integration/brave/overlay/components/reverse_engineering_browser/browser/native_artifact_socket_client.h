// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_SOCKET_CLIENT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_SOCKET_CLIENT_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "base/memory/scoped_refptr.h"
#include "base/no_destructor.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/thread_annotations.h"
#include "base/threading/thread.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_header.h"

namespace base {
class SequencedTaskRunner;
}

namespace reb {

struct NativeArtifactTransfer final {
  NativeArtifactHeader header;
  std::string url;
  std::string mime_type;
  std::vector<std::uint8_t> content;
};

using NativeArtifactCompletion = void (*)(std::uint64_t artifact_id,
                                          NativeArtifactReceiveStatus status) noexcept;

// Owns the browser-process side of the independently bounded artifact stream.
// Network and generated-source capture sequences enqueue completed immutable
// bodies; a dedicated writer thread performs all socket I/O and waits for
// durable receiver acks.
class NativeArtifactSocketClient final {
 public:
  static NativeArtifactSocketClient& Get();

  NativeArtifactSocketClient(const NativeArtifactSocketClient&) = delete;
  NativeArtifactSocketClient& operator=(const NativeArtifactSocketClient&) = delete;

  [[nodiscard]] bool StartFromCommandLine(std::uint64_t session_id,
                                          NativeArtifactCompletion completion);
  [[nodiscard]] bool Enqueue(std::unique_ptr<NativeArtifactTransfer> transfer) noexcept;
  [[nodiscard]] bool IsConnected() const noexcept;
  void Stop();

 private:
  friend class base::NoDestructor<NativeArtifactSocketClient>;

  NativeArtifactSocketClient();
  ~NativeArtifactSocketClient();

  void Run();
  void Report(std::uint64_t artifact_id, NativeArtifactReceiveStatus status);
  void DisconnectPending(NativeArtifactReceiveStatus status);

  base::Lock lock_;
  base::ConditionVariable wakeup_{&lock_};
  std::deque<std::unique_ptr<NativeArtifactTransfer>> queue_ GUARDED_BY(lock_);
  std::size_t queued_bytes_ GUARDED_BY(lock_) = 0;
  base::Thread writer_thread_{"REB artifact writer"};
  scoped_refptr<base::SequencedTaskRunner> browser_task_runner_;
  NativeArtifactCompletion completion_ = nullptr;
  std::atomic<bool> connected_{false};
  int socket_descriptor_ = -1;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_SOCKET_CLIENT_H_
