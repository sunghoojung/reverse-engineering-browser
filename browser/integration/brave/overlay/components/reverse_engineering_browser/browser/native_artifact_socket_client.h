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

#include "base/files/file_path.h"
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
// Runs once on the starting sequence when the channel is lost for the rest of
// the session, after every queued transfer has been reported.
using NativeArtifactChannelLost = void (*)() noexcept;

// Lifecycle of the artifact channel. Writer-driven changes go through
// Transition(); only start, Stop() and its completion set a state outright.
enum class NativeArtifactChannelState : std::uint8_t {
  // Not started, or Stop() has finished.
  kIdle,
  // The writer owns an authenticated receiver connection.
  kConnected,
  // That connection failed. The writer reconnects while new transfers wait in
  // the same bounded queue.
  kReconnecting,
  // Reconnection failed. Queued transfers were reported as I/O errors, the
  // loss was announced, and new transfers are refused until Stop().
  kLost,
  // Stop() is shutting the connection down and joining the writer.
  kStopping,
};

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
                                          NativeArtifactCompletion completion,
                                          NativeArtifactChannelLost channel_lost);
  [[nodiscard]] bool Enqueue(std::unique_ptr<NativeArtifactTransfer> transfer) noexcept;
  // True while transfers are accepted: connected, or reconnecting with them
  // held in the bounded queue. Capture admission keys off this, so a brief
  // reconnect never skips a capture without a record.
  [[nodiscard]] bool IsConnected() const noexcept;
  [[nodiscard]] NativeArtifactChannelState state() const noexcept;
  void Stop();

 private:
  friend class base::NoDestructor<NativeArtifactSocketClient>;

  NativeArtifactSocketClient();
  ~NativeArtifactSocketClient();

  [[nodiscard]] bool Transition(NativeArtifactChannelState from,
                                NativeArtifactChannelState to) noexcept;
  [[nodiscard]] int Connect() const;
  [[nodiscard]] bool Reconnect();
  void LoseChannel();
  void Run();
  void Report(std::uint64_t artifact_id, NativeArtifactReceiveStatus status);
  void DisconnectPending(NativeArtifactReceiveStatus status);
  void JoinWriter();
  void FinishStop();

  base::Lock lock_;
  base::ConditionVariable wakeup_{&lock_};
  std::deque<std::unique_ptr<NativeArtifactTransfer>> queue_ GUARDED_BY(lock_);
  std::size_t queued_bytes_ GUARDED_BY(lock_) = 0;
  // The writer replaces it on reconnect and Stop() shuts it down, both under
  // lock_, so Stop() never touches a descriptor the writer already closed.
  int socket_descriptor_ GUARDED_BY(lock_) = -1;
  base::Thread writer_thread_{"REB artifact writer"};
  // Written before the writer starts and cleared after it is joined.
  scoped_refptr<base::SequencedTaskRunner> browser_task_runner_;
  NativeArtifactCompletion completion_ = nullptr;
  NativeArtifactChannelLost channel_lost_ = nullptr;
  std::string socket_path_;
  base::FilePath token_path_;
  std::uint64_t session_id_ = 0;
  // Transitions that order against the descriptor happen under lock_; the
  // atomic lets admission read it without the lock.
  std::atomic<NativeArtifactChannelState> state_{NativeArtifactChannelState::kIdle};
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_ARTIFACT_SOCKET_CLIENT_H_
