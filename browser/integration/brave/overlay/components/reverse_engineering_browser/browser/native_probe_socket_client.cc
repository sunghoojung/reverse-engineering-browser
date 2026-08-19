// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_socket_client.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <limits>
#include <string>
#include <utility>

#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_local_ipc_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"

namespace reb {

namespace {

constexpr char kBrokerSocketSwitch[] = "reb-broker-socket";
constexpr char kBrokerTokenFileSwitch[] = "reb-broker-token-file";
constexpr char kSessionIdSwitch[] = "reb-session-id";
constexpr char kCategoryMaskSwitch[] = "reb-category-mask";
constexpr char kDurationSecondsSwitch[] = "reb-duration-seconds";
constexpr char kArtifactSocketSwitch[] = "reb-artifact-socket";
constexpr std::size_t kSocketBatchCapacity = 32;

bool SendAll(const int descriptor, base::span<const std::uint8_t> bytes, const bool non_blocking) {
  while (!bytes.empty()) {
    ssize_t count = -1;
#if defined(MSG_NOSIGNAL)
    count = send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
#else
    count = send(descriptor, bytes.data(), bytes.size(), 0);
#endif
    if (count > 0) {
      bytes = bytes.subspan(static_cast<std::size_t>(count));
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (non_blocking && count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      pollfd writable{descriptor, static_cast<short>(POLLOUT), 0};
      const int poll_result = poll(&writable, 1, 250);
      if (poll_result > 0 && (writable.revents & POLLOUT) != 0) {
        continue;
      }
      if (poll_result < 0 && errno == EINTR) {
        continue;
      }
      if (poll_result == 0) {
        continue;
      }
    }
    return false;
  }
  return true;
}

}  // namespace

NativeProbeSocketClient& NativeProbeSocketClient::Get() {
  static base::NoDestructor<NativeProbeSocketClient> client;
  return *client;
}

NativeProbeSocketClient::NativeProbeSocketClient() = default;

NativeProbeSocketClient::~NativeProbeSocketClient() = default;

bool NativeProbeSocketClient::StartFromCommandLine() {
  if (connected_.load(std::memory_order_acquire)) {
    return true;
  }

  const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  const bool has_socket = command_line.HasSwitch(kBrokerSocketSwitch);
  const bool has_token = command_line.HasSwitch(kBrokerTokenFileSwitch);
  const bool has_session = command_line.HasSwitch(kSessionIdSwitch);
  const bool has_category_mask = command_line.HasSwitch(kCategoryMaskSwitch);
  const bool has_duration = command_line.HasSwitch(kDurationSecondsSwitch);
  if (!has_socket && !has_token && !has_session && !has_category_mask && !has_duration) {
    return false;
  }
  if (!has_socket || !has_token || !has_session || !has_category_mask || !has_duration) {
    LOG(ERROR) << "All native probe session switches are required";
    return false;
  }

  std::uint64_t session_id = 0;
  if (!base::StringToUint64(command_line.GetSwitchValueASCII(kSessionIdSwitch), &session_id) ||
      session_id == 0) {
    LOG(ERROR) << "Invalid native probe session ID";
    return false;
  }

  std::uint64_t category_mask = 0;
  if (!base::StringToUint64(command_line.GetSwitchValueASCII(kCategoryMaskSwitch),
                            &category_mask) ||
      !IsValidNativeProbeCategoryMask(category_mask)) {
    LOG(ERROR) << "Invalid native probe category mask";
    return false;
  }

  std::uint64_t duration_seconds = 0;
  if (!base::StringToUint64(command_line.GetSwitchValueASCII(kDurationSecondsSwitch),
                            &duration_seconds) ||
      duration_seconds == 0 ||
      duration_seconds > std::numeric_limits<std::uint64_t>::max() / 1'000'000'000ULL) {
    LOG(ERROR) << "Invalid native probe session duration";
    return false;
  }
  const std::uint64_t duration_ns = duration_seconds * 1'000'000'000ULL;
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (duration_ns > std::numeric_limits<std::uint64_t>::max() - now) {
    LOG(ERROR) << "Native probe session duration overflows the monotonic clock";
    return false;
  }
  const std::uint64_t expires_at_monotonic_ns = now + duration_ns;

  const base::FilePath token_path = command_line.GetSwitchValuePath(kBrokerTokenFileSwitch);
  socket_descriptor_ = ConnectNativeLocalIpc(command_line.GetSwitchValueASCII(kBrokerSocketSwitch),
                                             token_path, session_id, true);
  if (socket_descriptor_ < 0) {
    LOG(ERROR) << "Unable to connect to native probe broker";
    return false;
  }

  const bool artifact_capture_enabled =
      (category_mask & NativeProbeCategoryMask(NativeProbeCategory::kArtifact)) != 0;
  const bool has_artifact_socket = command_line.HasSwitch(kArtifactSocketSwitch);
  if (artifact_capture_enabled &&
      (!has_artifact_socket || !NativeArtifactSocketClient::Get().StartFromCommandLine(
                                   session_id, &NativeArtifactCaptureSink::TransferCompleted))) {
    close(socket_descriptor_);
    socket_descriptor_ = -1;
    return false;
  }

  browser_task_runner_ = base::SequencedTaskRunner::GetCurrentDefault();
  if (!writer_thread_.Start()) {
    NativeArtifactSocketClient::Get().Stop();
    close(socket_descriptor_);
    socket_descriptor_ = -1;
    return false;
  }
  connected_.store(true, std::memory_order_release);
  writer_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&NativeProbeSocketClient::Run, base::Unretained(this)));
  if (!NativeProbeSession::Get().StartSession(session_id, category_mask, expires_at_monotonic_ns,
                                              &NativeProbeSocketClient::Emit)) {
    connected_.store(false, std::memory_order_release);
    wakeup_.Signal();
    close(socket_descriptor_);
    socket_descriptor_ = -1;
    NativeArtifactSocketClient::Get().Stop();
    return false;
  }
  return true;
}

void NativeProbeSocketClient::Emit(const NativeProbeEvent& event) noexcept {
  Get().Enqueue(event);
}

void NativeProbeSocketClient::Enqueue(const NativeProbeEvent& event) noexcept {
  if (!connected_.load(std::memory_order_acquire) || !queue_.TryPush(event)) {
    return;
  }
  if (queue_.MarkNotificationPending()) {
    wakeup_.Signal();
  }
}

void NativeProbeSocketClient::Run() {
  std::uint64_t reported_dropped = 0;
  while (connected_.load(std::memory_order_acquire)) {
    wakeup_.Wait();
    std::array<NativeProbeEvent, kSocketBatchCapacity> batch;
    NativeProbeEvent last_event;
    bool drained_event = false;
    for (;;) {
      std::size_t batch_size = 0;
      while (batch_size < batch.size() && queue_.TryPop(batch[batch_size])) {
        last_event = batch[batch_size];
        ++batch_size;
      }
      if (batch_size == 0) {
        break;
      }
      drained_event = true;
      if (!SendAll(socket_descriptor_, base::as_bytes(base::span(batch).first(batch_size)), true)) {
        browser_task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(&NativeProbeSocketClient::HandleDisconnect, base::Unretained(this)));
        return;
      }
    }

    const std::uint64_t dropped = queue_.DroppedCount();
    if (drained_event && dropped > reported_dropped) {
      const NativeProbeEvent gap = MakeNativeProbeGapEvent(last_event, dropped - reported_dropped);
      if (!SendAll(socket_descriptor_, base::byte_span_from_ref(gap), true)) {
        browser_task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(&NativeProbeSocketClient::HandleDisconnect, base::Unretained(this)));
        return;
      }
      reported_dropped = dropped;
    }

    queue_.ClearNotificationPending();
    if (!queue_.Empty() && queue_.MarkNotificationPending()) {
      wakeup_.Signal();
    }
  }
}

void NativeProbeSocketClient::HandleDisconnect() {
  if (!connected_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  NativeProbeSession::Get().StopSession();
  NativeArtifactSocketClient::Get().Stop();
  if (socket_descriptor_ >= 0) {
    close(socket_descriptor_);
    socket_descriptor_ = -1;
  }
  LOG(ERROR) << "Native probe broker disconnected; capture disabled";
}

}  // namespace reb

#else

namespace reb {

NativeProbeSocketClient& NativeProbeSocketClient::Get() {
  static base::NoDestructor<NativeProbeSocketClient> client;
  return *client;
}

NativeProbeSocketClient::NativeProbeSocketClient() = default;
NativeProbeSocketClient::~NativeProbeSocketClient() = default;
bool NativeProbeSocketClient::StartFromCommandLine() {
  return false;
}
void NativeProbeSocketClient::Emit(const NativeProbeEvent&) noexcept {}
void NativeProbeSocketClient::Enqueue(const NativeProbeEvent&) noexcept {}
void NativeProbeSocketClient::Run() {}
void NativeProbeSocketClient::HandleDisconnect() {}

}  // namespace reb

#endif
