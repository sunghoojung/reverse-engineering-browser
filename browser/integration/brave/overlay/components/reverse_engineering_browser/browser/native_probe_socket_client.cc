// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_socket_client.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_ipc.h"

namespace reb {

namespace {

constexpr char kBrokerSocketSwitch[] = "reb-broker-socket";
constexpr char kBrokerTokenFileSwitch[] = "reb-broker-token-file";
constexpr char kSessionIdSwitch[] = "reb-session-id";
constexpr char kCategoryMaskSwitch[] = "reb-category-mask";
constexpr char kDurationSecondsSwitch[] = "reb-duration-seconds";
constexpr std::size_t kSocketBatchCapacity = 32;

int HexValue(const char value) noexcept {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

bool LoadToken(const base::FilePath& path, NativeProbeLocalIpcToken& token) {
  const int descriptor = open(path.value().c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    return false;
  }
  struct stat status{};
  if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
      (status.st_mode & 0777) != 0600) {
    close(descriptor);
    return false;
  }

  std::array<char, kNativeProbeLocalIpcTokenSize * 2 + 2> buffer{};
  std::size_t size = 0;
  while (size < buffer.size()) {
    const ssize_t count = read(descriptor, buffer.data() + size, buffer.size() - size);
    if (count > 0) {
      size += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      close(descriptor);
      return false;
    }
    break;
  }
  if (close(descriptor) != 0) {
    return false;
  }
  std::string encoded(buffer.data(), size);
  if (!encoded.empty() && encoded.back() == '\n') {
    encoded.pop_back();
  }
  if (encoded.size() != token.size() * 2) {
    return false;
  }
  for (std::size_t index = 0; index < token.size(); ++index) {
    const int high = HexValue(encoded[index * 2]);
    const int low = HexValue(encoded[index * 2 + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    token[index] = static_cast<std::byte>((high << 4) | low);
  }
  return true;
}

bool SendAll(const int descriptor,
             const void* const data,
             const std::size_t size,
             const bool non_blocking) {
  const auto* bytes = static_cast<const std::byte*>(data);
  std::size_t offset = 0;
  while (offset < size) {
    ssize_t count = -1;
#if defined(MSG_NOSIGNAL)
    count = send(descriptor, bytes + offset, size - offset, MSG_NOSIGNAL);
#else
    count = send(descriptor, bytes + offset, size - offset, 0);
#endif
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
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

int Connect(const std::string& socket_path, const NativeProbeLocalIpcHello& hello) {
  sockaddr_un address{};
  if (socket_path.empty() || socket_path.size() >= sizeof(address.sun_path)) {
    return -1;
  }

  const int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) {
    return -1;
  }
#if defined(SO_NOSIGPIPE)
  const int enabled = 1;
  if (setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                 static_cast<socklen_t>(sizeof(enabled))) != 0) {
    close(descriptor);
    return -1;
  }
#endif
  address.sun_family = AF_UNIX;
  std::copy(socket_path.begin(), socket_path.end(), address.sun_path);
  if (connect(descriptor, reinterpret_cast<const sockaddr*>(&address),
              static_cast<socklen_t>(sizeof(address))) != 0 ||
      !SendAll(descriptor, &hello, sizeof(hello), false)) {
    close(descriptor);
    return -1;
  }

  const int flags = fcntl(descriptor, F_GETFL, 0);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
    close(descriptor);
    return -1;
  }
  return descriptor;
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

  NativeProbeLocalIpcHello hello;
  hello.session_id = session_id;
  const base::FilePath token_path = command_line.GetSwitchValuePath(kBrokerTokenFileSwitch);
  if (!LoadToken(token_path, hello.token)) {
    LOG(ERROR) << "Native probe broker token is unavailable or insecure";
    return false;
  }

  socket_descriptor_ = Connect(command_line.GetSwitchValueASCII(kBrokerSocketSwitch), hello);
  if (socket_descriptor_ < 0) {
    LOG(ERROR) << "Unable to connect to native probe broker";
    return false;
  }

  browser_task_runner_ = base::SequencedTaskRunner::GetCurrentDefault();
  if (!writer_thread_.Start()) {
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
      if (!SendAll(socket_descriptor_, batch.data(), batch_size * sizeof(NativeProbeEvent), true)) {
        browser_task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(&NativeProbeSocketClient::HandleDisconnect, base::Unretained(this)));
        return;
      }
    }

    const std::uint64_t dropped = queue_.DroppedCount();
    if (drained_event && dropped > reported_dropped) {
      const NativeProbeEvent gap = MakeNativeProbeGapEvent(last_event, dropped - reported_dropped);
      if (!SendAll(socket_descriptor_, &gap, sizeof(gap), true)) {
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
