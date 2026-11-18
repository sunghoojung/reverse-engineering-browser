// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "native_console_io.h"

#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <climits>

namespace reb {
namespace {

bool Ready(int socket, short events, NativeConsoleDeadline deadline) noexcept {
  for (;;) {
    const auto remaining = deadline - std::chrono::steady_clock::now();
    if (remaining <= decltype(remaining)::zero()) {
      return false;
    }
    const auto millis = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
    pollfd descriptor{socket, events, 0};
    const int result =
        poll(&descriptor, 1, static_cast<int>(std::min<decltype(millis)>(millis, INT_MAX)));
    if (result > 0) {
      // POLLHUP may accompany the last readable bytes. Let recv distinguish
      // those bytes from EOF instead of discarding a complete final response.
      return (descriptor.revents & events) != 0;
    }
    if (result == 0 || errno != EINTR) {
      return false;
    }
  }
}

// `deadline` is fixed when `stall` is zero, and otherwise moves to `stall`
// after every transfer that makes progress.
bool Read(int socket,
          std::span<std::byte> bytes,
          NativeConsoleDeadline deadline,
          std::chrono::milliseconds stall) noexcept {
  while (!bytes.empty()) {
    if (stall.count() > 0) {
      deadline = std::chrono::steady_clock::now() + stall;
    }
    if (!Ready(socket, POLLIN, deadline)) {
      return false;
    }
    const ssize_t count = recv(socket, bytes.data(), bytes.size(), MSG_DONTWAIT);
    if (count > 0) {
      bytes = bytes.subspan(static_cast<std::size_t>(count));
    } else if (count == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
      return false;
    }
  }
  return true;
}

bool Write(int socket,
           std::span<const std::byte> bytes,
           NativeConsoleDeadline deadline,
           std::chrono::milliseconds stall) noexcept {
  while (!bytes.empty()) {
    if (stall.count() > 0) {
      deadline = std::chrono::steady_clock::now() + stall;
    }
    if (!Ready(socket, POLLOUT, deadline)) {
      return false;
    }
    int flags = MSG_DONTWAIT;
#if defined(MSG_NOSIGNAL)
    flags |= MSG_NOSIGNAL;
#endif
    const ssize_t count = send(socket, bytes.data(), bytes.size(), flags);
    if (count > 0) {
      bytes = bytes.subspan(static_cast<std::size_t>(count));
    } else if (count == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool NativeConsoleRead(int socket,
                       std::span<std::byte> bytes,
                       NativeConsoleDeadline deadline) noexcept {
  return Read(socket, bytes, deadline, std::chrono::milliseconds::zero());
}

bool NativeConsoleWrite(int socket,
                        std::span<const std::byte> bytes,
                        NativeConsoleDeadline deadline) noexcept {
  return Write(socket, bytes, deadline, std::chrono::milliseconds::zero());
}

bool NativeConsoleRead(int socket,
                       std::span<std::byte> bytes,
                       std::chrono::milliseconds stall) noexcept {
  return Read(socket, bytes, {}, stall);
}

bool NativeConsoleWrite(int socket,
                        std::span<const std::byte> bytes,
                        std::chrono::milliseconds stall) noexcept {
  return Write(socket, bytes, {}, stall);
}

}  // namespace reb
