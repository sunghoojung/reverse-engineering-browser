// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_local_ipc_client.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <string>

#include "base/containers/span.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_ipc.h"

namespace reb {
namespace {

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
  struct stat status {};
  if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
      (status.st_mode & 0777) != 0600) {
    close(descriptor);
    return false;
  }

  std::array<char, kNativeProbeLocalIpcTokenSize * 2 + 2> buffer{};
  std::size_t size = 0;
  while (size < buffer.size()) {
    const base::span<char> remaining = base::span(buffer).subspan(size);
    const ssize_t count = read(descriptor, remaining.data(), remaining.size());
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

bool SendAll(const int descriptor, base::span<const std::uint8_t> bytes) {
  while (!bytes.empty()) {
#if defined(MSG_NOSIGNAL)
    const ssize_t count = send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
#else
    const ssize_t count = send(descriptor, bytes.data(), bytes.size(), 0);
#endif
    if (count > 0) {
      bytes = bytes.subspan(static_cast<std::size_t>(count));
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

}  // namespace

int ConnectNativeLocalIpc(const std::string& socket_path,
                          const base::FilePath& token_path,
                          const std::uint64_t session_id,
                          const bool non_blocking) {
  sockaddr_un address{};
  NativeProbeLocalIpcHello hello;
  hello.session_id = session_id;
  if (session_id == 0 || socket_path.empty() || socket_path.size() >= sizeof(address.sun_path) ||
      !LoadToken(token_path, hello.token)) {
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
      !SendAll(descriptor, base::byte_span_from_ref(hello))) {
    close(descriptor);
    return -1;
  }
  if (non_blocking) {
    const int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
      close(descriptor);
      return -1;
    }
  }
  return descriptor;
}

}  // namespace reb

#else

namespace reb {

int ConnectNativeLocalIpc(const std::string&,
                          const base::FilePath&,
                          const std::uint64_t,
                          const bool) {
  return -1;
}

}  // namespace reb

#endif
