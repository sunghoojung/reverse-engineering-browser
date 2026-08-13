#include "reb/local_ipc.hpp"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

#include <algorithm>
#include <array>
#include <limits>

namespace reb {

namespace {

constexpr std::array<char, 16> kHex = {'0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

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

bool ValidateTokenFile(const int descriptor, const std::string& path, std::string& error) {
  struct stat status {};
  if (fstat(descriptor, &status) != 0) {
    error = "Unable to inspect token file " + path + ": " + std::strerror(errno);
    return false;
  }
  if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() || (status.st_mode & 0777) != 0600) {
    error = "Token file must be a user-owned regular file with mode 0600: " + path;
    return false;
  }
  return true;
}

bool FillRandomToken(LocalIpcToken& token, std::string& error) {
  const int descriptor = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    error = "Unable to open /dev/urandom: " + std::string(std::strerror(errno));
    return false;
  }
  const bool read = ReadExact(descriptor, token, error);
  const int close_result = close(descriptor);
  if (read && close_result != 0) {
    error = "Unable to close /dev/urandom: " + std::string(std::strerror(errno));
    return false;
  }
  return read;
}

}  // namespace

bool DecodeLocalIpcToken(const std::string_view encoded, LocalIpcToken& token) noexcept {
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

std::string EncodeLocalIpcToken(const LocalIpcToken& token) {
  std::string encoded;
  encoded.resize(token.size() * 2);
  for (std::size_t index = 0; index < token.size(); ++index) {
    const unsigned value = std::to_integer<unsigned>(token[index]);
    encoded[index * 2] = kHex[value >> 4];
    encoded[index * 2 + 1] = kHex[value & 0x0fU];
  }
  return encoded;
}

bool LoadLocalIpcToken(const std::string& path, LocalIpcToken& token, std::string& error) {
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    error = "Unable to open token file " + path + ": " + std::strerror(errno);
    return false;
  }
  if (!ValidateTokenFile(descriptor, path, error)) {
    close(descriptor);
    return false;
  }

  std::array<char, kLocalIpcTokenSize * 2 + 2> buffer{};
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
      error = "Unable to read token file " + path + ": " + std::strerror(errno);
      close(descriptor);
      return false;
    }
    break;
  }
  if (close(descriptor) != 0) {
    error = "Unable to close token file " + path + ": " + std::strerror(errno);
    return false;
  }
  std::string_view encoded(buffer.data(), size);
  if (!encoded.empty() && encoded.back() == '\n') {
    encoded.remove_suffix(1);
  }
  if (!DecodeLocalIpcToken(encoded, token)) {
    error = "Token file must contain exactly 64 hexadecimal characters: " + path;
    return false;
  }
  return true;
}

bool LoadOrCreateLocalIpcToken(const std::string& path, LocalIpcToken& token, std::string& error) {
  struct stat status {};
  if (lstat(path.c_str(), &status) == 0) {
    return LoadLocalIpcToken(path, token, error);
  }
  if (errno != ENOENT) {
    error = "Unable to inspect token file " + path + ": " + std::strerror(errno);
    return false;
  }
  error.clear();

  if (!FillRandomToken(token, error)) {
    return false;
  }
  const int descriptor =
      open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0) {
    error = "Unable to create token file " + path + ": " + std::strerror(errno);
    return false;
  }
  const std::string encoded = EncodeLocalIpcToken(token) + '\n';
  const auto bytes = std::as_bytes(std::span(encoded));
  const bool written = WriteExact(descriptor, bytes, error);
  if (written && fsync(descriptor) != 0) {
    error = "Unable to sync token file " + path + ": " + std::strerror(errno);
  }
  const bool closed = close(descriptor) == 0;
  if (written && !closed && error.empty()) {
    error = "Unable to close token file " + path + ": " + std::strerror(errno);
  }
  return written && closed && error.empty();
}

bool ConstantTimeTokenEquals(const LocalIpcToken& left, const LocalIpcToken& right) noexcept {
  unsigned difference = 0;
  for (std::size_t index = 0; index < left.size(); ++index) {
    difference |= std::to_integer<unsigned>(left[index] ^ right[index]);
  }
  return difference == 0;
}

int ConnectAuthenticatedLocalIpc(const std::string& socket_path,
                                 const std::string& token_path,
                                 const std::uint64_t session_id,
                                 std::string& error) {
  sockaddr_un address{};
  if (session_id == 0 || socket_path.empty() || socket_path.size() >= sizeof(address.sun_path)) {
    error = "Invalid local IPC connection configuration";
    return -1;
  }

  LocalIpcToken token{};
  if (!LoadLocalIpcToken(token_path, token, error)) {
    return -1;
  }

  const int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) {
    error = "Unable to create local IPC socket: " + std::string(std::strerror(errno));
    return -1;
  }
#if defined(SO_NOSIGPIPE)
  const int enabled = 1;
  if (setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
    error = "Unable to protect local IPC socket: " + std::string(std::strerror(errno));
    close(descriptor);
    return -1;
  }
#endif

  address.sun_family = AF_UNIX;
  std::copy(socket_path.begin(), socket_path.end(), address.sun_path);
  if (connect(descriptor, reinterpret_cast<const sockaddr*>(&address),
              static_cast<socklen_t>(sizeof(address))) != 0) {
    error = "Unable to connect to broker socket: " + std::string(std::strerror(errno));
    close(descriptor);
    return -1;
  }

  LocalIpcHello hello;
  hello.session_id = session_id;
  hello.token = token;
  if (!WriteExact(descriptor, std::as_bytes(std::span(&hello, 1)), error)) {
    close(descriptor);
    return -1;
  }
  return descriptor;
}

bool ReadExact(const int descriptor, const std::span<std::byte> output, std::string& error) {
  std::size_t offset = 0;
  while (offset < output.size()) {
    const ssize_t count = read(descriptor, output.data() + offset, output.size() - offset);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count == 0) {
      error = "Connection closed after " + std::to_string(offset) + " of " +
              std::to_string(output.size()) + " bytes";
    } else {
      error = "Read failed: " + std::string(std::strerror(errno));
    }
    return false;
  }
  return true;
}

bool WriteExact(const int descriptor, const std::span<const std::byte> input, std::string& error) {
  std::size_t offset = 0;
  while (offset < input.size()) {
    ssize_t count = -1;
#if defined(MSG_NOSIGNAL)
    count = send(descriptor, input.data() + offset, input.size() - offset, MSG_NOSIGNAL);
    if (count < 0 && errno == ENOTSOCK) {
      count = write(descriptor, input.data() + offset, input.size() - offset);
    }
#else
    count = write(descriptor, input.data() + offset, input.size() - offset);
#endif
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    error = "Write failed: " + std::string(std::strerror(errno));
    return false;
  }
  return true;
}

}  // namespace reb
