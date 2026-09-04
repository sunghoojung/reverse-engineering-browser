#include "reb/debugger_transport.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace reb {

namespace detail {

bool IsDebuggerLoopbackSockaddr(const sockaddr* const address,
                                const std::size_t address_length) noexcept {
  if (address == nullptr) {
    return false;
  }
  if (address->sa_family == AF_INET && address_length >= sizeof(sockaddr_in)) {
    const auto* const ipv4 = reinterpret_cast<const sockaddr_in*>(address);
    return (ntohl(ipv4->sin_addr.s_addr) >> 24U) == 127U;
  }
  if (address->sa_family == AF_INET6 && address_length >= sizeof(sockaddr_in6)) {
    const auto* const ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
    return IN6_IS_ADDR_LOOPBACK(&ipv6->sin6_addr) != 0;
  }
  return false;
}

}  // namespace detail

namespace {

constexpr std::chrono::milliseconds kConnectTimeout(2'000);
constexpr std::chrono::milliseconds kFrameIoTimeout(5'000);
constexpr std::string_view kWebSocketScheme = "ws://";
constexpr std::string_view kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr std::array<unsigned char, 3> kControlMagic = {'R', 'E', 'B'};

enum class ReadStatus : std::uint8_t {
  kComplete,
  kTimeout,
  kClosed,
  kError,
};

std::string ErrnoMessage(const std::string_view prefix) {
  return std::string(prefix) + ": " + std::strerror(errno);
}

bool FillRandomBytes(unsigned char* output, const std::size_t length, std::string& error) {
  const int descriptor = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    error = ErrnoMessage("Debugger transport could not open the system random source");
    return false;
  }
  std::size_t offset = 0;
  while (offset < length) {
    const ssize_t count = read(descriptor, output + offset, length - offset);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    error = count == 0 ? "Debugger transport random source closed unexpectedly"
                       : ErrnoMessage("Debugger transport random source failed");
    static_cast<void>(close(descriptor));
    return false;
  }
  if (close(descriptor) != 0) {
    error = ErrnoMessage("Debugger transport random source could not be closed");
    return false;
  }
  return true;
}

std::string Base64Encode(const unsigned char* input, const std::size_t length) {
  constexpr std::string_view alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string output;
  output.reserve(((length + 2U) / 3U) * 4U);
  for (std::size_t offset = 0; offset < length; offset += 3U) {
    const std::uint32_t first = input[offset];
    const std::uint32_t second = offset + 1U < length ? input[offset + 1U] : 0U;
    const std::uint32_t third = offset + 2U < length ? input[offset + 2U] : 0U;
    const std::uint32_t value = (first << 16U) | (second << 8U) | third;
    output.push_back(alphabet[(value >> 18U) & 0x3fU]);
    output.push_back(alphabet[(value >> 12U) & 0x3fU]);
    output.push_back(offset + 1U < length ? alphabet[(value >> 6U) & 0x3fU] : '=');
    output.push_back(offset + 2U < length ? alphabet[value & 0x3fU] : '=');
  }
  return output;
}

std::array<unsigned char, 20> Sha1(const std::string_view input) {
  std::vector<unsigned char> padded(input.begin(), input.end());
  const std::uint64_t bit_length = static_cast<std::uint64_t>(input.size()) * 8U;
  padded.push_back(0x80U);
  while ((padded.size() % 64U) != 56U) {
    padded.push_back(0U);
  }
  for (int shift = 56; shift >= 0; shift -= 8) {
    padded.push_back(
        static_cast<unsigned char>((bit_length >> static_cast<unsigned int>(shift)) & 0xffU));
  }

  std::uint32_t h0 = 0x67452301U;
  std::uint32_t h1 = 0xefcdab89U;
  std::uint32_t h2 = 0x98badcfeU;
  std::uint32_t h3 = 0x10325476U;
  std::uint32_t h4 = 0xc3d2e1f0U;
  for (std::size_t block = 0; block < padded.size(); block += 64U) {
    std::array<std::uint32_t, 80> words{};
    for (std::size_t index = 0; index < 16U; ++index) {
      const std::size_t offset = block + index * 4U;
      words[index] = (static_cast<std::uint32_t>(padded[offset]) << 24U) |
                     (static_cast<std::uint32_t>(padded[offset + 1U]) << 16U) |
                     (static_cast<std::uint32_t>(padded[offset + 2U]) << 8U) |
                     static_cast<std::uint32_t>(padded[offset + 3U]);
    }
    for (std::size_t index = 16U; index < words.size(); ++index) {
      words[index] = std::rotl(
          words[index - 3U] ^ words[index - 8U] ^ words[index - 14U] ^ words[index - 16U], 1);
    }

    std::uint32_t a = h0;
    std::uint32_t b = h1;
    std::uint32_t c = h2;
    std::uint32_t d = h3;
    std::uint32_t e = h4;
    for (std::size_t index = 0; index < words.size(); ++index) {
      std::uint32_t function = 0;
      std::uint32_t constant = 0;
      if (index < 20U) {
        function = (b & c) | ((~b) & d);
        constant = 0x5a827999U;
      } else if (index < 40U) {
        function = b ^ c ^ d;
        constant = 0x6ed9eba1U;
      } else if (index < 60U) {
        function = (b & c) | (b & d) | (c & d);
        constant = 0x8f1bbcdcU;
      } else {
        function = b ^ c ^ d;
        constant = 0xca62c1d6U;
      }
      const std::uint32_t temporary = std::rotl(a, 5) + function + e + constant + words[index];
      e = d;
      d = c;
      c = std::rotl(b, 30);
      b = a;
      a = temporary;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::array<unsigned char, 20> digest{};
  const std::array<std::uint32_t, 5> words = {h0, h1, h2, h3, h4};
  for (std::size_t index = 0; index < words.size(); ++index) {
    digest[index * 4U] = static_cast<unsigned char>((words[index] >> 24U) & 0xffU);
    digest[index * 4U + 1U] = static_cast<unsigned char>((words[index] >> 16U) & 0xffU);
    digest[index * 4U + 2U] = static_cast<unsigned char>((words[index] >> 8U) & 0xffU);
    digest[index * 4U + 3U] = static_cast<unsigned char>(words[index] & 0xffU);
  }
  return digest;
}

std::string Lowercase(std::string_view input) {
  std::string output(input);
  std::transform(output.begin(), output.end(), output.begin(), [](const char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  return output;
}

std::string_view Trim(std::string_view input) {
  while (!input.empty() && (input.front() == ' ' || input.front() == '\t')) {
    input.remove_prefix(1U);
  }
  while (!input.empty() && (input.back() == ' ' || input.back() == '\t')) {
    input.remove_suffix(1U);
  }
  return input;
}

bool ContainsHeaderToken(const std::string_view value, const std::string_view expected) {
  std::size_t start = 0;
  while (start <= value.size()) {
    const std::size_t end = value.find(',', start);
    const std::string token = Lowercase(Trim(value.substr(start, end - start)));
    if (token == expected) {
      return true;
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 1U;
  }
  return false;
}

bool PollDescriptor(const int descriptor,
                    const short events,
                    const std::chrono::milliseconds timeout,
                    bool& ready,
                    std::string& error) {
  pollfd entry{descriptor, events, 0};
  const auto started = std::chrono::steady_clock::now();
  auto remaining = timeout;
  while (true) {
    const auto bounded_count = std::clamp<std::int64_t>(remaining.count(), 0, INT_MAX);
    const int result = poll(&entry, 1, static_cast<int>(bounded_count));
    if (result > 0) {
      ready = (entry.revents & (events | POLLERR | POLLHUP | POLLNVAL)) != 0;
      return true;
    }
    if (result == 0) {
      ready = false;
      return true;
    }
    if (errno != EINTR) {
      error = ErrnoMessage("Debugger transport poll failed");
      return false;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    if (elapsed >= timeout) {
      ready = false;
      return true;
    }
    remaining = timeout - elapsed;
  }
}

bool SetSocketBlocking(const int descriptor, const bool blocking, std::string& error) {
  const int flags = fcntl(descriptor, F_GETFL, 0);
  if (flags < 0 ||
      fcntl(descriptor, F_SETFL, blocking ? flags & ~O_NONBLOCK : flags | O_NONBLOCK) < 0) {
    error = ErrnoMessage("Debugger transport could not configure its socket");
    return false;
  }
  return true;
}

int ConnectSocket(const DebuggerWebSocketEndpoint& endpoint, std::string& error) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* addresses = nullptr;
  const std::string port = std::to_string(endpoint.port);
  const int lookup = getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints, &addresses);
  if (lookup != 0) {
    error = std::string("Debugger transport could not resolve its loopback endpoint: ") +
            gai_strerror(lookup);
    return -1;
  }

  int connected = -1;
  std::string last_error = "Debugger transport could not connect to the browser";
  for (addrinfo* address = addresses; address != nullptr; address = address->ai_next) {
    if (!detail::IsDebuggerLoopbackSockaddr(address->ai_addr,
                                            static_cast<std::size_t>(address->ai_addrlen))) {
      last_error = "Debugger endpoint did not resolve to loopback";
      continue;
    }
    const int descriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (descriptor < 0) {
      last_error = ErrnoMessage("Debugger transport could not create its socket");
      continue;
    }
#if defined(SO_NOSIGPIPE)
    const int enabled = 1;
    static_cast<void>(setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)));
#endif
    const int descriptor_flags = fcntl(descriptor, F_GETFD, 0);
    if (descriptor_flags < 0 || fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
      last_error = ErrnoMessage("Debugger transport could not protect its socket");
      static_cast<void>(close(descriptor));
      continue;
    }
    if (!SetSocketBlocking(descriptor, false, last_error)) {
      static_cast<void>(close(descriptor));
      continue;
    }
    const int result = connect(descriptor, address->ai_addr, address->ai_addrlen);
    if (result != 0 && errno != EINPROGRESS) {
      last_error = ErrnoMessage("Debugger transport could not connect to the browser");
      static_cast<void>(close(descriptor));
      continue;
    }
    if (result != 0) {
      bool ready = false;
      if (!PollDescriptor(descriptor, POLLOUT, kConnectTimeout, ready, last_error) || !ready) {
        if (last_error.empty()) {
          last_error = "Debugger transport connection timed out";
        }
        static_cast<void>(close(descriptor));
        continue;
      }
      int socket_error = 0;
      socklen_t length = sizeof(socket_error);
      if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error, &length) != 0 ||
          socket_error != 0) {
        errno = socket_error == 0 ? errno : socket_error;
        last_error = ErrnoMessage("Debugger transport could not connect to the browser");
        static_cast<void>(close(descriptor));
        continue;
      }
    }
    connected = descriptor;
    break;
  }
  freeaddrinfo(addresses);
  if (connected < 0) {
    error = last_error;
  }
  return connected;
}

bool SendAllSocket(const int descriptor,
                   const unsigned char* data,
                   const std::size_t size,
                   const std::chrono::steady_clock::time_point deadline,
                   std::string& error) {
  std::size_t offset = 0;
  while (offset < size) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      error = "Debugger WebSocket send timed out";
      return false;
    }
    bool ready = false;
    if (!PollDescriptor(descriptor, POLLOUT,
                        std::chrono::ceil<std::chrono::milliseconds>(deadline - now), ready,
                        error)) {
      return false;
    }
    if (!ready) {
      error = "Debugger WebSocket send timed out";
      return false;
    }
#if defined(MSG_NOSIGNAL)
    constexpr int flags = MSG_NOSIGNAL;
#else
    constexpr int flags = 0;
#endif
    const ssize_t count = send(descriptor, data + offset, size - offset, flags);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      continue;
    }
    error = count == 0 ? "Debugger WebSocket closed while sending"
                       : ErrnoMessage("Debugger WebSocket send failed");
    return false;
  }
  return true;
}

ReadStatus ReadExactSocket(const int descriptor,
                           unsigned char* output,
                           const std::size_t size,
                           const std::chrono::steady_clock::time_point deadline,
                           std::string& error) {
  std::size_t offset = 0;
  while (offset < size) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      error = "Debugger WebSocket frame timed out";
      return ReadStatus::kTimeout;
    }
    bool ready = false;
    if (!PollDescriptor(descriptor, POLLIN,
                        std::chrono::ceil<std::chrono::milliseconds>(deadline - now), ready,
                        error)) {
      return ReadStatus::kError;
    }
    if (!ready) {
      error = "Debugger WebSocket frame timed out";
      return ReadStatus::kTimeout;
    }
    const ssize_t count = recv(descriptor, output + offset, size - offset, 0);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count == 0) {
      return ReadStatus::kClosed;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      continue;
    }
    error = ErrnoMessage("Debugger WebSocket receive failed");
    return ReadStatus::kError;
  }
  return ReadStatus::kComplete;
}

bool SendHandshake(const int descriptor,
                   const DebuggerWebSocketEndpoint& endpoint,
                   std::string& key,
                   std::string& error) {
  std::array<unsigned char, 16> random{};
  if (!FillRandomBytes(random.data(), random.size(), error)) {
    return false;
  }
  key = Base64Encode(random.data(), random.size());
  const std::string request =
      "GET " + endpoint.path + " HTTP/1.1\r\nHost: " + endpoint.host_header + ":" +
      std::to_string(endpoint.port) + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
      "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
  return SendAllSocket(descriptor, reinterpret_cast<const unsigned char*>(request.data()),
                       request.size(), std::chrono::steady_clock::now() + kConnectTimeout, error);
}

bool ReadHandshake(const int descriptor, const std::string_view key, std::string& error) {
  std::string response;
  response.reserve(4'096U);
  const auto deadline = std::chrono::steady_clock::now() + kConnectTimeout;
  while (response.find("\r\n\r\n") == std::string::npos) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      error = "Debugger WebSocket handshake timed out";
      return false;
    }
    bool ready = false;
    if (!PollDescriptor(descriptor, POLLIN,
                        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now),
                        ready, error)) {
      return false;
    }
    if (!ready) {
      error = "Debugger WebSocket handshake timed out";
      return false;
    }
    std::array<char, 4'096> chunk{};
    const ssize_t count = recv(descriptor, chunk.data(), chunk.size(), 0);
    if (count == 0) {
      error = "Debugger WebSocket closed during handshake";
      return false;
    }
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      error = ErrnoMessage("Debugger WebSocket handshake failed");
      return false;
    }
    response.append(chunk.data(), static_cast<std::size_t>(count));
    if (response.size() > kDebuggerMaxHandshakeBytes) {
      error = "Debugger WebSocket handshake is oversized";
      return false;
    }
  }

  const std::size_t end = response.find("\r\n\r\n");
  if (end + 4U != response.size()) {
    error = "Debugger WebSocket sent data during handshake";
    return false;
  }
  const std::string_view headers(response.data(), end);
  const std::size_t first_line_end = headers.find("\r\n");
  const std::string_view status = headers.substr(0, first_line_end);
  if (!status.starts_with("HTTP/1.1 101 ")) {
    error = "Debugger WebSocket rejected the connection: " + std::string(status);
    return false;
  }

  std::string accept;
  std::string upgrade;
  std::string connection;
  std::size_t position =
      first_line_end == std::string_view::npos ? headers.size() : first_line_end + 2U;
  while (position < headers.size()) {
    const std::size_t line_end = headers.find("\r\n", position);
    const std::string_view line = headers.substr(position, line_end - position);
    const std::size_t colon = line.find(':');
    if (colon != std::string_view::npos) {
      const std::string name = Lowercase(Trim(line.substr(0, colon)));
      const std::string value(Trim(line.substr(colon + 1U)));
      if (name == "sec-websocket-accept") {
        accept = value;
      } else if (name == "upgrade") {
        upgrade = Lowercase(value);
      } else if (name == "connection") {
        connection = value;
      }
    }
    if (line_end == std::string_view::npos) {
      break;
    }
    position = line_end + 2U;
  }
  const std::string digest_input = std::string(key) + std::string(kWebSocketGuid);
  const auto digest = Sha1(digest_input);
  const std::string expected = Base64Encode(digest.data(), digest.size());
  if (accept != expected || upgrade != "websocket" || !ContainsHeaderToken(connection, "upgrade")) {
    error = "Debugger WebSocket returned an invalid handshake";
    return false;
  }
  return true;
}

struct DebuggerWebSocketFrame final {
  bool final = false;
  std::uint8_t opcode = 0;
  std::string payload;
};

ReadStatus ReadDebuggerWebSocketFrame(const int descriptor,
                                      const std::chrono::steady_clock::time_point deadline,
                                      const std::size_t maximum_data_bytes,
                                      DebuggerWebSocketFrame& frame,
                                      std::string& error) {
  frame = {};
  std::array<unsigned char, 2> prefix{};
  ReadStatus status = ReadExactSocket(descriptor, prefix.data(), prefix.size(), deadline, error);
  if (status != ReadStatus::kComplete) {
    return status;
  }

  frame.final = (prefix[0] & 0x80U) != 0U;
  frame.opcode = prefix[0] & 0x0fU;
  const bool reserved = (prefix[0] & 0x70U) != 0U;
  const bool masked = (prefix[1] & 0x80U) != 0U;
  const bool supported_opcode =
      frame.opcode <= 0x2U || (frame.opcode >= 0x8U && frame.opcode <= 0x0aU);
  if (reserved || masked || !supported_opcode) {
    error = "Debugger WebSocket returned an unsupported frame";
    return ReadStatus::kError;
  }

  const bool control_frame = frame.opcode >= 0x8U;
  if (control_frame && !frame.final) {
    error = "Debugger WebSocket returned a fragmented control frame";
    return ReadStatus::kError;
  }

  std::uint64_t length = prefix[1] & 0x7fU;
  if (length == 126U) {
    std::array<unsigned char, 2> extended{};
    status = ReadExactSocket(descriptor, extended.data(), extended.size(), deadline, error);
    if (status != ReadStatus::kComplete) {
      return status;
    }
    length = (static_cast<std::uint64_t>(extended[0]) << 8U) | extended[1];
    if (length < 126U) {
      error = "Debugger WebSocket returned a noncanonical frame length";
      return ReadStatus::kError;
    }
  } else if (length == 127U) {
    std::array<unsigned char, 8> extended{};
    status = ReadExactSocket(descriptor, extended.data(), extended.size(), deadline, error);
    if (status != ReadStatus::kComplete) {
      return status;
    }
    if ((extended[0] & 0x80U) != 0U) {
      error = "Debugger WebSocket returned an invalid frame length";
      return ReadStatus::kError;
    }
    length = 0;
    for (const unsigned char byte : extended) {
      length = (length << 8U) | byte;
    }
    if (length <= std::numeric_limits<std::uint16_t>::max()) {
      error = "Debugger WebSocket returned a noncanonical frame length";
      return ReadStatus::kError;
    }
  }

  const std::uint64_t maximum_bytes =
      control_frame ? 125U : static_cast<std::uint64_t>(maximum_data_bytes);
  if (length > maximum_bytes || (frame.opcode == 0x8U && length == 1U)) {
    error = length > maximum_bytes ? "Debugger WebSocket message is oversized"
                                   : "Debugger WebSocket returned a malformed close frame";
    return ReadStatus::kError;
  }

  frame.payload.resize(static_cast<std::size_t>(length));
  return ReadExactSocket(descriptor, reinterpret_cast<unsigned char*>(frame.payload.data()),
                         frame.payload.size(), deadline, error);
}

bool WriteAllDescriptor(const int descriptor,
                        const unsigned char* data,
                        const std::size_t size,
                        std::string& error) {
  std::size_t offset = 0;
  while (offset < size) {
    const ssize_t count = write(descriptor, data + offset, size - offset);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    error = count == 0 ? "Debugger control pipe closed while writing"
                       : ErrnoMessage("Debugger control pipe write failed");
    return false;
  }
  return true;
}

}  // namespace

bool ParseDebuggerWebSocketUrl(const std::string_view url,
                               DebuggerWebSocketEndpoint& endpoint,
                               std::string& error) {
  endpoint = {};
  if (url.size() > kDebuggerMaxWebSocketUrlBytes) {
    error = "The debugger WebSocket URL is oversized";
    return false;
  }
  if (!url.starts_with(kWebSocketScheme) || url.find('#') != std::string_view::npos) {
    error = url.starts_with(kWebSocketScheme) ? "The debugger WebSocket URL is malformed"
                                              : "The debugger WebSocket must use loopback ws://";
    return false;
  }
  std::string_view remainder = url.substr(kWebSocketScheme.size());
  const std::size_t path_start = remainder.find_first_of("/?");
  const std::string_view authority = remainder.substr(0, path_start);
  std::string_view path =
      path_start == std::string_view::npos ? std::string_view{} : remainder.substr(path_start);
  if (authority.empty() || authority.find('@') != std::string_view::npos) {
    error = "The debugger WebSocket URL is malformed";
    return false;
  }

  std::string_view host;
  std::string_view port_text;
  if (authority.front() == '[') {
    const std::size_t bracket = authority.find(']');
    if (bracket == std::string_view::npos) {
      error = "The debugger WebSocket URL is malformed";
      return false;
    }
    host = authority.substr(1U, bracket - 1U);
    const std::string_view suffix = authority.substr(bracket + 1U);
    if (!suffix.empty()) {
      if (suffix.front() != ':' || suffix.size() == 1U) {
        error = "The debugger WebSocket URL is malformed";
        return false;
      }
      port_text = suffix.substr(1U);
    }
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon == std::string_view::npos) {
      host = authority;
    } else {
      host = authority.substr(0, colon);
      port_text = authority.substr(colon + 1U);
      if (host.empty() || port_text.empty() || host.find(':') != std::string_view::npos) {
        error = "The debugger WebSocket URL is malformed";
        return false;
      }
    }
  }

  const std::string normalized_host = Lowercase(host);
  if (normalized_host != "127.0.0.1" && normalized_host != "localhost" &&
      normalized_host != "::1") {
    error = "The debugger WebSocket must use loopback ws://";
    return false;
  }
  unsigned int port = 80U;
  if (!port_text.empty()) {
    const auto parsed =
        std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (parsed.ec != std::errc{} || parsed.ptr != port_text.data() + port_text.size() ||
        port == 0U || port > std::numeric_limits<std::uint16_t>::max()) {
      error = "The debugger WebSocket URL is malformed";
      return false;
    }
  }
  if (path.empty()) {
    path = "/";
  } else if (path.front() == '?') {
    endpoint.path = "/";
  }
  if (endpoint.path.empty()) {
    endpoint.path.assign(path);
  } else {
    endpoint.path.append(path);
  }
  if (std::any_of(endpoint.path.begin(), endpoint.path.end(), [](const char character) {
        const auto byte = static_cast<unsigned char>(character);
        return byte < 0x20U || byte > 0x7eU;
      })) {
    error = "The debugger WebSocket URL is malformed";
    endpoint = {};
    return false;
  }
  endpoint.host = normalized_host;
  endpoint.host_header = normalized_host == "::1" ? "[::1]" : normalized_host;
  endpoint.port = static_cast<std::uint16_t>(port);
  return true;
}

DebuggerTransport::~DebuggerTransport() {
  if (descriptor_ >= 0) {
    static_cast<void>(close(descriptor_));
  }
}

bool DebuggerTransport::Connect(const std::string_view url, std::string& error) {
  if (descriptor_ >= 0) {
    error = "Debugger transport is already connected";
    return false;
  }
  DebuggerWebSocketEndpoint endpoint;
  if (!ParseDebuggerWebSocketUrl(url, endpoint, error)) {
    return false;
  }
  const int descriptor = ConnectSocket(endpoint, error);
  if (descriptor < 0) {
    return false;
  }
  std::string key;
  if (!SendHandshake(descriptor, endpoint, key, error) || !ReadHandshake(descriptor, key, error)) {
    static_cast<void>(close(descriptor));
    return false;
  }
  descriptor_ = descriptor;
  return true;
}

bool DebuggerTransport::SendFrame(const std::uint8_t opcode,
                                  const std::string_view payload,
                                  std::string& error) {
  if (descriptor_ < 0) {
    error = "Debugger WebSocket is closed";
    return false;
  }
  std::array<unsigned char, 14> header{};
  std::size_t header_size = 2U;
  header[0] = static_cast<unsigned char>(0x80U | opcode);
  const std::uint64_t length = payload.size();
  if (length < 126U) {
    header[1] = static_cast<unsigned char>(0x80U | length);
  } else if (length <= std::numeric_limits<std::uint16_t>::max()) {
    header[1] = 0xfeU;
    header[2] = static_cast<unsigned char>((length >> 8U) & 0xffU);
    header[3] = static_cast<unsigned char>(length & 0xffU);
    header_size = 4U;
  } else {
    header[1] = 0xffU;
    for (std::size_t index = 0; index < 8U; ++index) {
      header[2U + index] = static_cast<unsigned char>((length >> ((7U - index) * 8U)) & 0xffU);
    }
    header_size = 10U;
  }
  std::array<unsigned char, 4> mask{};
  if (!FillRandomBytes(mask.data(), mask.size(), error)) {
    return false;
  }
  std::copy(mask.begin(), mask.end(), header.begin() + static_cast<std::ptrdiff_t>(header_size));
  header_size += mask.size();
  const auto deadline = std::chrono::steady_clock::now() + kFrameIoTimeout;
  if (!SendAllSocket(descriptor_, header.data(), header_size, deadline, error)) {
    return false;
  }
  std::array<unsigned char, 16U * 1024U> buffer{};
  std::size_t offset = 0;
  while (offset < payload.size()) {
    const std::size_t chunk_size = std::min(buffer.size(), payload.size() - offset);
    for (std::size_t index = 0; index < chunk_size; ++index) {
      buffer[index] = static_cast<unsigned char>(payload[offset + index]) ^
                      mask[(offset + index) % mask.size()];
    }
    if (!SendAllSocket(descriptor_, buffer.data(), chunk_size, deadline, error)) {
      return false;
    }
    offset += chunk_size;
  }
  return true;
}

bool DebuggerTransport::SendText(const std::string_view message, std::string& error) {
  if (message.size() > kDebuggerMaxCommandBytes) {
    error = "Debugger command is oversized";
    return false;
  }
  return SendFrame(0x1U, message, error);
}

DebuggerReceiveStatus DebuggerTransport::ReceiveText(std::string& message,
                                                     const std::chrono::milliseconds timeout,
                                                     std::string& error) {
  message.clear();
  if (descriptor_ < 0) {
    error = "Debugger WebSocket is closed";
    return DebuggerReceiveStatus::kClosed;
  }
  const auto deadline =
      std::chrono::steady_clock::now() + std::max(timeout, std::chrono::milliseconds(0));
  bool fragmented_message = false;
  while (true) {
    const auto now = std::chrono::steady_clock::now();
    const auto remaining =
        now >= deadline ? std::chrono::milliseconds(0)
                        : std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    bool ready = false;
    if (!PollDescriptor(descriptor_, POLLIN, remaining, ready, error)) {
      return DebuggerReceiveStatus::kError;
    }
    if (!ready) {
      if (fragmented_message) {
        error = "Debugger WebSocket fragmented message timed out";
        return DebuggerReceiveStatus::kError;
      }
      return DebuggerReceiveStatus::kTimeout;
    }

    DebuggerWebSocketFrame frame;
    const std::size_t remaining_capacity = kDebuggerMaxMessageBytes - message.size();
    const ReadStatus frame_status =
        ReadDebuggerWebSocketFrame(descriptor_, deadline, remaining_capacity, frame, error);
    if (frame_status == ReadStatus::kClosed) {
      return DebuggerReceiveStatus::kClosed;
    }
    if (frame_status == ReadStatus::kTimeout || frame_status == ReadStatus::kError) {
      return DebuggerReceiveStatus::kError;
    }

    if (frame.opcode == 0x8U) {
      if (!SendFrame(0x8U, frame.payload, error)) {
        return DebuggerReceiveStatus::kError;
      }
      return DebuggerReceiveStatus::kClosed;
    }
    if (frame.opcode == 0x9U) {
      if (!SendFrame(0x0aU, frame.payload, error)) {
        return DebuggerReceiveStatus::kError;
      }
      if (!fragmented_message) {
        return DebuggerReceiveStatus::kTimeout;
      }
      continue;
    }
    if (frame.opcode == 0x0aU) {
      if (!fragmented_message) {
        return DebuggerReceiveStatus::kTimeout;
      }
      continue;
    }

    if (frame.opcode == 0x2U) {
      error = "Debugger WebSocket sent a non-text message";
      return DebuggerReceiveStatus::kError;
    }
    if (frame.opcode == 0x1U) {
      if (fragmented_message) {
        error = "Debugger WebSocket started a new message before completing a fragmented message";
        return DebuggerReceiveStatus::kError;
      }
      message = std::move(frame.payload);
      if (frame.final) {
        return DebuggerReceiveStatus::kMessage;
      }
      fragmented_message = true;
      continue;
    }
    if (!fragmented_message) {
      error = "Debugger WebSocket returned an unexpected continuation frame";
      return DebuggerReceiveStatus::kError;
    }
    message.append(frame.payload);
    if (frame.final) {
      return DebuggerReceiveStatus::kMessage;
    }
  }
}

bool ReadDebuggerControlMessage(const int descriptor,
                                const std::size_t maximum_bytes,
                                std::string& message,
                                bool& reached_end,
                                std::string& error) {
  message.clear();
  reached_end = false;
  std::array<unsigned char, 8> header{};
  std::size_t offset = 0;
  while (offset < header.size()) {
    const ssize_t count = read(descriptor, header.data() + offset, header.size() - offset);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count == 0) {
      if (offset == 0) {
        reached_end = true;
        return true;
      }
      error = "Debugger control pipe closed during a frame header";
      return false;
    }
    if (errno == EINTR) {
      continue;
    }
    error = ErrnoMessage("Debugger control pipe read failed");
    return false;
  }
  if (!std::equal(kControlMagic.begin(), kControlMagic.end(), header.begin()) ||
      header[3] != kDebuggerControlProtocolVersion) {
    error = "Debugger control message has an invalid protocol header";
    return false;
  }
  const std::uint32_t length = (static_cast<std::uint32_t>(header[4]) << 24U) |
                               (static_cast<std::uint32_t>(header[5]) << 16U) |
                               (static_cast<std::uint32_t>(header[6]) << 8U) |
                               static_cast<std::uint32_t>(header[7]);
  if (length > maximum_bytes) {
    error = "Debugger control message is oversized";
    return false;
  }
  message.resize(length);
  offset = 0;
  while (offset < message.size()) {
    const ssize_t count = read(descriptor, message.data() + offset, message.size() - offset);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count == 0) {
      error = "Debugger control pipe closed during a frame body";
      return false;
    }
    if (errno == EINTR) {
      continue;
    }
    error = ErrnoMessage("Debugger control pipe read failed");
    return false;
  }
  return true;
}

bool WriteDebuggerControlMessage(const int descriptor,
                                 const std::string_view message,
                                 std::string& error) {
  if (message.size() > std::numeric_limits<std::uint32_t>::max()) {
    error = "Debugger control message is oversized";
    return false;
  }
  const std::uint32_t length = static_cast<std::uint32_t>(message.size());
  const std::array<unsigned char, 8> header = {
      kControlMagic[0],
      kControlMagic[1],
      kControlMagic[2],
      kDebuggerControlProtocolVersion,
      static_cast<unsigned char>((length >> 24U) & 0xffU),
      static_cast<unsigned char>((length >> 16U) & 0xffU),
      static_cast<unsigned char>((length >> 8U) & 0xffU),
      static_cast<unsigned char>(length & 0xffU),
  };
  return WriteAllDescriptor(descriptor, header.data(), header.size(), error) &&
         WriteAllDescriptor(descriptor, reinterpret_cast<const unsigned char*>(message.data()),
                            message.size(), error);
}

}  // namespace reb
