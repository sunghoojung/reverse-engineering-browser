#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "reb/debugger_transport.hpp"

namespace reb {

class DebuggerTransportTestPeer final {
 public:
  static void AdoptDescriptor(DebuggerTransport& transport, const int descriptor) {
    transport.descriptor_ = descriptor;
  }
};

}  // namespace reb

namespace {

#define CHECK(condition)                                                                         \
  do {                                                                                           \
    if (!(condition)) {                                                                          \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition << '\n'; \
      std::exit(1);                                                                              \
    }                                                                                            \
  } while (false)

class Pipe final {
 public:
  Pipe() { CHECK(pipe(descriptors_.data()) == 0); }
  Pipe(const Pipe&) = delete;
  Pipe& operator=(const Pipe&) = delete;
  ~Pipe() {
    for (const int descriptor : descriptors_) {
      if (descriptor >= 0) {
        static_cast<void>(close(descriptor));
      }
    }
  }

  [[nodiscard]] int ReadDescriptor() const noexcept { return descriptors_[0]; }
  [[nodiscard]] int WriteDescriptor() const noexcept { return descriptors_[1]; }
  void CloseWrite() {
    CHECK(descriptors_[1] >= 0);
    CHECK(close(descriptors_[1]) == 0);
    descriptors_[1] = -1;
  }

 private:
  std::array<int, 2> descriptors_ = {-1, -1};
};

class SocketPair final {
 public:
  SocketPair() {
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors_.data()) == 0);
    const int flags = fcntl(descriptors_[0], F_GETFL, 0);
    CHECK(flags >= 0);
    CHECK(fcntl(descriptors_[0], F_SETFL, flags | O_NONBLOCK) == 0);
  }
  SocketPair(const SocketPair&) = delete;
  SocketPair& operator=(const SocketPair&) = delete;
  ~SocketPair() {
    for (const int descriptor : descriptors_) {
      if (descriptor >= 0) {
        static_cast<void>(close(descriptor));
      }
    }
  }

  [[nodiscard]] int ReleaseTransportDescriptor() noexcept {
    const int descriptor = descriptors_[0];
    descriptors_[0] = -1;
    return descriptor;
  }
  [[nodiscard]] int PeerDescriptor() const noexcept { return descriptors_[1]; }

 private:
  std::array<int, 2> descriptors_ = {-1, -1};
};

void WriteAll(const int descriptor, const std::span<const unsigned char> bytes) {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = write(descriptor, bytes.data() + offset, bytes.size() - offset);
    CHECK(count > 0);
    offset += static_cast<std::size_t>(count);
  }
}

std::vector<unsigned char> ServerFrame(const bool final,
                                       const std::uint8_t opcode,
                                       const std::string_view payload) {
  CHECK(payload.size() < 126U);
  std::vector<unsigned char> frame = {
      static_cast<unsigned char>((final ? 0x80U : 0U) | opcode),
      static_cast<unsigned char>(payload.size()),
  };
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

void Append(std::vector<unsigned char>& destination, const std::vector<unsigned char>& source) {
  destination.insert(destination.end(), source.begin(), source.end());
}

reb::DebuggerReceiveStatus ReceiveFrames(const std::span<const unsigned char> frames,
                                         std::string& message,
                                         std::string& error) {
  SocketPair sockets;
  reb::DebuggerTransport transport;
  reb::DebuggerTransportTestPeer::AdoptDescriptor(transport, sockets.ReleaseTransportDescriptor());
  WriteAll(sockets.PeerDescriptor(), frames);
  return transport.ReceiveText(message, std::chrono::milliseconds(250), error);
}

void CheckPartialFrameTimeout(const std::span<const unsigned char> frame_prefix) {
  SocketPair sockets;
  reb::DebuggerTransport transport;
  reb::DebuggerTransportTestPeer::AdoptDescriptor(transport, sockets.ReleaseTransportDescriptor());
  WriteAll(sockets.PeerDescriptor(), frame_prefix);
  std::string message;
  std::string error;
  const auto started = std::chrono::steady_clock::now();
  CHECK(transport.ReceiveText(message, std::chrono::milliseconds(50), error) ==
        reb::DebuggerReceiveStatus::kError);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  CHECK(elapsed < std::chrono::seconds(1));
  CHECK(error == "Debugger WebSocket frame timed out");
}

void TestLoopbackSockaddrValidation() {
  sockaddr_in ipv4{};
  ipv4.sin_family = AF_INET;
  CHECK(inet_pton(AF_INET, "127.42.0.9", &ipv4.sin_addr) == 1);
  CHECK(reb::detail::IsDebuggerLoopbackSockaddr(reinterpret_cast<const sockaddr*>(&ipv4),
                                                sizeof(ipv4)));
  CHECK(inet_pton(AF_INET, "192.0.2.10", &ipv4.sin_addr) == 1);
  CHECK(!reb::detail::IsDebuggerLoopbackSockaddr(reinterpret_cast<const sockaddr*>(&ipv4),
                                                 sizeof(ipv4)));
  CHECK(!reb::detail::IsDebuggerLoopbackSockaddr(reinterpret_cast<const sockaddr*>(&ipv4),
                                                 sizeof(ipv4) - 1U));

  sockaddr_in6 ipv6{};
  ipv6.sin6_family = AF_INET6;
  CHECK(inet_pton(AF_INET6, "::1", &ipv6.sin6_addr) == 1);
  CHECK(reb::detail::IsDebuggerLoopbackSockaddr(reinterpret_cast<const sockaddr*>(&ipv6),
                                                sizeof(ipv6)));
  CHECK(inet_pton(AF_INET6, "2001:db8::1", &ipv6.sin6_addr) == 1);
  CHECK(!reb::detail::IsDebuggerLoopbackSockaddr(reinterpret_cast<const sockaddr*>(&ipv6),
                                                 sizeof(ipv6)));
  CHECK(!reb::detail::IsDebuggerLoopbackSockaddr(nullptr, 0));
}

void TestPartialFrameTimeouts() {
  const std::array<unsigned char, 1> partial_prefix = {0x81U};
  CheckPartialFrameTimeout(partial_prefix);
  const std::array<unsigned char, 3> partial_length = {0x81U, 126U, 0U};
  CheckPartialFrameTimeout(partial_length);
  const std::array<unsigned char, 4> partial_payload = {0x81U, 5U, 'o', 'k'};
  CheckPartialFrameTimeout(partial_payload);
}

void TestFragmentedMessageReassembly() {
  std::vector<unsigned char> frames;
  Append(frames, ServerFrame(false, 0x1U, "{\"id\":"));
  Append(frames, ServerFrame(true, 0x9U, "p"));
  Append(frames, ServerFrame(false, 0x0U, "1,"));
  Append(frames, ServerFrame(true, 0x0U, "\"result\":{}}"));
  std::string message;
  std::string error;
  CHECK(ReceiveFrames(frames, message, error) == reb::DebuggerReceiveStatus::kMessage);
  CHECK(message == "{\"id\":1,\"result\":{}}");
}

void TestMalformedFragmentation() {
  std::string message;
  std::string error;
  const auto unexpected_continuation = ServerFrame(true, 0x0U, "orphan");
  CHECK(ReceiveFrames(unexpected_continuation, message, error) ==
        reb::DebuggerReceiveStatus::kError);
  CHECK(error == "Debugger WebSocket returned an unexpected continuation frame");

  std::vector<unsigned char> restarted;
  Append(restarted, ServerFrame(false, 0x1U, "first"));
  Append(restarted, ServerFrame(true, 0x1U, "second"));
  CHECK(ReceiveFrames(restarted, message, error) == reb::DebuggerReceiveStatus::kError);
  CHECK(error == "Debugger WebSocket started a new message before completing a fragmented message");

  const auto fragmented_ping = ServerFrame(false, 0x9U, "p");
  CHECK(ReceiveFrames(fragmented_ping, message, error) == reb::DebuggerReceiveStatus::kError);
  CHECK(error == "Debugger WebSocket returned a fragmented control frame");
}

void TestCanonicalFrameLengths() {
  std::string message;
  std::string error;
  const std::array<unsigned char, 4> short_sixteen_bit = {0x81U, 126U, 0U, 125U};
  CHECK(ReceiveFrames(short_sixteen_bit, message, error) == reb::DebuggerReceiveStatus::kError);
  CHECK(error == "Debugger WebSocket returned a noncanonical frame length");

  const std::array<unsigned char, 10> short_sixty_four_bit = {
      0x81U, 127U, 0U, 0U, 0U, 0U, 0U, 0U, 0xffU, 0xffU,
  };
  CHECK(ReceiveFrames(short_sixty_four_bit, message, error) == reb::DebuggerReceiveStatus::kError);
  CHECK(error == "Debugger WebSocket returned a noncanonical frame length");
}

}  // namespace

int main() {
  TestLoopbackSockaddrValidation();
  TestPartialFrameTimeouts();
  TestFragmentedMessageReassembly();
  TestMalformedFragmentation();
  TestCanonicalFrameLengths();

  reb::DebuggerWebSocketEndpoint endpoint;
  std::string error;
  CHECK(reb::ParseDebuggerWebSocketUrl("ws://127.0.0.1:9222/devtools/page/one?token=value",
                                       endpoint, error));
  CHECK(endpoint.host == "127.0.0.1");
  CHECK(endpoint.host_header == "127.0.0.1");
  CHECK(endpoint.port == 9222);
  CHECK(endpoint.path == "/devtools/page/one?token=value");

  CHECK(reb::ParseDebuggerWebSocketUrl("ws://[::1]/devtools/browser/id", endpoint, error));
  CHECK(endpoint.host == "::1");
  CHECK(endpoint.host_header == "[::1]");
  CHECK(endpoint.port == 80);
  CHECK(endpoint.path == "/devtools/browser/id");

  CHECK(reb::ParseDebuggerWebSocketUrl("ws://LOCALHOST?target=one", endpoint, error));
  CHECK(endpoint.host == "localhost");
  CHECK(endpoint.path == "/?target=one");

  CHECK(!reb::ParseDebuggerWebSocketUrl("wss://127.0.0.1/devtools/page/one", endpoint, error));
  CHECK(error == "The debugger WebSocket must use loopback ws://");
  CHECK(!reb::ParseDebuggerWebSocketUrl("ws://192.0.2.10/devtools/page/one", endpoint, error));
  CHECK(error == "The debugger WebSocket must use loopback ws://");
  CHECK(!reb::ParseDebuggerWebSocketUrl("ws://user@localhost/devtools/page/one", endpoint, error));
  CHECK(!reb::ParseDebuggerWebSocketUrl("ws://localhost:0/devtools/page/one", endpoint, error));
  CHECK(!reb::ParseDebuggerWebSocketUrl("ws://localhost:65536/devtools/page/one", endpoint, error));
  CHECK(!reb::ParseDebuggerWebSocketUrl("ws://localhost/devtools/page/one#fragment", endpoint,
                                        error));
  CHECK(!reb::ParseDebuggerWebSocketUrl("ws://localhost/devtools/\npage", endpoint, error));
  const std::string oversized_url(reb::kDebuggerMaxWebSocketUrlBytes + 1U, 'a');
  CHECK(!reb::ParseDebuggerWebSocketUrl(oversized_url, endpoint, error));
  CHECK(error == "The debugger WebSocket URL is oversized");

  Pipe accepted;
  const std::string expected = "{\"id\":1,\"method\":\"Runtime.enable\"}";
  CHECK(reb::WriteDebuggerControlMessage(accepted.WriteDescriptor(), expected, error));
  std::string actual;
  bool reached_end = false;
  CHECK(reb::ReadDebuggerControlMessage(accepted.ReadDescriptor(), reb::kDebuggerMaxCommandBytes,
                                        actual, reached_end, error));
  CHECK(!reached_end);
  CHECK(actual == expected);

  Pipe ready;
  CHECK(reb::WriteDebuggerControlMessage(ready.WriteDescriptor(), {}, error));
  CHECK(reb::ReadDebuggerControlMessage(ready.ReadDescriptor(), reb::kDebuggerMaxCommandBytes,
                                        actual, reached_end, error));
  CHECK(!reached_end);
  CHECK(actual.empty());

  Pipe oversized;
  constexpr std::uint32_t oversized_length =
      static_cast<std::uint32_t>(reb::kDebuggerMaxCommandBytes + 1U);
  const std::array<unsigned char, 8> oversized_header = {
      'R',
      'E',
      'B',
      reb::kDebuggerControlProtocolVersion,
      static_cast<unsigned char>((oversized_length >> 24U) & 0xffU),
      static_cast<unsigned char>((oversized_length >> 16U) & 0xffU),
      static_cast<unsigned char>((oversized_length >> 8U) & 0xffU),
      static_cast<unsigned char>(oversized_length & 0xffU),
  };
  CHECK(write(oversized.WriteDescriptor(), oversized_header.data(), oversized_header.size()) ==
        static_cast<ssize_t>(oversized_header.size()));
  CHECK(!reb::ReadDebuggerControlMessage(oversized.ReadDescriptor(), reb::kDebuggerMaxCommandBytes,
                                         actual, reached_end, error));
  CHECK(error == "Debugger control message is oversized");

  Pipe invalid_version;
  const std::array<unsigned char, 8> invalid_header = {'R', 'E', 'B', 2U, 0U, 0U, 0U, 0U};
  CHECK(write(invalid_version.WriteDescriptor(), invalid_header.data(), invalid_header.size()) ==
        static_cast<ssize_t>(invalid_header.size()));
  CHECK(!reb::ReadDebuggerControlMessage(
      invalid_version.ReadDescriptor(), reb::kDebuggerMaxCommandBytes, actual, reached_end, error));
  CHECK(error == "Debugger control message has an invalid protocol header");

  Pipe closed;
  closed.CloseWrite();
  CHECK(reb::ReadDebuggerControlMessage(closed.ReadDescriptor(), reb::kDebuggerMaxCommandBytes,
                                        actual, reached_end, error));
  CHECK(reached_end);

  std::cout << "debugger_transport_test passed\n";
  return 0;
}
