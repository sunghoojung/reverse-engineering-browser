#ifndef REB_DEBUGGER_TRANSPORT_HPP_
#define REB_DEBUGGER_TRANSPORT_HPP_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

struct sockaddr;

namespace reb {

inline constexpr std::size_t kDebuggerMaxCommandBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kDebuggerMaxMessageBytes = 64U * 1024U * 1024U;
inline constexpr std::size_t kDebuggerMaxHandshakeBytes = 64U * 1024U;
inline constexpr std::size_t kDebuggerMaxWebSocketUrlBytes = 64U * 1024U;
inline constexpr std::uint8_t kDebuggerControlProtocolVersion = 1;

struct DebuggerWebSocketEndpoint final {
  std::string host;
  std::string host_header;
  std::string path;
  std::uint16_t port = 0;
};

namespace detail {

[[nodiscard]] bool IsDebuggerLoopbackSockaddr(const sockaddr* address,
                                              std::size_t address_length) noexcept;

}  // namespace detail

[[nodiscard]] bool ParseDebuggerWebSocketUrl(std::string_view url,
                                             DebuggerWebSocketEndpoint& endpoint,
                                             std::string& error);

enum class DebuggerReceiveStatus : std::uint8_t {
  kMessage,
  kTimeout,
  kClosed,
  kError,
};

class DebuggerTransport final {
 public:
  DebuggerTransport() = default;
  DebuggerTransport(const DebuggerTransport&) = delete;
  DebuggerTransport& operator=(const DebuggerTransport&) = delete;
  ~DebuggerTransport();

  [[nodiscard]] bool Connect(std::string_view url, std::string& error);
  [[nodiscard]] bool SendText(std::string_view message, std::string& error);
  [[nodiscard]] DebuggerReceiveStatus ReceiveText(std::string& message,
                                                  std::chrono::milliseconds timeout,
                                                  std::string& error);
  [[nodiscard]] int Descriptor() const noexcept { return descriptor_; }

 private:
  friend class DebuggerTransportTestPeer;

  [[nodiscard]] bool SendFrame(std::uint8_t opcode, std::string_view payload, std::string& error);

  int descriptor_ = -1;
};

[[nodiscard]] bool ReadDebuggerControlMessage(int descriptor,
                                              std::size_t maximum_bytes,
                                              std::string& message,
                                              bool& reached_end,
                                              std::string& error);

[[nodiscard]] bool WriteDebuggerControlMessage(int descriptor,
                                               std::string_view message,
                                               std::string& error);

}  // namespace reb

#endif  // REB_DEBUGGER_TRANSPORT_HPP_
