#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

#include <poll.h>
#include <unistd.h>

#include "reb/debugger_transport.hpp"

namespace {

constexpr std::size_t kMaxReportedErrorBytes = 4U * 1024U;
constexpr std::chrono::milliseconds kFrameReadTimeout(5'000);

void Usage() {
  std::cerr << "Usage: reb-debugger-transport --url LOOPBACK_WS_URL\n";
}

int Fail(const std::string& error) {
  std::cerr << error.substr(0, kMaxReportedErrorBytes) << '\n';
  return 1;
}

}  // namespace

int main(const int argc, const char* const argv[]) {
  if (argc != 3 || std::string_view(argv[1]) != "--url") {
    Usage();
    return 2;
  }
  static_cast<void>(std::signal(SIGPIPE, SIG_IGN));

  std::string error;
  reb::DebuggerTransport transport;
  if (!transport.Connect(argv[2], error)) {
    return Fail(error);
  }
  if (!reb::WriteDebuggerControlMessage(STDOUT_FILENO, {}, error)) {
    return Fail(error);
  }

  while (true) {
    pollfd descriptors[2] = {
        {STDIN_FILENO, POLLIN, 0},
        {transport.Descriptor(), POLLIN, 0},
    };
    int poll_result = 0;
    do {
      poll_result = poll(descriptors, 2, -1);
    } while (poll_result < 0 && errno == EINTR);
    if (poll_result < 0) {
      return Fail(std::string("Debugger transport poll failed: ") + std::strerror(errno));
    }

    if ((descriptors[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
      std::string command;
      bool reached_end = false;
      if (!reb::ReadDebuggerControlMessage(STDIN_FILENO, reb::kDebuggerMaxCommandBytes, command,
                                           reached_end, error)) {
        return Fail(error);
      }
      if (reached_end) {
        return 0;
      }
      if (!transport.SendText(command, error)) {
        return Fail(error);
      }
    }

    if ((descriptors[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
      std::string message;
      const auto status = transport.ReceiveText(message, kFrameReadTimeout, error);
      if (status == reb::DebuggerReceiveStatus::kMessage) {
        if (!reb::WriteDebuggerControlMessage(STDOUT_FILENO, message, error)) {
          return Fail(error);
        }
      } else if (status == reb::DebuggerReceiveStatus::kClosed) {
        return Fail("Debugger WebSocket closed");
      } else if (status == reb::DebuggerReceiveStatus::kError) {
        return Fail(error);
      }
    }
  }
}
