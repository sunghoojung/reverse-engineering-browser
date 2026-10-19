#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include "brave/components/reverse_engineering_browser/browser/native_local_ipc_client.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_ipc.h"

int main(int argc, char** argv) {
  assert(argc == 2);
  const std::string root(argv[1]);
  const std::string socket_path = root + "/listener";
  const base::FilePath token_path(root + "/token");
  const int token = open(token_path.value().c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(token >= 0);
  const std::string encoded(64, 'a');
  assert(write(token, encoded.data(), encoded.size()) == static_cast<ssize_t>(encoded.size()));
  assert(close(token) == 0);
  assert(reb::ConnectNativeLocalIpc(socket_path, token_path, 1, true) == -1);
  assert(reb::ConnectNativeLocalIpc(socket_path, token_path, 0, true) == -1);
  const int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener < 0) {
    std::cerr << "Native IPC test unavailable: AF_UNIX socket: " << std::strerror(errno) << '\n';
    return 2;
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  assert(socket_path.size() < sizeof(address.sun_path));
  std::memcpy(address.sun_path, socket_path.c_str(), socket_path.size() + 1);
  assert(bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0);
  // Darwin maps a zero backlog to somaxconn, rather than a minimal queue.
  // Request one pending connection explicitly so the bounded saturation test
  // exercises refusal on both Darwin and Linux.
  assert(listen(listener, 1) == 0);
  for (bool non_blocking : {true, false}) {
    const int client = reb::ConnectNativeLocalIpc(socket_path, token_path, 33, non_blocking);
    assert(client >= 0);
    assert(((fcntl(client, F_GETFL, 0) & O_NONBLOCK) != 0) == non_blocking);
    const int peer = accept(listener, nullptr, nullptr);
    assert(peer >= 0);
    reb::NativeProbeLocalIpcHello hello;
    assert(recv(peer, &hello, sizeof(hello), MSG_WAITALL) == sizeof(hello));
    assert(hello.session_id == 33 && hello.token.front() == std::byte{0xaa});
    close(peer);
    close(client);
  }
  assert(chmod(token_path.value().c_str(), 0644) == 0);
  assert(reb::ConnectNativeLocalIpc(socket_path, token_path, 33, true) == -1);
  assert(chmod(token_path.value().c_str(), 0600) == 0);
  // Saturate an owned local listen queue. No accept task can unblock connect;
  // the production client must fail closed rather than hang startup.
  int pending[32]{};
  std::size_t count = 0;
  bool refused = false;
  const auto before = std::chrono::steady_clock::now();
  for (; count < 32; ++count) {
    pending[count] = reb::ConnectNativeLocalIpc(socket_path, token_path, 33, true);
    if (pending[count] < 0) {
      refused = true;
      break;
    }
  }
  assert(refused);
  assert(std::chrono::steady_clock::now() - before < std::chrono::seconds(1));
  for (std::size_t i = 0; i < count; ++i)
    close(pending[i]);
  close(listener);
  unlink(socket_path.c_str());
  unlink(token_path.value().c_str());
  std::cout << "PASS native IPC: missing listener, invalid session/token mode, hello, descriptor "
               "mode, saturated listener fails closed\n";
}
