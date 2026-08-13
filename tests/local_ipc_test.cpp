#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <thread>

#include "reb/local_ipc.hpp"

namespace {

bool TestTokenEncoding() {
  reb::LocalIpcToken token{};
  for (std::size_t index = 0; index < token.size(); ++index) {
    token[index] = static_cast<std::byte>(index);
  }
  const std::string encoded = reb::EncodeLocalIpcToken(token);
  reb::LocalIpcToken decoded{};
  return encoded.size() == 64 && reb::DecodeLocalIpcToken(encoded, decoded) &&
         reb::ConstantTimeTokenEquals(token, decoded) &&
         !reb::DecodeLocalIpcToken(encoded + "0", decoded);
}

bool TestSecureTokenFile() {
  std::array<char, 64> directory_template{};
  const std::string pattern = "/tmp/reb-local-ipc-test.XXXXXX";
  std::copy(pattern.begin(), pattern.end(), directory_template.begin());
  char* const directory = mkdtemp(directory_template.data());
  if (!directory) {
    return false;
  }
  const std::string path = std::string(directory) + "/token";

  reb::LocalIpcToken created{};
  std::string error;
  bool passed = reb::LoadOrCreateLocalIpcToken(path, created, error);
  reb::LocalIpcToken loaded{};
  passed = passed && reb::LoadLocalIpcToken(path, loaded, error) &&
           reb::ConstantTimeTokenEquals(created, loaded);

  struct stat status {};
  passed = passed && stat(path.c_str(), &status) == 0 && (status.st_mode & 0777) == 0600;

  if (chmod(path.c_str(), 0644) != 0) {
    passed = false;
  } else {
    error.clear();
    passed = passed && !reb::LoadLocalIpcToken(path, loaded, error);
  }

  unlink(path.c_str());
  rmdir(directory);
  return passed;
}

bool TestHelloFraming() {
  int descriptors[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) != 0) {
    return false;
  }

  reb::LocalIpcHello sent;
  sent.session_id = 42;
  sent.token[0] = std::byte{0xa5};
  std::string write_error;
  std::thread writer([&] {
    const auto bytes = std::as_bytes(std::span(&sent, 1));
    static_cast<void>(reb::WriteExact(descriptors[0], bytes, write_error));
    close(descriptors[0]);
  });

  reb::LocalIpcHello received;
  std::string read_error;
  const auto bytes = std::as_writable_bytes(std::span(&received, 1));
  const bool read = reb::ReadExact(descriptors[1], bytes, read_error);
  close(descriptors[1]);
  writer.join();
  return read && write_error.empty() && received.magic == reb::kLocalIpcMagic &&
         received.version == reb::kLocalIpcVersion && received.session_id == 42 &&
         received.token[0] == std::byte{0xa5};
}

}  // namespace

int main() {
  if (!TestTokenEncoding() || !TestSecureTokenFile() || !TestHelloFraming()) {
    std::cerr << "local_ipc_test failed\n";
    return 1;
  }
  std::cout << "local_ipc_test passed\n";
  return 0;
}
