#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <utility>

#include "reb/artifact.hpp"
#include "reb/local_ipc.hpp"

namespace {

constexpr std::uint64_t kDefaultMaxArtifactBytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kDefaultMaxStoreBytes = 256ULL * 1024ULL * 1024ULL;
constexpr int kSocketTimeoutSeconds = 30;

struct Options final {
  std::string store_path;
  std::string socket_path;
  std::string token_path;
  std::uint64_t session_id = 0;
  std::uint64_t max_artifact_bytes = kDefaultMaxArtifactBytes;
  std::uint64_t max_store_bytes = kDefaultMaxStoreBytes;
  bool allow_sensitive = false;
};

class ScopedDescriptor final {
 public:
  explicit ScopedDescriptor(const int descriptor = -1) : descriptor_(descriptor) {}
  ScopedDescriptor(const ScopedDescriptor&) = delete;
  ScopedDescriptor& operator=(const ScopedDescriptor&) = delete;
  ~ScopedDescriptor() {
    if (descriptor_ >= 0) {
      close(descriptor_);
    }
  }

  [[nodiscard]] int get() const noexcept { return descriptor_; }
  [[nodiscard]] bool is_valid() const noexcept { return descriptor_ >= 0; }

 private:
  int descriptor_;
};

class ScopedSocketPath final {
 public:
  explicit ScopedSocketPath(std::string path) : path_(std::move(path)) {}
  ScopedSocketPath(const ScopedSocketPath&) = delete;
  ScopedSocketPath& operator=(const ScopedSocketPath&) = delete;
  ~ScopedSocketPath() {
    if (!path_.empty()) {
      unlink(path_.c_str());
    }
  }

 private:
  std::string path_;
};

class DescriptorStreamBuffer final : public std::streambuf {
 public:
  explicit DescriptorStreamBuffer(const int descriptor) : descriptor_(descriptor) {
    setg(buffer_.data(), buffer_.data(), buffer_.data());
  }

 protected:
  int_type underflow() override {
    for (;;) {
      const ssize_t count = read(descriptor_, buffer_.data(), buffer_.size());
      if (count > 0) {
        setg(buffer_.data(), buffer_.data(), buffer_.data() + static_cast<std::ptrdiff_t>(count));
        return traits_type::to_int_type(*gptr());
      }
      if (count < 0 && errno == EINTR) {
        continue;
      }
      return traits_type::eof();
    }
  }

 private:
  int descriptor_;
  std::array<char, 64 * 1024> buffer_{};
};

void PrintUsage(const char* program) {
  std::cerr << "Usage: " << program
            << " --store PATH [--max-artifact-bytes COUNT] [--max-store-bytes COUNT]"
               " [--allow-sensitive]\n"
            << "       " << program
            << " --store PATH --socket PATH --token-file PATH --session-id ID"
               " [--max-artifact-bytes COUNT] [--max-store-bytes COUNT]"
               " [--allow-sensitive]\n";
}

bool ParseSize(const std::string_view value, std::uint64_t& result) {
  const char* const begin = value.data();
  const char* const end = begin + value.size();
  const auto parsed = std::from_chars(begin, end, result);
  return parsed.ec == std::errc{} && parsed.ptr == end && result > 0;
}

bool ParseOptions(const int argc, char* argv[], Options& options) {
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--store" && index + 1 < argc) {
      options.store_path = argv[++index];
    } else if (argument == "--socket" && index + 1 < argc) {
      options.socket_path = argv[++index];
    } else if (argument == "--token-file" && index + 1 < argc) {
      options.token_path = argv[++index];
    } else if (argument == "--session-id" && index + 1 < argc) {
      if (!ParseSize(argv[++index], options.session_id)) {
        return false;
      }
    } else if (argument == "--max-artifact-bytes" && index + 1 < argc) {
      if (!ParseSize(argv[++index], options.max_artifact_bytes)) {
        return false;
      }
    } else if (argument == "--max-store-bytes" && index + 1 < argc) {
      if (!ParseSize(argv[++index], options.max_store_bytes)) {
        return false;
      }
    } else if (argument == "--allow-sensitive") {
      options.allow_sensitive = true;
    } else {
      return false;
    }
  }
  const bool any_socket_option =
      !options.socket_path.empty() || !options.token_path.empty() || options.session_id != 0;
  const bool all_socket_options =
      !options.socket_path.empty() && !options.token_path.empty() && options.session_id != 0;
  return !options.store_path.empty() && options.max_artifact_bytes <= options.max_store_bytes &&
         (!any_socket_option || all_socket_options);
}

int ListenOnUnixSocket(const std::string& path) {
  sockaddr_un address{};
  if (path.empty() || path.size() >= sizeof(address.sun_path)) {
    std::cerr << "Artifact socket path is invalid or too long\n";
    return -1;
  }

  struct stat existing {};
  if (lstat(path.c_str(), &existing) == 0 || errno != ENOENT) {
    std::cerr << "Artifact socket path already exists: " << path << '\n';
    return -1;
  }

  const int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) {
    std::cerr << "Unable to create artifact socket: " << std::strerror(errno) << '\n';
    return -1;
  }
  address.sun_family = AF_UNIX;
  std::copy(path.begin(), path.end(), address.sun_path);
  if (bind(descriptor, reinterpret_cast<const sockaddr*>(&address),
           static_cast<socklen_t>(sizeof(address))) != 0 ||
      chmod(path.c_str(), 0600) != 0 || listen(descriptor, 1) != 0) {
    std::cerr << "Unable to prepare artifact socket: " << std::strerror(errno) << '\n';
    close(descriptor);
    unlink(path.c_str());
    return -1;
  }
  return descriptor;
}

bool PeerIsCurrentUser(const int descriptor) noexcept {
#if defined(__APPLE__)
  uid_t user_id = 0;
  gid_t group_id = 0;
  return getpeereid(descriptor, &user_id, &group_id) == 0 && user_id == geteuid();
#elif defined(__linux__)
  struct ucred credentials {};
  socklen_t size = sizeof(credentials);
  return getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &size) == 0 &&
         size == sizeof(credentials) && credentials.uid == geteuid();
#else
  return false;
#endif
}

bool Authenticate(const int descriptor,
                  const std::uint64_t session_id,
                  const reb::LocalIpcToken& expected_token) {
  if (!PeerIsCurrentUser(descriptor)) {
    std::cerr << "Artifact connection peer is not the current user\n";
    return false;
  }
  reb::LocalIpcHello hello;
  std::string error;
  if (!reb::ReadExact(descriptor, std::as_writable_bytes(std::span(&hello, 1)), error)) {
    std::cerr << "Unable to read artifact authentication: " << error << '\n';
    return false;
  }
  const bool reserved_clear = std::ranges::all_of(
      hello.reserved, [](const std::byte value) { return value == std::byte{0}; });
  if (hello.magic != reb::kLocalIpcMagic || hello.version != reb::kLocalIpcVersion ||
      hello.size != sizeof(reb::LocalIpcHello) || hello.session_id != session_id ||
      !reserved_clear || !reb::ConstantTimeTokenEquals(hello.token, expected_token)) {
    std::cerr << "Artifact authentication rejected\n";
    return false;
  }
  return true;
}

bool SendAck(const int descriptor,
             const reb::ArtifactReceiveStatus status,
             const std::uint64_t artifact_id) {
  reb::ArtifactAck ack;
  ack.status = status;
  ack.artifact_id = artifact_id;
  std::string error;
  if (!reb::WriteExact(descriptor, std::as_bytes(std::span(&ack, 1)), error)) {
    std::cerr << "Unable to acknowledge artifact: " << error << '\n';
    return false;
  }
  return true;
}

bool ReceiveStream(std::istream& stream,
                   reb::ArtifactReceiver& receiver,
                   const int acknowledgment_descriptor) {
  for (;;) {
    const reb::ArtifactReceiveStatus status = receiver.ReceiveOne(stream);
    if (status == reb::ArtifactReceiveStatus::kEndOfStream) {
      return true;
    }
    if (acknowledgment_descriptor >= 0 &&
        !SendAck(acknowledgment_descriptor, status, receiver.LastArtifactId())) {
      return false;
    }
    if (status != reb::ArtifactReceiveStatus::kAccepted) {
      std::cerr << "Artifact receiver stopped: " << receiver.LastError() << '\n';
      return false;
    }
  }
}

void PrintStats(const reb::ArtifactReceiver& receiver) {
  const reb::ArtifactReceiverStats stats = receiver.Stats();
  std::cerr << "Artifact receiver stopped: accepted=" << stats.accepted
            << " bytes_accepted=" << stats.bytes_accepted << " invalid=" << stats.invalid
            << " too_large=" << stats.too_large
            << " sensitive_rejected=" << stats.sensitive_rejected
            << " conflicts=" << stats.conflicts << " io_errors=" << stats.io_errors
            << " stored_bytes=" << receiver.StoredBytes() << '\n';
}

}  // namespace

int main(const int argc, char* argv[]) {
  Options options;
  if (!ParseOptions(argc, argv, options)) {
    PrintUsage(argv[0]);
    return 2;
  }

  try {
    reb::ArtifactReceiver receiver(options.store_path, options.max_artifact_bytes,
                                   options.max_store_bytes, options.allow_sensitive);
    bool received = false;
    if (options.socket_path.empty()) {
      received = ReceiveStream(std::cin, receiver, -1);
    } else {
      reb::LocalIpcToken token{};
      std::string error;
      if (!reb::LoadLocalIpcToken(options.token_path, token, error)) {
        std::cerr << error << '\n';
        return 1;
      }
      const ScopedDescriptor listener(ListenOnUnixSocket(options.socket_path));
      if (!listener.is_valid()) {
        return 1;
      }
      const ScopedSocketPath socket_path(options.socket_path);
      std::cerr << "Artifact receiver listening on " << options.socket_path << '\n';
      const ScopedDescriptor connection(accept(listener.get(), nullptr, nullptr));
      if (!connection.is_valid()) {
        std::cerr << "Unable to accept artifact connection: " << std::strerror(errno) << '\n';
        return 1;
      }
      const timeval timeout{kSocketTimeoutSeconds, 0};
      if (setsockopt(connection.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
          setsockopt(connection.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        std::cerr << "Unable to bound artifact connection I/O: " << std::strerror(errno) << '\n';
        return 1;
      }
      if (!Authenticate(connection.get(), options.session_id, token)) {
        return 1;
      }
      DescriptorStreamBuffer buffer(connection.get());
      std::istream stream(&buffer);
      received = ReceiveStream(stream, receiver, connection.get());
    }
    PrintStats(receiver);
    return received ? 0 : 1;
  } catch (const std::exception& exception) {
    std::cerr << "Unable to start artifact receiver: " << exception.what() << '\n';
    return 1;
  }
}
