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
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "reb/event.hpp"
#include "reb/event_broker.hpp"
#include "reb/local_ipc.hpp"

namespace {

struct Options final {
  std::string store_path;
  std::string socket_path;
  std::string token_path;
  std::size_t capacity = 10'000;
  std::uint64_t session_id = 0;
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

  [[nodiscard]] int get() const { return descriptor_; }
  [[nodiscard]] bool is_valid() const { return descriptor_ >= 0; }

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

void PrintUsage(const char* program) {
  std::cerr << "Usage: " << program << " --store PATH [--capacity COUNT]\n"
            << "       " << program
            << " --store PATH --socket PATH --token-file PATH --session-id ID"
               " [--capacity COUNT]\n";
}

template <typename Integer>
bool ParseInteger(const std::string_view value, Integer& result) {
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
      if (!ParseInteger<std::uint64_t>(argv[++index], options.session_id)) {
        return false;
      }
    } else if (argument == "--capacity" && index + 1 < argc) {
      if (!ParseInteger<std::size_t>(argv[++index], options.capacity)) {
        return false;
      }
    } else {
      return false;
    }
  }

  if (options.store_path.empty()) {
    return false;
  }
  const bool any_socket_option = !options.socket_path.empty() ||
                                 !options.token_path.empty() ||
                                 options.session_id != 0;
  const bool all_socket_options = !options.socket_path.empty() &&
                                 !options.token_path.empty() &&
                                 options.session_id != 0;
  return !any_socket_option || all_socket_options;
}

bool StoreEvent(reb::EventBroker& broker, std::ofstream& store,
                const reb::EventRecord& event) {
  if (broker.Ingest(event) != reb::IngestStatus::kAccepted) {
    return true;
  }
  store << reb::EventToJson(event) << '\n';
  store.flush();
  if (!store) {
    std::cerr << "Unable to write event store\n";
    return false;
  }
  return true;
}

bool IngestStandardInput(reb::EventBroker& broker, std::ofstream& store) {
  reb::EventRecord event{};
  while (std::cin.read(reinterpret_cast<char*>(&event), sizeof(event))) {
    if (!StoreEvent(broker, store, event)) {
      return false;
    }
  }
  if (std::cin.gcount() != 0) {
    std::cerr << "Truncated native event record received\n";
    return false;
  }
  return true;
}

bool IngestSocket(const int descriptor, const Options& options,
                  const reb::LocalIpcToken& expected_token,
                  reb::EventBroker& broker, std::ofstream& store) {
  reb::LocalIpcHello hello;
  std::string error;
  if (!reb::ReadExact(descriptor,
                      std::as_writable_bytes(std::span(&hello, 1)), error)) {
    std::cerr << "Unable to read broker authentication: " << error << '\n';
    return false;
  }
  const bool reserved_clear = std::ranges::all_of(
      hello.reserved, [](const std::byte value) { return value == std::byte{0}; });
  if (hello.magic != reb::kLocalIpcMagic ||
      hello.version != reb::kLocalIpcVersion ||
      hello.size != sizeof(reb::LocalIpcHello) ||
      hello.session_id != options.session_id || !reserved_clear ||
      !reb::ConstantTimeTokenEquals(hello.token, expected_token)) {
    std::cerr << "Broker authentication rejected\n";
    return false;
  }

  for (;;) {
    reb::EventRecord event{};
    auto bytes = std::as_writable_bytes(std::span(&event, 1));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
      const ssize_t count =
          read(descriptor, bytes.data() + offset, bytes.size() - offset);
      if (count > 0) {
        offset += static_cast<std::size_t>(count);
        continue;
      }
      if (count < 0 && errno == EINTR) {
        continue;
      }
      if (count == 0 && offset == 0) {
        return true;
      }
      if (count == 0) {
        std::cerr << "Truncated native event record received\n";
      } else {
        std::cerr << "Broker socket read failed: " << std::strerror(errno) << '\n';
      }
      return false;
    }

    if (event.header.session_id != options.session_id) {
      std::cerr << "Event session does not match authenticated broker session\n";
      return false;
    }
    if (!StoreEvent(broker, store, event)) {
      return false;
    }
  }
}

int ListenOnUnixSocket(const std::string& path) {
  sockaddr_un address{};
  if (path.size() >= sizeof(address.sun_path)) {
    std::cerr << "Broker socket path is too long\n";
    return -1;
  }

  struct stat existing {};
  if (lstat(path.c_str(), &existing) == 0 || errno != ENOENT) {
    std::cerr << "Broker socket path already exists: " << path << '\n';
    return -1;
  }

  const int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) {
    std::cerr << "Unable to create broker socket: " << std::strerror(errno) << '\n';
    return -1;
  }

  address.sun_family = AF_UNIX;
  std::copy(path.begin(), path.end(), address.sun_path);
  if (bind(descriptor, reinterpret_cast<const sockaddr*>(&address),
           static_cast<socklen_t>(sizeof(address))) != 0 ||
      chmod(path.c_str(), 0600) != 0 || listen(descriptor, 1) != 0) {
    std::cerr << "Unable to prepare broker socket: " << std::strerror(errno) << '\n';
    close(descriptor);
    unlink(path.c_str());
    return -1;
  }
  return descriptor;
}

void PrintStats(const reb::BrokerStats& stats) {
  std::cerr << "Broker stopped: accepted=" << stats.accepted
            << " invalid=" << stats.invalid
            << " sequence_gaps=" << stats.sequence_gaps
            << " sequence_gaps_saturated=" << stats.sequence_gaps_saturated
            << " sequence_tracking_evictions=" << stats.sequence_tracking_evictions
            << " evicted=" << stats.evicted << '\n';
}

}  // namespace

int main(const int argc, char* argv[]) {
  Options options;
  if (!ParseOptions(argc, argv, options)) {
    PrintUsage(argv[0]);
    return 2;
  }

  std::ofstream store(options.store_path, std::ios::out | std::ios::trunc);
  if (!store) {
    std::cerr << "Unable to open event store: " << options.store_path << '\n';
    return 1;
  }

  reb::EventBroker broker(options.capacity);
  bool ingested = false;
  if (options.socket_path.empty()) {
    ingested = IngestStandardInput(broker, store);
  } else {
    reb::LocalIpcToken token{};
    std::string error;
    if (!reb::LoadOrCreateLocalIpcToken(options.token_path, token, error)) {
      std::cerr << error << '\n';
      return 1;
    }

    const ScopedDescriptor listener(ListenOnUnixSocket(options.socket_path));
    if (!listener.is_valid()) {
      return 1;
    }
    const ScopedSocketPath socket_path(options.socket_path);
    std::cerr << "Broker listening on " << options.socket_path << '\n';
    const ScopedDescriptor connection(accept(listener.get(), nullptr, nullptr));
    if (!connection.is_valid()) {
      std::cerr << "Unable to accept browser connection: " << std::strerror(errno)
                << '\n';
      return 1;
    }
    ingested = IngestSocket(connection.get(), options, token, broker, store);
  }

  const reb::BrokerStats stats = broker.Stats();
  PrintStats(stats);
  return ingested && stats.invalid == 0 ? 0 : 1;
}
