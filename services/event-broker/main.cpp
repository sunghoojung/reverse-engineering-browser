#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <poll.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "reb/event.hpp"
#include "reb/event_broker.hpp"
#include "reb/local_ipc.hpp"
#include "reb/origin_trace.hpp"
#include "reb/request_signal_profile.hpp"

namespace {

constexpr std::size_t kSocketEventBatchCapacity = 256;

struct Options final {
  std::string store_path;
  std::string trace_store_path;
  std::string signal_store_path;
  std::string socket_path;
  std::string token_path;
  std::size_t capacity = 10'000;
  std::uint64_t session_id = 0;
  std::uint64_t category_mask = 0;
  std::uint64_t duration_seconds = 0;
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
  std::cerr << "Usage: " << program
            << " --store PATH [--trace-store PATH] [--signal-store PATH] [--capacity COUNT]\n"
            << "       " << program
            << " --store PATH --socket PATH --token-file PATH --session-id ID"
               " --category-mask MASK --duration-seconds SECONDS"
               " [--trace-store PATH] [--signal-store PATH] [--capacity COUNT]\n";
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
    } else if (argument == "--trace-store" && index + 1 < argc) {
      options.trace_store_path = argv[++index];
    } else if (argument == "--signal-store" && index + 1 < argc) {
      options.signal_store_path = argv[++index];
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
    } else if (argument == "--category-mask" && index + 1 < argc) {
      if (!ParseInteger<std::uint64_t>(argv[++index], options.category_mask)) {
        return false;
      }
    } else if (argument == "--duration-seconds" && index + 1 < argc) {
      if (!ParseInteger<std::uint64_t>(argv[++index], options.duration_seconds)) {
        return false;
      }
    } else {
      return false;
    }
  }

  std::error_code path_error;
  const std::filesystem::path event_store_path =
      std::filesystem::weakly_canonical(options.store_path, path_error);
  if (path_error) {
    return false;
  }
  const std::filesystem::path trace_store_path =
      options.trace_store_path.empty()
          ? std::filesystem::path{}
          : std::filesystem::weakly_canonical(options.trace_store_path, path_error);
  const std::filesystem::path signal_store_path =
      options.signal_store_path.empty()
          ? std::filesystem::path{}
          : std::filesystem::weakly_canonical(options.signal_store_path, path_error);
  if (options.store_path.empty() || path_error ||
      (!trace_store_path.empty() && trace_store_path == event_store_path) ||
      (!signal_store_path.empty() && signal_store_path == event_store_path) ||
      (!signal_store_path.empty() && signal_store_path == trace_store_path)) {
    return false;
  }
  const bool any_socket_option = !options.socket_path.empty() || !options.token_path.empty() ||
                                 options.session_id != 0 || options.category_mask != 0 ||
                                 options.duration_seconds != 0;
  const bool all_socket_options = !options.socket_path.empty() && !options.token_path.empty() &&
                                  options.session_id != 0 && options.category_mask != 0 &&
                                  options.duration_seconds != 0;
  return (!any_socket_option || all_socket_options) &&
         (options.category_mask & ~reb::kAllEventCategoryMask) == 0 &&
         options.duration_seconds <= std::numeric_limits<std::uint64_t>::max() / 1'000'000'000ULL;
}

std::uint64_t MonotonicTimeNs() noexcept {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch())
                                        .count());
}

int MillisecondsUntil(const std::uint64_t deadline_ns) noexcept {
  const std::uint64_t now = MonotonicTimeNs();
  if (now >= deadline_ns) {
    return 0;
  }
  const std::uint64_t remaining_ns = deadline_ns - now;
  const std::uint64_t remaining_ms =
      remaining_ns / 1'000'000ULL + (remaining_ns % 1'000'000ULL != 0 ? 1ULL : 0ULL);
  return static_cast<int>(std::min<std::uint64_t>(
      remaining_ms, static_cast<std::uint64_t>(std::numeric_limits<int>::max())));
}

bool MakeSessionPolicy(const Options& options, reb::SessionPolicy& policy) noexcept {
  if (options.socket_path.empty()) {
    return true;
  }
  const std::uint64_t duration_ns = options.duration_seconds * 1'000'000'000ULL;
  const std::uint64_t now = MonotonicTimeNs();
  if (duration_ns > std::numeric_limits<std::uint64_t>::max() - now) {
    return false;
  }
  policy = {.category_mask = options.category_mask, .expires_at_monotonic_ns = now + duration_ns};
  return true;
}

bool StoreEvent(reb::EventBroker& broker,
                std::ofstream& store,
                reb::OriginTraceIndex* trace_index,
                std::ofstream* trace_store,
                reb::RequestSignalProfileIndex* signal_index,
                std::ofstream* signal_store,
                const reb::EventRecord& event) {
  if (broker.Ingest(event) != reb::IngestStatus::kAccepted) {
    return true;
  }
  store << reb::EventToJson(event) << '\n';
  if (!store) {
    std::cerr << "Unable to write event store\n";
    return false;
  }
  if (trace_index && trace_store) {
    const reb::OriginTraceEdgeBatch edges = trace_index->Ingest(event);
    for (std::size_t index = 0; index < edges.count; ++index) {
      *trace_store << reb::OriginTraceEdgeToJson(edges.edges[index]) << '\n';
    }
    if (!*trace_store) {
      std::cerr << "Unable to write origin trace store\n";
      return false;
    }
  }
  if (signal_index && signal_store) {
    const std::optional<reb::RequestSignalProfile> profile = signal_index->Ingest(event);
    if (profile) {
      *signal_store << reb::RequestSignalProfileToJson(*profile) << '\n';
    }
    if (!*signal_store) {
      std::cerr << "Unable to write request signal profile store\n";
      return false;
    }
  }
  return true;
}

bool FlushStores(std::ofstream& store, std::ofstream* trace_store, std::ofstream* signal_store) {
  store.flush();
  if (!store) {
    std::cerr << "Unable to write event store\n";
    return false;
  }
  if (trace_store) {
    trace_store->flush();
    if (!*trace_store) {
      std::cerr << "Unable to write origin trace store\n";
      return false;
    }
  }
  if (signal_store) {
    signal_store->flush();
    if (!*signal_store) {
      std::cerr << "Unable to write request signal profile store\n";
      return false;
    }
  }
  return true;
}

bool IngestStandardInput(reb::EventBroker& broker,
                         std::ofstream& store,
                         reb::OriginTraceIndex* trace_index,
                         std::ofstream* trace_store,
                         reb::RequestSignalProfileIndex* signal_index,
                         std::ofstream* signal_store) {
  reb::EventRecord event{};
  while (std::cin.read(reinterpret_cast<char*>(&event), sizeof(event))) {
    if (!StoreEvent(broker, store, trace_index, trace_store, signal_index, signal_store, event)) {
      return false;
    }
  }
  if (std::cin.gcount() != 0) {
    std::cerr << "Truncated native event record received\n";
    static_cast<void>(FlushStores(store, trace_store, signal_store));
    return false;
  }
  return FlushStores(store, trace_store, signal_store);
}

enum class TimedReadStatus {
  kComplete,
  kEndOfFile,
  kExpired,
  kError,
};

TimedReadStatus ReadExactUntil(const int descriptor,
                               const std::span<std::byte> output,
                               const std::uint64_t deadline_ns,
                               std::string& error) {
  std::size_t offset = 0;
  while (offset < output.size()) {
    pollfd readable{descriptor, static_cast<short>(POLLIN), 0};
    const int poll_result = poll(&readable, 1, MillisecondsUntil(deadline_ns));
    if (poll_result == 0) {
      return TimedReadStatus::kExpired;
    }
    if (poll_result < 0) {
      if (errno == EINTR) {
        continue;
      }
      error = std::string("socket poll failed: ") + std::strerror(errno);
      return TimedReadStatus::kError;
    }

    const ssize_t count = read(descriptor, output.data() + offset, output.size() - offset);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count == 0 && offset == 0) {
      return TimedReadStatus::kEndOfFile;
    }
    error = count == 0 ? "unexpected end of stream"
                       : std::string("socket read failed: ") + std::strerror(errno);
    return TimedReadStatus::kError;
  }
  return TimedReadStatus::kComplete;
}

class SocketEventReader final {
 public:
  TimedReadStatus ReadBatch(const int descriptor,
                            const std::span<reb::EventRecord> output,
                            const std::uint64_t deadline_ns,
                            std::size_t& event_count,
                            std::string& error) {
    event_count = 0;
    while (buffered_bytes_ < sizeof(reb::EventRecord)) {
      pollfd readable{descriptor, static_cast<short>(POLLIN), 0};
      const int poll_result = poll(&readable, 1, MillisecondsUntil(deadline_ns));
      if (poll_result == 0) {
        return TimedReadStatus::kExpired;
      }
      if (poll_result < 0) {
        if (errno == EINTR) {
          continue;
        }
        error = std::string("socket poll failed: ") + std::strerror(errno);
        return TimedReadStatus::kError;
      }

      const ssize_t count =
          read(descriptor, bytes_.data() + buffered_bytes_, bytes_.size() - buffered_bytes_);
      if (count > 0) {
        buffered_bytes_ += static_cast<std::size_t>(count);
        continue;
      }
      if (count < 0 && errno == EINTR) {
        continue;
      }
      if (count == 0 && buffered_bytes_ == 0) {
        return TimedReadStatus::kEndOfFile;
      }
      error = count == 0 ? "unexpected end of stream"
                         : std::string("socket read failed: ") + std::strerror(errno);
      return TimedReadStatus::kError;
    }

    event_count = std::min(output.size(), buffered_bytes_ / sizeof(reb::EventRecord));
    const std::size_t consumed_bytes = event_count * sizeof(reb::EventRecord);
    std::memcpy(output.data(), bytes_.data(), consumed_bytes);
    buffered_bytes_ -= consumed_bytes;
    if (buffered_bytes_ != 0) {
      std::memmove(bytes_.data(), bytes_.data() + consumed_bytes, buffered_bytes_);
    }
    return TimedReadStatus::kComplete;
  }

 private:
  std::array<std::byte, sizeof(reb::EventRecord) * kSocketEventBatchCapacity> bytes_{};
  std::size_t buffered_bytes_ = 0;
};

bool IngestSocket(const int descriptor,
                  const Options& options,
                  const reb::SessionPolicy& policy,
                  const reb::LocalIpcToken& expected_token,
                  reb::EventBroker& broker,
                  std::ofstream& store,
                  reb::OriginTraceIndex* trace_index,
                  std::ofstream* trace_store,
                  reb::RequestSignalProfileIndex* signal_index,
                  std::ofstream* signal_store) {
  reb::LocalIpcHello hello;
  std::string error;
  const TimedReadStatus hello_status =
      ReadExactUntil(descriptor, std::as_writable_bytes(std::span(&hello, 1)),
                     policy.expires_at_monotonic_ns, error);
  if (hello_status == TimedReadStatus::kExpired) {
    std::cerr << "Capture session expired\n";
    return true;
  }
  if (hello_status == TimedReadStatus::kEndOfFile) {
    std::cerr << "Browser connection closed before authentication\n";
    return false;
  }
  if (hello_status != TimedReadStatus::kComplete) {
    std::cerr << "Unable to read broker authentication: " << error << '\n';
    return false;
  }
  const bool reserved_clear = std::ranges::all_of(
      hello.reserved, [](const std::byte value) { return value == std::byte{0}; });
  if (hello.magic != reb::kLocalIpcMagic || hello.version != reb::kLocalIpcVersion ||
      hello.size != sizeof(reb::LocalIpcHello) || hello.session_id != options.session_id ||
      !reserved_clear || !reb::ConstantTimeTokenEquals(hello.token, expected_token)) {
    std::cerr << "Broker authentication rejected\n";
    return false;
  }

  SocketEventReader reader;
  std::array<reb::EventRecord, kSocketEventBatchCapacity> events{};
  for (;;) {
    std::size_t event_count = 0;
    const TimedReadStatus event_status =
        reader.ReadBatch(descriptor, events, policy.expires_at_monotonic_ns, event_count, error);
    if (event_status == TimedReadStatus::kEndOfFile) {
      return true;
    }
    if (event_status == TimedReadStatus::kExpired) {
      std::cerr << "Capture session expired\n";
      return true;
    }
    if (event_status == TimedReadStatus::kError) {
      std::cerr << "Unable to read native event: " << error << '\n';
      return false;
    }

    for (std::size_t index = 0; index < event_count; ++index) {
      const reb::EventRecord& event = events[index];
      if (event.header.session_id != options.session_id) {
        std::cerr << "Event session does not match authenticated broker session\n";
        if (index != 0) {
          static_cast<void>(FlushStores(store, trace_store, signal_store));
        }
        return false;
      }
      if (!StoreEvent(broker, store, trace_index, trace_store, signal_index, signal_store, event)) {
        return false;
      }
    }
    if (!FlushStores(store, trace_store, signal_store)) {
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

int AcceptUntil(const int listener, const std::uint64_t deadline_ns) {
  for (;;) {
    pollfd readable{listener, static_cast<short>(POLLIN), 0};
    const int poll_result = poll(&readable, 1, MillisecondsUntil(deadline_ns));
    if (poll_result > 0) {
      return accept(listener, nullptr, nullptr);
    }
    if (poll_result == 0) {
      std::cerr << "Capture session expired\n";
      return -2;
    }
    if (errno != EINTR) {
      std::cerr << "Unable to wait for browser connection: " << std::strerror(errno) << '\n';
      return -1;
    }
  }
}

void PrintStats(const reb::BrokerStats& stats) {
  std::cerr << "Broker stopped: accepted=" << stats.accepted << " invalid=" << stats.invalid
            << " category_rejected=" << stats.category_rejected << " expired=" << stats.expired
            << " sequence_gaps=" << stats.sequence_gaps
            << " sequence_gaps_saturated=" << stats.sequence_gaps_saturated
            << " sequence_tracking_evictions=" << stats.sequence_tracking_evictions
            << " evicted=" << stats.evicted << '\n';
}

void PrintTraceStats(const reb::OriginTraceIndexStats& stats) {
  std::cerr << "Origin trace stopped: indexed_events=" << stats.indexed_events
            << " emitted_edges=" << stats.emitted_edges
            << " duplicate_events=" << stats.duplicate_events
            << " evicted_events=" << stats.evicted_events << '\n';
}

void PrintSignalStats(const reb::RequestSignalProfileIndexStats& stats) {
  std::cerr << "Request signal profile stopped: indexed_events=" << stats.indexed_events
            << " emitted_profiles=" << stats.emitted_profiles
            << " duplicate_events=" << stats.duplicate_events
            << " evicted_events=" << stats.evicted_events
            << " evicted_contexts=" << stats.evicted_contexts
            << " evicted_profiles=" << stats.evicted_profiles
            << " copied_profiles=" << stats.copied_profiles << '\n';
}

}  // namespace

int main(const int argc, char* argv[]) {
  umask(S_IRWXG | S_IRWXO);
  Options options;
  if (!ParseOptions(argc, argv, options)) {
    PrintUsage(argv[0]);
    return 2;
  }

  reb::SessionPolicy policy;
  if (!MakeSessionPolicy(options, policy)) {
    std::cerr << "Session duration overflows the monotonic clock\n";
    return 2;
  }

  std::ofstream store(options.store_path, std::ios::out | std::ios::trunc);
  if (!store) {
    std::cerr << "Unable to open event store: " << options.store_path << '\n';
    return 1;
  }

  std::ofstream trace_store;
  std::unique_ptr<reb::OriginTraceIndex> trace_index;
  if (!options.trace_store_path.empty()) {
    trace_store.open(options.trace_store_path, std::ios::out | std::ios::trunc);
    if (!trace_store) {
      std::cerr << "Unable to open origin trace store: " << options.trace_store_path << '\n';
      return 1;
    }
    trace_index = std::make_unique<reb::OriginTraceIndex>(options.capacity);
  }

  std::ofstream signal_store;
  std::unique_ptr<reb::RequestSignalProfileIndex> signal_index;
  if (!options.signal_store_path.empty()) {
    signal_store.open(options.signal_store_path, std::ios::out | std::ios::trunc);
    if (!signal_store) {
      std::cerr << "Unable to open request signal profile store: " << options.signal_store_path
                << '\n';
      return 1;
    }
    signal_index = std::make_unique<reb::RequestSignalProfileIndex>(options.capacity);
  }

  reb::EventBroker broker(options.capacity, policy);
  bool ingested = false;
  if (options.socket_path.empty()) {
    ingested =
        IngestStandardInput(broker, store, trace_index.get(), trace_index ? &trace_store : nullptr,
                            signal_index.get(), signal_index ? &signal_store : nullptr);
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
    const int accepted_descriptor = AcceptUntil(listener.get(), policy.expires_at_monotonic_ns);
    if (accepted_descriptor == -2) {
      ingested = true;
    } else {
      const ScopedDescriptor connection(accepted_descriptor);
      if (!connection.is_valid()) {
        std::cerr << "Unable to accept browser connection: " << std::strerror(errno) << '\n';
        return 1;
      }
      ingested = IngestSocket(connection.get(), options, policy, token, broker, store,
                              trace_index.get(), trace_index ? &trace_store : nullptr,
                              signal_index.get(), signal_index ? &signal_store : nullptr);
    }
  }

  const reb::BrokerStats stats = broker.Stats();
  PrintStats(stats);
  if (trace_index) {
    PrintTraceStats(trace_index->Stats());
  }
  if (signal_index) {
    PrintSignalStats(signal_index->Stats());
  }
  return ingested && stats.invalid == 0 ? 0 : 1;
}
