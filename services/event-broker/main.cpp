#include <charconv>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

#include "reb/event.hpp"
#include "reb/event_broker.hpp"

namespace {

struct Options final {
  std::string store_path;
  std::size_t capacity = 10'000;
};

void PrintUsage(const char* program) {
  std::cerr << "Usage: " << program << " --store PATH [--capacity COUNT]\n";
}

bool ParseSize(const std::string_view value, std::size_t& result) {
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
    } else if (argument == "--capacity" && index + 1 < argc) {
      if (!ParseSize(argv[++index], options.capacity)) {
        return false;
      }
    } else {
      return false;
    }
  }
  return !options.store_path.empty();
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
  reb::EventRecord event{};
  while (std::cin.read(reinterpret_cast<char*>(&event), sizeof(event))) {
    if (broker.Ingest(event) != reb::IngestStatus::kAccepted) {
      continue;
    }
    store << reb::EventToJson(event) << '\n';
    store.flush();
    if (!store) {
      std::cerr << "Unable to write event store\n";
      return 1;
    }
  }

  if (std::cin.gcount() != 0) {
    std::cerr << "Truncated native event record received\n";
    return 1;
  }

  const reb::BrokerStats stats = broker.Stats();
  std::cerr << "Broker stopped: accepted=" << stats.accepted << " invalid=" << stats.invalid
            << " sequence_gaps=" << stats.sequence_gaps
            << " sequence_gaps_saturated=" << stats.sequence_gaps_saturated
            << " sequence_tracking_evictions=" << stats.sequence_tracking_evictions
            << " evicted=" << stats.evicted << '\n';
  return stats.invalid == 0 ? 0 : 1;
}
