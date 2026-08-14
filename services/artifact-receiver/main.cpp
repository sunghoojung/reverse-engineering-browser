#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "reb/artifact.hpp"

namespace {

constexpr std::uint64_t kDefaultMaxArtifactBytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kDefaultMaxStoreBytes = 256ULL * 1024ULL * 1024ULL;

struct Options final {
  std::string store_path;
  std::uint64_t max_artifact_bytes = kDefaultMaxArtifactBytes;
  std::uint64_t max_store_bytes = kDefaultMaxStoreBytes;
  bool allow_sensitive = false;
};

void PrintUsage(const char* program) {
  std::cerr << "Usage: " << program
            << " --store PATH [--max-artifact-bytes COUNT] [--max-store-bytes COUNT]"
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
  return !options.store_path.empty() && options.max_artifact_bytes <= options.max_store_bytes;
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
    while (true) {
      const reb::ArtifactReceiveStatus status = receiver.ReceiveOne(std::cin);
      if (status == reb::ArtifactReceiveStatus::kEndOfStream) {
        break;
      }
      if (status != reb::ArtifactReceiveStatus::kAccepted) {
        std::cerr << "Artifact receiver stopped: " << receiver.LastError() << '\n';
        return 1;
      }
    }
    const reb::ArtifactReceiverStats stats = receiver.Stats();
    std::cerr << "Artifact receiver stopped: accepted=" << stats.accepted
              << " bytes_accepted=" << stats.bytes_accepted << " invalid=" << stats.invalid
              << " too_large=" << stats.too_large
              << " sensitive_rejected=" << stats.sensitive_rejected
              << " conflicts=" << stats.conflicts << " io_errors=" << stats.io_errors
              << " stored_bytes=" << receiver.StoredBytes() << '\n';
  } catch (const std::exception& exception) {
    std::cerr << "Unable to start artifact receiver: " << exception.what() << '\n';
    return 1;
  }
  return 0;
}
