#include <charconv>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>

#include "reb/heap_snapshot.hpp"

namespace {

void Usage() {
  std::cerr << "Usage: reb-heap-snapshot --snapshot PATH --query TEXT "
               "[--case-sensitive] [--limit COUNT]\n";
}

bool ParseLimit(const std::string_view text, std::size_t& limit) {
  if (text.empty()) {
    return false;
  }
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), limit);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && limit > 0 &&
         limit <= reb::kHeapSnapshotMaxResults;
}

}  // namespace

int main(const int argc, const char* const argv[]) {
  std::filesystem::path snapshot_path;
  std::string query;
  std::size_t result_limit = reb::kHeapSnapshotMaxResults;
  bool case_sensitive = false;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--snapshot" && index + 1 < argc) {
      snapshot_path = argv[++index];
    } else if (argument == "--query" && index + 1 < argc) {
      query = argv[++index];
    } else if (argument == "--limit" && index + 1 < argc) {
      if (!ParseLimit(argv[++index], result_limit)) {
        Usage();
        return 2;
      }
    } else if (argument == "--case-sensitive") {
      case_sensitive = true;
    } else {
      Usage();
      return 2;
    }
  }
  if (snapshot_path.empty() || query.empty() || query.size() > 512) {
    Usage();
    return 2;
  }

  reb::HeapSnapshotSearchResult result;
  std::string error;
  try {
    if (!reb::SearchV8HeapSnapshot(snapshot_path, query, case_sensitive, result_limit, result,
                                   error)) {
      std::cerr << error << '\n';
      return 1;
    }
    std::cout << reb::HeapSnapshotSearchResultToJson(result) << '\n';
  } catch (const std::bad_alloc&) {
    std::cerr << "Heap snapshot search exhausted its bounded native allocation budget\n";
    return 1;
  }
  return 0;
}
