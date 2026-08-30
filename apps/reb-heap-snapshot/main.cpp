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
               "[--case-sensitive] [--scope all|reachable|unreachable] "
               "[--limit COUNT | --probe]\n"
               "       reb-heap-snapshot --baseline PATH --current PATH [--limit COUNT]\n";
}

bool ParseScope(const std::string_view text, reb::HeapSnapshotSearchScope& scope) noexcept {
  if (text == "all") {
    scope = reb::HeapSnapshotSearchScope::kAll;
  } else if (text == "reachable") {
    scope = reb::HeapSnapshotSearchScope::kReachable;
  } else if (text == "unreachable") {
    scope = reb::HeapSnapshotSearchScope::kUnreachable;
  } else {
    return false;
  }
  return true;
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
  std::filesystem::path baseline_path;
  std::filesystem::path current_path;
  std::string query;
  std::size_t result_limit = reb::kHeapSnapshotMaxResults;
  reb::HeapSnapshotSearchScope scope = reb::HeapSnapshotSearchScope::kAll;
  bool case_sensitive = false;
  bool probe_only = false;
  bool limit_supplied = false;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--snapshot" && index + 1 < argc) {
      snapshot_path = argv[++index];
    } else if (argument == "--baseline" && index + 1 < argc) {
      baseline_path = argv[++index];
    } else if (argument == "--current" && index + 1 < argc) {
      current_path = argv[++index];
    } else if (argument == "--query" && index + 1 < argc) {
      query = argv[++index];
    } else if (argument == "--limit" && index + 1 < argc) {
      if (!ParseLimit(argv[++index], result_limit)) {
        Usage();
        return 2;
      }
      limit_supplied = true;
    } else if (argument == "--scope" && index + 1 < argc) {
      if (!ParseScope(argv[++index], scope)) {
        Usage();
        return 2;
      }
    } else if (argument == "--case-sensitive") {
      case_sensitive = true;
    } else if (argument == "--probe") {
      probe_only = true;
    } else {
      Usage();
      return 2;
    }
  }
  const bool search_mode = !snapshot_path.empty() && baseline_path.empty() && current_path.empty();
  const bool diff_mode = snapshot_path.empty() && !baseline_path.empty() && !current_path.empty();
  if ((!search_mode && !diff_mode) || (search_mode && (query.empty() || query.size() > 512)) ||
      (probe_only && (!search_mode || limit_supplied)) ||
      (diff_mode && (!query.empty() || case_sensitive || probe_only ||
                     scope != reb::HeapSnapshotSearchScope::kAll))) {
    Usage();
    return 2;
  }

  std::string error;
  try {
    if (search_mode) {
      if (probe_only) {
        reb::HeapSnapshotProbeResult result;
        if (!reb::ProbeV8HeapSnapshot(snapshot_path, query, case_sensitive, scope, result, error)) {
          std::cerr << error << '\n';
          return 1;
        }
        std::cout << reb::HeapSnapshotProbeResultToJson(result) << '\n';
      } else {
        reb::HeapSnapshotSearchResult result;
        if (!reb::SearchV8HeapSnapshot(snapshot_path, query, case_sensitive, scope, result_limit,
                                       result, error)) {
          std::cerr << error << '\n';
          return 1;
        }
        std::cout << reb::HeapSnapshotSearchResultToJson(result) << '\n';
      }
    } else {
      reb::HeapSnapshotDiffResult result;
      if (!reb::CompareV8HeapSnapshots(baseline_path, current_path, result_limit, result, error)) {
        std::cerr << error << '\n';
        return 1;
      }
      std::cout << reb::HeapSnapshotDiffResultToJson(result) << '\n';
    }
  } catch (const std::bad_alloc&) {
    std::cerr << "Heap snapshot analysis exhausted its bounded native allocation budget\n";
    return 1;
  }
  return 0;
}
