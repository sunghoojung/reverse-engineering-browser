#ifndef REB_HEAP_SNAPSHOT_HPP_
#define REB_HEAP_SNAPSHOT_HPP_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace reb {

inline constexpr std::uint32_t kHeapSnapshotSearchProtocolVersion = 1;
inline constexpr std::size_t kHeapSnapshotMaxFileBytes = 256U * 1024U * 1024U;
inline constexpr std::size_t kHeapSnapshotMaxNodes = 2'000'000;
inline constexpr std::size_t kHeapSnapshotMaxEdges = 8'000'000;
inline constexpr std::size_t kHeapSnapshotMaxStrings = 2'000'000;
inline constexpr std::size_t kHeapSnapshotMaxStringBytes = 64U * 1024U * 1024U;
inline constexpr std::size_t kHeapSnapshotMaxStoredStringBytes = 4'096;
inline constexpr std::size_t kHeapSnapshotMaxResults = 50;
inline constexpr std::size_t kHeapSnapshotMaxRetainingDepth = 12;

struct HeapSnapshotRetainingStep final {
  std::string edge_name;
  std::string node_type;
  std::string node_name;
};

struct HeapSnapshotMatch final {
  std::uint64_t node_id = 0;
  std::uint64_t self_size = 0;
  std::string node_type;
  std::string node_name;
  std::vector<HeapSnapshotRetainingStep> retaining_path;
  bool retaining_path_complete = false;
};

struct HeapSnapshotSearchResult final {
  std::uint32_t protocol_version = kHeapSnapshotSearchProtocolVersion;
  std::uint64_t file_bytes = 0;
  std::uint64_t total_nodes = 0;
  std::uint64_t analyzed_nodes = 0;
  std::uint64_t total_edges = 0;
  std::uint64_t indexed_edges = 0;
  std::uint64_t total_strings = 0;
  std::uint64_t duration_ms = 0;
  std::size_t result_limit = kHeapSnapshotMaxResults;
  bool result_limit_reached = false;
  bool node_limit_reached = false;
  bool edge_limit_reached = false;
  bool string_limit_reached = false;
  bool retaining_paths_partial = false;
  std::vector<HeapSnapshotMatch> matches;
};

[[nodiscard]] bool SearchV8HeapSnapshot(const std::filesystem::path& snapshot_path,
                                        std::string_view query,
                                        bool case_sensitive,
                                        std::size_t result_limit,
                                        HeapSnapshotSearchResult& result,
                                        std::string& error);

[[nodiscard]] std::string HeapSnapshotSearchResultToJson(const HeapSnapshotSearchResult& result);

}  // namespace reb

#endif  // REB_HEAP_SNAPSHOT_HPP_
