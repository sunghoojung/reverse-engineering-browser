#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "reb/heap_snapshot.hpp"

#define CHECK(condition)                                                                   \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " << #condition \
                << '\n';                                                                   \
      return 1;                                                                            \
    }                                                                                      \
  } while (false)

namespace {

class TemporarySnapshot final {
 public:
  TemporarySnapshot() {
    path_ = std::filesystem::temp_directory_path() /
            ("reb-heap-snapshot-" + std::to_string(reinterpret_cast<std::uintptr_t>(this)) +
             ".heapsnapshot");
  }

  ~TemporarySnapshot() {
    std::error_code error;
    std::filesystem::remove(path_, error);
  }

  [[nodiscard]] const std::filesystem::path& Path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

}  // namespace

int main() {
  TemporarySnapshot snapshot;
  std::ofstream output(snapshot.Path(), std::ios::binary);
  output << R"({
    "snapshot": {
      "meta": {
        "node_fields": ["type", "name", "id", "self_size", "edge_count"],
        "node_types": [["hidden", "array", "string", "object", "code", "closure", "synthetic"], "string", "number", "number", "number"],
        "edge_fields": ["type", "name_or_index", "to_node"],
        "edge_types": [["context", "element", "property", "internal", "hidden", "shortcut", "weak"], "string_or_number", "node"]
      },
      "node_count": 4,
      "edge_count": 3
    },
    "nodes": [6,0,1,0,1, 3,1,3,64,2, 2,2,5,24,0, 5,3,7,32,0],
    "edges": [2,4,5, 2,5,10, 2,6,15],
    "trace_function_infos": [],
    "strings": ["", "CheckoutState", "secret-value", "submit", "app", "token", "handler"]
  })";
  output.close();
  CHECK(output.good());

  reb::HeapSnapshotSearchResult result;
  std::string error;
  CHECK(reb::SearchV8HeapSnapshot(snapshot.Path(), "SECRET", false, 50, result, error));
  CHECK(error.empty());
  CHECK(result.total_nodes == 4);
  CHECK(result.total_edges == 3);
  CHECK(result.analyzed_nodes == 4);
  CHECK(result.matches.size() == 1);
  CHECK(result.matches[0].node_id == 5);
  CHECK(result.matches[0].node_type == "string");
  CHECK(result.matches[0].node_name == "secret-value");
  CHECK(result.matches[0].self_size == 24);
  CHECK(result.matches[0].retaining_path_complete);
  CHECK(result.matches[0].retaining_path.size() == 2);
  CHECK(result.matches[0].retaining_path[0].edge_name == "app");
  CHECK(result.matches[0].retaining_path[0].node_name == "CheckoutState");
  CHECK(result.matches[0].retaining_path[1].edge_name == "token");
  CHECK(result.matches[0].retaining_path[1].node_name == "secret-value");

  const std::string json = reb::HeapSnapshotSearchResultToJson(result);
  CHECK(json.find("\"protocol_version\":1") != std::string::npos);
  CHECK(json.find("\"name\":\"secret-value\"") != std::string::npos);
  CHECK(json.find("\"edge\":\"token\"") != std::string::npos);

  reb::HeapSnapshotSearchResult limited;
  CHECK(reb::SearchV8HeapSnapshot(snapshot.Path(), "t", false, 1, limited, error));
  CHECK(limited.matches.size() == 1);
  CHECK(limited.result_limit_reached);
  CHECK(limited.analyzed_nodes < limited.total_nodes);

  TemporarySnapshot malformed;
  std::ofstream malformed_output(malformed.Path(), std::ios::binary);
  malformed_output << "{\"snapshot\":{},\"nodes\":[]}";
  malformed_output.close();
  CHECK(!reb::SearchV8HeapSnapshot(malformed.Path(), "x", false, 50, result, error));
  CHECK(!error.empty());

  std::cout << "heap_snapshot_test passed\n";
  return 0;
}
