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

  reb::HeapSnapshotSearchResult case_sensitive;
  CHECK(reb::SearchV8HeapSnapshot(snapshot.Path(), "SECRET", true, 50, case_sensitive, error));
  CHECK(case_sensitive.matches.empty());

  TemporarySnapshot long_name_snapshot;
  std::ofstream long_name_output(long_name_snapshot.Path(), std::ios::binary);
  const std::string long_name(300, 'x');
  long_name_output
      << R"({"snapshot":{"meta":{"node_fields":["type","name","id","self_size","edge_count"],"node_types":[["synthetic","string"],"string","number","number","number"],"edge_fields":["type","name_or_index","to_node"],"edge_types":[["property"],"string_or_number","node"]},"node_count":2,"edge_count":1},"nodes":[0,0,1,0,1,1,1,3,300,0],"edges":[0,2,5],"strings":["",")"
      << long_name << R"(","value"]})";
  long_name_output.close();
  CHECK(long_name_output.good());

  reb::HeapSnapshotSearchResult long_name_result;
  CHECK(reb::SearchV8HeapSnapshot(long_name_snapshot.Path(), "xxxx", false, 50, long_name_result,
                                  error));
  CHECK(long_name_result.matches.size() == 1);
  CHECK(long_name_result.matches[0].node_name.size() == 256);
  CHECK(long_name_result.matches[0].node_name.ends_with("..."));

  TemporarySnapshot long_name_current;
  std::ofstream long_name_current_output(long_name_current.Path(), std::ios::binary);
  long_name_current_output
      << R"({"snapshot":{"meta":{"node_fields":["type","name","id","self_size","edge_count"],"node_types":[["synthetic","string"],"string","number","number","number"],"edge_fields":["type","name_or_index","to_node"],"edge_types":[["property"],"string_or_number","node"]},"node_count":2,"edge_count":1},"nodes":[0,0,1,0,1,1,1,3,350,0],"edges":[0,2,5],"strings":["",")"
      << long_name << R"(","value"]})";
  long_name_current_output.close();
  CHECK(long_name_current_output.good());
  reb::HeapSnapshotDiffResult long_name_diff;
  CHECK(reb::CompareV8HeapSnapshots(long_name_snapshot.Path(), long_name_current.Path(), 50,
                                    long_name_diff, error));
  CHECK(long_name_diff.groups.size() == 1);
  CHECK(long_name_diff.groups[0].baseline_count == 1);
  CHECK(long_name_diff.groups[0].current_count == 1);
  CHECK(long_name_diff.groups[0].self_size_delta == 50);
  CHECK(long_name_diff.groups[0].node_name.size() == 256);
  CHECK(long_name_diff.groups[0].node_name.ends_with("..."));

  const std::string json = reb::HeapSnapshotSearchResultToJson(result);
  CHECK(json.find("\"protocol_version\":1") != std::string::npos);
  CHECK(json.find("\"name\":\"secret-value\"") != std::string::npos);
  CHECK(json.find("\"edge\":\"token\"") != std::string::npos);

  reb::HeapSnapshotSearchResult limited;
  CHECK(reb::SearchV8HeapSnapshot(snapshot.Path(), "t", false, 1, limited, error));
  CHECK(limited.matches.size() == 1);
  CHECK(limited.result_limit_reached);
  CHECK(limited.analyzed_nodes < limited.total_nodes);

  TemporarySnapshot baseline_snapshot;
  std::ofstream baseline_output(baseline_snapshot.Path(), std::ios::binary);
  baseline_output << R"({
    "snapshot": {
      "meta": {
        "node_fields": ["type", "name", "id", "self_size", "edge_count"],
        "node_types": [["synthetic", "object"], "string", "number", "number", "number"],
        "edge_fields": ["type", "name_or_index", "to_node"],
        "edge_types": [["property", "weak"], "string_or_number", "node"]
      },
      "node_count": 4,
      "edge_count": 3
    },
    "nodes": [0,0,1,0,2, 1,1,3,10,1, 1,2,5,20,0, 1,3,7,5,0],
    "edges": [0,5,5, 0,6,15, 0,7,10],
    "strings": ["", "Owner", "Stable", "Removed", "Added", "owner", "removed", "stable"]
  })";
  baseline_output.close();
  CHECK(baseline_output.good());

  TemporarySnapshot current_snapshot;
  std::ofstream current_output(current_snapshot.Path(), std::ios::binary);
  current_output << R"({
    "snapshot": {
      "meta": {
        "node_fields": ["type", "name", "id", "self_size", "edge_count"],
        "node_types": [["synthetic", "object"], "string", "number", "number", "number"],
        "edge_fields": ["type", "name_or_index", "to_node"],
        "edge_types": [["property", "weak"], "string_or_number", "node"]
      },
      "node_count": 4,
      "edge_count": 3
    },
    "nodes": [0,0,1,0,1, 1,1,3,10,2, 1,2,5,20,0, 1,4,9,40,0],
    "edges": [0,5,5, 0,7,10, 0,8,15],
    "strings": ["", "Owner", "Stable", "Removed", "Added", "owner", "removed", "stable", "added"]
  })";
  current_output.close();
  CHECK(current_output.good());

  reb::HeapSnapshotDiffResult diff;
  CHECK(reb::CompareV8HeapSnapshots(baseline_snapshot.Path(), current_snapshot.Path(), 50, diff,
                                    error));
  CHECK(error.empty());
  CHECK(diff.baseline_nodes == 4);
  CHECK(diff.current_nodes == 4);
  CHECK(diff.baseline_reachable_nodes == 4);
  CHECK(diff.current_reachable_nodes == 4);
  CHECK(diff.baseline_self_size == 35);
  CHECK(diff.current_self_size == 70);
  CHECK(diff.self_size_delta == 35);
  CHECK(diff.groups.size() == 2);
  CHECK(diff.groups[0].node_name == "Added");
  CHECK(diff.groups[0].count_delta == 1);
  CHECK(diff.groups[0].self_size_delta == 40);
  CHECK(diff.groups[1].node_name == "Removed");
  CHECK(diff.groups[1].count_delta == -1);
  CHECK(diff.groups[1].self_size_delta == -5);
  CHECK(diff.dominators.size() == 3);
  CHECK(diff.dominators[0].node_id == 3);
  CHECK(diff.dominators[0].baseline_retained_size == 30);
  CHECK(diff.dominators[0].current_retained_size == 70);
  CHECK(diff.dominators[0].retained_size_delta == 40);
  CHECK(diff.dominators[1].node_id == 9);
  CHECK(diff.dominators[1].retained_size_delta == 40);
  CHECK(diff.dominators[2].node_id == 7);
  CHECK(diff.dominators[2].retained_size_delta == -5);
  CHECK(!diff.retained_size_saturated);

  reb::HeapSnapshotDiffResult limited_diff;
  CHECK(reb::CompareV8HeapSnapshots(baseline_snapshot.Path(), current_snapshot.Path(), 1,
                                    limited_diff, error));
  CHECK(limited_diff.groups.size() == 1);
  CHECK(limited_diff.groups[0].node_name == "Added");
  CHECK(limited_diff.group_result_limit_reached);
  CHECK(limited_diff.dominators.size() == 1);
  CHECK(limited_diff.dominators[0].node_id == 3);
  CHECK(limited_diff.dominator_result_limit_reached);

  const std::string diff_json = reb::HeapSnapshotDiffResultToJson(diff);
  CHECK(diff_json.find("\"self_size_delta\":35") != std::string::npos);
  CHECK(diff_json.find("\"name\":\"Added\"") != std::string::npos);
  CHECK(diff_json.find("\"retained_size_delta\":40") != std::string::npos);

  reb::HeapSnapshotDiffResult unchanged;
  CHECK(reb::CompareV8HeapSnapshots(baseline_snapshot.Path(), baseline_snapshot.Path(), 50,
                                    unchanged, error));
  CHECK(unchanged.groups.empty());
  CHECK(unchanged.dominators.empty());

  TemporarySnapshot diamond_baseline;
  std::ofstream diamond_baseline_output(diamond_baseline.Path(), std::ios::binary);
  diamond_baseline_output << R"({
    "snapshot":{"meta":{
      "node_fields":["type","name","id","self_size","edge_count"],
      "node_types":[["synthetic","object"],"string","number","number","number"],
      "edge_fields":["type","name_or_index","to_node"],
      "edge_types":[["property"],"string_or_number","node"]},
      "node_count":4,"edge_count":4},
    "nodes":[0,0,1,0,2, 1,1,3,3,1, 1,2,5,4,1, 1,3,7,5,0],
    "edges":[0,4,5, 0,5,10, 0,6,15, 0,6,15],
    "strings":["","Left","Right","Shared","left","right","shared"]
  })";
  diamond_baseline_output.close();
  CHECK(diamond_baseline_output.good());

  TemporarySnapshot diamond_current;
  std::ofstream diamond_current_output(diamond_current.Path(), std::ios::binary);
  diamond_current_output << R"({
    "snapshot":{"meta":{
      "node_fields":["type","name","id","self_size","edge_count"],
      "node_types":[["synthetic","object"],"string","number","number","number"],
      "edge_fields":["type","name_or_index","to_node"],
      "edge_types":[["property"],"string_or_number","node"]},
      "node_count":4,"edge_count":4},
    "nodes":[0,0,1,0,2, 1,1,3,3,1, 1,2,5,4,1, 1,3,7,15,0],
    "edges":[0,4,5, 0,5,10, 0,6,15, 0,6,15],
    "strings":["","Left","Right","Shared","left","right","shared"]
  })";
  diamond_current_output.close();
  CHECK(diamond_current_output.good());

  reb::HeapSnapshotDiffResult diamond_diff;
  CHECK(reb::CompareV8HeapSnapshots(diamond_baseline.Path(), diamond_current.Path(), 50,
                                    diamond_diff, error));
  CHECK(diamond_diff.dominators.size() == 1);
  CHECK(diamond_diff.dominators[0].node_id == 7);
  CHECK(diamond_diff.dominators[0].baseline_retained_size == 5);
  CHECK(diamond_diff.dominators[0].current_retained_size == 15);
  CHECK(diamond_diff.dominators[0].retained_size_delta == 10);

  TemporarySnapshot malformed;
  std::ofstream malformed_output(malformed.Path(), std::ios::binary);
  malformed_output << "{\"snapshot\":{},\"nodes\":[]}";
  malformed_output.close();
  CHECK(!reb::SearchV8HeapSnapshot(malformed.Path(), "x", false, 50, result, error));
  CHECK(!error.empty());
  CHECK(!reb::CompareV8HeapSnapshots(malformed.Path(), current_snapshot.Path(), 50, diff, error));
  CHECK(!error.empty());

  std::cout << "heap_snapshot_test passed\n";
  return 0;
}
