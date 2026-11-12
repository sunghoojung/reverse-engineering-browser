// C ABI between the graph layout worker (src/graph_layout.rs) and the vendored
// Triskel engine. It lays out exactly the graph it is given; the worker adds the
// virtual root Triskel needs and drops it from the result.
//
// This code runs only inside the contained `--graph-layout-worker` process,
// never in the HTTP server: Triskel is third-party code fed graphs shaped by
// captured pages, and it is built with NDEBUG, so a broken invariant is not
// caught by an assert.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <new>
#include <string>
#include <vector>

#include "triskel/triskel.hpp"

extern "C" {

// Read-only view of one result. Every pointer stays valid until
// reb_graph_layout_free releases the handle that filled it.
struct RebGraphLayoutView {
  // x, y of each node's top-left corner, node_count pairs.
  const float* nodes;
  size_t node_count;
  // edge_count + 1 offsets into points; edge i is points[offsets[i], offsets[i + 1]).
  const size_t* edge_offsets;
  size_t edge_count;
  // x, y of each waypoint, point_count pairs.
  const float* points;
  size_t point_count;
  // NUL-terminated reason when the layout failed, otherwise null.
  const char* error;
};

}  // extern "C"

namespace {

struct Layout {
  std::vector<float> nodes;
  std::vector<size_t> offsets;
  std::vector<float> points;
  std::string error;
};

void lay_out(Layout& layout,
             size_t node_count,
             const float* sizes,
             size_t edge_count,
             const uint32_t* endpoints) {
  auto builder = triskel::make_layout_builder();
  std::vector<size_t> nodes;
  nodes.reserve(node_count);
  for (size_t node = 0; node < node_count; ++node) {
    // Triskel takes the height first.
    nodes.push_back(builder->make_node(sizes[2 * node + 1], sizes[2 * node]));
  }
  std::vector<size_t> edges;
  edges.reserve(edge_count);
  for (size_t edge = 0; edge < edge_count; ++edge) {
    edges.push_back(
        builder->make_edge(nodes.at(endpoints[2 * edge]), nodes.at(endpoints[2 * edge + 1])));
  }
  auto result = builder->build();
  layout.nodes.reserve(2 * node_count);
  for (size_t node : nodes) {
    auto corner = result->get_coords(node);
    layout.nodes.push_back(corner.x);
    layout.nodes.push_back(corner.y);
  }
  layout.offsets.reserve(edge_count + 1);
  layout.offsets.push_back(0);
  for (size_t edge : edges) {
    for (const auto& point : result->get_waypoints(edge)) {
      layout.points.push_back(point.x);
      layout.points.push_back(point.y);
    }
    layout.offsets.push_back(layout.points.size() / 2);
  }
}

}  // namespace

extern "C" {

// Lays out node_count nodes (sizes holds width, height pairs) and edge_count
// edges (endpoints holds from, to pairs of node indexes). Returns a handle for
// reb_graph_layout_free and fills view, or returns null when not even the
// result could be allocated. Every C++ exception becomes view->error.
void* reb_graph_layout(size_t node_count,
                       const float* sizes,
                       size_t edge_count,
                       const uint32_t* endpoints,
                       RebGraphLayoutView* view) noexcept {
  auto* layout = new (std::nothrow) Layout;
  if (layout == nullptr) {
    return nullptr;
  }
  try {
    lay_out(*layout, node_count, sizes, edge_count, endpoints);
  } catch (const std::exception& error) {
    layout->error = error.what();
  } catch (...) {
    layout->error = "unknown exception";
  }
  if (layout->error.empty() &&
      (layout->nodes.size() != 2 * node_count || layout->offsets.size() != edge_count + 1)) {
    layout->error = "incomplete layout";
  }
  if (!layout->error.empty()) {
    layout->nodes.clear();
    layout->offsets.clear();
    layout->points.clear();
  }
  view->nodes = layout->nodes.data();
  view->node_count = layout->nodes.size() / 2;
  view->edge_offsets = layout->offsets.data();
  view->edge_count = layout->offsets.empty() ? 0 : layout->offsets.size() - 1;
  view->points = layout->points.data();
  view->point_count = layout->points.size() / 2;
  view->error = layout->error.empty() ? nullptr : layout->error.c_str();
  return layout;
}

void reb_graph_layout_free(void* layout) noexcept {
  delete static_cast<Layout*>(layout);
}

}  // extern "C"
