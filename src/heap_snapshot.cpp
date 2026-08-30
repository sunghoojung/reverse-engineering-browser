#include "reb/heap_snapshot.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <limits>
#include <queue>
#include <sstream>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace reb {
namespace {

constexpr std::size_t kMaxJsonDepth = 64;
constexpr std::size_t kMaxMetadataFields = 64;
constexpr std::size_t kMaxMetadataTextBytes = 256;
constexpr std::size_t kNoNode = std::numeric_limits<std::size_t>::max();

struct SnapshotData final {
  std::uint64_t declared_nodes = 0;
  std::uint64_t declared_edges = 0;
  std::vector<std::string> node_fields;
  std::vector<std::string> node_types;
  std::vector<std::string> edge_fields;
  std::vector<std::string> edge_types;
  std::vector<std::uint64_t> nodes;
  std::vector<std::uint64_t> edges;
  std::vector<std::string> strings;
  std::size_t node_values_seen = 0;
  std::size_t edge_values_seen = 0;
  std::size_t strings_seen = 0;
  std::size_t stored_string_bytes = 0;
  bool node_values_truncated = false;
  bool edge_values_truncated = false;
  bool strings_truncated = false;
};

class JsonReader final {
 public:
  explicit JsonReader(const std::string_view input) noexcept : input_(input) {}

  [[nodiscard]] bool AtEnd() noexcept {
    SkipWhitespace();
    return position_ == input_.size();
  }

  [[nodiscard]] bool Consume(const char expected) noexcept {
    SkipWhitespace();
    if (position_ >= input_.size() || input_[position_] != expected) {
      return false;
    }
    ++position_;
    return true;
  }

  [[nodiscard]] bool ReadString(std::string& output,
                                const std::size_t maximum_bytes,
                                bool& truncated) {
    SkipWhitespace();
    if (position_ >= input_.size() || input_[position_] != '"') {
      return false;
    }
    ++position_;
    output.clear();
    truncated = false;
    while (position_ < input_.size()) {
      const auto character = static_cast<unsigned char>(input_[position_++]);
      if (character == '"') {
        return true;
      }
      if (character < 0x20U) {
        return false;
      }
      if (character != '\\') {
        AppendByte(character, output, maximum_bytes, truncated);
        continue;
      }
      if (position_ >= input_.size()) {
        return false;
      }
      const char escape = input_[position_++];
      switch (escape) {
        case '"':
        case '\\':
        case '/':
          AppendByte(static_cast<unsigned char>(escape), output, maximum_bytes, truncated);
          break;
        case 'b':
          AppendByte('\b', output, maximum_bytes, truncated);
          break;
        case 'f':
          AppendByte('\f', output, maximum_bytes, truncated);
          break;
        case 'n':
          AppendByte('\n', output, maximum_bytes, truncated);
          break;
        case 'r':
          AppendByte('\r', output, maximum_bytes, truncated);
          break;
        case 't':
          AppendByte('\t', output, maximum_bytes, truncated);
          break;
        case 'u': {
          std::uint32_t code_point = 0;
          if (!ReadHexQuad(code_point)) {
            return false;
          }
          if (code_point >= 0xd800U && code_point <= 0xdbffU) {
            if (position_ + 2 > input_.size() || input_[position_] != '\\' ||
                input_[position_ + 1] != 'u') {
              return false;
            }
            position_ += 2;
            std::uint32_t low = 0;
            if (!ReadHexQuad(low) || low < 0xdc00U || low > 0xdfffU) {
              return false;
            }
            code_point = 0x10000U + ((code_point - 0xd800U) << 10U) + (low - 0xdc00U);
          } else if (code_point >= 0xdc00U && code_point <= 0xdfffU) {
            return false;
          }
          AppendCodePoint(code_point, output, maximum_bytes, truncated);
          break;
        }
        default:
          return false;
      }
    }
    return false;
  }

  [[nodiscard]] bool ReadUnsigned(std::uint64_t& value) noexcept {
    SkipWhitespace();
    const std::size_t start = position_;
    while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
      ++position_;
    }
    if (start == position_) {
      return false;
    }
    const char* first = input_.data() + start;
    const char* last = input_.data() + position_;
    const auto parsed = std::from_chars(first, last, value);
    return parsed.ec == std::errc{} && parsed.ptr == last;
  }

  [[nodiscard]] bool SkipValue(const std::size_t depth = 0) {
    if (depth > kMaxJsonDepth) {
      return false;
    }
    SkipWhitespace();
    if (position_ >= input_.size()) {
      return false;
    }
    if (input_[position_] == '"') {
      std::string ignored;
      bool truncated = false;
      return ReadString(ignored, 0, truncated);
    }
    if (input_[position_] == '{') {
      ++position_;
      SkipWhitespace();
      if (position_ < input_.size() && input_[position_] == '}') {
        ++position_;
        return true;
      }
      while (position_ < input_.size()) {
        std::string ignored;
        bool truncated = false;
        if (!ReadString(ignored, 0, truncated) || !Consume(':') || !SkipValue(depth + 1)) {
          return false;
        }
        SkipWhitespace();
        if (position_ < input_.size() && input_[position_] == '}') {
          ++position_;
          return true;
        }
        if (!Consume(',')) {
          return false;
        }
      }
      return false;
    }
    if (input_[position_] == '[') {
      ++position_;
      SkipWhitespace();
      if (position_ < input_.size() && input_[position_] == ']') {
        ++position_;
        return true;
      }
      while (position_ < input_.size()) {
        if (!SkipValue(depth + 1)) {
          return false;
        }
        SkipWhitespace();
        if (position_ < input_.size() && input_[position_] == ']') {
          ++position_;
          return true;
        }
        if (!Consume(',')) {
          return false;
        }
      }
      return false;
    }
    if (input_.substr(position_).starts_with("true")) {
      position_ += 4;
      return true;
    }
    if (input_.substr(position_).starts_with("false")) {
      position_ += 5;
      return true;
    }
    if (input_.substr(position_).starts_with("null")) {
      position_ += 4;
      return true;
    }
    return SkipNumber();
  }

 private:
  void SkipWhitespace() noexcept {
    while (position_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[position_])) != 0) {
      ++position_;
    }
  }

  [[nodiscard]] bool ReadHexQuad(std::uint32_t& value) noexcept {
    if (position_ + 4 > input_.size()) {
      return false;
    }
    value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
      const char digit = input_[position_++];
      value <<= 4U;
      if (digit >= '0' && digit <= '9') {
        value |= static_cast<std::uint32_t>(digit - '0');
      } else if (digit >= 'a' && digit <= 'f') {
        value |= static_cast<std::uint32_t>(digit - 'a' + 10);
      } else if (digit >= 'A' && digit <= 'F') {
        value |= static_cast<std::uint32_t>(digit - 'A' + 10);
      } else {
        return false;
      }
    }
    return true;
  }

  static void AppendByte(const unsigned char byte,
                         std::string& output,
                         const std::size_t maximum_bytes,
                         bool& truncated) {
    if (output.size() < maximum_bytes) {
      output.push_back(static_cast<char>(byte));
    } else {
      truncated = true;
    }
  }

  static void AppendCodePoint(const std::uint32_t code_point,
                              std::string& output,
                              const std::size_t maximum_bytes,
                              bool& truncated) {
    std::array<unsigned char, 4> encoded{};
    std::size_t size = 0;
    if (code_point <= 0x7fU) {
      encoded[0] = static_cast<unsigned char>(code_point);
      size = 1;
    } else if (code_point <= 0x7ffU) {
      encoded[0] = static_cast<unsigned char>(0xc0U | (code_point >> 6U));
      encoded[1] = static_cast<unsigned char>(0x80U | (code_point & 0x3fU));
      size = 2;
    } else if (code_point <= 0xffffU) {
      encoded[0] = static_cast<unsigned char>(0xe0U | (code_point >> 12U));
      encoded[1] = static_cast<unsigned char>(0x80U | ((code_point >> 6U) & 0x3fU));
      encoded[2] = static_cast<unsigned char>(0x80U | (code_point & 0x3fU));
      size = 3;
    } else {
      encoded[0] = static_cast<unsigned char>(0xf0U | (code_point >> 18U));
      encoded[1] = static_cast<unsigned char>(0x80U | ((code_point >> 12U) & 0x3fU));
      encoded[2] = static_cast<unsigned char>(0x80U | ((code_point >> 6U) & 0x3fU));
      encoded[3] = static_cast<unsigned char>(0x80U | (code_point & 0x3fU));
      size = 4;
    }
    if (size <= maximum_bytes - std::min(maximum_bytes, output.size())) {
      for (std::size_t index = 0; index < size; ++index) {
        output.push_back(static_cast<char>(encoded[index]));
      }
    } else {
      truncated = true;
    }
  }

  [[nodiscard]] bool SkipNumber() noexcept {
    const std::size_t start = position_;
    if (position_ < input_.size() && input_[position_] == '-') {
      ++position_;
    }
    if (position_ >= input_.size()) {
      return false;
    }
    if (input_[position_] == '0') {
      ++position_;
    } else {
      if (input_[position_] < '1' || input_[position_] > '9') {
        return false;
      }
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
        ++position_;
      }
    }
    if (position_ < input_.size() && input_[position_] == '.') {
      ++position_;
      const std::size_t fraction = position_;
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
        ++position_;
      }
      if (fraction == position_) {
        return false;
      }
    }
    if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
      ++position_;
      if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) {
        ++position_;
      }
      const std::size_t exponent = position_;
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
        ++position_;
      }
      if (exponent == position_) {
        return false;
      }
    }
    return position_ > start;
  }

  std::string_view input_;
  std::size_t position_ = 0;
};

bool ParseStringArray(JsonReader& reader,
                      std::vector<std::string>& output,
                      const std::size_t maximum_count,
                      const std::size_t maximum_text_bytes,
                      bool& truncated) {
  if (!reader.Consume('[')) {
    return false;
  }
  if (reader.Consume(']')) {
    return true;
  }
  while (true) {
    std::string value;
    bool value_truncated = false;
    if (!reader.ReadString(value, maximum_text_bytes, value_truncated)) {
      return false;
    }
    if (output.size() < maximum_count) {
      output.push_back(std::move(value));
    } else {
      truncated = true;
    }
    truncated = truncated || value_truncated;
    if (reader.Consume(']')) {
      return true;
    }
    if (!reader.Consume(',')) {
      return false;
    }
  }
}

bool ParseTypeTable(JsonReader& reader, std::vector<std::string>& types, bool& truncated) {
  if (!reader.Consume('[')) {
    return false;
  }
  if (reader.Consume(']')) {
    return true;
  }
  if (!ParseStringArray(reader, types, kMaxMetadataFields, kMaxMetadataTextBytes, truncated)) {
    return false;
  }
  while (!reader.Consume(']')) {
    if (!reader.Consume(',') || !reader.SkipValue()) {
      return false;
    }
  }
  return true;
}

bool ParseMeta(JsonReader& reader, SnapshotData& data) {
  if (!reader.Consume('{')) {
    return false;
  }
  if (reader.Consume('}')) {
    return true;
  }
  while (true) {
    std::string key;
    bool key_truncated = false;
    if (!reader.ReadString(key, kMaxMetadataTextBytes, key_truncated) || key_truncated ||
        !reader.Consume(':')) {
      return false;
    }
    bool truncated = false;
    if (key == "node_fields") {
      if (!ParseStringArray(reader, data.node_fields, kMaxMetadataFields, kMaxMetadataTextBytes,
                            truncated) ||
          truncated) {
        return false;
      }
    } else if (key == "node_types") {
      if (!ParseTypeTable(reader, data.node_types, truncated) || truncated) {
        return false;
      }
    } else if (key == "edge_fields") {
      if (!ParseStringArray(reader, data.edge_fields, kMaxMetadataFields, kMaxMetadataTextBytes,
                            truncated) ||
          truncated) {
        return false;
      }
    } else if (key == "edge_types") {
      if (!ParseTypeTable(reader, data.edge_types, truncated) || truncated) {
        return false;
      }
    } else if (!reader.SkipValue()) {
      return false;
    }
    if (reader.Consume('}')) {
      return true;
    }
    if (!reader.Consume(',')) {
      return false;
    }
  }
}

bool ParseSnapshotHeader(JsonReader& reader, SnapshotData& data) {
  if (!reader.Consume('{')) {
    return false;
  }
  if (reader.Consume('}')) {
    return true;
  }
  while (true) {
    std::string key;
    bool truncated = false;
    if (!reader.ReadString(key, kMaxMetadataTextBytes, truncated) || truncated ||
        !reader.Consume(':')) {
      return false;
    }
    if (key == "meta") {
      if (!ParseMeta(reader, data)) {
        return false;
      }
    } else if (key == "node_count") {
      if (!reader.ReadUnsigned(data.declared_nodes)) {
        return false;
      }
    } else if (key == "edge_count") {
      if (!reader.ReadUnsigned(data.declared_edges)) {
        return false;
      }
    } else if (!reader.SkipValue()) {
      return false;
    }
    if (reader.Consume('}')) {
      return true;
    }
    if (!reader.Consume(',')) {
      return false;
    }
  }
}

bool ParseUnsignedArray(JsonReader& reader,
                        std::vector<std::uint64_t>& output,
                        const std::size_t maximum_values,
                        std::size_t& values_seen,
                        bool& truncated) {
  if (!reader.Consume('[')) {
    return false;
  }
  if (reader.Consume(']')) {
    return true;
  }
  while (true) {
    std::uint64_t value = 0;
    if (!reader.ReadUnsigned(value)) {
      return false;
    }
    if (values_seen == std::numeric_limits<std::size_t>::max()) {
      return false;
    }
    ++values_seen;
    if (output.size() < maximum_values) {
      output.push_back(value);
    } else {
      truncated = true;
    }
    if (reader.Consume(']')) {
      return true;
    }
    if (!reader.Consume(',')) {
      return false;
    }
  }
}

bool ParseSnapshotStrings(JsonReader& reader, SnapshotData& data) {
  if (!reader.Consume('[')) {
    return false;
  }
  if (reader.Consume(']')) {
    return true;
  }
  while (true) {
    std::string value;
    bool value_truncated = false;
    const bool count_available = data.strings.size() < kHeapSnapshotMaxStrings;
    const bool bytes_available = data.stored_string_bytes < kHeapSnapshotMaxStringBytes;
    const std::size_t per_string_limit =
        count_available && bytes_available
            ? std::min(kHeapSnapshotMaxStoredStringBytes,
                       kHeapSnapshotMaxStringBytes - data.stored_string_bytes)
            : 0;
    if (!reader.ReadString(value, per_string_limit, value_truncated)) {
      return false;
    }
    if (data.strings_seen == std::numeric_limits<std::size_t>::max()) {
      return false;
    }
    ++data.strings_seen;
    if (count_available && bytes_available) {
      data.stored_string_bytes += value.size();
      data.strings.push_back(std::move(value));
    } else {
      data.strings_truncated = true;
    }
    data.strings_truncated = data.strings_truncated || value_truncated;
    if (reader.Consume(']')) {
      return true;
    }
    if (!reader.Consume(',')) {
      return false;
    }
  }
}

bool ParseSnapshotDocument(const std::string_view document, SnapshotData& data) {
  JsonReader reader(document);
  if (!reader.Consume('{') || reader.Consume('}')) {
    return false;
  }
  while (true) {
    std::string key;
    bool truncated = false;
    if (!reader.ReadString(key, kMaxMetadataTextBytes, truncated) || truncated ||
        !reader.Consume(':')) {
      return false;
    }
    if (key == "snapshot") {
      if (!ParseSnapshotHeader(reader, data)) {
        return false;
      }
    } else if (key == "nodes") {
      if (data.node_fields.empty() ||
          data.node_fields.size() >
              std::numeric_limits<std::size_t>::max() / kHeapSnapshotMaxNodes ||
          !ParseUnsignedArray(reader, data.nodes, data.node_fields.size() * kHeapSnapshotMaxNodes,
                              data.node_values_seen, data.node_values_truncated)) {
        return false;
      }
    } else if (key == "edges") {
      if (data.edge_fields.empty() ||
          data.edge_fields.size() >
              std::numeric_limits<std::size_t>::max() / kHeapSnapshotMaxEdges ||
          !ParseUnsignedArray(reader, data.edges, data.edge_fields.size() * kHeapSnapshotMaxEdges,
                              data.edge_values_seen, data.edge_values_truncated)) {
        return false;
      }
    } else if (key == "strings") {
      if (!ParseSnapshotStrings(reader, data)) {
        return false;
      }
    } else if (!reader.SkipValue()) {
      return false;
    }
    if (reader.Consume('}')) {
      return reader.AtEnd();
    }
    if (!reader.Consume(',')) {
      return false;
    }
  }
}

std::size_t FieldIndex(const std::vector<std::string>& fields, const std::string_view name) {
  const auto iterator = std::find(fields.begin(), fields.end(), name);
  return iterator == fields.end() ? kNoNode : static_cast<std::size_t>(iterator - fields.begin());
}

std::string_view StringAt(const SnapshotData& data, const std::uint64_t index) noexcept {
  if (index >= data.strings.size()) {
    return {};
  }
  return data.strings[static_cast<std::size_t>(index)];
}

std::string_view NodeTypeAt(const SnapshotData& data,
                            const std::size_t node_offset,
                            const std::size_t type_field) noexcept {
  const std::uint64_t type_index = data.nodes[node_offset + type_field];
  if (type_index >= data.node_types.size()) {
    return "unknown";
  }
  return data.node_types[static_cast<std::size_t>(type_index)];
}

char AsciiFold(const char character) noexcept {
  return character >= 'A' && character <= 'Z' ? static_cast<char>(character - 'A' + 'a')
                                              : character;
}

bool ContainsText(const std::string_view haystack,
                  const std::string_view needle,
                  const bool case_sensitive) noexcept {
  if (case_sensitive) {
    return haystack.find(needle) != std::string_view::npos;
  }
  return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                     [](const char left, const char right) {
                       return AsciiFold(left) == AsciiFold(right);
                     }) != haystack.end();
}

std::string BoundedText(const std::string_view value, const std::size_t limit = 256) {
  if (value.size() <= limit) {
    return std::string(value);
  }
  std::string output(value.substr(0, limit));
  output.append("...");
  return output;
}

std::string EdgeName(const SnapshotData& data,
                     const std::size_t edge_offset,
                     const std::size_t edge_type_field,
                     const std::size_t edge_name_field) {
  const std::uint64_t type_index = data.edges[edge_offset + edge_type_field];
  const std::string_view type =
      type_index < data.edge_types.size()
          ? std::string_view(data.edge_types[static_cast<std::size_t>(type_index)])
          : std::string_view("unknown");
  const std::uint64_t name_or_index = data.edges[edge_offset + edge_name_field];
  if (type == "element" || type == "hidden") {
    return "[" + std::to_string(name_or_index) + "]";
  }
  const std::string_view name = StringAt(data, name_or_index);
  return name.empty() ? std::string(type) : BoundedText(name, 128);
}

bool IsWeakEdge(const SnapshotData& data,
                const std::size_t edge_offset,
                const std::size_t edge_type_field) noexcept {
  const std::uint64_t type_index = data.edges[edge_offset + edge_type_field];
  return type_index < data.edge_types.size() &&
         data.edge_types[static_cast<std::size_t>(type_index)] == "weak";
}

std::string JsonEscape(const std::string_view text) {
  std::ostringstream output;
  for (const char raw_character : text) {
    const auto character = static_cast<unsigned char>(raw_character);
    switch (character) {
      case '"':
        output << "\\\"";
        break;
      case '\\':
        output << "\\\\";
        break;
      case '\b':
        output << "\\b";
        break;
      case '\f':
        output << "\\f";
        break;
      case '\n':
        output << "\\n";
        break;
      case '\r':
        output << "\\r";
        break;
      case '\t':
        output << "\\t";
        break;
      default:
        if (character < 0x20U) {
          output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                 << static_cast<unsigned int>(character) << std::dec;
        } else {
          output << static_cast<char>(character);
        }
    }
  }
  return output.str();
}

}  // namespace

bool SearchV8HeapSnapshot(const std::filesystem::path& snapshot_path,
                          const std::string_view query,
                          const bool case_sensitive,
                          const std::size_t requested_result_limit,
                          HeapSnapshotSearchResult& result,
                          std::string& error) {
  const auto started = std::chrono::steady_clock::now();
  result = {};
  result.result_limit = std::min(requested_result_limit, kHeapSnapshotMaxResults);
  error.clear();
  if (query.empty() || query.size() > 512 || result.result_limit == 0) {
    error = "Heap snapshot query or result limit is invalid";
    return false;
  }
  std::error_code file_error;
  const std::uintmax_t file_size = std::filesystem::file_size(snapshot_path, file_error);
  if (file_error || file_size == 0 || file_size > kHeapSnapshotMaxFileBytes ||
      file_size > std::numeric_limits<std::size_t>::max()) {
    error = "Heap snapshot file is missing, empty, or exceeds 256 MiB";
    return false;
  }
  result.file_bytes = static_cast<std::uint64_t>(file_size);
  std::ifstream input(snapshot_path, std::ios::binary);
  if (!input) {
    error = "Heap snapshot file could not be opened";
    return false;
  }
  std::string document(static_cast<std::size_t>(file_size), '\0');
  input.read(document.data(), static_cast<std::streamsize>(document.size()));
  if (!input || input.gcount() != static_cast<std::streamsize>(document.size())) {
    error = "Heap snapshot file could not be read completely";
    return false;
  }

  SnapshotData data;
  if (!ParseSnapshotDocument(document, data)) {
    error = "Heap snapshot JSON is malformed or unsupported";
    return false;
  }
  const std::size_t node_width = data.node_fields.size();
  const std::size_t edge_width = data.edge_fields.size();
  const std::size_t node_type_field = FieldIndex(data.node_fields, "type");
  const std::size_t node_name_field = FieldIndex(data.node_fields, "name");
  const std::size_t node_id_field = FieldIndex(data.node_fields, "id");
  const std::size_t node_size_field = FieldIndex(data.node_fields, "self_size");
  const std::size_t node_edge_count_field = FieldIndex(data.node_fields, "edge_count");
  const std::size_t edge_type_field = FieldIndex(data.edge_fields, "type");
  const std::size_t edge_name_field = FieldIndex(data.edge_fields, "name_or_index");
  const std::size_t edge_target_field = FieldIndex(data.edge_fields, "to_node");
  if (node_width == 0 || edge_width == 0 || node_type_field == kNoNode ||
      node_name_field == kNoNode || node_id_field == kNoNode || node_size_field == kNoNode ||
      node_edge_count_field == kNoNode || edge_type_field == kNoNode ||
      edge_name_field == kNoNode || edge_target_field == kNoNode || data.node_types.empty() ||
      data.edge_types.empty() || data.node_values_seen % node_width != 0 ||
      data.edge_values_seen % edge_width != 0) {
    error = "Heap snapshot metadata is incomplete";
    return false;
  }
  const std::size_t actual_nodes = data.node_values_seen / node_width;
  const std::size_t actual_edges = data.edge_values_seen / edge_width;
  if (data.declared_nodes != actual_nodes || data.declared_edges != actual_edges) {
    error = "Heap snapshot counts do not match its data arrays";
    return false;
  }
  const std::size_t stored_nodes = data.nodes.size() / node_width;
  const std::size_t stored_edges = data.edges.size() / edge_width;
  result.total_nodes = data.declared_nodes;
  result.total_edges = data.declared_edges;
  result.indexed_edges = stored_edges;
  result.total_strings = data.strings_seen;
  result.node_limit_reached = data.node_values_truncated;
  result.edge_limit_reached = data.edge_values_truncated;
  result.string_limit_reached = data.strings_truncated;

  std::vector<std::size_t> match_nodes;
  match_nodes.reserve(result.result_limit);
  for (std::size_t ordinal = 0; ordinal < stored_nodes; ++ordinal) {
    const std::size_t offset = ordinal * node_width;
    ++result.analyzed_nodes;
    const std::string_view name = StringAt(data, data.nodes[offset + node_name_field]);
    if (!ContainsText(name, query, case_sensitive)) {
      continue;
    }
    HeapSnapshotMatch match;
    match.node_id = data.nodes[offset + node_id_field];
    match.self_size = data.nodes[offset + node_size_field];
    match.node_type = BoundedText(NodeTypeAt(data, offset, node_type_field), 64);
    match.node_name = BoundedText(name);
    result.matches.push_back(std::move(match));
    match_nodes.push_back(ordinal);
    if (result.matches.size() >= result.result_limit) {
      result.result_limit_reached = true;
      break;
    }
  }

  if (!match_nodes.empty() && stored_nodes > 0) {
    std::vector<std::size_t> edge_starts(stored_nodes, 0);
    std::size_t edge_cursor = 0;
    for (std::size_t ordinal = 0; ordinal < stored_nodes; ++ordinal) {
      edge_starts[ordinal] = edge_cursor;
      const std::uint64_t count = data.nodes[ordinal * node_width + node_edge_count_field];
      if (count > std::numeric_limits<std::size_t>::max() - edge_cursor) {
        error = "Heap snapshot edge counts overflow the native index";
        return false;
      }
      edge_cursor += static_cast<std::size_t>(count);
    }

    std::vector<std::size_t> parents(stored_nodes, kNoNode);
    std::vector<std::size_t> parent_edges(stored_nodes, kNoNode);
    std::queue<std::size_t> pending;
    parents[0] = 0;
    pending.push(0);
    while (!pending.empty()) {
      const std::size_t from = pending.front();
      pending.pop();
      const std::size_t first_edge = edge_starts[from];
      const std::uint64_t count_value = data.nodes[from * node_width + node_edge_count_field];
      const std::size_t count = static_cast<std::size_t>(count_value);
      for (std::size_t local = 0; local < count && first_edge + local < stored_edges; ++local) {
        const std::size_t edge_ordinal = first_edge + local;
        const std::size_t edge_offset = edge_ordinal * edge_width;
        if (IsWeakEdge(data, edge_offset, edge_type_field)) {
          continue;
        }
        const std::uint64_t raw_target = data.edges[edge_offset + edge_target_field];
        if (raw_target % node_width != 0) {
          continue;
        }
        const std::uint64_t target_value = raw_target / node_width;
        if (target_value >= stored_nodes) {
          continue;
        }
        const std::size_t target = static_cast<std::size_t>(target_value);
        if (parents[target] != kNoNode) {
          continue;
        }
        parents[target] = from;
        parent_edges[target] = edge_ordinal;
        pending.push(target);
      }
    }

    for (std::size_t match_index = 0; match_index < match_nodes.size(); ++match_index) {
      const std::size_t target = match_nodes[match_index];
      auto& match = result.matches[match_index];
      if (parents[target] == kNoNode) {
        result.retaining_paths_partial = true;
        continue;
      }
      std::vector<HeapSnapshotRetainingStep> reverse_path;
      std::size_t current = target;
      while (current != 0 && reverse_path.size() < kHeapSnapshotMaxRetainingDepth) {
        const std::size_t edge_ordinal = parent_edges[current];
        if (edge_ordinal == kNoNode || edge_ordinal >= stored_edges) {
          break;
        }
        const std::size_t node_offset = current * node_width;
        const std::size_t edge_offset = edge_ordinal * edge_width;
        reverse_path.push_back({
            EdgeName(data, edge_offset, edge_type_field, edge_name_field),
            BoundedText(NodeTypeAt(data, node_offset, node_type_field), 64),
            BoundedText(StringAt(data, data.nodes[node_offset + node_name_field])),
        });
        current = parents[current];
      }
      match.retaining_path_complete = current == 0;
      if (!match.retaining_path_complete) {
        result.retaining_paths_partial = true;
      }
      std::reverse(reverse_path.begin(), reverse_path.end());
      match.retaining_path = std::move(reverse_path);
    }
  }

  result.duration_ms =
      static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started)
                                     .count());
  return true;
}

std::string HeapSnapshotSearchResultToJson(const HeapSnapshotSearchResult& result) {
  std::ostringstream output;
  output << "{\"protocol_version\":" << result.protocol_version
         << ",\"file_bytes\":" << result.file_bytes << ",\"total_nodes\":" << result.total_nodes
         << ",\"analyzed_nodes\":" << result.analyzed_nodes
         << ",\"total_edges\":" << result.total_edges
         << ",\"indexed_edges\":" << result.indexed_edges
         << ",\"total_strings\":" << result.total_strings
         << ",\"duration_ms\":" << result.duration_ms << ",\"result_limit\":" << result.result_limit
         << ",\"result_limit_reached\":" << (result.result_limit_reached ? "true" : "false")
         << ",\"node_limit_reached\":" << (result.node_limit_reached ? "true" : "false")
         << ",\"edge_limit_reached\":" << (result.edge_limit_reached ? "true" : "false")
         << ",\"string_limit_reached\":" << (result.string_limit_reached ? "true" : "false")
         << ",\"retaining_paths_partial\":" << (result.retaining_paths_partial ? "true" : "false")
         << ",\"results\":[";
  for (std::size_t index = 0; index < result.matches.size(); ++index) {
    if (index != 0) {
      output << ',';
    }
    const auto& match = result.matches[index];
    output << "{\"id\":\"" << match.node_id << "\",\"type\":\"" << JsonEscape(match.node_type)
           << "\",\"name\":\"" << JsonEscape(match.node_name)
           << "\",\"self_size\":" << match.self_size
           << ",\"retaining_path_complete\":" << (match.retaining_path_complete ? "true" : "false")
           << ",\"retaining_path\":[";
    for (std::size_t path_index = 0; path_index < match.retaining_path.size(); ++path_index) {
      if (path_index != 0) {
        output << ',';
      }
      const auto& step = match.retaining_path[path_index];
      output << "{\"edge\":\"" << JsonEscape(step.edge_name) << "\",\"type\":\""
             << JsonEscape(step.node_type) << "\",\"name\":\"" << JsonEscape(step.node_name)
             << "\"}";
    }
    output << "]}";
  }
  output << "]}";
  return output.str();
}

}  // namespace reb
