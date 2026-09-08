#include "reb/heap_snapshot.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <iomanip>
#include <limits>
#include <sstream>
#include <system_error>
#include <unordered_map>
#include <utility>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace reb {
namespace {

constexpr std::size_t kMaxJsonDepth = 64;
constexpr std::size_t kMaxMetadataFields = 64;
constexpr std::size_t kMaxMetadataTextBytes = 256;
constexpr std::size_t kMaxStoredNodeBytes = 128U * 1024U * 1024U;
constexpr std::size_t kMaxStoredEdgeBytes = 192U * 1024U * 1024U;
constexpr std::size_t kInitialBfsQueueReserve = 64U * 1024U;
constexpr std::size_t kNoNode = std::numeric_limits<std::size_t>::max();

class ReadOnlyFileMapping final {
 public:
  ReadOnlyFileMapping() = default;
  ReadOnlyFileMapping(const ReadOnlyFileMapping&) = delete;
  ReadOnlyFileMapping& operator=(const ReadOnlyFileMapping&) = delete;

  ~ReadOnlyFileMapping() {
    if (data_ != MAP_FAILED) {
      static_cast<void>(munmap(data_, size_));
    }
  }

  bool Open(const std::filesystem::path& path, std::string& error) noexcept {
    const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
      error = "Heap snapshot file could not be opened";
      return false;
    }
    struct stat metadata {};
    const bool valid_metadata =
        fstat(descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode) && metadata.st_size > 0 &&
        static_cast<std::uintmax_t>(metadata.st_size) <= kHeapSnapshotMaxFileBytes &&
        static_cast<std::uintmax_t>(metadata.st_size) <= std::numeric_limits<std::size_t>::max();
    if (!valid_metadata) {
      static_cast<void>(close(descriptor));
      error = "Heap snapshot file is missing, empty, or exceeds 256 MiB";
      return false;
    }
    size_ = static_cast<std::size_t>(metadata.st_size);
    data_ = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, descriptor, 0);
    static_cast<void>(close(descriptor));
    if (data_ == MAP_FAILED) {
      size_ = 0;
      error = "Heap snapshot file could not be mapped";
      return false;
    }
    static_cast<void>(madvise(data_, size_, MADV_SEQUENTIAL));
    return true;
  }

  [[nodiscard]] std::string_view View() const noexcept {
    return {static_cast<const char*>(data_), size_};
  }

  [[nodiscard]] std::size_t Size() const noexcept { return size_; }

 private:
  void* data_ = MAP_FAILED;
  std::size_t size_ = 0;
};

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
              std::numeric_limits<std::size_t>::max() / kHeapSnapshotMaxNodes) {
        return false;
      }
      const std::size_t maximum_records =
          std::min(kHeapSnapshotMaxNodes,
                   kMaxStoredNodeBytes / sizeof(std::uint64_t) / data.node_fields.size());
      const std::size_t maximum_values = data.node_fields.size() * maximum_records;
      const std::uint64_t reserved_nodes =
          std::min<std::uint64_t>(data.declared_nodes, maximum_records);
      const std::size_t reserved_values =
          static_cast<std::size_t>(reserved_nodes) * data.node_fields.size();
      data.nodes.reserve(std::min(reserved_values, document.size() / 2 + 1));
      if (!ParseUnsignedArray(reader, data.nodes, maximum_values, data.node_values_seen,
                              data.node_values_truncated)) {
        return false;
      }
    } else if (key == "edges") {
      if (data.edge_fields.empty() ||
          data.edge_fields.size() >
              std::numeric_limits<std::size_t>::max() / kHeapSnapshotMaxEdges) {
        return false;
      }
      const std::size_t maximum_records =
          std::min(kHeapSnapshotMaxEdges,
                   kMaxStoredEdgeBytes / sizeof(std::uint64_t) / data.edge_fields.size());
      const std::size_t maximum_values = data.edge_fields.size() * maximum_records;
      const std::uint64_t reserved_edges =
          std::min<std::uint64_t>(data.declared_edges, maximum_records);
      const std::size_t reserved_values =
          static_cast<std::size_t>(reserved_edges) * data.edge_fields.size();
      data.edges.reserve(std::min(reserved_values, document.size() / 2 + 1));
      if (!ParseUnsignedArray(reader, data.edges, maximum_values, data.edge_values_seen,
                              data.edge_values_truncated)) {
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
                     [](const char left, const char right) { return AsciiFold(left) == right; }) !=
         haystack.end();
}

std::string BoundedText(const std::string_view value, const std::size_t limit = 256) {
  if (value.size() <= limit) {
    return std::string(value);
  }
  if (limit <= 3) {
    return std::string(value.substr(0, limit));
  }
  std::string output(value.substr(0, limit - 3));
  output.append("...");
  return output;
}

std::string_view EdgeTypeAt(const SnapshotData& data,
                            const std::size_t edge_offset,
                            const std::size_t edge_type_field) noexcept {
  const std::uint64_t type_index = data.edges[edge_offset + edge_type_field];
  return type_index < data.edge_types.size()
             ? std::string_view(data.edge_types[static_cast<std::size_t>(type_index)])
             : std::string_view("unknown");
}

std::string EdgeName(const SnapshotData& data,
                     const std::size_t edge_offset,
                     const std::size_t edge_type_field,
                     const std::size_t edge_name_field) {
  const std::string_view type = EdgeTypeAt(data, edge_offset, edge_type_field);
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
  return EdgeTypeAt(data, edge_offset, edge_type_field) == "weak";
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

struct SnapshotLayout final {
  std::size_t node_width = 0;
  std::size_t edge_width = 0;
  std::size_t node_type_field = kNoNode;
  std::size_t node_name_field = kNoNode;
  std::size_t node_id_field = kNoNode;
  std::size_t node_size_field = kNoNode;
  std::size_t node_edge_count_field = kNoNode;
  std::size_t edge_type_field = kNoNode;
  std::size_t edge_name_field = kNoNode;
  std::size_t edge_target_field = kNoNode;
  std::size_t stored_nodes = 0;
  std::size_t stored_edges = 0;
};

struct SnapshotStats final {
  std::uint64_t file_bytes = 0;
  std::uint64_t total_nodes = 0;
  std::uint64_t total_edges = 0;
  std::uint64_t total_strings = 0;
  bool node_limit_reached = false;
  bool edge_limit_reached = false;
  bool string_limit_reached = false;
};

bool LoadSnapshot(const std::filesystem::path& snapshot_path,
                  SnapshotData& data,
                  SnapshotLayout& layout,
                  SnapshotStats& stats,
                  std::string& error) {
  ReadOnlyFileMapping document;
  if (!document.Open(snapshot_path, error)) {
    return false;
  }
  if (!ParseSnapshotDocument(document.View(), data)) {
    error = "Heap snapshot JSON is malformed or unsupported";
    return false;
  }

  layout.node_width = data.node_fields.size();
  layout.edge_width = data.edge_fields.size();
  layout.node_type_field = FieldIndex(data.node_fields, "type");
  layout.node_name_field = FieldIndex(data.node_fields, "name");
  layout.node_id_field = FieldIndex(data.node_fields, "id");
  layout.node_size_field = FieldIndex(data.node_fields, "self_size");
  layout.node_edge_count_field = FieldIndex(data.node_fields, "edge_count");
  layout.edge_type_field = FieldIndex(data.edge_fields, "type");
  layout.edge_name_field = FieldIndex(data.edge_fields, "name_or_index");
  layout.edge_target_field = FieldIndex(data.edge_fields, "to_node");
  if (layout.node_width == 0 || layout.edge_width == 0 || layout.node_type_field == kNoNode ||
      layout.node_name_field == kNoNode || layout.node_id_field == kNoNode ||
      layout.node_size_field == kNoNode || layout.node_edge_count_field == kNoNode ||
      layout.edge_type_field == kNoNode || layout.edge_name_field == kNoNode ||
      layout.edge_target_field == kNoNode || data.node_types.empty() || data.edge_types.empty() ||
      data.node_values_seen % layout.node_width != 0 ||
      data.edge_values_seen % layout.edge_width != 0) {
    error = "Heap snapshot metadata is incomplete";
    return false;
  }
  const std::size_t actual_nodes = data.node_values_seen / layout.node_width;
  const std::size_t actual_edges = data.edge_values_seen / layout.edge_width;
  if (data.declared_nodes != actual_nodes || data.declared_edges != actual_edges) {
    error = "Heap snapshot counts do not match its data arrays";
    return false;
  }

  layout.stored_nodes = data.nodes.size() / layout.node_width;
  layout.stored_edges = data.edges.size() / layout.edge_width;
  stats.file_bytes = static_cast<std::uint64_t>(document.Size());
  stats.total_nodes = data.declared_nodes;
  stats.total_edges = data.declared_edges;
  stats.total_strings = data.strings_seen;
  stats.node_limit_reached = data.node_values_truncated;
  stats.edge_limit_reached = data.edge_values_truncated;
  stats.string_limit_reached = data.strings_truncated;
  return true;
}

using GraphIndex = std::uint32_t;
constexpr GraphIndex kNoGraphIndex = std::numeric_limits<GraphIndex>::max();

bool BuildEdgeStarts(const SnapshotData& data,
                     const SnapshotLayout& layout,
                     std::vector<GraphIndex>& edge_starts,
                     std::string& error) {
  edge_starts.assign(layout.stored_nodes, 0);
  GraphIndex edge_cursor = 0;
  for (std::size_t ordinal = 0; ordinal < layout.stored_nodes; ++ordinal) {
    edge_starts[ordinal] = edge_cursor;
    const std::uint64_t count =
        data.nodes[ordinal * layout.node_width + layout.node_edge_count_field];
    if (count > static_cast<std::uint64_t>(kNoGraphIndex - edge_cursor)) {
      error = "Heap snapshot edge counts overflow the native index";
      return false;
    }
    edge_cursor += static_cast<GraphIndex>(count);
  }
  if (!data.edge_values_truncated && edge_cursor != layout.stored_edges) {
    error = "Heap snapshot node edge counts do not match its edge array";
    return false;
  }
  return true;
}

bool ValidateEdgeCounts(const SnapshotData& data,
                        const SnapshotLayout& layout,
                        std::string& error) {
  std::uint64_t edge_count = 0;
  for (std::size_t ordinal = 0; ordinal < layout.stored_nodes; ++ordinal) {
    const std::uint64_t count =
        data.nodes[ordinal * layout.node_width + layout.node_edge_count_field];
    if (count > std::numeric_limits<std::uint64_t>::max() - edge_count) {
      error = "Heap snapshot edge counts overflow the native index";
      return false;
    }
    edge_count += count;
  }
  if (!data.edge_values_truncated && edge_count != layout.stored_edges) {
    error = "Heap snapshot node edge counts do not match its edge array";
    return false;
  }
  return true;
}

struct SnapshotNodeSummary final {
  std::uint64_t node_id = 0;
  std::uint64_t self_size = 0;
  std::uint64_t retained_size = 0;
  GraphIndex name_index = kNoGraphIndex;
  std::uint16_t type_index = std::numeric_limits<std::uint16_t>::max();
  std::uint8_t flags = 0;
};

static_assert(sizeof(SnapshotNodeSummary) == 32);

constexpr std::uint8_t kSnapshotNodeReachable = 1U << 0U;
constexpr std::uint8_t kSnapshotNodeRoot = 1U << 1U;

bool IsReachable(const SnapshotNodeSummary& node) noexcept {
  return (node.flags & kSnapshotNodeReachable) != 0;
}

bool IsRoot(const SnapshotNodeSummary& node) noexcept {
  return (node.flags & kSnapshotNodeRoot) != 0;
}

struct SnapshotSummary final {
  SnapshotStats stats;
  std::uint64_t reachable_nodes = 0;
  std::uint64_t total_self_size = 0;
  bool size_saturated = false;
  std::vector<std::string> strings;
  std::vector<std::string> node_types;
  std::vector<SnapshotNodeSummary> nodes;
};

struct DfsFrame final {
  GraphIndex node = 0;
  GraphIndex next_edge = 0;
  GraphIndex end_edge = 0;
};

std::uint64_t SaturatingAdd(const std::uint64_t left,
                            const std::uint64_t right,
                            bool& saturated) noexcept {
  if (right > std::numeric_limits<std::uint64_t>::max() - left) {
    saturated = true;
    return std::numeric_limits<std::uint64_t>::max();
  }
  return left + right;
}

std::int64_t SaturatingDelta(const std::uint64_t current,
                             const std::uint64_t baseline,
                             bool& saturated) noexcept {
  if (current >= baseline) {
    const std::uint64_t delta = current - baseline;
    if (delta > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      saturated = true;
      return std::numeric_limits<std::int64_t>::max();
    }
    return static_cast<std::int64_t>(delta);
  }
  const std::uint64_t delta = baseline - current;
  constexpr std::uint64_t kNegativeLimit =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1U;
  if (delta > kNegativeLimit) {
    saturated = true;
    return std::numeric_limits<std::int64_t>::min();
  }
  if (delta == kNegativeLimit) {
    return std::numeric_limits<std::int64_t>::min();
  }
  return -static_cast<std::int64_t>(delta);
}

std::uint64_t DeltaMagnitude(const std::int64_t delta) noexcept {
  if (delta >= 0) {
    return static_cast<std::uint64_t>(delta);
  }
  return static_cast<std::uint64_t>(-(delta + 1)) + 1U;
}

bool EdgeTarget(const SnapshotData& data,
                const SnapshotLayout& layout,
                const std::size_t edge_ordinal,
                GraphIndex& target) noexcept {
  if (edge_ordinal >= layout.stored_edges) {
    return false;
  }
  const std::size_t edge_offset = edge_ordinal * layout.edge_width;
  if (IsWeakEdge(data, edge_offset, layout.edge_type_field)) {
    return false;
  }
  const std::uint64_t raw_target = data.edges[edge_offset + layout.edge_target_field];
  if (raw_target % layout.node_width != 0) {
    return false;
  }
  const std::uint64_t target_ordinal = raw_target / layout.node_width;
  if (target_ordinal >= layout.stored_nodes ||
      target_ordinal >= std::numeric_limits<GraphIndex>::max()) {
    return false;
  }
  target = static_cast<GraphIndex>(target_ordinal);
  return true;
}

DfsFrame MakeDfsFrame(const SnapshotData& data,
                      const SnapshotLayout& layout,
                      const std::vector<GraphIndex>& edge_starts,
                      const GraphIndex node) noexcept {
  const GraphIndex first_edge = edge_starts[node];
  const std::uint64_t count_value =
      data.nodes[static_cast<std::size_t>(node) * layout.node_width + layout.node_edge_count_field];
  const GraphIndex count = static_cast<GraphIndex>(count_value);
  return {node, first_edge,
          std::min(static_cast<GraphIndex>(layout.stored_edges),
                   static_cast<GraphIndex>(first_edge + count))};
}

bool BuildSnapshotSummary(const std::filesystem::path& snapshot_path,
                          SnapshotSummary& summary,
                          std::string& error) {
  SnapshotData data;
  SnapshotLayout layout;
  SnapshotStats stats;
  if (!LoadSnapshot(snapshot_path, data, layout, stats, error)) {
    return false;
  }
  summary = {};
  summary.stats = stats;
  if (layout.stored_nodes == 0) {
    summary.strings = std::move(data.strings);
    summary.node_types = std::move(data.node_types);
    return true;
  }
  if (layout.stored_nodes >= std::numeric_limits<GraphIndex>::max()) {
    error = "Heap snapshot node index exceeds the native dominator format";
    return false;
  }

  std::vector<GraphIndex> edge_starts;
  if (!BuildEdgeStarts(data, layout, edge_starts, error)) {
    return false;
  }

  std::vector<GraphIndex> node_to_dfs(layout.stored_nodes, 0);
  std::vector<GraphIndex> vertex(2, 0);
  std::vector<GraphIndex> parent(2, 0);
  vertex.reserve(layout.stored_nodes + 1);
  parent.reserve(layout.stored_nodes + 1);
  node_to_dfs[0] = 1;
  vertex[1] = 0;
  std::vector<DfsFrame> dfs_stack;
  dfs_stack.reserve(std::min(layout.stored_nodes, kInitialBfsQueueReserve));
  dfs_stack.push_back(MakeDfsFrame(data, layout, edge_starts, 0));
  while (!dfs_stack.empty()) {
    DfsFrame& frame = dfs_stack.back();
    if (frame.next_edge >= frame.end_edge) {
      dfs_stack.pop_back();
      continue;
    }
    GraphIndex target = 0;
    if (!EdgeTarget(data, layout, frame.next_edge++, target) || node_to_dfs[target] != 0) {
      continue;
    }
    const GraphIndex dfs_number = static_cast<GraphIndex>(vertex.size());
    node_to_dfs[target] = dfs_number;
    vertex.push_back(target);
    parent.push_back(node_to_dfs[frame.node]);
    dfs_stack.push_back(MakeDfsFrame(data, layout, edge_starts, target));
  }
  const GraphIndex reachable = static_cast<GraphIndex>(vertex.size() - 1);
  summary.reachable_nodes = reachable;

  std::vector<GraphIndex> predecessor_counts(static_cast<std::size_t>(reachable) + 2, 0);
  for (GraphIndex dfs_number = 1; dfs_number <= reachable; ++dfs_number) {
    const GraphIndex node = vertex[dfs_number];
    const DfsFrame frame = MakeDfsFrame(data, layout, edge_starts, node);
    for (std::size_t edge = frame.next_edge; edge < frame.end_edge; ++edge) {
      GraphIndex target = 0;
      if (!EdgeTarget(data, layout, edge, target)) {
        continue;
      }
      const GraphIndex target_dfs = node_to_dfs[target];
      if (target_dfs == 0) {
        continue;
      }
      if (predecessor_counts[target_dfs] == std::numeric_limits<GraphIndex>::max()) {
        error = "Heap snapshot predecessor count exceeds the native dominator format";
        return false;
      }
      ++predecessor_counts[target_dfs];
    }
  }

  std::vector<GraphIndex> predecessor_offsets(static_cast<std::size_t>(reachable) + 2, 0);
  for (GraphIndex dfs_number = 1; dfs_number <= reachable; ++dfs_number) {
    const std::uint64_t next = static_cast<std::uint64_t>(predecessor_offsets[dfs_number]) +
                               predecessor_counts[dfs_number];
    if (next >= std::numeric_limits<GraphIndex>::max()) {
      error = "Heap snapshot predecessor index exceeds the native dominator format";
      return false;
    }
    predecessor_offsets[static_cast<std::size_t>(dfs_number) + 1] = static_cast<GraphIndex>(next);
  }
  std::vector<GraphIndex> predecessors(predecessor_offsets[static_cast<std::size_t>(reachable) + 1],
                                       0);
  predecessor_counts = predecessor_offsets;
  for (GraphIndex dfs_number = 1; dfs_number <= reachable; ++dfs_number) {
    const GraphIndex node = vertex[dfs_number];
    const DfsFrame frame = MakeDfsFrame(data, layout, edge_starts, node);
    for (std::size_t edge = frame.next_edge; edge < frame.end_edge; ++edge) {
      GraphIndex target = 0;
      if (!EdgeTarget(data, layout, edge, target)) {
        continue;
      }
      const GraphIndex target_dfs = node_to_dfs[target];
      if (target_dfs != 0) {
        predecessors[predecessor_counts[target_dfs]++] = dfs_number;
      }
    }
  }
  std::vector<GraphIndex>().swap(predecessor_counts);
  std::vector<GraphIndex>().swap(edge_starts);
  std::vector<std::uint64_t>().swap(data.edges);
  std::vector<std::string>().swap(data.edge_types);

  const std::size_t dominator_size = static_cast<std::size_t>(reachable) + 1;
  std::vector<GraphIndex> semi(dominator_size, 0);
  std::vector<GraphIndex> immediate_dominator(dominator_size, 0);
  std::vector<GraphIndex> ancestor(dominator_size, 0);
  std::vector<GraphIndex> label(dominator_size, 0);
  std::vector<GraphIndex> bucket_head(dominator_size, 0);
  std::vector<GraphIndex> bucket_next(dominator_size, 0);
  for (GraphIndex dfs_number = 1; dfs_number <= reachable; ++dfs_number) {
    semi[dfs_number] = dfs_number;
    label[dfs_number] = dfs_number;
  }
  std::vector<GraphIndex> compression_path;
  compression_path.reserve(128);
  const auto evaluate = [&](const GraphIndex node) {
    if (ancestor[node] == 0) {
      return label[node];
    }
    compression_path.clear();
    GraphIndex current = node;
    while (ancestor[current] != 0 && ancestor[ancestor[current]] != 0) {
      compression_path.push_back(current);
      current = ancestor[current];
    }
    for (auto iterator = compression_path.rbegin(); iterator != compression_path.rend();
         ++iterator) {
      const GraphIndex item = *iterator;
      const GraphIndex item_ancestor = ancestor[item];
      if (semi[label[item_ancestor]] < semi[label[item]]) {
        label[item] = label[item_ancestor];
      }
      ancestor[item] = ancestor[item_ancestor];
    }
    return label[node];
  };

  for (GraphIndex current = reachable; current > 1; --current) {
    const GraphIndex first_predecessor = predecessor_offsets[current];
    const GraphIndex end_predecessor = predecessor_offsets[static_cast<std::size_t>(current) + 1];
    for (GraphIndex position = first_predecessor; position < end_predecessor; ++position) {
      const GraphIndex evaluated = evaluate(predecessors[position]);
      semi[current] = std::min(semi[current], semi[evaluated]);
    }
    bucket_next[current] = bucket_head[semi[current]];
    bucket_head[semi[current]] = current;
    ancestor[current] = parent[current];
    GraphIndex bucket_item = bucket_head[parent[current]];
    while (bucket_item != 0) {
      const GraphIndex next = bucket_next[bucket_item];
      const GraphIndex evaluated = evaluate(bucket_item);
      immediate_dominator[bucket_item] =
          semi[evaluated] < semi[bucket_item] ? evaluated : parent[current];
      bucket_item = next;
    }
    bucket_head[parent[current]] = 0;
  }
  for (GraphIndex current = 2; current <= reachable; ++current) {
    if (immediate_dominator[current] != semi[current]) {
      immediate_dominator[current] = immediate_dominator[immediate_dominator[current]];
    }
  }
  immediate_dominator[1] = 1;

  std::vector<GraphIndex>().swap(parent);
  std::vector<GraphIndex>().swap(predecessor_offsets);
  std::vector<GraphIndex>().swap(predecessors);
  std::vector<GraphIndex>().swap(semi);
  std::vector<GraphIndex>().swap(ancestor);
  std::vector<GraphIndex>().swap(label);
  std::vector<GraphIndex>().swap(bucket_head);
  std::vector<GraphIndex>().swap(bucket_next);
  std::vector<GraphIndex>().swap(compression_path);

  std::vector<std::uint64_t> retained_sizes(layout.stored_nodes, 0);
  for (std::size_t ordinal = 0; ordinal < layout.stored_nodes; ++ordinal) {
    const std::uint64_t self_size =
        data.nodes[ordinal * layout.node_width + layout.node_size_field];
    retained_sizes[ordinal] = self_size;
    summary.total_self_size =
        SaturatingAdd(summary.total_self_size, self_size, summary.size_saturated);
  }
  for (GraphIndex current = reachable; current > 1; --current) {
    const GraphIndex node = vertex[current];
    const GraphIndex dominator_node = vertex[immediate_dominator[current]];
    retained_sizes[dominator_node] =
        SaturatingAdd(retained_sizes[dominator_node], retained_sizes[node], summary.size_saturated);
  }
  std::vector<GraphIndex>().swap(vertex);
  std::vector<GraphIndex>().swap(immediate_dominator);

  summary.nodes.reserve(layout.stored_nodes);
  for (std::size_t ordinal = 0; ordinal < layout.stored_nodes; ++ordinal) {
    const std::size_t offset = ordinal * layout.node_width;
    const std::uint64_t raw_name = data.nodes[offset + layout.node_name_field];
    const std::uint64_t raw_type = data.nodes[offset + layout.node_type_field];
    SnapshotNodeSummary node;
    node.node_id = data.nodes[offset + layout.node_id_field];
    node.self_size = data.nodes[offset + layout.node_size_field];
    node.retained_size = retained_sizes[ordinal];
    node.name_index = raw_name < std::numeric_limits<GraphIndex>::max()
                          ? static_cast<GraphIndex>(raw_name)
                          : kNoGraphIndex;
    node.type_index = raw_type < std::numeric_limits<std::uint16_t>::max()
                          ? static_cast<std::uint16_t>(raw_type)
                          : std::numeric_limits<std::uint16_t>::max();
    if (node_to_dfs[ordinal] != 0) {
      node.flags |= kSnapshotNodeReachable;
    }
    if (ordinal == 0) {
      node.flags |= kSnapshotNodeRoot;
    }
    summary.nodes.push_back(node);
  }
  std::sort(summary.nodes.begin(), summary.nodes.end(),
            [](const SnapshotNodeSummary& left, const SnapshotNodeSummary& right) {
              return left.node_id < right.node_id;
            });
  if (std::adjacent_find(summary.nodes.begin(), summary.nodes.end(),
                         [](const SnapshotNodeSummary& left, const SnapshotNodeSummary& right) {
                           return left.node_id == right.node_id;
                         }) != summary.nodes.end()) {
    error = "Heap snapshot node identifiers are not unique";
    return false;
  }
  summary.strings = std::move(data.strings);
  summary.node_types = std::move(data.node_types);
  return true;
}

std::string_view SummaryName(const SnapshotSummary& summary,
                             const SnapshotNodeSummary& node) noexcept {
  if (node.name_index >= summary.strings.size()) {
    return {};
  }
  return summary.strings[node.name_index];
}

std::string_view SummaryType(const SnapshotSummary& summary,
                             const SnapshotNodeSummary& node) noexcept {
  if (node.type_index >= summary.node_types.size()) {
    return "unknown";
  }
  return summary.node_types[node.type_index];
}

struct DiffAccumulator final {
  std::uint64_t baseline_count = 0;
  std::uint64_t current_count = 0;
  std::uint64_t baseline_self_size = 0;
  std::uint64_t current_self_size = 0;
};

struct DiffSignatureView final {
  std::string_view node_type;
  std::string_view node_name;
};

struct DiffSignature final {
  std::string node_type;
  std::string node_name;
};

std::size_t HashBoundedText(const std::string_view text, const std::size_t maximum_bytes) noexcept {
  constexpr std::size_t kFnvOffset =
      sizeof(std::size_t) == 8 ? 1469598103934665603ULL : 2166136261U;
  constexpr std::size_t kFnvPrime = sizeof(std::size_t) == 8 ? 1099511628211ULL : 16777619U;
  std::size_t hash = kFnvOffset;
  const bool truncated = text.size() > maximum_bytes;
  const std::size_t prefix_size = truncated ? maximum_bytes - 3 : text.size();
  for (std::size_t index = 0; index < prefix_size; ++index) {
    hash ^= static_cast<unsigned char>(text[index]);
    hash *= kFnvPrime;
  }
  if (truncated) {
    for (int index = 0; index < 3; ++index) {
      hash ^= static_cast<unsigned char>('.');
      hash *= kFnvPrime;
    }
  }
  return hash;
}

bool EqualsBoundedText(const std::string_view stored,
                       const std::string_view input,
                       const std::size_t maximum_bytes) noexcept {
  if (input.size() <= maximum_bytes) {
    return stored == input;
  }
  return stored.size() == maximum_bytes && stored.ends_with("...") &&
         stored.compare(0, maximum_bytes - 3, input.data(), maximum_bytes - 3) == 0;
}

struct DiffSignatureHash final {
  using is_transparent = void;

  std::size_t operator()(const DiffSignature& signature) const noexcept {
    return Hash({signature.node_type, signature.node_name});
  }

  std::size_t operator()(const DiffSignatureView signature) const noexcept {
    return Hash(signature);
  }

 private:
  static std::size_t Hash(const DiffSignatureView signature) noexcept {
    const std::size_t type_hash = HashBoundedText(signature.node_type, 64);
    const std::size_t name_hash = HashBoundedText(signature.node_name, 256);
    return type_hash ^ (name_hash + 0x9e3779b9U + (type_hash << 6U) + (type_hash >> 2U));
  }
};

struct DiffSignatureEqual final {
  using is_transparent = void;

  bool operator()(const DiffSignature& left, const DiffSignature& right) const noexcept {
    return left.node_type == right.node_type && left.node_name == right.node_name;
  }

  bool operator()(const DiffSignature& left, const DiffSignatureView right) const noexcept {
    return Equals(left, right);
  }

  bool operator()(const DiffSignatureView left, const DiffSignature& right) const noexcept {
    return Equals(right, left);
  }

 private:
  static bool Equals(const DiffSignature& stored, const DiffSignatureView input) noexcept {
    return EqualsBoundedText(stored.node_type, input.node_type, 64) &&
           EqualsBoundedText(stored.node_name, input.node_name, 256);
  }
};

void AccumulateSignatures(
    const SnapshotSummary& summary,
    const bool baseline,
    std::unordered_map<DiffSignature, std::size_t, DiffSignatureHash, DiffSignatureEqual>&
        signature_index,
    std::vector<const DiffSignature*>& signature_keys,
    std::vector<DiffAccumulator>& accumulators,
    bool& aggregation_limit_reached,
    bool& size_saturated) {
  for (const auto& node : summary.nodes) {
    const DiffSignatureView signature{SummaryType(summary, node), SummaryName(summary, node)};
    auto iterator = signature_index.find(signature);
    if (iterator == signature_index.end()) {
      if (accumulators.size() >= kHeapSnapshotMaxDiffSignatures) {
        aggregation_limit_reached = true;
        continue;
      }
      const std::size_t index = accumulators.size();
      const auto inserted = signature_index.emplace(
          DiffSignature{BoundedText(signature.node_type, 64), BoundedText(signature.node_name)},
          index);
      iterator = inserted.first;
      signature_keys.push_back(&iterator->first);
      accumulators.emplace_back();
    }
    DiffAccumulator& accumulator = accumulators[iterator->second];
    if (baseline) {
      ++accumulator.baseline_count;
      accumulator.baseline_self_size =
          SaturatingAdd(accumulator.baseline_self_size, node.self_size, size_saturated);
    } else {
      ++accumulator.current_count;
      accumulator.current_self_size =
          SaturatingAdd(accumulator.current_self_size, node.self_size, size_saturated);
    }
  }
}

bool BetterDominatorChange(const HeapSnapshotDominatorChange& left,
                           const HeapSnapshotDominatorChange& right) noexcept {
  const std::uint64_t left_magnitude = DeltaMagnitude(left.retained_size_delta);
  const std::uint64_t right_magnitude = DeltaMagnitude(right.retained_size_delta);
  if (left_magnitude != right_magnitude) {
    return left_magnitude > right_magnitude;
  }
  return left.node_id < right.node_id;
}

bool BetterDominatorCandidate(const std::uint64_t node_id,
                              const std::int64_t retained_size_delta,
                              const HeapSnapshotDominatorChange& right) noexcept {
  const std::uint64_t left_magnitude = DeltaMagnitude(retained_size_delta);
  const std::uint64_t right_magnitude = DeltaMagnitude(right.retained_size_delta);
  return left_magnitude != right_magnitude ? left_magnitude > right_magnitude
                                           : node_id < right.node_id;
}

void KeepTopDominatorChange(const std::uint64_t node_id,
                            const std::string_view node_type,
                            const std::string_view node_name,
                            const std::uint64_t baseline_retained_size,
                            const std::uint64_t current_retained_size,
                            const std::int64_t retained_size_delta,
                            const std::size_t result_limit,
                            std::size_t& change_count,
                            bool& heap_ready,
                            std::vector<HeapSnapshotDominatorChange>& changes) {
  ++change_count;
  if (heap_ready && !BetterDominatorCandidate(node_id, retained_size_delta, changes.front())) {
    return;
  }
  HeapSnapshotDominatorChange change;
  change.node_id = node_id;
  change.node_type = BoundedText(node_type, 64);
  change.node_name = BoundedText(node_name);
  change.baseline_retained_size = baseline_retained_size;
  change.current_retained_size = current_retained_size;
  change.retained_size_delta = retained_size_delta;
  if (changes.size() < result_limit) {
    changes.push_back(std::move(change));
    if (changes.size() == result_limit) {
      std::make_heap(changes.begin(), changes.end(), BetterDominatorChange);
      heap_ready = true;
    }
    return;
  }
  std::pop_heap(changes.begin(), changes.end(), BetterDominatorChange);
  changes.back() = std::move(change);
  std::push_heap(changes.begin(), changes.end(), BetterDominatorChange);
}

bool BetterDiffGroup(const HeapSnapshotDiffGroup& left,
                     const HeapSnapshotDiffGroup& right) noexcept {
  const std::uint64_t left_size = DeltaMagnitude(left.self_size_delta);
  const std::uint64_t right_size = DeltaMagnitude(right.self_size_delta);
  if (left_size != right_size) {
    return left_size > right_size;
  }
  const std::uint64_t left_count = DeltaMagnitude(left.count_delta);
  const std::uint64_t right_count = DeltaMagnitude(right.count_delta);
  if (left_count != right_count) {
    return left_count > right_count;
  }
  if (left.node_type != right.node_type) {
    return left.node_type < right.node_type;
  }
  return left.node_name < right.node_name;
}

bool BetterDiffGroupCandidate(const std::int64_t self_size_delta,
                              const std::int64_t count_delta,
                              const DiffSignature& signature,
                              const HeapSnapshotDiffGroup& right) noexcept {
  const std::uint64_t left_size = DeltaMagnitude(self_size_delta);
  const std::uint64_t right_size = DeltaMagnitude(right.self_size_delta);
  if (left_size != right_size) {
    return left_size > right_size;
  }
  const std::uint64_t left_count = DeltaMagnitude(count_delta);
  const std::uint64_t right_count = DeltaMagnitude(right.count_delta);
  if (left_count != right_count) {
    return left_count > right_count;
  }
  if (signature.node_type != right.node_type) {
    return signature.node_type < right.node_type;
  }
  return signature.node_name < right.node_name;
}

void KeepTopDiffGroup(const DiffAccumulator& accumulator,
                      const std::int64_t count_delta,
                      const std::int64_t self_size_delta,
                      const DiffSignature& signature,
                      const std::size_t result_limit,
                      std::size_t& change_count,
                      bool& heap_ready,
                      std::vector<HeapSnapshotDiffGroup>& groups) {
  ++change_count;
  if (heap_ready &&
      !BetterDiffGroupCandidate(self_size_delta, count_delta, signature, groups.front())) {
    return;
  }
  HeapSnapshotDiffGroup group;
  group.node_type = signature.node_type;
  group.node_name = signature.node_name;
  group.baseline_count = accumulator.baseline_count;
  group.current_count = accumulator.current_count;
  group.count_delta = count_delta;
  group.baseline_self_size = accumulator.baseline_self_size;
  group.current_self_size = accumulator.current_self_size;
  group.self_size_delta = self_size_delta;
  if (groups.size() < result_limit) {
    groups.push_back(std::move(group));
    if (groups.size() == result_limit) {
      std::make_heap(groups.begin(), groups.end(), BetterDiffGroup);
      heap_ready = true;
    }
    return;
  }
  std::pop_heap(groups.begin(), groups.end(), BetterDiffGroup);
  groups.back() = std::move(group);
  std::push_heap(groups.begin(), groups.end(), BetterDiffGroup);
}

std::string_view SearchScopeName(const HeapSnapshotSearchScope scope) noexcept {
  switch (scope) {
    case HeapSnapshotSearchScope::kReachable:
      return "reachable";
    case HeapSnapshotSearchScope::kUnreachable:
      return "unreachable";
    case HeapSnapshotSearchScope::kAll:
      return "all";
  }
  return "all";
}

bool MatchesSearchScope(const bool reachable, const HeapSnapshotSearchScope scope) noexcept {
  return scope == HeapSnapshotSearchScope::kAll ||
         (scope == HeapSnapshotSearchScope::kReachable && reachable) ||
         (scope == HeapSnapshotSearchScope::kUnreachable && !reachable);
}

std::uint8_t IncomingReferencePriority(const std::string_view edge_type) noexcept {
  if (edge_type == "internal" || edge_type == "hidden") {
    return 0;
  }
  if (edge_type == "weak") {
    return 1;
  }
  if (edge_type == "context" || edge_type == "shortcut") {
    return 2;
  }
  return 3;
}

struct IncomingReferenceCandidate final {
  std::uint64_t source_node_id = 0;
  GraphIndex source_node = 0;
  GraphIndex edge = 0;
  std::uint8_t priority = 0;
};

bool BetterIncomingReferenceCandidate(const IncomingReferenceCandidate& left,
                                      const IncomingReferenceCandidate& right) noexcept {
  if (left.priority != right.priority) {
    return left.priority < right.priority;
  }
  if (left.source_node_id != right.source_node_id) {
    return left.source_node_id < right.source_node_id;
  }
  return left.edge < right.edge;
}

void KeepTopIncomingReference(const IncomingReferenceCandidate candidate,
                              std::vector<IncomingReferenceCandidate>& references) {
  if (references.size() < kHeapSnapshotMaxIncomingReferences) {
    references.push_back(candidate);
    if (references.size() == kHeapSnapshotMaxIncomingReferences) {
      std::make_heap(references.begin(), references.end(), BetterIncomingReferenceCandidate);
    }
    return;
  }
  if (!BetterIncomingReferenceCandidate(candidate, references.front())) {
    return;
  }
  std::pop_heap(references.begin(), references.end(), BetterIncomingReferenceCandidate);
  references.back() = candidate;
  std::push_heap(references.begin(), references.end(), BetterIncomingReferenceCandidate);
}

}  // namespace

bool SearchV8HeapSnapshot(const std::filesystem::path& snapshot_path,
                          const std::string_view query,
                          const bool case_sensitive,
                          const HeapSnapshotSearchScope scope,
                          const std::size_t requested_result_limit,
                          HeapSnapshotSearchResult& result,
                          std::string& error) {
  const auto started = std::chrono::steady_clock::now();
  result = {};
  result.result_limit = std::min(requested_result_limit, kHeapSnapshotMaxResults);
  result.reference_limit = kHeapSnapshotMaxIncomingReferences;
  result.scope = scope;
  error.clear();
  if (query.empty() || query.size() > 512 || result.result_limit == 0 ||
      (scope != HeapSnapshotSearchScope::kAll && scope != HeapSnapshotSearchScope::kReachable &&
       scope != HeapSnapshotSearchScope::kUnreachable)) {
    error = "Heap snapshot query or result limit is invalid";
    return false;
  }
  SnapshotData data;
  SnapshotLayout layout;
  SnapshotStats stats;
  if (!LoadSnapshot(snapshot_path, data, layout, stats, error)) {
    return false;
  }
  const std::size_t node_width = layout.node_width;
  const std::size_t edge_width = layout.edge_width;
  const std::size_t node_type_field = layout.node_type_field;
  const std::size_t node_name_field = layout.node_name_field;
  const std::size_t node_id_field = layout.node_id_field;
  const std::size_t node_size_field = layout.node_size_field;
  const std::size_t node_edge_count_field = layout.node_edge_count_field;
  const std::size_t edge_type_field = layout.edge_type_field;
  const std::size_t edge_name_field = layout.edge_name_field;
  const std::size_t edge_target_field = layout.edge_target_field;
  const std::size_t stored_nodes = layout.stored_nodes;
  const std::size_t stored_edges = layout.stored_edges;
  result.file_bytes = stats.file_bytes;
  result.total_nodes = stats.total_nodes;
  result.total_edges = stats.total_edges;
  result.indexed_edges = stored_edges;
  result.total_strings = stats.total_strings;
  result.node_limit_reached = stats.node_limit_reached;
  result.edge_limit_reached = stats.edge_limit_reached;
  result.string_limit_reached = stats.string_limit_reached;

  if (stored_nodes >= std::numeric_limits<GraphIndex>::max() ||
      stored_edges >= std::numeric_limits<GraphIndex>::max()) {
    error = "Heap snapshot exceeds the native reference index";
    return false;
  }

  std::vector<GraphIndex> edge_starts;
  std::vector<GraphIndex> parents(stored_nodes, kNoGraphIndex);
  std::vector<GraphIndex> parent_edges(stored_nodes, kNoGraphIndex);
  if (stored_nodes > 0) {
    if (!BuildEdgeStarts(data, layout, edge_starts, error)) {
      return false;
    }
    parents[0] = 0;
    std::vector<GraphIndex> pending;
    pending.reserve(std::min(stored_nodes, kInitialBfsQueueReserve));
    pending.push_back(0);
    for (std::size_t pending_index = 0; pending_index < pending.size(); ++pending_index) {
      const GraphIndex source = pending[pending_index];
      const std::size_t first_edge = edge_starts[source];
      const std::uint64_t count_value =
          data.nodes[static_cast<std::size_t>(source) * node_width + node_edge_count_field];
      const std::size_t end_edge =
          std::min(stored_edges, first_edge + static_cast<std::size_t>(count_value));
      for (std::size_t edge_ordinal = first_edge; edge_ordinal < end_edge; ++edge_ordinal) {
        GraphIndex target = 0;
        if (!EdgeTarget(data, layout, edge_ordinal, target) || parents[target] != kNoGraphIndex) {
          continue;
        }
        parents[target] = source;
        parent_edges[target] = static_cast<GraphIndex>(edge_ordinal);
        pending.push_back(target);
      }
    }
    result.reachable_nodes = pending.size();
  }

  std::string folded_query(query);
  if (!case_sensitive) {
    std::transform(folded_query.begin(), folded_query.end(), folded_query.begin(), AsciiFold);
  }
  const std::string_view search_query = case_sensitive ? query : std::string_view(folded_query);

  std::vector<GraphIndex> match_nodes;
  match_nodes.reserve(result.result_limit);
  for (std::size_t ordinal = 0; ordinal < stored_nodes; ++ordinal) {
    const std::size_t offset = ordinal * node_width;
    ++result.analyzed_nodes;
    const bool reachable = parents[ordinal] != kNoGraphIndex;
    if (!MatchesSearchScope(reachable, scope)) {
      continue;
    }
    const std::string_view name = StringAt(data, data.nodes[offset + node_name_field]);
    if (!ContainsText(name, search_query, case_sensitive)) {
      continue;
    }
    ++result.matched_nodes;
    if (result.matches.size() >= result.result_limit) {
      continue;
    }
    HeapSnapshotMatch match;
    match.node_id = data.nodes[offset + node_id_field];
    match.self_size = data.nodes[offset + node_size_field];
    match.node_type = BoundedText(NodeTypeAt(data, offset, node_type_field), 64);
    match.node_name = BoundedText(name);
    match.reachable = reachable;
    result.matches.push_back(std::move(match));
    match_nodes.push_back(static_cast<GraphIndex>(ordinal));
  }
  result.result_limit_reached = result.matched_nodes > result.result_limit;

  if (!match_nodes.empty()) {
    for (std::size_t match_index = 0; match_index < match_nodes.size(); ++match_index) {
      const GraphIndex target = match_nodes[match_index];
      auto& match = result.matches[match_index];
      if (!match.reachable) {
        continue;
      }
      std::vector<HeapSnapshotRetainingStep> reverse_path;
      GraphIndex current = target;
      while (current != 0 && reverse_path.size() < kHeapSnapshotMaxRetainingDepth) {
        const GraphIndex edge_ordinal = parent_edges[current];
        if (edge_ordinal == kNoGraphIndex || edge_ordinal >= stored_edges) {
          break;
        }
        const std::size_t node_offset = static_cast<std::size_t>(current) * node_width;
        const std::size_t edge_offset = static_cast<std::size_t>(edge_ordinal) * edge_width;
        reverse_path.push_back({
            BoundedText(EdgeTypeAt(data, edge_offset, edge_type_field), 32),
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

    constexpr std::uint8_t kNoMatch = std::numeric_limits<std::uint8_t>::max();
    std::vector<std::uint8_t> match_lookup(stored_nodes, kNoMatch);
    for (std::size_t index = 0; index < match_nodes.size(); ++index) {
      match_lookup[match_nodes[index]] = static_cast<std::uint8_t>(index);
    }
    std::vector<std::vector<IncomingReferenceCandidate>> reference_candidates(match_nodes.size());
    for (auto& references : reference_candidates) {
      references.reserve(kHeapSnapshotMaxIncomingReferences);
    }
    for (std::size_t source = 0; source < stored_nodes; ++source) {
      const std::size_t first_edge = edge_starts[source];
      const std::uint64_t count_value = data.nodes[source * node_width + node_edge_count_field];
      const std::size_t end_edge =
          std::min(stored_edges, first_edge + static_cast<std::size_t>(count_value));
      const std::uint64_t source_node_id = data.nodes[source * node_width + node_id_field];
      for (std::size_t edge_ordinal = first_edge; edge_ordinal < end_edge; ++edge_ordinal) {
        const std::size_t edge_offset = edge_ordinal * edge_width;
        const std::uint64_t raw_target = data.edges[edge_offset + edge_target_field];
        if (raw_target % node_width != 0) {
          continue;
        }
        const std::uint64_t target_value = raw_target / node_width;
        if (target_value >= stored_nodes) {
          continue;
        }
        const std::uint8_t match_index = match_lookup[static_cast<std::size_t>(target_value)];
        if (match_index == kNoMatch) {
          continue;
        }
        auto& match = result.matches[match_index];
        ++match.incoming_reference_count;
        KeepTopIncomingReference(
            {source_node_id, static_cast<GraphIndex>(source), static_cast<GraphIndex>(edge_ordinal),
             IncomingReferencePriority(EdgeTypeAt(data, edge_offset, edge_type_field))},
            reference_candidates[match_index]);
      }
    }
    std::vector<std::uint8_t>().swap(match_lookup);

    for (std::size_t match_index = 0; match_index < match_nodes.size(); ++match_index) {
      auto& candidates = reference_candidates[match_index];
      std::sort(candidates.begin(), candidates.end(), BetterIncomingReferenceCandidate);
      auto& match = result.matches[match_index];
      match.incoming_reference_limit_reached = match.incoming_reference_count > candidates.size();
      match.incoming_references.reserve(candidates.size());
      for (const IncomingReferenceCandidate& candidate : candidates) {
        const std::size_t source_offset =
            static_cast<std::size_t>(candidate.source_node) * node_width;
        const std::size_t edge_offset = static_cast<std::size_t>(candidate.edge) * edge_width;
        match.incoming_references.push_back({
            candidate.source_node_id,
            BoundedText(EdgeTypeAt(data, edge_offset, edge_type_field), 32),
            EdgeName(data, edge_offset, edge_type_field, edge_name_field),
            BoundedText(NodeTypeAt(data, source_offset, node_type_field), 64),
            BoundedText(StringAt(data, data.nodes[source_offset + node_name_field])),
        });
      }
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
         << ",\"matched_nodes\":" << result.matched_nodes
         << ",\"reachable_nodes\":" << result.reachable_nodes
         << ",\"total_edges\":" << result.total_edges
         << ",\"indexed_edges\":" << result.indexed_edges
         << ",\"total_strings\":" << result.total_strings
         << ",\"duration_ms\":" << result.duration_ms << ",\"scope\":\""
         << SearchScopeName(result.scope) << "\",\"result_limit\":" << result.result_limit
         << ",\"reference_limit\":" << result.reference_limit
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
           << ",\"reachable\":" << (match.reachable ? "true" : "false")
           << ",\"incoming_reference_count\":" << match.incoming_reference_count
           << ",\"incoming_reference_limit_reached\":"
           << (match.incoming_reference_limit_reached ? "true" : "false")
           << ",\"retaining_path_complete\":" << (match.retaining_path_complete ? "true" : "false")
           << ",\"retaining_path\":[";
    for (std::size_t path_index = 0; path_index < match.retaining_path.size(); ++path_index) {
      if (path_index != 0) {
        output << ',';
      }
      const auto& step = match.retaining_path[path_index];
      output << "{\"edge_type\":\"" << JsonEscape(step.edge_type) << "\",\"edge\":\""
             << JsonEscape(step.edge_name) << "\",\"type\":\"" << JsonEscape(step.node_type)
             << "\",\"name\":\"" << JsonEscape(step.node_name) << "\"}";
    }
    output << "],\"incoming_references\":[";
    for (std::size_t reference_index = 0; reference_index < match.incoming_references.size();
         ++reference_index) {
      if (reference_index != 0) {
        output << ',';
      }
      const auto& reference = match.incoming_references[reference_index];
      output << "{\"source_id\":\"" << reference.source_node_id << "\",\"edge_type\":\""
             << JsonEscape(reference.edge_type) << "\",\"edge\":\""
             << JsonEscape(reference.edge_name) << "\",\"source_type\":\""
             << JsonEscape(reference.source_node_type) << "\",\"source_name\":\""
             << JsonEscape(reference.source_node_name) << "\"}";
    }
    output << "]}";
  }
  output << "]}";
  return output.str();
}

bool ProbeV8HeapSnapshot(const std::filesystem::path& snapshot_path,
                         const std::string_view query,
                         const bool case_sensitive,
                         const HeapSnapshotSearchScope scope,
                         HeapSnapshotProbeResult& result,
                         std::string& error) {
  const auto started = std::chrono::steady_clock::now();
  result = {};
  result.scope = scope;
  error.clear();
  if (query.empty() || query.size() > 512 ||
      (scope != HeapSnapshotSearchScope::kAll && scope != HeapSnapshotSearchScope::kReachable &&
       scope != HeapSnapshotSearchScope::kUnreachable)) {
    error = "Heap snapshot probe query or scope is invalid";
    return false;
  }

  SnapshotData data;
  SnapshotLayout layout;
  SnapshotStats stats;
  if (!LoadSnapshot(snapshot_path, data, layout, stats, error)) {
    return false;
  }
  if (layout.stored_nodes >= std::numeric_limits<GraphIndex>::max() ||
      layout.stored_edges >= std::numeric_limits<GraphIndex>::max()) {
    error = "Heap snapshot exceeds the native reference index";
    return false;
  }
  if (!ValidateEdgeCounts(data, layout, error)) {
    return false;
  }

  result.file_bytes = stats.file_bytes;
  result.total_nodes = stats.total_nodes;
  result.total_edges = stats.total_edges;
  result.total_strings = stats.total_strings;
  result.node_limit_reached = stats.node_limit_reached;
  result.edge_limit_reached = stats.edge_limit_reached;
  result.string_limit_reached = stats.string_limit_reached;

  std::vector<std::uint8_t> reachable;
  if (scope != HeapSnapshotSearchScope::kAll) {
    result.reachability_indexed = true;
    result.indexed_edges = layout.stored_edges;
  }
  if (scope != HeapSnapshotSearchScope::kAll && layout.stored_nodes > 0) {
    std::vector<GraphIndex> edge_starts;
    if (!BuildEdgeStarts(data, layout, edge_starts, error)) {
      return false;
    }
    reachable.assign(layout.stored_nodes, 0);
    reachable[0] = 1;
    std::vector<GraphIndex> pending;
    pending.reserve(std::min(layout.stored_nodes, kInitialBfsQueueReserve));
    pending.push_back(0);
    for (std::size_t pending_index = 0; pending_index < pending.size(); ++pending_index) {
      const GraphIndex source = pending[pending_index];
      const std::size_t first_edge = edge_starts[source];
      const std::uint64_t count_value =
          data.nodes[static_cast<std::size_t>(source) * layout.node_width +
                     layout.node_edge_count_field];
      const std::size_t end_edge =
          std::min(layout.stored_edges, first_edge + static_cast<std::size_t>(count_value));
      for (std::size_t edge_ordinal = first_edge; edge_ordinal < end_edge; ++edge_ordinal) {
        GraphIndex target = 0;
        if (!EdgeTarget(data, layout, edge_ordinal, target) || reachable[target] != 0) {
          continue;
        }
        reachable[target] = 1;
        pending.push_back(target);
      }
    }
    result.reachable_nodes = pending.size();
  }

  std::string folded_query(query);
  if (!case_sensitive) {
    std::transform(folded_query.begin(), folded_query.end(), folded_query.begin(), AsciiFold);
  }
  const std::string_view search_query = case_sensitive ? query : std::string_view(folded_query);
  for (std::size_t ordinal = 0; ordinal < layout.stored_nodes; ++ordinal) {
    ++result.analyzed_nodes;
    const bool node_reachable = !reachable.empty() && reachable[ordinal] != 0;
    if (!MatchesSearchScope(node_reachable, scope)) {
      continue;
    }
    const std::size_t offset = ordinal * layout.node_width;
    const std::string_view name = StringAt(data, data.nodes[offset + layout.node_name_field]);
    if (!ContainsText(name, search_query, case_sensitive)) {
      continue;
    }
    result.match_found = true;
    result.match.node_id = data.nodes[offset + layout.node_id_field];
    result.match.self_size = data.nodes[offset + layout.node_size_field];
    result.match.node_type = BoundedText(NodeTypeAt(data, offset, layout.node_type_field), 64);
    result.match.node_name = BoundedText(name);
    break;
  }

  result.duration_ms =
      static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started)
                                     .count());
  return true;
}

std::string HeapSnapshotProbeResultToJson(const HeapSnapshotProbeResult& result) {
  std::ostringstream output;
  output << "{\"protocol_version\":" << result.protocol_version
         << ",\"file_bytes\":" << result.file_bytes << ",\"total_nodes\":" << result.total_nodes
         << ",\"analyzed_nodes\":" << result.analyzed_nodes
         << ",\"reachable_nodes\":" << result.reachable_nodes
         << ",\"total_edges\":" << result.total_edges
         << ",\"indexed_edges\":" << result.indexed_edges
         << ",\"total_strings\":" << result.total_strings
         << ",\"duration_ms\":" << result.duration_ms << ",\"scope\":\""
         << SearchScopeName(result.scope)
         << "\",\"match_found\":" << (result.match_found ? "true" : "false")
         << ",\"reachability_indexed\":" << (result.reachability_indexed ? "true" : "false")
         << ",\"node_limit_reached\":" << (result.node_limit_reached ? "true" : "false")
         << ",\"edge_limit_reached\":" << (result.edge_limit_reached ? "true" : "false")
         << ",\"string_limit_reached\":" << (result.string_limit_reached ? "true" : "false")
         << ",\"match\":";
  if (result.match_found) {
    output << "{\"id\":\"" << result.match.node_id << "\",\"type\":\""
           << JsonEscape(result.match.node_type) << "\",\"name\":\""
           << JsonEscape(result.match.node_name) << "\",\"self_size\":" << result.match.self_size
           << '}';
  } else {
    output << "null";
  }
  output << '}';
  return output.str();
}

bool CompareV8HeapSnapshots(const std::filesystem::path& baseline_path,
                            const std::filesystem::path& current_path,
                            const std::size_t requested_result_limit,
                            HeapSnapshotDiffResult& result,
                            std::string& error) {
  const auto started = std::chrono::steady_clock::now();
  result = {};
  result.result_limit = std::min(requested_result_limit, kHeapSnapshotMaxResults);
  error.clear();
  if (result.result_limit == 0) {
    error = "Heap snapshot diff result limit is invalid";
    return false;
  }

  SnapshotSummary baseline;
  if (!BuildSnapshotSummary(baseline_path, baseline, error)) {
    return false;
  }
  SnapshotSummary current;
  if (!BuildSnapshotSummary(current_path, current, error)) {
    return false;
  }

  result.baseline_file_bytes = baseline.stats.file_bytes;
  result.current_file_bytes = current.stats.file_bytes;
  result.baseline_nodes = baseline.stats.total_nodes;
  result.current_nodes = current.stats.total_nodes;
  result.baseline_edges = baseline.stats.total_edges;
  result.current_edges = current.stats.total_edges;
  result.baseline_reachable_nodes = baseline.reachable_nodes;
  result.current_reachable_nodes = current.reachable_nodes;
  result.baseline_self_size = baseline.total_self_size;
  result.current_self_size = current.total_self_size;
  result.baseline_node_limit_reached = baseline.stats.node_limit_reached;
  result.baseline_edge_limit_reached = baseline.stats.edge_limit_reached;
  result.baseline_string_limit_reached = baseline.stats.string_limit_reached;
  result.current_node_limit_reached = current.stats.node_limit_reached;
  result.current_edge_limit_reached = current.stats.edge_limit_reached;
  result.current_string_limit_reached = current.stats.string_limit_reached;
  result.retained_size_saturated = baseline.size_saturated || current.size_saturated;
  result.self_size_delta = SaturatingDelta(result.current_self_size, result.baseline_self_size,
                                           result.retained_size_saturated);

  const std::size_t signature_reserve =
      std::min(kHeapSnapshotMaxDiffSignatures, baseline.nodes.size() + current.nodes.size());
  std::unordered_map<DiffSignature, std::size_t, DiffSignatureHash, DiffSignatureEqual>
      signature_index;
  signature_index.reserve(signature_reserve);
  std::vector<const DiffSignature*> signature_keys;
  std::vector<DiffAccumulator> accumulators;
  signature_keys.reserve(signature_reserve);
  accumulators.reserve(signature_reserve);
  AccumulateSignatures(baseline, true, signature_index, signature_keys, accumulators,
                       result.aggregation_limit_reached, result.retained_size_saturated);
  AccumulateSignatures(current, false, signature_index, signature_keys, accumulators,
                       result.aggregation_limit_reached, result.retained_size_saturated);

  std::vector<HeapSnapshotDiffGroup> groups;
  groups.reserve(result.result_limit);
  std::size_t group_change_count = 0;
  bool group_heap_ready = false;
  for (std::size_t index = 0; index < accumulators.size(); ++index) {
    const DiffAccumulator& accumulator = accumulators[index];
    bool delta_saturated = false;
    const std::int64_t count_delta =
        SaturatingDelta(accumulator.current_count, accumulator.baseline_count, delta_saturated);
    const std::int64_t self_size_delta = SaturatingDelta(
        accumulator.current_self_size, accumulator.baseline_self_size, delta_saturated);
    result.retained_size_saturated = result.retained_size_saturated || delta_saturated;
    if (count_delta == 0 && self_size_delta == 0) {
      continue;
    }
    const DiffSignature& signature = *signature_keys[index];
    KeepTopDiffGroup(accumulator, count_delta, self_size_delta, signature, result.result_limit,
                     group_change_count, group_heap_ready, groups);
  }
  std::sort(groups.begin(), groups.end(), BetterDiffGroup);
  result.group_result_limit_reached = group_change_count > result.result_limit;
  result.groups = std::move(groups);

  std::size_t baseline_index = 0;
  std::size_t current_index = 0;
  std::size_t dominator_change_count = 0;
  bool dominator_heap_ready = false;
  std::vector<HeapSnapshotDominatorChange> dominators;
  dominators.reserve(result.result_limit);
  while (baseline_index < baseline.nodes.size() || current_index < current.nodes.size()) {
    const SnapshotNodeSummary* baseline_node = nullptr;
    const SnapshotNodeSummary* current_node = nullptr;
    if (current_index >= current.nodes.size() ||
        (baseline_index < baseline.nodes.size() &&
         baseline.nodes[baseline_index].node_id < current.nodes[current_index].node_id)) {
      baseline_node = &baseline.nodes[baseline_index++];
    } else if (baseline_index >= baseline.nodes.size() ||
               current.nodes[current_index].node_id < baseline.nodes[baseline_index].node_id) {
      current_node = &current.nodes[current_index++];
    } else {
      baseline_node = &baseline.nodes[baseline_index++];
      current_node = &current.nodes[current_index++];
    }
    if ((baseline_node != nullptr && IsRoot(*baseline_node)) ||
        (current_node != nullptr && IsRoot(*current_node))) {
      continue;
    }
    const std::uint64_t baseline_retained =
        baseline_node != nullptr && IsReachable(*baseline_node) ? baseline_node->retained_size : 0;
    const std::uint64_t current_retained =
        current_node != nullptr && IsReachable(*current_node) ? current_node->retained_size : 0;
    bool delta_saturated = false;
    const std::int64_t retained_delta =
        SaturatingDelta(current_retained, baseline_retained, delta_saturated);
    result.retained_size_saturated = result.retained_size_saturated || delta_saturated;
    if (retained_delta == 0) {
      continue;
    }
    const bool use_current = current_node != nullptr;
    const SnapshotSummary& name_summary = use_current ? current : baseline;
    const SnapshotNodeSummary& name_node = use_current ? *current_node : *baseline_node;
    KeepTopDominatorChange(name_node.node_id, SummaryType(name_summary, name_node),
                           SummaryName(name_summary, name_node), baseline_retained,
                           current_retained, retained_delta, result.result_limit,
                           dominator_change_count, dominator_heap_ready, dominators);
  }
  std::sort(dominators.begin(), dominators.end(), BetterDominatorChange);
  result.dominator_result_limit_reached = dominator_change_count > result.result_limit;
  result.dominators = std::move(dominators);
  result.duration_ms =
      static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started)
                                     .count());
  return true;
}

std::string HeapSnapshotDiffResultToJson(const HeapSnapshotDiffResult& result) {
  std::ostringstream output;
  output << "{\"protocol_version\":" << result.protocol_version
         << ",\"baseline_file_bytes\":" << result.baseline_file_bytes
         << ",\"current_file_bytes\":" << result.current_file_bytes
         << ",\"baseline_nodes\":" << result.baseline_nodes
         << ",\"current_nodes\":" << result.current_nodes
         << ",\"baseline_edges\":" << result.baseline_edges
         << ",\"current_edges\":" << result.current_edges
         << ",\"baseline_reachable_nodes\":" << result.baseline_reachable_nodes
         << ",\"current_reachable_nodes\":" << result.current_reachable_nodes
         << ",\"baseline_self_size\":" << result.baseline_self_size
         << ",\"current_self_size\":" << result.current_self_size
         << ",\"self_size_delta\":" << result.self_size_delta
         << ",\"duration_ms\":" << result.duration_ms << ",\"result_limit\":" << result.result_limit
         << ",\"group_result_limit_reached\":"
         << (result.group_result_limit_reached ? "true" : "false")
         << ",\"dominator_result_limit_reached\":"
         << (result.dominator_result_limit_reached ? "true" : "false")
         << ",\"aggregation_limit_reached\":"
         << (result.aggregation_limit_reached ? "true" : "false")
         << ",\"baseline_node_limit_reached\":"
         << (result.baseline_node_limit_reached ? "true" : "false")
         << ",\"baseline_edge_limit_reached\":"
         << (result.baseline_edge_limit_reached ? "true" : "false")
         << ",\"baseline_string_limit_reached\":"
         << (result.baseline_string_limit_reached ? "true" : "false")
         << ",\"current_node_limit_reached\":"
         << (result.current_node_limit_reached ? "true" : "false")
         << ",\"current_edge_limit_reached\":"
         << (result.current_edge_limit_reached ? "true" : "false")
         << ",\"current_string_limit_reached\":"
         << (result.current_string_limit_reached ? "true" : "false")
         << ",\"retained_size_saturated\":" << (result.retained_size_saturated ? "true" : "false")
         << ",\"groups\":[";
  for (std::size_t index = 0; index < result.groups.size(); ++index) {
    if (index != 0) {
      output << ',';
    }
    const auto& group = result.groups[index];
    output << "{\"type\":\"" << JsonEscape(group.node_type) << "\",\"name\":\""
           << JsonEscape(group.node_name) << "\",\"baseline_count\":" << group.baseline_count
           << ",\"current_count\":" << group.current_count
           << ",\"count_delta\":" << group.count_delta
           << ",\"baseline_self_size\":" << group.baseline_self_size
           << ",\"current_self_size\":" << group.current_self_size
           << ",\"self_size_delta\":" << group.self_size_delta << '}';
  }
  output << "],\"dominators\":[";
  for (std::size_t index = 0; index < result.dominators.size(); ++index) {
    if (index != 0) {
      output << ',';
    }
    const auto& change = result.dominators[index];
    output << "{\"id\":\"" << change.node_id << "\",\"type\":\"" << JsonEscape(change.node_type)
           << "\",\"name\":\"" << JsonEscape(change.node_name)
           << "\",\"baseline_retained_size\":" << change.baseline_retained_size
           << ",\"current_retained_size\":" << change.current_retained_size
           << ",\"retained_size_delta\":" << change.retained_size_delta << '}';
  }
  output << "]}";
  return output.str();
}

}  // namespace reb
