#include "reb/artifact.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace reb {
namespace {

bool SyncFile(const std::filesystem::path& path, std::string& error) {
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    error = "Unable to open file for durable commit: " + std::string(std::strerror(errno));
    return false;
  }
  if (fsync(descriptor) != 0) {
    const int sync_error = errno;
    close(descriptor);
    error = "Unable to durably commit file: " + std::string(std::strerror(sync_error));
    return false;
  }
  if (close(descriptor) != 0) {
    error = "Unable to close durably committed file: " + std::string(std::strerror(errno));
    return false;
  }
  return true;
}

bool SyncDirectory(const std::filesystem::path& path, std::string& error) {
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    error = "Unable to open directory for durable commit: " + std::string(std::strerror(errno));
    return false;
  }
  if (fsync(descriptor) != 0) {
    const int sync_error = errno;
    close(descriptor);
    error = "Unable to durably commit directory: " + std::string(std::strerror(sync_error));
    return false;
  }
  if (close(descriptor) != 0) {
    error = "Unable to close durably committed directory: " + std::string(std::strerror(errno));
    return false;
  }
  return true;
}

constexpr std::array<std::uint32_t, 64> kSha256RoundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U,
};

class Sha256 final {
 public:
  void Update(const std::uint8_t* data, std::size_t size) noexcept {
    total_size_ += size;
    while (size > 0) {
      const std::size_t copied = std::min(size, block_.size() - block_size_);
      std::copy_n(data, copied, block_.begin() + static_cast<std::ptrdiff_t>(block_size_));
      block_size_ += copied;
      data += copied;
      size -= copied;
      if (block_size_ == block_.size()) {
        Transform();
        block_size_ = 0;
      }
    }
  }

  [[nodiscard]] std::array<std::uint8_t, 32> Final() noexcept {
    const std::uint64_t bit_size = static_cast<std::uint64_t>(total_size_) * 8U;
    block_[block_size_++] = 0x80U;
    if (block_size_ > 56) {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.end(), 0U);
      Transform();
      block_size_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.begin() + 56, 0U);
    for (std::size_t index = 0; index < 8; ++index) {
      block_[63 - index] = static_cast<std::uint8_t>(bit_size >> (index * 8U));
    }
    Transform();

    std::array<std::uint8_t, 32> digest{};
    for (std::size_t index = 0; index < state_.size(); ++index) {
      digest[index * 4] = static_cast<std::uint8_t>(state_[index] >> 24U);
      digest[index * 4 + 1] = static_cast<std::uint8_t>(state_[index] >> 16U);
      digest[index * 4 + 2] = static_cast<std::uint8_t>(state_[index] >> 8U);
      digest[index * 4 + 3] = static_cast<std::uint8_t>(state_[index]);
    }
    return digest;
  }

 private:
  void Transform() noexcept {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t index = 0; index < 16; ++index) {
      const std::size_t offset = index * 4;
      schedule[index] = (static_cast<std::uint32_t>(block_[offset]) << 24U) |
                        (static_cast<std::uint32_t>(block_[offset + 1]) << 16U) |
                        (static_cast<std::uint32_t>(block_[offset + 2]) << 8U) |
                        static_cast<std::uint32_t>(block_[offset + 3]);
    }
    for (std::size_t index = 16; index < schedule.size(); ++index) {
      const std::uint32_t s0 = std::rotr(schedule[index - 15], 7) ^
                               std::rotr(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3U);
      const std::uint32_t s1 = std::rotr(schedule[index - 2], 17) ^
                               std::rotr(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10U);
      schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];
    for (std::size_t index = 0; index < schedule.size(); ++index) {
      const std::uint32_t sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      const std::uint32_t choice = (e & f) ^ (~e & g);
      const std::uint32_t temporary1 =
          h + sum1 + choice + kSha256RoundConstants[index] + schedule[index];
      const std::uint32_t sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temporary2 = sum0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + temporary1;
      d = c;
      c = b;
      b = a;
      a = temporary1 + temporary2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_ = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  std::array<std::uint8_t, 64> block_{};
  std::size_t block_size_ = 0;
  std::size_t total_size_ = 0;
};

bool IsZeroDigest(const std::array<std::uint8_t, 32>& digest) noexcept {
  return std::all_of(digest.begin(), digest.end(),
                     [](const std::uint8_t byte) { return byte == 0; });
}

std::string DigestHex(const std::array<std::uint8_t, 32>& digest) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string result;
  result.resize(digest.size() * 2);
  for (std::size_t index = 0; index < digest.size(); ++index) {
    result[index * 2] = kHex[digest[index] >> 4U];
    result[index * 2 + 1] = kHex[digest[index] & 0x0fU];
  }
  return result;
}

bool IsValidUtf8(const std::string_view text) noexcept {
  std::size_t index = 0;
  while (index < text.size()) {
    const auto byte = static_cast<std::uint8_t>(text[index]);
    std::size_t continuation_count = 0;
    std::uint32_t code_point = 0;
    if (byte <= 0x7fU) {
      if (byte < 0x20U || byte == 0x7fU) {
        return false;
      }
      ++index;
      continue;
    }
    if ((byte & 0xe0U) == 0xc0U) {
      continuation_count = 1;
      code_point = byte & 0x1fU;
    } else if ((byte & 0xf0U) == 0xe0U) {
      continuation_count = 2;
      code_point = byte & 0x0fU;
    } else if ((byte & 0xf8U) == 0xf0U) {
      continuation_count = 3;
      code_point = byte & 0x07U;
    } else {
      return false;
    }
    if (index + continuation_count >= text.size()) {
      return false;
    }
    for (std::size_t offset = 1; offset <= continuation_count; ++offset) {
      const auto continuation = static_cast<std::uint8_t>(text[index + offset]);
      if ((continuation & 0xc0U) != 0x80U) {
        return false;
      }
      code_point = (code_point << 6U) | (continuation & 0x3fU);
    }
    const bool overlong = (continuation_count == 1 && code_point < 0x80U) ||
                          (continuation_count == 2 && code_point < 0x800U) ||
                          (continuation_count == 3 && code_point < 0x10000U);
    if (overlong || code_point > 0x10ffffU || (code_point >= 0xd800U && code_point <= 0xdfffU)) {
      return false;
    }
    index += continuation_count + 1;
  }
  return true;
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

bool ConsumePrefix(const std::string_view text,
                   std::size_t& position,
                   const std::string_view prefix) noexcept {
  if (!text.substr(position).starts_with(prefix)) {
    return false;
  }
  position += prefix.size();
  return true;
}

bool ParseUnsignedField(const std::string_view line,
                        std::size_t& position,
                        const std::string_view suffix,
                        std::uint64_t& value) noexcept {
  const std::size_t end = line.find(suffix, position);
  if (end == std::string_view::npos) {
    return false;
  }
  const std::string_view encoded = line.substr(position, end - position);
  const auto parsed = std::from_chars(encoded.data(), encoded.data() + encoded.size(), value);
  position = end + suffix.size();
  return parsed.ec == std::errc{} && parsed.ptr == encoded.data() + encoded.size() &&
         !encoded.empty();
}

bool IsLowercaseHex(const char value) noexcept {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
}

bool SkipJsonString(const std::string_view line, std::size_t& position) noexcept {
  while (position < line.size()) {
    const unsigned char character = static_cast<unsigned char>(line[position++]);
    if (character == '"') {
      return true;
    }
    if (character < 0x20U) {
      return false;
    }
    if (character != '\\') {
      continue;
    }
    if (position >= line.size()) {
      return false;
    }
    const char escape = line[position++];
    if (escape == 'u') {
      if (position + 4 > line.size() ||
          !std::all_of(line.begin() + static_cast<std::ptrdiff_t>(position),
                       line.begin() + static_cast<std::ptrdiff_t>(position + 4), IsLowercaseHex)) {
        return false;
      }
      position += 4;
    } else if (std::string_view("\"\\/bfnrt").find(escape) == std::string_view::npos) {
      return false;
    }
  }
  return false;
}

bool ParseManifestRecord(const std::string_view line,
                         std::uint64_t& artifact_id,
                         std::uint64_t& session_id) {
  std::size_t position = 0;
  std::uint64_t ignored = 0;
  std::uint64_t execution_context_id = 0;
  std::string_view capture_origin;
  if (!ConsumePrefix(line, position, "{\"protocol_version\":1,\"artifact_id\":\"") ||
      !ParseUnsignedField(line, position, "\",\"session_id\":\"", artifact_id) ||
      artifact_id == 0 ||
      !ParseUnsignedField(line, position, "\",\"navigation_id\":\"", session_id) ||
      session_id == 0 || !ParseUnsignedField(line, position, "\",\"frame_id\":\"", ignored) ||
      !ParseUnsignedField(line, position, "\",\"parent_artifact_id\":\"", ignored) ||
      !ParseUnsignedField(line, position, "\",\"creator_event_id\":\"", ignored) ||
      !ParseUnsignedField(line, position, "\"", ignored)) {
    return false;
  }

  if (ConsumePrefix(line, position, ",\"execution_context_id\":\"")) {
    if (!ParseUnsignedField(line, position, "\",\"capture_origin\":\"", execution_context_id)) {
      return false;
    }
    const std::size_t origin_end = line.find("\",\"kind\":\"", position);
    if (origin_end == std::string_view::npos) {
      return false;
    }
    capture_origin = line.substr(position, origin_end - position);
    if (capture_origin != "unknown" && capture_origin != "network_response" &&
        capture_origin != "dynamic_javascript" && capture_origin != "webassembly_compile" &&
        capture_origin != "webassembly_module" && capture_origin != "webassembly_instantiate") {
      return false;
    }
    position = origin_end + std::string_view("\",\"kind\":\"").size();
  } else if (!ConsumePrefix(line, position, ",\"kind\":\"")) {
    return false;
  }

  const std::size_t kind_end = line.find("\",\"url\":\"", position);
  if (kind_end == std::string_view::npos) {
    return false;
  }
  const std::string_view kind = line.substr(position, kind_end - position);
  if (kind != "javascript" && kind != "wasm" && kind != "source_map" && kind != "response_body") {
    return false;
  }
  if ((!capture_origin.empty() && capture_origin != "unknown" &&
       capture_origin != "network_response" && execution_context_id == 0) ||
      (capture_origin == "dynamic_javascript" && kind != "javascript") ||
      (capture_origin.starts_with("webassembly_") && kind != "wasm")) {
    return false;
  }
  position = kind_end + std::string_view("\",\"url\":\"").size();
  if (!SkipJsonString(line, position) || !ConsumePrefix(line, position, ",\"mime_type\":\"") ||
      !SkipJsonString(line, position) || !ConsumePrefix(line, position, ",\"byte_size\":")) {
    return false;
  }
  std::uint64_t byte_size = 0;
  if (!ParseUnsignedField(line, position, ",\"sha256\":\"", byte_size)) {
    return false;
  }
  const std::size_t digest_end = line.find('"', position);
  if (digest_end == std::string_view::npos || digest_end - position != 64) {
    return false;
  }
  const std::string_view digest = line.substr(position, 64);
  if (!std::all_of(digest.begin(), digest.end(), IsLowercaseHex)) {
    return false;
  }
  position = digest_end + 1;
  if (!ConsumePrefix(line, position, ",\"sensitive\":")) {
    return false;
  }
  const bool sensitive = line.substr(position).starts_with("true");
  if (sensitive) {
    position += 4;
  } else if (line.substr(position).starts_with("false")) {
    position += 5;
  } else {
    return false;
  }
  if (sensitive != (kind == "response_body") ||
      !ConsumePrefix(line, position, ",\"content_path\":\"blobs/") ||
      line.substr(position, digest.size()) != digest) {
    return false;
  }
  position += digest.size();
  return line.substr(position) == ".bin\"}";
}

void SaturatingAdd(std::uint64_t& value, const std::uint64_t increment) noexcept {
  value = increment > std::numeric_limits<std::uint64_t>::max() - value
              ? std::numeric_limits<std::uint64_t>::max()
              : value + increment;
}

void RemoveFileBestEffort(const std::filesystem::path& path) noexcept {
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}

}  // namespace

bool IsValidArtifactHeader(const ArtifactHeader& header) noexcept {
  if (header.magic != kArtifactMagic || header.protocol_version != kArtifactProtocolVersion ||
      header.header_size != kArtifactHeaderSize || header.session_id == 0 ||
      header.artifact_id == 0 || header.url_size == 0 || header.url_size > kMaxArtifactUrlBytes ||
      header.mime_type_size == 0 || header.mime_type_size > kMaxArtifactMimeTypeBytes ||
      (header.flags & ~kArtifactFlagSensitive) != 0 || header.reserved0 != 0 ||
      header.reserved1 != 0 || header.reserved2 != 0) {
    return false;
  }
  const bool sensitive = (header.flags & kArtifactFlagSensitive) != 0;
  if ((header.kind == ArtifactKind::kResponseBody) != sensitive) {
    return false;
  }
  const bool valid_kind =
      header.kind == ArtifactKind::kJavaScript || header.kind == ArtifactKind::kWasm ||
      header.kind == ArtifactKind::kSourceMap || header.kind == ArtifactKind::kResponseBody;
  const bool valid_origin = header.capture_origin == ArtifactCaptureOrigin::kUnknown ||
                            header.capture_origin == ArtifactCaptureOrigin::kNetworkResponse ||
                            header.capture_origin == ArtifactCaptureOrigin::kDynamicJavaScript ||
                            header.capture_origin == ArtifactCaptureOrigin::kWebAssemblyCompile ||
                            header.capture_origin == ArtifactCaptureOrigin::kWebAssemblyModule ||
                            header.capture_origin == ArtifactCaptureOrigin::kWebAssemblyInstantiate;
  const bool compatible_origin =
      header.capture_origin == ArtifactCaptureOrigin::kUnknown ||
      header.capture_origin == ArtifactCaptureOrigin::kNetworkResponse ||
      (header.kind == ArtifactKind::kJavaScript &&
       header.capture_origin == ArtifactCaptureOrigin::kDynamicJavaScript) ||
      (header.kind == ArtifactKind::kWasm &&
       (header.capture_origin == ArtifactCaptureOrigin::kWebAssemblyCompile ||
        header.capture_origin == ArtifactCaptureOrigin::kWebAssemblyModule ||
        header.capture_origin == ArtifactCaptureOrigin::kWebAssemblyInstantiate));
  const bool runtime_has_context =
      header.capture_origin == ArtifactCaptureOrigin::kUnknown ||
      header.capture_origin == ArtifactCaptureOrigin::kNetworkResponse ||
      header.execution_context_id != 0;
  return valid_kind && valid_origin && compatible_origin && runtime_has_context;
}

const char* ArtifactKindName(const ArtifactKind kind) noexcept {
  switch (kind) {
    case ArtifactKind::kJavaScript:
      return "javascript";
    case ArtifactKind::kWasm:
      return "wasm";
    case ArtifactKind::kSourceMap:
      return "source_map";
    case ArtifactKind::kResponseBody:
      return "response_body";
    case ArtifactKind::kUnknown:
      return "unknown";
  }
  return "unknown";
}

const char* ArtifactCaptureOriginName(const ArtifactCaptureOrigin origin) noexcept {
  switch (origin) {
    case ArtifactCaptureOrigin::kNetworkResponse:
      return "network_response";
    case ArtifactCaptureOrigin::kDynamicJavaScript:
      return "dynamic_javascript";
    case ArtifactCaptureOrigin::kWebAssemblyCompile:
      return "webassembly_compile";
    case ArtifactCaptureOrigin::kWebAssemblyModule:
      return "webassembly_module";
    case ArtifactCaptureOrigin::kWebAssemblyInstantiate:
      return "webassembly_instantiate";
    case ArtifactCaptureOrigin::kUnknown:
      return "unknown";
  }
  return "unknown";
}

ArtifactReceiver::ArtifactReceiver(std::filesystem::path store_directory,
                                   ArtifactReceiverLimits limits)
    : store_directory_(std::move(store_directory)),
      blob_directory_(store_directory_ / "blobs"),
      manifest_path_(store_directory_ / "manifest.jsonl"),
      limits_(limits) {
  if (limits_.max_artifact_bytes == 0 || limits_.max_store_bytes == 0 ||
      limits_.max_artifact_bytes > limits_.max_store_bytes || limits_.max_artifacts == 0 ||
      limits_.max_manifest_bytes == 0) {
    throw std::invalid_argument("Artifact receiver limits are invalid");
  }
  std::error_code error;
  std::filesystem::create_directories(blob_directory_, error);
  if (error) {
    throw std::runtime_error("Unable to create artifact store: " + error.message());
  }
  std::filesystem::permissions(store_directory_, std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace, error);
  if (error) {
    throw std::runtime_error("Unable to secure artifact store: " + error.message());
  }
  std::filesystem::permissions(blob_directory_, std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace, error);
  if (error) {
    throw std::runtime_error("Unable to secure artifact blob store: " + error.message());
  }
  for (const auto& entry : std::filesystem::directory_iterator(blob_directory_)) {
    if (!entry.is_regular_file() || entry.path().extension() != ".bin") {
      continue;
    }
    const std::uint64_t size = entry.file_size();
    if (size > std::numeric_limits<std::uint64_t>::max() - stored_bytes_) {
      throw std::runtime_error("Artifact store byte count overflow");
    }
    stored_bytes_ += size;
  }
  if (stored_bytes_ > limits_.max_store_bytes) {
    throw std::runtime_error("Existing artifact store exceeds its configured byte limit");
  }

  const bool manifest_exists = std::filesystem::exists(manifest_path_, error);
  if (error) {
    throw std::runtime_error("Unable to inspect artifact manifest: " + error.message());
  }
  if (manifest_exists) {
    manifest_bytes_ = std::filesystem::file_size(manifest_path_, error);
    if (error || manifest_bytes_ > limits_.max_manifest_bytes) {
      throw std::runtime_error(error ? "Unable to size artifact manifest: " + error.message()
                                     : "Existing artifact manifest exceeds its byte limit");
    }
    std::filesystem::permissions(
        manifest_path_, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, error);
    if (error) {
      throw std::runtime_error("Unable to secure artifact manifest: " + error.message());
    }
    std::ifstream manifest(manifest_path_, std::ios::binary);
    if (!manifest) {
      throw std::runtime_error("Unable to read artifact manifest");
    }
    if (manifest_bytes_ > 0) {
      manifest.seekg(-1, std::ios::end);
      if (manifest.get() != '\n') {
        throw std::runtime_error("Artifact manifest ends with an incomplete record");
      }
      manifest.seekg(0, std::ios::beg);
    }
    std::string line;
    while (std::getline(manifest, line)) {
      std::uint64_t artifact_id = 0;
      std::uint64_t session_id = 0;
      if (!ParseManifestRecord(line, artifact_id, session_id) ||
          (limits_.expected_session_id != 0 && session_id != limits_.expected_session_id) ||
          !artifact_ids_.insert(artifact_id).second) {
        throw std::runtime_error(
            "Artifact manifest contains an invalid, duplicate, or mismatched record");
      }
      if (artifact_ids_.size() > limits_.max_artifacts) {
        throw std::runtime_error("Existing artifact manifest exceeds its artifact count limit");
      }
    }
    if (!manifest.eof()) {
      throw std::runtime_error("Unable to read artifact manifest");
    }
  }
}

ArtifactReceiveStatus ArtifactReceiver::ReceiveOne(std::istream& stream) {
  last_error_.clear();
  last_artifact_id_ = 0;
  ArtifactHeader header{};
  stream.read(reinterpret_cast<char*>(&header), static_cast<std::streamsize>(sizeof(header)));
  if (stream.gcount() == 0 && stream.eof()) {
    return ArtifactReceiveStatus::kEndOfStream;
  }
  if (stream.gcount() != static_cast<std::streamsize>(sizeof(header))) {
    return Reject(ArtifactReceiveStatus::kInvalid, "Truncated artifact header");
  }
  last_artifact_id_ = header.artifact_id;
  if (!IsValidArtifactHeader(header)) {
    return Reject(ArtifactReceiveStatus::kInvalid, "Invalid artifact header");
  }
  if (limits_.expected_session_id != 0 && header.session_id != limits_.expected_session_id) {
    return Reject(ArtifactReceiveStatus::kInvalid,
                  "Artifact session does not match the authenticated connection");
  }
  if (artifact_ids_.size() >= limits_.max_artifacts) {
    return Reject(ArtifactReceiveStatus::kTooLarge, "Artifact count exceeds its configured limit");
  }
  if (header.content_size > limits_.max_artifact_bytes ||
      header.content_size > limits_.max_store_bytes - stored_bytes_) {
    return Reject(ArtifactReceiveStatus::kTooLarge, "Artifact exceeds a configured byte limit");
  }
  if (header.kind == ArtifactKind::kResponseBody && !limits_.allow_sensitive) {
    return Reject(ArtifactReceiveStatus::kSensitiveCaptureDisabled,
                  "Sensitive response body capture is disabled");
  }
  if (artifact_ids_.contains(header.artifact_id)) {
    return Reject(ArtifactReceiveStatus::kConflict, "Artifact identifier already exists");
  }

  std::string url(header.url_size, '\0');
  std::string mime_type(header.mime_type_size, '\0');
  stream.read(url.data(), static_cast<std::streamsize>(url.size()));
  if (stream.gcount() != static_cast<std::streamsize>(url.size())) {
    return Reject(ArtifactReceiveStatus::kInvalid, "Truncated artifact URL");
  }
  stream.read(mime_type.data(), static_cast<std::streamsize>(mime_type.size()));
  if (stream.gcount() != static_cast<std::streamsize>(mime_type.size())) {
    return Reject(ArtifactReceiveStatus::kInvalid, "Truncated artifact MIME type");
  }
  if (!IsValidUtf8(url) || !IsValidUtf8(mime_type)) {
    return Reject(ArtifactReceiveStatus::kInvalid,
                  "Artifact metadata is not valid printable UTF-8");
  }

  const std::filesystem::path temporary_path =
      store_directory_ / ("artifact-" + std::to_string(header.artifact_id) + ".part");
  std::ofstream temporary(temporary_path, std::ios::binary | std::ios::trunc);
  if (!temporary) {
    return Reject(ArtifactReceiveStatus::kIoError, "Unable to open temporary artifact file");
  }
  std::error_code permission_error;
  std::filesystem::permissions(
      temporary_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace, permission_error);
  if (permission_error) {
    temporary.close();
    RemoveFileBestEffort(temporary_path);
    return Reject(ArtifactReceiveStatus::kIoError,
                  "Unable to secure temporary artifact file: " + permission_error.message());
  }

  Sha256 sha256;
  std::array<std::uint8_t, 64 * 1024> buffer{};
  std::uint64_t remaining = header.content_size;
  while (remaining > 0) {
    const std::size_t requested = static_cast<std::size_t>(
        std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(buffer.size())));
    stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(requested));
    const std::streamsize received = stream.gcount();
    if (received <= 0) {
      temporary.close();
      RemoveFileBestEffort(temporary_path);
      return Reject(ArtifactReceiveStatus::kInvalid, "Truncated artifact content");
    }
    const auto received_size = static_cast<std::size_t>(received);
    temporary.write(reinterpret_cast<const char*>(buffer.data()), received);
    if (!temporary) {
      temporary.close();
      RemoveFileBestEffort(temporary_path);
      return Reject(ArtifactReceiveStatus::kIoError, "Unable to write artifact content");
    }
    sha256.Update(buffer.data(), received_size);
    remaining -= static_cast<std::uint64_t>(received_size);
  }
  temporary.flush();
  temporary.close();
  if (!temporary) {
    RemoveFileBestEffort(temporary_path);
    return Reject(ArtifactReceiveStatus::kIoError, "Unable to flush artifact content");
  }
  std::string sync_error;
  if (!SyncFile(temporary_path, sync_error)) {
    RemoveFileBestEffort(temporary_path);
    return Reject(ArtifactReceiveStatus::kIoError, std::move(sync_error));
  }

  const std::array<std::uint8_t, 32> digest = sha256.Final();
  if (!IsZeroDigest(header.expected_sha256) && digest != header.expected_sha256) {
    RemoveFileBestEffort(temporary_path);
    return Reject(ArtifactReceiveStatus::kInvalid, "Artifact SHA-256 mismatch");
  }
  const std::string digest_hex = DigestHex(digest);
  const std::filesystem::path blob_path = blob_directory_ / (digest_hex + ".bin");
  std::error_code error;
  const bool blob_exists = std::filesystem::exists(blob_path, error);
  if (error) {
    RemoveFileBestEffort(temporary_path);
    return Reject(ArtifactReceiveStatus::kIoError,
                  "Unable to inspect artifact blob: " + error.message());
  }
  if (blob_exists) {
    std::filesystem::remove(temporary_path, error);
  } else {
    std::filesystem::rename(temporary_path, blob_path, error);
  }
  if (error) {
    RemoveFileBestEffort(temporary_path);
    return Reject(ArtifactReceiveStatus::kIoError,
                  "Unable to commit artifact blob: " + error.message());
  }
  if (!blob_exists && !SyncDirectory(blob_directory_, sync_error)) {
    return Reject(ArtifactReceiveStatus::kIoError, std::move(sync_error));
  }

  std::ostringstream manifest_entry;
  manifest_entry << "{\"protocol_version\":1,\"artifact_id\":\"" << header.artifact_id
                 << "\",\"session_id\":\"" << header.session_id << "\",\"navigation_id\":\""
                 << header.navigation_id << "\",\"frame_id\":\"" << header.frame_id
                 << "\",\"parent_artifact_id\":\"" << header.parent_artifact_id
                 << "\",\"creator_event_id\":\"" << header.creator_event_id
                 << "\",\"execution_context_id\":\"" << header.execution_context_id
                 << "\",\"capture_origin\":\"" << ArtifactCaptureOriginName(header.capture_origin)
                 << "\",\"kind\":\"" << ArtifactKindName(header.kind) << "\",\"url\":\""
                 << JsonEscape(url) << "\",\"mime_type\":\"" << JsonEscape(mime_type)
                 << "\",\"byte_size\":" << header.content_size << ",\"sha256\":\"" << digest_hex
                 << "\",\"sensitive\":"
                 << (header.kind == ArtifactKind::kResponseBody ? "true" : "false")
                 << ",\"content_path\":\"blobs/" << digest_hex << ".bin\"}\n";
  const std::string manifest_line = manifest_entry.str();
  if (manifest_line.size() > limits_.max_manifest_bytes - manifest_bytes_) {
    if (!blob_exists) {
      RemoveFileBestEffort(blob_path);
    }
    return Reject(ArtifactReceiveStatus::kTooLarge,
                  "Artifact manifest exceeds its configured byte limit");
  }

  const bool manifest_existed = std::filesystem::exists(manifest_path_, error);
  if (error) {
    return Reject(ArtifactReceiveStatus::kIoError,
                  "Unable to inspect artifact manifest: " + error.message());
  }
  std::ofstream manifest(manifest_path_, std::ios::app);
  if (!manifest) {
    return Reject(ArtifactReceiveStatus::kIoError, "Unable to open artifact manifest");
  }
  std::filesystem::permissions(
      manifest_path_, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace, permission_error);
  if (permission_error) {
    return Reject(ArtifactReceiveStatus::kIoError,
                  "Unable to secure artifact manifest: " + permission_error.message());
  }
  manifest << manifest_line;
  manifest.flush();
  manifest.close();
  if (!manifest) {
    return Reject(ArtifactReceiveStatus::kIoError, "Unable to write artifact manifest");
  }
  if (!SyncFile(manifest_path_, sync_error)) {
    return Reject(ArtifactReceiveStatus::kIoError, std::move(sync_error));
  }
  if (!manifest_existed && !SyncDirectory(store_directory_, sync_error)) {
    return Reject(ArtifactReceiveStatus::kIoError, std::move(sync_error));
  }

  if (!blob_exists) {
    stored_bytes_ += header.content_size;
  }
  manifest_bytes_ += manifest_line.size();
  artifact_ids_.insert(header.artifact_id);
  SaturatingAdd(stats_.accepted, 1);
  SaturatingAdd(stats_.bytes_accepted, header.content_size);
  return ArtifactReceiveStatus::kAccepted;
}

ArtifactReceiverStats ArtifactReceiver::Stats() const noexcept {
  return stats_;
}

std::uint64_t ArtifactReceiver::StoredBytes() const noexcept {
  return stored_bytes_;
}

std::uint64_t ArtifactReceiver::LastArtifactId() const noexcept {
  return last_artifact_id_;
}

const std::string& ArtifactReceiver::LastError() const noexcept {
  return last_error_;
}

ArtifactReceiveStatus ArtifactReceiver::Reject(const ArtifactReceiveStatus status,
                                               std::string message) {
  last_error_ = std::move(message);
  switch (status) {
    case ArtifactReceiveStatus::kInvalid:
      SaturatingAdd(stats_.invalid, 1);
      break;
    case ArtifactReceiveStatus::kTooLarge:
      SaturatingAdd(stats_.too_large, 1);
      break;
    case ArtifactReceiveStatus::kSensitiveCaptureDisabled:
      SaturatingAdd(stats_.sensitive_rejected, 1);
      break;
    case ArtifactReceiveStatus::kConflict:
      SaturatingAdd(stats_.conflicts, 1);
      break;
    case ArtifactReceiveStatus::kIoError:
      SaturatingAdd(stats_.io_errors, 1);
      break;
    case ArtifactReceiveStatus::kAccepted:
    case ArtifactReceiveStatus::kEndOfStream:
      break;
  }
  return status;
}

}  // namespace reb
