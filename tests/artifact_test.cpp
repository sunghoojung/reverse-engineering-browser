#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include "../browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_artifact_header.h"
#include "reb/artifact.hpp"

#define CHECK(condition)                                                                   \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " << #condition \
                << '\n';                                                                   \
      return 1;                                                                            \
    }                                                                                      \
  } while (false)

#define CHECK_ARTIFACT_WIRE_OFFSET(field) \
  static_assert(offsetof(reb::ArtifactHeader, field) == offsetof(reb::NativeArtifactHeader, field))

CHECK_ARTIFACT_WIRE_OFFSET(magic);
CHECK_ARTIFACT_WIRE_OFFSET(protocol_version);
CHECK_ARTIFACT_WIRE_OFFSET(header_size);
CHECK_ARTIFACT_WIRE_OFFSET(kind);
CHECK_ARTIFACT_WIRE_OFFSET(flags);
CHECK_ARTIFACT_WIRE_OFFSET(reserved0);
CHECK_ARTIFACT_WIRE_OFFSET(session_id);
CHECK_ARTIFACT_WIRE_OFFSET(navigation_id);
CHECK_ARTIFACT_WIRE_OFFSET(frame_id);
CHECK_ARTIFACT_WIRE_OFFSET(artifact_id);
CHECK_ARTIFACT_WIRE_OFFSET(parent_artifact_id);
CHECK_ARTIFACT_WIRE_OFFSET(creator_event_id);
CHECK_ARTIFACT_WIRE_OFFSET(content_size);
CHECK_ARTIFACT_WIRE_OFFSET(url_size);
CHECK_ARTIFACT_WIRE_OFFSET(mime_type_size);
CHECK_ARTIFACT_WIRE_OFFSET(expected_sha256);
CHECK_ARTIFACT_WIRE_OFFSET(reserved1);

#undef CHECK_ARTIFACT_WIRE_OFFSET

static_assert(reb::kArtifactAckMagic == reb::kNativeArtifactAckMagic);
static_assert(reb::kArtifactAckSize == reb::kNativeArtifactAckSize);
static_assert(reb::kMaxArtifactUrlBytes == reb::kNativeArtifactMaxUrlBytes);
static_assert(reb::kMaxArtifactMimeTypeBytes == reb::kNativeArtifactMaxMimeTypeBytes);
static_assert(sizeof(reb::ArtifactAck) == sizeof(reb::NativeArtifactAck));
static_assert(offsetof(reb::ArtifactAck, status) == offsetof(reb::NativeArtifactAck, status));
static_assert(offsetof(reb::ArtifactAck, artifact_id) ==
              offsetof(reb::NativeArtifactAck, artifact_id));
#define CHECK_ARTIFACT_STATUS_VALUE(value)                                       \
  static_assert(static_cast<std::uint32_t>(reb::ArtifactReceiveStatus::value) == \
                static_cast<std::uint32_t>(reb::NativeArtifactReceiveStatus::value))
CHECK_ARTIFACT_STATUS_VALUE(kAccepted);
CHECK_ARTIFACT_STATUS_VALUE(kEndOfStream);
CHECK_ARTIFACT_STATUS_VALUE(kInvalid);
CHECK_ARTIFACT_STATUS_VALUE(kTooLarge);
CHECK_ARTIFACT_STATUS_VALUE(kSensitiveCaptureDisabled);
CHECK_ARTIFACT_STATUS_VALUE(kConflict);
CHECK_ARTIFACT_STATUS_VALUE(kIoError);
#undef CHECK_ARTIFACT_STATUS_VALUE

static_assert(reb::kArtifactMagic == reb::kNativeArtifactMagic);
static_assert(reb::kArtifactProtocolVersion == reb::kNativeArtifactProtocolVersion);
static_assert(reb::kArtifactHeaderSize == reb::kNativeArtifactHeaderSize);
static_assert(reb::kArtifactFlagSensitive == reb::kNativeArtifactFlagSensitive);
static_assert(sizeof(reb::ArtifactHeader) == sizeof(reb::NativeArtifactHeader));
#define CHECK_ARTIFACT_KIND_VALUE(value)                                \
  static_assert(static_cast<std::uint16_t>(reb::ArtifactKind::value) == \
                static_cast<std::uint16_t>(reb::NativeArtifactKind::value))
CHECK_ARTIFACT_KIND_VALUE(kUnknown);
CHECK_ARTIFACT_KIND_VALUE(kJavaScript);
CHECK_ARTIFACT_KIND_VALUE(kWasm);
CHECK_ARTIFACT_KIND_VALUE(kSourceMap);
CHECK_ARTIFACT_KIND_VALUE(kResponseBody);
#undef CHECK_ARTIFACT_KIND_VALUE

namespace {

class TemporaryDirectory final {
 public:
  explicit TemporaryDirectory(const std::string_view label) {
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    path_ = std::filesystem::temp_directory_path() /
            ("reb-artifact-test-" + std::string(label) + '-' + std::to_string(nonce));
    std::filesystem::create_directories(path_);
  }

  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  [[nodiscard]] const std::filesystem::path& Path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

reb::ArtifactHeader Header(const std::uint64_t artifact_id,
                           const std::size_t content_size,
                           const reb::ArtifactKind kind = reb::ArtifactKind::kJavaScript) {
  reb::ArtifactHeader header;
  header.kind = kind;
  header.flags = kind == reb::ArtifactKind::kResponseBody ? reb::kArtifactFlagSensitive : 0;
  header.session_id = 7;
  header.navigation_id = 100;
  header.frame_id = 200;
  header.artifact_id = artifact_id;
  header.parent_artifact_id = 0;
  header.creator_event_id = 79;
  header.content_size = static_cast<std::uint64_t>(content_size);
  header.url_size = 44;
  header.mime_type_size = 15;
  return header;
}

std::string Frame(reb::ArtifactHeader header,
                  const std::string_view content,
                  const std::string_view url = "https://checkout.acme.test/assets/cart.js",
                  const std::string_view mime_type = "text/javascript") {
  header.url_size = static_cast<std::uint32_t>(url.size());
  header.mime_type_size = static_cast<std::uint32_t>(mime_type.size());
  std::ostringstream output;
  output.write(reinterpret_cast<const char*>(&header), sizeof(header));
  output.write(url.data(), static_cast<std::streamsize>(url.size()));
  output.write(mime_type.data(), static_cast<std::streamsize>(mime_type.size()));
  output.write(content.data(), static_cast<std::streamsize>(content.size()));
  return output.str();
}

std::array<std::uint8_t, 32> DigestFromHex(const std::string_view hex) {
  std::array<std::uint8_t, 32> digest{};
  for (std::size_t index = 0; index < digest.size(); ++index) {
    digest[index] =
        static_cast<std::uint8_t>(std::stoul(std::string(hex.substr(index * 2, 2)), nullptr, 16));
  }
  return digest;
}

}  // namespace

int main() {
  reb::ArtifactHeader valid = Header(300, 3);
  CHECK(sizeof(valid) == 128);
  CHECK(reb::IsValidArtifactHeader(valid));
  valid.reserved1[0] = 1;
  CHECK(!reb::IsValidArtifactHeader(valid));
  valid.reserved1[0] = 0;
  valid.kind = reb::ArtifactKind::kResponseBody;
  CHECK(!reb::IsValidArtifactHeader(valid));

  TemporaryDirectory accepted_directory("accepted");
  reb::ArtifactReceiver receiver(accepted_directory.Path(), 1024, 4096, false);
  std::istringstream accepted_stream(Frame(Header(300, 3), "abc"));
  CHECK(receiver.ReceiveOne(accepted_stream) == reb::ArtifactReceiveStatus::kAccepted);
  CHECK(receiver.ReceiveOne(accepted_stream) == reb::ArtifactReceiveStatus::kEndOfStream);
  CHECK(receiver.Stats().accepted == 1);
  CHECK(receiver.Stats().bytes_accepted == 3);
  CHECK(receiver.StoredBytes() == 3);

  std::ifstream manifest(accepted_directory.Path() / "manifest.jsonl");
  const std::string manifest_line((std::istreambuf_iterator<char>(manifest)),
                                  std::istreambuf_iterator<char>());
  CHECK(manifest_line.find("\"artifact_id\":\"300\"") != std::string::npos);
  CHECK(manifest_line.find("\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9c"
                           "b410ff61f20015ad\"") != std::string::npos);
  CHECK(std::filesystem::file_size(
            accepted_directory.Path() /
            "blobs/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.bin") == 3);

  std::istringstream conflict_stream(Frame(Header(300, 3), "abc"));
  CHECK(receiver.ReceiveOne(conflict_stream) == reb::ArtifactReceiveStatus::kConflict);
  CHECK(receiver.Stats().conflicts == 1);

  TemporaryDirectory limit_directory("limit");
  reb::ArtifactReceiver limited(limit_directory.Path(), 3, 4, false);
  std::istringstream oversized_stream(Frame(Header(400, 4), "four"));
  CHECK(limited.ReceiveOne(oversized_stream) == reb::ArtifactReceiveStatus::kTooLarge);
  std::istringstream small_stream(Frame(Header(400, 3), "one"));
  CHECK(limited.ReceiveOne(small_stream) == reb::ArtifactReceiveStatus::kAccepted);
  std::istringstream total_stream(Frame(Header(401, 2), "xx"));
  CHECK(limited.ReceiveOne(total_stream) == reb::ArtifactReceiveStatus::kTooLarge);
  CHECK(limited.Stats().too_large == 2);

  TemporaryDirectory sensitive_directory("sensitive");
  reb::ArtifactReceiver default_receiver(sensitive_directory.Path(), 1024, 4096, false);
  const std::string response_frame = Frame(Header(500, 2, reb::ArtifactKind::kResponseBody), "{}",
                                           "https://checkout.acme.test/cart", "application/json");
  std::istringstream rejected_response(response_frame);
  CHECK(default_receiver.ReceiveOne(rejected_response) ==
        reb::ArtifactReceiveStatus::kSensitiveCaptureDisabled);

  TemporaryDirectory approved_directory("approved");
  reb::ArtifactReceiver approved_receiver(approved_directory.Path(), 1024, 4096, true);
  std::istringstream approved_response(response_frame);
  CHECK(approved_receiver.ReceiveOne(approved_response) == reb::ArtifactReceiveStatus::kAccepted);

  TemporaryDirectory invalid_directory("invalid");
  reb::ArtifactReceiver invalid_receiver(invalid_directory.Path(), 1024, 4096, false);
  std::string truncated = Frame(Header(600, 4), "two");
  std::istringstream truncated_stream(truncated);
  CHECK(invalid_receiver.ReceiveOne(truncated_stream) == reb::ArtifactReceiveStatus::kInvalid);

  reb::ArtifactHeader bad_hash_header = Header(601, 3);
  bad_hash_header.expected_sha256 = DigestFromHex(std::string(64, '0'));
  bad_hash_header.expected_sha256[0] = 1;
  std::istringstream bad_hash_stream(Frame(bad_hash_header, "abc"));
  CHECK(invalid_receiver.ReceiveOne(bad_hash_stream) == reb::ArtifactReceiveStatus::kInvalid);
  CHECK(invalid_receiver.LastError().find("SHA-256") != std::string::npos);

  std::cout << "artifact_test passed\n";
  return 0;
}
