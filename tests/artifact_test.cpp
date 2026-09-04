#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
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
CHECK_ARTIFACT_WIRE_OFFSET(execution_context_id);
CHECK_ARTIFACT_WIRE_OFFSET(capture_origin);
CHECK_ARTIFACT_WIRE_OFFSET(reserved1);
CHECK_ARTIFACT_WIRE_OFFSET(reserved2);

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

#define CHECK_ARTIFACT_ORIGIN_VALUE(value)                                       \
  static_assert(static_cast<std::uint16_t>(reb::ArtifactCaptureOrigin::value) == \
                static_cast<std::uint16_t>(reb::NativeArtifactCaptureOrigin::value))
CHECK_ARTIFACT_ORIGIN_VALUE(kUnknown);
CHECK_ARTIFACT_ORIGIN_VALUE(kNetworkResponse);
CHECK_ARTIFACT_ORIGIN_VALUE(kDynamicJavaScript);
CHECK_ARTIFACT_ORIGIN_VALUE(kWebAssemblyCompile);
CHECK_ARTIFACT_ORIGIN_VALUE(kWebAssemblyModule);
CHECK_ARTIFACT_ORIGIN_VALUE(kWebAssemblyInstantiate);
#undef CHECK_ARTIFACT_ORIGIN_VALUE

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

reb::ArtifactReceiverLimits Limits(const std::uint64_t max_artifact_bytes,
                                   const std::uint64_t max_store_bytes,
                                   const bool allow_sensitive = false) {
  reb::ArtifactReceiverLimits limits;
  limits.max_artifact_bytes = max_artifact_bytes;
  limits.max_store_bytes = max_store_bytes;
  limits.allow_sensitive = allow_sensitive;
  return limits;
}

}  // namespace

int main() {
  reb::ArtifactHeader valid = Header(300, 3);
  CHECK(sizeof(valid) == 128);
  CHECK(reb::IsValidArtifactHeader(valid));
  valid.reserved1 = 1;
  CHECK(!reb::IsValidArtifactHeader(valid));
  valid.reserved1 = 0;
  valid.reserved2 = 1;
  CHECK(!reb::IsValidArtifactHeader(valid));
  valid.reserved2 = 0;
  valid.capture_origin = reb::ArtifactCaptureOrigin::kWebAssemblyCompile;
  CHECK(!reb::IsValidArtifactHeader(valid));
  valid.capture_origin = reb::ArtifactCaptureOrigin::kDynamicJavaScript;
  CHECK(!reb::IsValidArtifactHeader(valid));
  valid.execution_context_id = 9001;
  CHECK(reb::IsValidArtifactHeader(valid));
  valid.kind = reb::ArtifactKind::kResponseBody;
  CHECK(!reb::IsValidArtifactHeader(valid));

  TemporaryDirectory accepted_directory("accepted");
  reb::ArtifactReceiver receiver(accepted_directory.Path(), Limits(1024, 4096));
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
  CHECK(manifest_line.find("\"execution_context_id\":\"0\"") != std::string::npos);
  CHECK(manifest_line.find("\"capture_origin\":\"unknown\"") != std::string::npos);
  CHECK(manifest_line.find("\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9c"
                           "b410ff61f20015ad\"") != std::string::npos);
  CHECK(std::filesystem::file_size(
            accepted_directory.Path() /
            "blobs/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.bin") == 3);

  TemporaryDirectory legacy_directory("legacy");
  std::filesystem::create_directories(legacy_directory.Path() / "blobs");
  std::string legacy_manifest = manifest_line;
  const std::string runtime_fields =
      ",\"execution_context_id\":\"0\",\"capture_origin\":\"unknown\"";
  const std::size_t runtime_fields_position = legacy_manifest.find(runtime_fields);
  CHECK(runtime_fields_position != std::string::npos);
  legacy_manifest.erase(runtime_fields_position, runtime_fields.size());
  {
    std::ofstream legacy_file(legacy_directory.Path() / "manifest.jsonl");
    legacy_file << legacy_manifest;
  }
  std::filesystem::copy_file(
      accepted_directory.Path() /
          "blobs/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.bin",
      legacy_directory.Path() /
          "blobs/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.bin");
  reb::ArtifactReceiver legacy_receiver(legacy_directory.Path(), Limits(1024, 4096));
  CHECK(legacy_receiver.StoredBytes() == 3);

  std::istringstream conflict_stream(Frame(Header(300, 3), "abc"));
  CHECK(receiver.ReceiveOne(conflict_stream) == reb::ArtifactReceiveStatus::kConflict);
  CHECK(receiver.Stats().conflicts == 1);
  reb::ArtifactReceiver reopened_receiver(accepted_directory.Path(), Limits(1024, 4096));
  std::istringstream reopened_conflict_stream(Frame(Header(300, 3), "abc"));
  CHECK(reopened_receiver.ReceiveOne(reopened_conflict_stream) ==
        reb::ArtifactReceiveStatus::kConflict);
  reb::ArtifactReceiverLimits mismatched_reopen_limits = Limits(1024, 4096);
  mismatched_reopen_limits.expected_session_id = 8;
  bool mismatched_reopen_rejected = false;
  try {
    reb::ArtifactReceiver mismatched_reopen(accepted_directory.Path(), mismatched_reopen_limits);
    (void)mismatched_reopen;
  } catch (const std::runtime_error&) {
    mismatched_reopen_rejected = true;
  }
  CHECK(mismatched_reopen_rejected);

  TemporaryDirectory truncated_manifest_directory("truncated-manifest");
  std::filesystem::create_directories(truncated_manifest_directory.Path() / "blobs");
  {
    std::ofstream truncated_manifest(truncated_manifest_directory.Path() / "manifest.jsonl");
    truncated_manifest << "{\"protocol_version\":1,\"artifact_id\":\"123\",";
  }
  bool truncated_manifest_rejected = false;
  try {
    reb::ArtifactReceiver truncated_manifest_receiver(truncated_manifest_directory.Path(),
                                                      Limits(1024, 4096));
    (void)truncated_manifest_receiver;
  } catch (const std::runtime_error&) {
    truncated_manifest_rejected = true;
  }
  CHECK(truncated_manifest_rejected);

  TemporaryDirectory limit_directory("limit");
  reb::ArtifactReceiver limited(limit_directory.Path(), Limits(3, 4));
  std::istringstream oversized_stream(Frame(Header(400, 4), "four"));
  CHECK(limited.ReceiveOne(oversized_stream) == reb::ArtifactReceiveStatus::kTooLarge);
  std::istringstream small_stream(Frame(Header(400, 3), "one"));
  CHECK(limited.ReceiveOne(small_stream) == reb::ArtifactReceiveStatus::kAccepted);
  std::istringstream total_stream(Frame(Header(401, 2), "xx"));
  CHECK(limited.ReceiveOne(total_stream) == reb::ArtifactReceiveStatus::kTooLarge);
  CHECK(limited.Stats().too_large == 2);

  TemporaryDirectory sensitive_directory("sensitive");
  reb::ArtifactReceiver default_receiver(sensitive_directory.Path(), Limits(1024, 4096));
  const std::string response_frame = Frame(Header(500, 2, reb::ArtifactKind::kResponseBody), "{}",
                                           "https://checkout.acme.test/cart", "application/json");
  std::istringstream rejected_response(response_frame);
  CHECK(default_receiver.ReceiveOne(rejected_response) ==
        reb::ArtifactReceiveStatus::kSensitiveCaptureDisabled);

  TemporaryDirectory approved_directory("approved");
  reb::ArtifactReceiver approved_receiver(approved_directory.Path(), Limits(1024, 4096, true));
  std::istringstream approved_response(response_frame);
  CHECK(approved_receiver.ReceiveOne(approved_response) == reb::ArtifactReceiveStatus::kAccepted);

  TemporaryDirectory invalid_directory("invalid");
  reb::ArtifactReceiver invalid_receiver(invalid_directory.Path(), Limits(1024, 4096));
  std::string truncated = Frame(Header(600, 4), "two");
  std::istringstream truncated_stream(truncated);
  CHECK(invalid_receiver.ReceiveOne(truncated_stream) == reb::ArtifactReceiveStatus::kInvalid);

  reb::ArtifactHeader bad_hash_header = Header(601, 3);
  bad_hash_header.expected_sha256 = DigestFromHex(std::string(64, '0'));
  bad_hash_header.expected_sha256[0] = 1;
  std::istringstream bad_hash_stream(Frame(bad_hash_header, "abc"));
  CHECK(invalid_receiver.ReceiveOne(bad_hash_stream) == reb::ArtifactReceiveStatus::kInvalid);
  CHECK(invalid_receiver.LastError().find("SHA-256") != std::string::npos);

  TemporaryDirectory session_directory("session");
  reb::ArtifactReceiverLimits session_limits = Limits(1024, 4096);
  session_limits.expected_session_id = 8;
  reb::ArtifactReceiver session_receiver(session_directory.Path(), session_limits);
  std::istringstream wrong_session_stream(Frame(Header(700, 0), ""));
  CHECK(session_receiver.ReceiveOne(wrong_session_stream) == reb::ArtifactReceiveStatus::kInvalid);
  CHECK(session_receiver.LastError().find("authenticated") != std::string::npos);

  TemporaryDirectory count_directory("count");
  reb::ArtifactReceiverLimits count_limits = Limits(1024, 4096);
  count_limits.max_artifacts = 32;
  reb::ArtifactReceiver count_receiver(count_directory.Path(), count_limits);
  for (std::uint64_t artifact_id = 800; artifact_id < 832; ++artifact_id) {
    std::istringstream empty_frame(Frame(Header(artifact_id, 0), ""));
    CHECK(count_receiver.ReceiveOne(empty_frame) == reb::ArtifactReceiveStatus::kAccepted);
  }
  std::istringstream excess_empty(Frame(Header(832, 0), ""));
  CHECK(count_receiver.ReceiveOne(excess_empty) == reb::ArtifactReceiveStatus::kTooLarge);

  TemporaryDirectory manifest_limit_directory("manifest-limit");
  reb::ArtifactReceiverLimits manifest_limits = Limits(1024, 4096);
  manifest_limits.max_manifest_bytes = 64;
  reb::ArtifactReceiver manifest_limited(manifest_limit_directory.Path(), manifest_limits);
  std::istringstream metadata_frame(Frame(Header(900, 0), ""));
  CHECK(manifest_limited.ReceiveOne(metadata_frame) == reb::ArtifactReceiveStatus::kTooLarge);
  CHECK(std::filesystem::is_empty(manifest_limit_directory.Path() / "blobs"));

  std::cout << "artifact_test passed\n";
  return 0;
}
