#ifndef REB_ARTIFACT_HPP_
#define REB_ARTIFACT_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <string>
#include <type_traits>

namespace reb {

inline constexpr std::uint32_t kArtifactMagic = 0x41424552U;
inline constexpr std::uint16_t kArtifactProtocolVersion = 1;
inline constexpr std::size_t kArtifactHeaderSize = 128;
inline constexpr std::uint32_t kMaxArtifactUrlBytes = 8'192;
inline constexpr std::uint32_t kMaxArtifactMimeTypeBytes = 255;
inline constexpr std::uint16_t kArtifactFlagSensitive = 1U << 0U;

enum class ArtifactKind : std::uint16_t {
  kUnknown = 0,
  kJavaScript = 1,
  kWasm = 2,
  kSourceMap = 3,
  kResponseBody = 4,
};

struct ArtifactHeader final {
  std::uint32_t magic = kArtifactMagic;
  std::uint16_t protocol_version = kArtifactProtocolVersion;
  std::uint16_t header_size = static_cast<std::uint16_t>(kArtifactHeaderSize);
  ArtifactKind kind = ArtifactKind::kUnknown;
  std::uint16_t flags = 0;
  std::uint32_t reserved0 = 0;
  std::uint64_t session_id = 0;
  std::uint64_t navigation_id = 0;
  std::uint64_t frame_id = 0;
  std::uint64_t artifact_id = 0;
  std::uint64_t parent_artifact_id = 0;
  std::uint64_t creator_event_id = 0;
  std::uint64_t content_size = 0;
  std::uint32_t url_size = 0;
  std::uint32_t mime_type_size = 0;
  std::array<std::uint8_t, 32> expected_sha256{};
  std::array<std::uint8_t, 16> reserved1{};
};

static_assert(sizeof(ArtifactHeader) == kArtifactHeaderSize);
static_assert(std::is_standard_layout_v<ArtifactHeader>);
static_assert(std::is_trivially_copyable_v<ArtifactHeader>);
static_assert(offsetof(ArtifactHeader, session_id) == 16);
static_assert(offsetof(ArtifactHeader, content_size) == 64);
static_assert(offsetof(ArtifactHeader, expected_sha256) == 80);

enum class ArtifactReceiveStatus {
  kAccepted,
  kEndOfStream,
  kInvalid,
  kTooLarge,
  kSensitiveCaptureDisabled,
  kConflict,
  kIoError,
};

struct ArtifactReceiverStats final {
  std::uint64_t accepted = 0;
  std::uint64_t bytes_accepted = 0;
  std::uint64_t invalid = 0;
  std::uint64_t too_large = 0;
  std::uint64_t sensitive_rejected = 0;
  std::uint64_t conflicts = 0;
  std::uint64_t io_errors = 0;
};

class ArtifactReceiver final {
 public:
  ArtifactReceiver(std::filesystem::path store_directory,
                   std::uint64_t max_artifact_bytes,
                   std::uint64_t max_store_bytes,
                   bool allow_sensitive);

  ArtifactReceiver(const ArtifactReceiver&) = delete;
  ArtifactReceiver& operator=(const ArtifactReceiver&) = delete;

  [[nodiscard]] ArtifactReceiveStatus ReceiveOne(std::istream& stream);
  [[nodiscard]] ArtifactReceiverStats Stats() const noexcept;
  [[nodiscard]] std::uint64_t StoredBytes() const noexcept;
  [[nodiscard]] const std::string& LastError() const noexcept;

 private:
  [[nodiscard]] ArtifactReceiveStatus Reject(ArtifactReceiveStatus status, std::string message);

  std::filesystem::path store_directory_;
  std::filesystem::path blob_directory_;
  std::filesystem::path manifest_path_;
  std::uint64_t max_artifact_bytes_ = 0;
  std::uint64_t max_store_bytes_ = 0;
  bool allow_sensitive_ = false;
  std::uint64_t stored_bytes_ = 0;
  ArtifactReceiverStats stats_;
  std::string last_error_;
};

[[nodiscard]] bool IsValidArtifactHeader(const ArtifactHeader& header) noexcept;
[[nodiscard]] const char* ArtifactKindName(ArtifactKind kind) noexcept;

}  // namespace reb

#endif  // REB_ARTIFACT_HPP_
