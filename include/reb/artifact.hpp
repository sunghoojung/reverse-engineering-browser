#ifndef REB_ARTIFACT_HPP_
#define REB_ARTIFACT_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <string>
#include <type_traits>
#include <unordered_set>

#include "reb/evidence_guard.hpp"

namespace reb {

inline constexpr std::uint32_t kArtifactMagic = 0x41424552U;
inline constexpr std::uint16_t kArtifactProtocolVersion = 1;
inline constexpr std::size_t kArtifactHeaderSize = 128;
inline constexpr std::uint32_t kArtifactAckMagic = 0x4b414252U;
inline constexpr std::size_t kArtifactAckSize = 32;
inline constexpr std::uint32_t kMaxArtifactUrlBytes = 8'192;
inline constexpr std::uint32_t kMaxArtifactMimeTypeBytes = 255;
inline constexpr std::uint16_t kArtifactFlagSensitive = 1U << 0U;
inline constexpr std::uint64_t kDefaultMaxStoredArtifacts = 4'096;
inline constexpr std::uint64_t kDefaultMaxManifestBytes = 64ULL * 1024ULL * 1024ULL;
// A rejected frame whose header was valid is read and discarded so the socket
// connection can carry the next frame. This covers the browser's 16 MiB
// per-artifact cap; a larger declared size than this and the configured
// artifact limit cannot come from a supported sender, so it closes instead.
inline constexpr std::uint64_t kMaxDiscardedArtifactBytes = 16ULL * 1024ULL * 1024ULL;

enum class ArtifactKind : std::uint16_t {
  kUnknown = 0,
  kJavaScript = 1,
  kWasm = 2,
  kSourceMap = 3,
  kResponseBody = 4,
  kCanvasDataUrl = 5,
  kBytecodeBuffer = 6,
  kWasmGuestAdapter = 7,
  kRequestBody = 8,
  kRequestTarget = 9,
  kRequestHeaders = 10,
  kResponseHeaders = 11,
  kCookieList = 12,
};

enum class ArtifactCaptureOrigin : std::uint16_t {
  kUnknown = 0,
  kNetworkResponse = 1,
  kDynamicJavaScript = 2,
  kWebAssemblyCompile = 3,
  kWebAssemblyModule = 4,
  kWebAssemblyInstantiate = 5,
  kCanvasToDataUrl = 6,
  kRuntimeTypedArray = 7,
  kRuntimeAllocatingScript = 8,
  kNativeWasmGuest = 9,
  kNetworkRequest = 10,
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
  std::uint64_t execution_context_id = 0;
  ArtifactCaptureOrigin capture_origin = ArtifactCaptureOrigin::kUnknown;
  std::uint16_t reserved1 = 0;
  std::uint32_t reserved2 = 0;
};

static_assert(sizeof(ArtifactHeader) == kArtifactHeaderSize);
static_assert(std::is_standard_layout_v<ArtifactHeader>);
static_assert(std::is_trivially_copyable_v<ArtifactHeader>);
static_assert(offsetof(ArtifactHeader, session_id) == 16);
static_assert(offsetof(ArtifactHeader, content_size) == 64);
static_assert(offsetof(ArtifactHeader, expected_sha256) == 80);
static_assert(offsetof(ArtifactHeader, execution_context_id) == 112);
static_assert(offsetof(ArtifactHeader, capture_origin) == 120);

enum class ArtifactReceiveStatus : std::uint32_t {
  kAccepted,
  kEndOfStream,
  kInvalid,
  kTooLarge,
  kSensitiveCaptureDisabled,
  kConflict,
  kIoError,
};

// Where ReceiveOne left its input stream. Only a frame boundary can carry
// another frame; an unsynchronized stream must be closed.
enum class ArtifactStreamPosition : std::uint8_t {
  // The whole frame was consumed, whether it was accepted or rejected.
  kFrameBoundary,
  // The header was invalid, the stream ended early, or a declared length was
  // too large to discard, so the next byte's meaning is unknown.
  kUnsynchronized,
};

struct ArtifactAck final {
  std::uint32_t magic = kArtifactAckMagic;
  std::uint16_t protocol_version = kArtifactProtocolVersion;
  std::uint16_t ack_size = static_cast<std::uint16_t>(kArtifactAckSize);
  ArtifactReceiveStatus status = ArtifactReceiveStatus::kInvalid;
  std::uint32_t reserved0 = 0;
  std::uint64_t artifact_id = 0;
  std::array<std::byte, 8> reserved1{};
};

static_assert(sizeof(ArtifactAck) == kArtifactAckSize);
static_assert(std::is_standard_layout_v<ArtifactAck>);
static_assert(std::is_trivially_copyable_v<ArtifactAck>);
static_assert(offsetof(ArtifactAck, status) == 8);
static_assert(offsetof(ArtifactAck, artifact_id) == 16);

struct ArtifactReceiverStats final {
  std::uint64_t accepted = 0;
  std::uint64_t bytes_accepted = 0;
  std::uint64_t invalid = 0;
  std::uint64_t too_large = 0;
  std::uint64_t sensitive_rejected = 0;
  std::uint64_t conflicts = 0;
  std::uint64_t io_errors = 0;
};

struct ArtifactReceiverLimits final {
  std::uint64_t max_artifact_bytes = 0;
  std::uint64_t max_store_bytes = 0;
  std::uint64_t max_artifacts = kDefaultMaxStoredArtifacts;
  std::uint64_t max_manifest_bytes = kDefaultMaxManifestBytes;
  std::uint64_t expected_session_id = 0;
  bool allow_sensitive = false;
};

class ArtifactReceiver final {
 public:
  ArtifactReceiver(std::filesystem::path store_directory, ArtifactReceiverLimits limits);

  ArtifactReceiver(const ArtifactReceiver&) = delete;
  ArtifactReceiver& operator=(const ArtifactReceiver&) = delete;

  [[nodiscard]] ArtifactReceiveStatus ReceiveOne(std::istream& stream);
  [[nodiscard]] ArtifactReceiverStats Stats() const noexcept;
  [[nodiscard]] std::uint64_t StoredBytes() const noexcept;
  [[nodiscard]] std::uint64_t LastArtifactId() const noexcept;
  [[nodiscard]] const std::string& LastError() const noexcept;
  // Set by every ReceiveOne call.
  [[nodiscard]] ArtifactStreamPosition StreamPosition() const noexcept;
  // Bytes of an unacknowledged final manifest record that construction cut
  // away; nonzero only after an interrupted append.
  [[nodiscard]] std::uint64_t RecoveredManifestBytes() const noexcept;

 private:
  // kFailed once a manifest append could not be rolled back. The file may
  // then hold an unacknowledged record, so bookkeeping no longer matches the
  // disk and every later frame is refused rather than appended after it.
  enum class StoreState : std::uint8_t { kConsistent, kFailed };

  [[nodiscard]] ArtifactReceiveStatus Reject(ArtifactReceiveStatus status, std::string message);
  [[nodiscard]] ArtifactReceiveStatus RejectFrame(std::istream& stream,
                                                  std::uint64_t unread_metadata,
                                                  std::uint64_t unread_content,
                                                  ArtifactReceiveStatus status,
                                                  std::string message);
  [[nodiscard]] bool RestoreManifest() noexcept;

  // Lives through all receiver-owned scans, writes, flushes and closes.
  EvidenceGuard evidence_guard_;
  std::filesystem::path store_directory_;
  EvidenceDirectory blob_directory_;
  ArtifactReceiverLimits limits_;
  // Both mirror the files on disk: blob bytes in blobs/ and the manifest's
  // size, whatever the outcome of the frame that changed them.
  std::uint64_t stored_bytes_ = 0;
  std::uint64_t manifest_bytes_ = 0;
  std::uint64_t recovered_manifest_bytes_ = 0;
  std::uint64_t last_artifact_id_ = 0;
  std::unordered_set<std::uint64_t> artifact_ids_;
  ArtifactReceiverStats stats_;
  std::string last_error_;
  ArtifactStreamPosition stream_position_ = ArtifactStreamPosition::kFrameBoundary;
  StoreState store_state_ = StoreState::kConsistent;
};

[[nodiscard]] bool IsValidArtifactHeader(const ArtifactHeader& header) noexcept;
[[nodiscard]] const char* ArtifactKindName(ArtifactKind kind) noexcept;
[[nodiscard]] const char* ArtifactCaptureOriginName(ArtifactCaptureOrigin origin) noexcept;

}  // namespace reb

#endif  // REB_ARTIFACT_HPP_
