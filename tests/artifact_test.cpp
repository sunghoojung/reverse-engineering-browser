#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "reb/artifact.hpp"

namespace {

// Commits fsync the manifest; failing those calls drives the rollback paths.
// The test needs ordering, not durability, so every other call succeeds.
ino_t g_failing_inode = 0;
int g_failures_left = 0;

int failures = 0;

void Expect(const bool condition, const std::string_view message) {
  if (!condition) {
    std::cerr << message << '\n';
    ++failures;
  }
}

std::string Frame(const std::uint64_t artifact_id,
                  const std::string& content,
                  const bool sensitive = false,
                  const std::uint64_t declared_size = 0) {
  reb::ArtifactHeader header;
  header.session_id = 7;
  header.artifact_id = artifact_id;
  const std::string url = "https://fixture.test/" + std::to_string(artifact_id);
  const std::string mime = sensitive ? "text/plain" : "text/javascript";
  if (sensitive) {
    header.kind = reb::ArtifactKind::kCanvasDataUrl;
    header.capture_origin = reb::ArtifactCaptureOrigin::kCanvasToDataUrl;
    header.flags = reb::kArtifactFlagSensitive;
    header.creator_event_id = 3;
  } else {
    header.kind = reb::ArtifactKind::kJavaScript;
  }
  header.content_size = declared_size != 0 ? declared_size : content.size();
  header.url_size = static_cast<std::uint32_t>(url.size());
  header.mime_type_size = static_cast<std::uint32_t>(mime.size());
  std::string frame(reinterpret_cast<const char*>(&header), sizeof(header));
  return frame + url + mime + content;
}

reb::ArtifactReceiverLimits Limits() {
  reb::ArtifactReceiverLimits limits;
  limits.max_artifact_bytes = 1024;
  limits.max_store_bytes = 1024 * 1024;
  limits.expected_session_id = 7;
  return limits;
}

// Serves exactly one frame. A socket blocks on a read past the frame while the
// sender waits for the acknowledgment, so any such read is recorded.
class FrameBuffer final : public std::streambuf {
 public:
  explicit FrameBuffer(std::string frame) : frame_(std::move(frame)) {
    setg(frame_.data(), frame_.data(), frame_.data() + frame_.size());
  }
  [[nodiscard]] bool ReadPastFrame() const noexcept { return read_past_frame_; }

 protected:
  int_type underflow() override {
    read_past_frame_ = true;
    return traits_type::eof();
  }

 private:
  std::string frame_;
  bool read_past_frame_ = false;
};

reb::ArtifactReceiveStatus Receive(reb::ArtifactReceiver& receiver, const std::string& frame) {
  std::istringstream stream(frame);
  return receiver.ReceiveOne(stream);
}

std::uintmax_t BlobBytes(const std::filesystem::path& store) {
  std::uintmax_t total = 0;
  for (const auto& entry : std::filesystem::directory_iterator(store / "blobs")) {
    total += entry.file_size();
  }
  return total;
}

std::size_t Lines(const std::filesystem::path& manifest) {
  std::ifstream input(manifest);
  std::size_t count = 0;
  for (std::string line; std::getline(input, line);) {
    ++count;
  }
  return count;
}

bool ContainsText(const std::string& text, const std::string_view needle) {
  return text.find(needle) != std::string::npos;
}

void CheckFraming() {
  const std::filesystem::path store =
      std::filesystem::temp_directory_path() / ("reb-artifact-framing-" + std::to_string(getpid()));
  std::filesystem::remove_all(store);
  {
    reb::ArtifactReceiver receiver(store, Limits());
    std::istringstream stream(Frame(1, std::string(512, 'c'), true) + Frame(2, "two();") +
                              Frame(3, std::string(2048, 'x')) + Frame(2, "again();") +
                              Frame(4, "four();") + std::string(128, '\0'));
    using Status = reb::ArtifactReceiveStatus;
    for (const Status expected : {Status::kSensitiveCaptureDisabled, Status::kAccepted,
                                  Status::kTooLarge, Status::kConflict, Status::kAccepted}) {
      Expect(receiver.ReceiveOne(stream) == expected, "valid frame status in a shared stream");
      Expect(receiver.StreamPosition() == reb::ArtifactStreamPosition::kFrameBoundary,
             "a valid rejected frame is consumed to its end");
    }
    Expect(receiver.ReceiveOne(stream) == Status::kInvalid &&
               receiver.StreamPosition() == reb::ArtifactStreamPosition::kUnsynchronized,
           "an invalid header leaves the stream unsynchronized");
    Expect(Receive(receiver, Frame(5, "", false, 32ULL * 1024 * 1024)) == Status::kTooLarge &&
               receiver.StreamPosition() == reb::ArtifactStreamPosition::kUnsynchronized,
           "a declared size past the discard bound is not read");
    Expect(Lines(store / "manifest.jsonl") == 2, "only accepted frames are recorded");
    FrameBuffer rejected(Frame(6, std::string(4096, 'y')));
    std::istream rejected_stream(&rejected);
    Expect(receiver.ReceiveOne(rejected_stream) == Status::kTooLarge &&
               receiver.StreamPosition() == reb::ArtifactStreamPosition::kFrameBoundary &&
               !rejected.ReadPastFrame(),
           "a discarded frame is consumed without reading past its end");
  }
  std::filesystem::remove_all(store);
}

void CheckManifestRollback() {
  const std::filesystem::path store = std::filesystem::temp_directory_path() /
                                      ("reb-artifact-rollback-" + std::to_string(getpid()));
  const std::filesystem::path manifest = store / "manifest.jsonl";
  std::filesystem::remove_all(store);
  using Status = reb::ArtifactReceiveStatus;
  {
    reb::ArtifactReceiver receiver(store, Limits());
    Expect(Receive(receiver, Frame(1, "one();")) == Status::kAccepted, "first accepted");
    const auto manifest_size = std::filesystem::file_size(manifest);
    struct stat metadata {};
    Expect(stat(manifest.c_str(), &metadata) == 0, "manifest inode");
    g_failing_inode = metadata.st_ino;

    // The record reached the file but was not durable: it is cut back and the
    // blob created for it is removed, so nothing unacknowledged remains.
    g_failures_left = 1;
    Expect(Receive(receiver, Frame(2, "two();")) == Status::kIoError &&
               ContainsText(receiver.LastError(), "rolled back"),
           "a failed manifest fsync is rolled back");
    Expect(receiver.StreamPosition() == reb::ArtifactStreamPosition::kFrameBoundary,
           "a commit failure still consumed the frame");
    Expect(std::filesystem::file_size(manifest) == manifest_size, "no record bytes remain");
    Expect(receiver.StoredBytes() == BlobBytes(store) && BlobBytes(store) == 6,
           "the new blob is retired and uncounted");
    Expect(Receive(receiver, Frame(2, "two();")) == Status::kAccepted,
           "a rolled-back identifier stays available");
    Expect(Lines(manifest) == 2 && receiver.StoredBytes() == BlobBytes(store),
           "bookkeeping matches the store after recovery");

    // The rollback itself cannot be made durable: the store refuses further
    // frames rather than appending after an unknown file.
    g_failures_left = 1000;
    Expect(Receive(receiver, Frame(3, "three();")) == Status::kIoError &&
               ContainsText(receiver.LastError(), "refusing further artifacts"),
           "an unrecoverable manifest failure is reported");
    g_failures_left = 0;
    Expect(receiver.StoredBytes() == BlobBytes(store),
           "a blob that may be referenced stays and stays counted");
    Expect(Receive(receiver, Frame(4, "four();")) == Status::kIoError &&
               receiver.StreamPosition() == reb::ArtifactStreamPosition::kFrameBoundary,
           "a failed store answers every later frame without reading it as evidence");
  }
  g_failing_inode = 0;
  {
    reb::ArtifactReceiver reopened(store, Limits());
    Expect(reopened.StoredBytes() == BlobBytes(store) && reopened.RecoveredManifestBytes() == 0,
           "a restart counts what is on disk");
    Expect(Receive(reopened, Frame(3, "three();")) == Status::kAccepted && Lines(manifest) == 3,
           "capture resumes after a restart");
  }
  std::filesystem::remove_all(store);
}

}  // namespace

extern "C" int fsync(const int descriptor) {
  struct stat metadata {};
  if (g_failures_left > 0 && g_failing_inode != 0 && fstat(descriptor, &metadata) == 0 &&
      metadata.st_ino == g_failing_inode) {
    --g_failures_left;
    errno = EIO;
    return -1;
  }
  return 0;
}

int main() {
  CheckFraming();
  CheckManifestRollback();
  if (failures != 0) {
    return 1;
  }
  reb::ArtifactHeader header;
  header.kind = reb::ArtifactKind::kBytecodeBuffer;
  header.session_id = 1;
  header.artifact_id = 2;
  header.content_size = 32;
  header.url_size = 24;
  header.mime_type_size = 24;
  header.execution_context_id = 3;
  header.capture_origin = reb::ArtifactCaptureOrigin::kRuntimeTypedArray;
  if (!reb::IsValidArtifactHeader(header) ||
      std::string_view(reb::ArtifactKindName(header.kind)) != "bytecode_buffer" ||
      std::string_view(reb::ArtifactCaptureOriginName(header.capture_origin)) !=
          "runtime_typed_array") {
    std::cerr << "runtime typed-array artifact contract failed\n";
    return 1;
  }
  header.kind = reb::ArtifactKind::kJavaScript;
  if (reb::IsValidArtifactHeader(header)) {
    std::cerr << "mismatched runtime typed-array origin accepted\n";
    return 1;
  }
  header.capture_origin = reb::ArtifactCaptureOrigin::kRuntimeAllocatingScript;
  if (!reb::IsValidArtifactHeader(header) ||
      std::string_view(reb::ArtifactCaptureOriginName(header.capture_origin)) !=
          "runtime_allocating_script") {
    std::cerr << "allocating-script origin rejected\n";
    return 1;
  }
  header.execution_context_id = 0;
  if (reb::IsValidArtifactHeader(header)) {
    std::cerr << "allocating-script origin accepted without execution context\n";
    return 1;
  }
  header.execution_context_id = 3;
  header.capture_origin = reb::ArtifactCaptureOrigin::kNativeWasmGuest;
  header.frame_id = 4;
  header.parent_artifact_id = 5;
  header.creator_event_id = 6;
  for (const auto kind :
       {reb::ArtifactKind::kBytecodeBuffer, reb::ArtifactKind::kWasmGuestAdapter}) {
    header.kind = kind;
    if (!reb::IsValidArtifactHeader(header))
      return 1;
  }
  if (std::string_view(reb::ArtifactKindName(header.kind)) != "wasm_guest_adapter" ||
      std::string_view(reb::ArtifactCaptureOriginName(header.capture_origin)) !=
          "native_wasm_guest")
    return 1;
  header.execution_context_id = 0;
  if (reb::IsValidArtifactHeader(header))
    return 1;
  header.execution_context_id = 3;
  for (const auto kind :
       {reb::ArtifactKind::kJavaScript, reb::ArtifactKind::kWasm, reb::ArtifactKind::kSourceMap}) {
    header.kind = kind;
    if (reb::IsValidArtifactHeader(header))
      return 1;
  }
  return 0;
}
