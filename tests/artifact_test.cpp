#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
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

std::string Open(const std::uint64_t artifact_id, const bool request_body = false) {
  std::string frame = Frame(artifact_id, "");
  reb::ArtifactHeader header;
  std::memcpy(&header, frame.data(), sizeof(header));
  header.protocol_version = reb::kArtifactStreamProtocolVersion;
  header.content_size = 0;
  if (request_body) {
    header.kind = reb::ArtifactKind::kRequestBody;
    header.capture_origin = reb::ArtifactCaptureOrigin::kNetworkRequest;
    header.flags = reb::kArtifactFlagSensitive;
  }
  std::memcpy(frame.data(), &header, sizeof(header));
  return frame;
}

std::string Chunk(const reb::ArtifactStreamOp op,
                  const std::uint64_t artifact_id,
                  const std::string& data = "",
                  const std::uint64_t value = 0,
                  const std::uint64_t content_size = 0,
                  const std::uint8_t digest_byte = 0) {
  reb::ArtifactStreamFrame frame;
  frame.op = op;
  frame.data_size = static_cast<std::uint32_t>(data.size());
  frame.session_id = 7;
  frame.artifact_id = artifact_id;
  frame.value = value;
  frame.content_size = content_size;
  frame.expected_sha256.fill(digest_byte);
  return std::string(reinterpret_cast<const char*>(&frame), sizeof(frame)) + data;
}

std::string ManifestLine(const std::filesystem::path& manifest, const std::uint64_t artifact_id) {
  std::ifstream input(manifest);
  const std::string needle = "\"artifact_id\":\"" + std::to_string(artifact_id) + "\"";
  for (std::string line; std::getline(input, line);) {
    if (ContainsText(line, needle)) {
      return line;
    }
  }
  return {};
}

std::string Field(const std::string& line, const std::string& name) {
  const std::string key = "\"" + name + "\":";
  const auto at = line.find(key);
  if (at == std::string::npos) {
    return {};
  }
  const auto begin = at + key.size() + (line[at + key.size()] == '"' ? 1 : 0);
  return line.substr(begin, line.find_first_of("\",}", begin) - begin);
}

void CheckStreams() {
  const std::filesystem::path store =
      std::filesystem::temp_directory_path() / ("reb-artifact-streams-" + std::to_string(getpid()));
  const std::filesystem::path manifest = store / "manifest.jsonl";
  std::filesystem::remove_all(store);
  using Op = reb::ArtifactStreamOp;
  using Status = reb::ArtifactReceiveStatus;
  const auto part = [&](const std::uint64_t id) {
    return std::filesystem::exists(store / ("artifact-" + std::to_string(id) + ".part"));
  };
  {
    auto limits = Limits();
    limits.allow_sensitive = true;
    reb::ArtifactReceiver receiver(store, limits);
    // Two interleaved streams, a checkpoint of the first and both ends.
    std::istringstream stream(Open(10) + Open(11) + Chunk(Op::kData, 10, "ab") +
                              Chunk(Op::kData, 11, "xy") + Chunk(Op::kData, 10, "c") +
                              Chunk(Op::kCheckpoint, 10, "", 12, 3) + Chunk(Op::kData, 10, "de") +
                              Chunk(Op::kEnd, 11, "", 0, 2) + Chunk(Op::kEnd, 10, "", 0, 5));
    for (std::size_t frame = 0; frame < 9; ++frame) {
      Expect(receiver.ReceiveOne(stream) == Status::kAccepted &&
                 receiver.StreamPosition() == reb::ArtifactStreamPosition::kFrameBoundary &&
                 receiver.ProtocolVersion() == reb::kArtifactStreamProtocolVersion,
             "interleaved stream frame accepted at a boundary: " + receiver.LastError());
      Expect(frame != 5 || receiver.LastArtifactId() == 12, "a checkpoint names its snapshot");
    }
    Expect(Field(ManifestLine(manifest, 10), "byte_size") == "5" &&
               Field(ManifestLine(manifest, 11), "byte_size") == "2" &&
               Field(ManifestLine(manifest, 12), "byte_size") == "3" && receiver.OpenStreams() == 0,
           "each stream and the snapshot publish their own byte count");
    Expect(Receive(receiver, Frame(13, "abcde")) == Status::kAccepted &&
               receiver.ProtocolVersion() == reb::kArtifactProtocolVersion &&
               Field(ManifestLine(manifest, 13), "sha256") ==
                   Field(ManifestLine(manifest, 10), "sha256"),
           "a streamed body digests exactly like the same whole frame");
    Expect(Receive(receiver, Frame(14, "abc")) == Status::kAccepted &&
               Field(ManifestLine(manifest, 14), "sha256") ==
                   Field(ManifestLine(manifest, 12), "sha256"),
           "a checkpoint digests the bytes it published");

    // A request body's creator record follows in its end frame.
    std::istringstream deferred(Open(20, true) + Chunk(Op::kData, 20, "{}") +
                                Chunk(Op::kEnd, 20, "", 0, 2) + Open(21, true) +
                                Chunk(Op::kData, 21, "{}") + Chunk(Op::kEnd, 21, "", 99, 2));
    Expect(receiver.ReceiveOne(deferred) == Status::kAccepted &&
               receiver.ReceiveOne(deferred) == Status::kAccepted &&
               receiver.ReceiveOne(deferred) == Status::kInvalid && !part(20),
           "an end without the deferred creator is refused");
    Expect(receiver.ReceiveOne(deferred) == Status::kAccepted &&
               receiver.ReceiveOne(deferred) == Status::kAccepted &&
               receiver.ReceiveOne(deferred) == Status::kAccepted &&
               Field(ManifestLine(manifest, 21), "creator_event_id") == "99",
           "the end frame names the request body's creator record");

    // Refusals keep the connection at a frame boundary.
    std::istringstream refusals(
        Open(30) + Chunk(Op::kData, 30, std::string(1000, 'a')) +
        Chunk(Op::kData, 30, std::string(100, 'b')) + Chunk(Op::kData, 30, "c") + Open(31) +
        Chunk(Op::kData, 31, "d") + Chunk(Op::kEnd, 31, "", 0, 1, 0xab) + Open(32) +
        Chunk(Op::kData, 32, "e") + Chunk(Op::kAbort, 32) + Chunk(Op::kData, 32, "f") +
        Chunk(Op::kEnd, 33, "", 0, 0) + Open(10));
    for (const Status expected :
         {Status::kAccepted, Status::kAccepted, Status::kTooLarge, Status::kInvalid,
          Status::kAccepted, Status::kAccepted, Status::kInvalid, Status::kAccepted,
          Status::kAccepted, Status::kAccepted, Status::kInvalid, Status::kInvalid,
          Status::kConflict}) {
      Expect(receiver.ReceiveOne(refusals) == expected &&
                 receiver.StreamPosition() == reb::ArtifactStreamPosition::kFrameBoundary,
             "stream refusal keeps the boundary: " + receiver.LastError());
    }
    Expect(!part(30) && !part(31) && !part(32) && ManifestLine(manifest, 30).empty() &&
               ManifestLine(manifest, 31).empty() && ManifestLine(manifest, 32).empty(),
           "refused, mismatched and aborted streams publish nothing and leave no file");

    // A stream counts against the store before it publishes; a closed
    // connection abandons it.
    std::istringstream abandoned(Open(40) + Chunk(Op::kData, 40, std::string(512, 'z')));
    Expect(receiver.ReceiveOne(abandoned) == Status::kAccepted &&
               receiver.ReceiveOne(abandoned) == Status::kAccepted && part(40),
           "an open stream holds its file");
    receiver.AbandonStreams();
    Expect(!part(40) && receiver.OpenStreams() == 0 && receiver.Stats().streams_abandoned == 1,
           "abandoned streams are removed and counted");

    Expect(
        Receive(receiver, Chunk(Op::kData, 41, std::string(70 * 1024, 'q'))) == Status::kInvalid &&
            receiver.StreamPosition() == reb::ArtifactStreamPosition::kUnsynchronized,
        "a chunk past 64 KiB is not read");
    std::string sized = Open(42);
    reinterpret_cast<reb::ArtifactHeader*>(sized.data())->content_size = 1;
    Expect(Receive(receiver, sized) == Status::kInvalid, "an open header declares no size");
  }
  {
    // A killed receiver leaves its partial files. Nothing else in the store is
    // removed, including a name that only resembles one.
    const std::filesystem::path killed = store / "killed";
    { const reb::ArtifactReceiver first(killed, Limits()); }
    std::ofstream(killed / "artifact-40.part") << "partial body";
    std::ofstream(killed / "artifact-41.part") << "";
    std::ofstream(killed / "artifact-x.part") << "keep";
    std::ofstream(killed / "note.part") << "keep";
    const reb::ArtifactReceiver restarted(killed, Limits());
    Expect(restarted.RemovedStreamFiles() == 2 &&
               !std::filesystem::exists(killed / "artifact-40.part") &&
               !std::filesystem::exists(killed / "artifact-41.part") &&
               std::filesystem::exists(killed / "artifact-x.part") &&
               std::filesystem::exists(killed / "note.part"),
           "startup removes only partial stream files and counts them");
  }
  {
    auto limits = Limits();
    limits.max_artifacts = 2;
    reb::ArtifactReceiver bounded(store / "bounded", limits);
    std::istringstream stream(Open(1) + Open(2) + Open(3));
    Expect(bounded.ReceiveOne(stream) == Status::kAccepted &&
               bounded.ReceiveOne(stream) == Status::kAccepted &&
               bounded.ReceiveOne(stream) == Status::kTooLarge,
           "open streams count against the artifact limit");
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
  CheckStreams();
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
