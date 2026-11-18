// Drives the production browser socket clients over real AF_UNIX sockets:
// the artifact writer against the production receiver executable and against
// a scripted older receiver, and the broker writer against a scripted broker.
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_socket_client.h"
#include "brave/components/reverse_engineering_browser/common/native_js_invocation.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_ipc.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_queue.h"

extern char** environ;

namespace {

using reb::NativeArtifactChannelState;
using reb::NativeArtifactReceiveStatus;
using Clock = std::chrono::steady_clock;

constexpr std::uint64_t kSessionId = 7;
constexpr auto kWait = std::chrono::seconds(15);

void Require(const bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL native artifact transport: " << message << '\n';
    std::exit(1);
  }
}

bool RunBrowserUntil(const std::function<bool()>& done) {
  return base::SequencedTaskRunner::GetCurrentDefault()->RunUntil(
      done, std::chrono::duration_cast<std::chrono::milliseconds>(kWait));
}

std::vector<reb::TestCompletion>& Completions() {
  return reb::NativeArtifactCaptureSink::completions;
}

NativeArtifactReceiveStatus StatusOf(const std::uint64_t artifact_id) {
  Require(RunBrowserUntil([artifact_id] {
            for (const auto& completion : Completions()) {
              if (completion.artifact_id == artifact_id) {
                return true;
              }
            }
            return false;
          }),
          "no completion for artifact " + std::to_string(artifact_id));
  NativeArtifactReceiveStatus status = NativeArtifactReceiveStatus::kAccepted;
  for (auto entry = Completions().begin(); entry != Completions().end(); ++entry) {
    if (entry->artifact_id == artifact_id) {
      status = entry->status;
      Completions().erase(entry);
      break;
    }
  }
  return status;
}

int g_channel_lost = 0;
void ChannelLost() noexcept {
  ++g_channel_lost;
}

// Every transfer holds a share of this pool, as capture transfers do; the
// writer must return it once the frame is written or reported.
reb::NativeArtifactMemoryPool g_pool{4U * 1024U * 1024U};

std::unique_ptr<reb::NativeArtifactTransfer> MakeTransfer(const std::uint64_t artifact_id,
                                                          const std::size_t size,
                                                          const bool canvas = false) {
  auto transfer = std::make_unique<reb::NativeArtifactTransfer>();
  transfer->reservation = reb::NativeArtifactReservation::Acquire(g_pool, size);
  Require(transfer->reservation.is_valid(), "transfer pool share");
  transfer->header.session_id = kSessionId;
  transfer->header.artifact_id = artifact_id;
  if (canvas) {
    transfer->header.kind = reb::NativeArtifactKind::kCanvasDataUrl;
    transfer->header.capture_origin = reb::NativeArtifactCaptureOrigin::kCanvasToDataUrl;
    transfer->header.flags = reb::kNativeArtifactFlagSensitive;
    transfer->header.creator_event_id = 3;
    transfer->mime_type = "text/plain";
  } else {
    transfer->header.kind = reb::NativeArtifactKind::kJavaScript;
    transfer->mime_type = "text/javascript";
  }
  transfer->url = "https://fixture.test/" + std::to_string(artifact_id) + ".js";
  transfer->content.assign(size, static_cast<std::uint8_t>('a' + artifact_id % 26));
  transfer->header.content_size = transfer->content.size();
  transfer->header.url_size = static_cast<std::uint32_t>(transfer->url.size());
  transfer->header.mime_type_size = static_cast<std::uint32_t>(transfer->mime_type.size());
  return transfer;
}

std::unique_ptr<reb::NativeArtifactTransfer> OpenStream(const std::uint64_t artifact_id) {
  auto transfer = MakeTransfer(artifact_id, 0);
  transfer->op = reb::NativeArtifactTransferOp::kOpen;
  transfer->header.protocol_version = reb::kNativeArtifactStreamProtocolVersion;
  transfer->header.content_size = 0;
  return transfer;
}

std::unique_ptr<reb::NativeArtifactTransfer> StreamFrame(const reb::NativeArtifactStreamOp op,
                                                         const std::uint64_t artifact_id,
                                                         const std::size_t size = 0,
                                                         const std::uint64_t content_size = 0) {
  auto transfer = std::make_unique<reb::NativeArtifactTransfer>();
  transfer->op = reb::NativeArtifactTransferOp::kStream;
  transfer->frame.op = op;
  transfer->frame.session_id = kSessionId;
  transfer->frame.artifact_id = artifact_id;
  transfer->frame.content_size = content_size;
  if (size != 0) {
    transfer->reservation = reb::NativeArtifactReservation::Acquire(g_pool, size);
    Require(transfer->reservation.is_valid(), "stream frame pool share");
    transfer->content.assign(size, 's');
    transfer->frame.data_size = static_cast<std::uint32_t>(size);
  }
  return transfer;
}

bool Reported(const std::uint64_t artifact_id) {
  return std::ranges::any_of(Completions(), [artifact_id](const reb::TestCompletion& completion) {
    return completion.artifact_id == artifact_id;
  });
}

void WriteToken(const std::string& path) {
  const int descriptor = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  Require(descriptor >= 0, "token file");
  const std::string encoded(64, 'a');
  Require(write(descriptor, encoded.data(), encoded.size()) == static_cast<ssize_t>(encoded.size()),
          "token write");
  Require(close(descriptor) == 0, "token close");
}

bool IsSocket(const std::string& path) {
  struct stat metadata {};
  return stat(path.c_str(), &metadata) == 0 && S_ISSOCK(metadata.st_mode);
}

bool WaitFor(const std::function<bool()>& done) {
  const auto deadline = Clock::now() + kWait;
  while (!done()) {
    if (Clock::now() >= deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return true;
}

std::string ReadFile(const std::string& path) {
  std::ifstream input(path);
  std::stringstream text;
  text << input.rdbuf();
  return text.str();
}

std::size_t CountOf(const std::string& text, const std::string& needle) {
  std::size_t count = 0;
  for (std::size_t at = text.find(needle); at != std::string::npos;
       at = text.find(needle, at + needle.size())) {
    ++count;
  }
  return count;
}

pid_t SpawnReceiver(const std::string& binary,
                    const std::string& root,
                    const std::string& socket_path,
                    const std::string& log_path) {
  const std::string store = root + "/artifacts";
  const std::string token = root + "/token";
  std::vector<std::string> arguments = {binary,
                                        "--store",
                                        store,
                                        "--socket",
                                        socket_path,
                                        "--token-file",
                                        token,
                                        "--session-id",
                                        std::to_string(kSessionId),
                                        "--max-artifact-bytes",
                                        "65536",
                                        "--max-store-bytes",
                                        "1048576"};
  std::vector<char*> argv;
  for (std::string& argument : arguments) {
    argv.push_back(argument.data());
  }
  argv.push_back(nullptr);
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, log_path.c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC, 0600);
  posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
  pid_t pid = -1;
  Require(posix_spawn(&pid, binary.c_str(), &actions, nullptr, argv.data(), environ) == 0,
          "spawn receiver");
  posix_spawn_file_actions_destroy(&actions);
  Require(WaitFor([&] { return IsSocket(socket_path); }), "receiver socket did not appear");
  return pid;
}

void StopReceiver(const pid_t pid) {
  Require(kill(pid, SIGTERM) == 0, "signal receiver");
  int status = 0;
  Require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "receiver exit status");
}

int Listen(const std::string& path) {
  const int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  Require(listener >= 0, "listener socket");
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  Require(path.size() < sizeof(address.sun_path), "socket path length");
  std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
  Require(bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0,
          "bind");
  Require(listen(listener, 4) == 0, "listen");
  return listener;
}

bool ReadExact(const int descriptor, void* data, std::size_t size) {
  auto* bytes = static_cast<std::uint8_t*>(data);
  while (size > 0) {
    const ssize_t count = read(descriptor, bytes, size);
    if (count <= 0) {
      return false;
    }
    bytes += count;
    size -= static_cast<std::size_t>(count);
  }
  return true;
}

void Discard(const int descriptor, std::size_t size) {
  std::vector<std::uint8_t> buffer(64 * 1024);
  while (size > 0) {
    const std::size_t part = std::min(size, buffer.size());
    Require(ReadExact(descriptor, buffer.data(), part), "scripted receiver read");
    size -= part;
  }
}

int AcceptHello(const int listener) {
  const int connection = accept(listener, nullptr, nullptr);
  Require(connection >= 0, "accept");
  reb::NativeProbeLocalIpcHello hello;
  Require(ReadExact(connection, &hello, sizeof(hello)) && hello.session_id != 0, "hello");
  return connection;
}

reb::NativeArtifactHeader ReadHeader(const int connection) {
  reb::NativeArtifactHeader header;
  Require(ReadExact(connection, &header, sizeof(header)), "scripted receiver header");
  return header;
}

void DiscardBody(const int connection, const reb::NativeArtifactHeader& header) {
  Discard(connection, header.url_size + header.mime_type_size + header.content_size);
}

void Ack(const int connection,
         const reb::NativeArtifactHeader& header,
         const NativeArtifactReceiveStatus status) {
  reb::NativeArtifactAck ack;
  ack.status = status;
  ack.artifact_id = header.artifact_id;
  Require(write(connection, &ack, sizeof(ack)) == static_cast<ssize_t>(sizeof(ack)), "ack");
}

void ConfigureArtifactSwitches(const std::string& socket_path, const std::string& token) {
  auto& switches = base::CommandLine::ForCurrentProcess()->switches;
  switches["reb-artifact-socket"] = socket_path;
  switches["reb-broker-token-file"] = token;
}

void StopArtifactClient() {
  reb::NativeArtifactSocketClient::Get().Stop();
  Require(RunBrowserUntil([] {
            return reb::NativeArtifactSocketClient::Get().state() ==
                   NativeArtifactChannelState::kIdle;
          }),
          "artifact client did not stop");
}

bool Enqueue(std::unique_ptr<reb::NativeArtifactTransfer> transfer) {
  return reb::NativeArtifactSocketClient::Get().Enqueue(std::move(transfer));
}

// Production receiver: rejections keep the connection and carry their real
// status even when the body exceeds the socket buffers; losing the receiver
// reports queued work, announces the loss once and then refuses transfers.
void CheckProductionReceiver(const std::string& receiver, const std::string& root) {
  const std::string socket_path = root + "/artifact.sock";
  const std::string log_path = root + "/receiver.log";
  const pid_t pid = SpawnReceiver(receiver, root, socket_path, log_path);
  ConfigureArtifactSwitches(socket_path, root + "/token");
  auto& client = reb::NativeArtifactSocketClient::Get();
  Require(client.StartFromCommandLine(
              kSessionId, &reb::NativeArtifactCaptureSink::TransferCompleted, &ChannelLost),
          "start against the production receiver");

  Require(Enqueue(MakeTransfer(1, 12)), "enqueue accepted artifact");
  Require(StatusOf(1) == NativeArtifactReceiveStatus::kAccepted, "first artifact accepted");
  // 32 KiB of sensitive Canvas content without --allow-sensitive.
  Require(Enqueue(MakeTransfer(2, 32 * 1024, true)), "enqueue sensitive artifact");
  Require(StatusOf(2) == NativeArtifactReceiveStatus::kSensitiveCaptureDisabled,
          "sensitive rejection keeps its status");
  // 256 KiB against a 64 KiB receiver limit: the body is larger than any
  // socket buffer, so this fails as an I/O error unless the receiver reads it.
  Require(Enqueue(MakeTransfer(3, 256 * 1024)), "enqueue oversize artifact");
  Require(StatusOf(3) == NativeArtifactReceiveStatus::kTooLarge, "oversize keeps its status");
  Require(Enqueue(MakeTransfer(1, 12)), "enqueue duplicate artifact");
  Require(StatusOf(1) == NativeArtifactReceiveStatus::kConflict, "duplicate keeps its status");
  Require(Enqueue(MakeTransfer(4, 20)), "enqueue after rejections");
  Require(StatusOf(4) == NativeArtifactReceiveStatus::kAccepted,
          "artifact after three rejections is accepted");
  Require(client.state() == NativeArtifactChannelState::kConnected && g_channel_lost == 0,
          "rejections never take the channel down");
  Require(CountOf(ReadFile(log_path), "accepted authenticated connection") == 1,
          "every rejection was answered on the same connection");
  const std::string manifest = ReadFile(root + "/artifacts/manifest.jsonl");
  Require(CountOf(manifest, "\n") == 2 && CountOf(manifest, "\"artifact_id\":\"1\"") == 1 &&
              CountOf(manifest, "\"artifact_id\":\"4\"") == 1,
          "only the accepted artifacts are in the manifest");
  Require(WaitFor([] { return g_pool.used() == 0; }),
          "written and rejected transfers return their pool share");
  std::cout << "PASS artifact writer: sensitive, oversize and duplicate rejections answered on one "
               "connection with their real status; the next artifact is accepted\n";

  // Streams interleave on the same connection. A refusal mid-stream is
  // reported once and the stream's later frames are dropped; an abort is
  // silent; a stream still open when the receiver goes is reported lost.
  using Op = reb::NativeArtifactStreamOp;
  Require(
      Enqueue(OpenStream(20)) && Enqueue(OpenStream(21)) && Enqueue(OpenStream(22)) &&
          Enqueue(StreamFrame(Op::kData, 20, 1000)) && Enqueue(StreamFrame(Op::kData, 21, 60000)) &&
          Enqueue(StreamFrame(Op::kData, 22, 10)) && Enqueue(StreamFrame(Op::kData, 20, 2000)) &&
          Enqueue(StreamFrame(Op::kData, 21, 10000)) && Enqueue(StreamFrame(Op::kData, 21, 5)) &&
          Enqueue(StreamFrame(Op::kAbort, 22)) && Enqueue(StreamFrame(Op::kEnd, 21, 0, 60005)) &&
          Enqueue(StreamFrame(Op::kEnd, 20, 0, 3000)),
      "enqueue interleaved streams");
  Require(StatusOf(21) == NativeArtifactReceiveStatus::kTooLarge,
          "a stream refused mid-body reports the receiver's status");
  Require(StatusOf(20) == NativeArtifactReceiveStatus::kAccepted, "an ended stream is accepted");
  Require(Enqueue(OpenStream(23)) && Enqueue(StreamFrame(Op::kData, 23, 7)) &&
              Enqueue(MakeTransfer(24, 4)) &&
              StatusOf(24) == NativeArtifactReceiveStatus::kAccepted,
          "a whole artifact follows the open stream");
  Require(!Reported(21) && !Reported(22) && !Reported(23),
          "a refused stream is reported once, an abort and an open stream not at all");
  const std::string streamed = ReadFile(root + "/artifacts/manifest.jsonl");
  Require(CountOf(streamed, "\"artifact_id\":\"20\"") == 1 &&
              CountOf(streamed, "\"byte_size\":3000") == 1 &&
              CountOf(streamed, "\"artifact_id\":\"21\"") == 0 &&
              CountOf(streamed, "\"artifact_id\":\"22\"") == 0,
          "only the ended stream is in the manifest");
  Require(WaitFor([] { return g_pool.used() == 0; }), "stream frames return their pool share");
  std::cout << "PASS artifact writer: interleaved streams, a refusal reported once with later "
               "frames dropped, a silent abort\n";

  StopReceiver(pid);
  const std::string stats = ReadFile(log_path);
  Require(CountOf(stats, "accepted=4 ") == 1 && CountOf(stats, "too_large=2 ") == 1 &&
              CountOf(stats, "streams_abandoned=1 ") == 1 &&
              CountOf(stats, "sensitive_rejected=1 ") == 1 && CountOf(stats, "conflicts=1 ") == 1,
          "receiver counted every rejection");
  const auto lost_started = Clock::now();
  Require(Enqueue(MakeTransfer(5, 8)), "enqueue to a vanished receiver");
  Require(Enqueue(MakeTransfer(6, 8)), "enqueue while the writer reconnects");
  Require(StatusOf(23) == NativeArtifactReceiveStatus::kIoError,
          "a stream open on the lost connection is reported");
  Require(StatusOf(5) == NativeArtifactReceiveStatus::kIoError &&
              StatusOf(6) == NativeArtifactReceiveStatus::kIoError,
          "transfers to a vanished receiver are reported");
  Require(RunBrowserUntil([] { return g_channel_lost == 1; }), "channel loss announced");
  Require(client.state() == NativeArtifactChannelState::kLost && !client.IsConnected(),
          "lost channel refuses admission");
  Require(!Enqueue(MakeTransfer(7, 8)), "lost channel refuses transfers");
  Require(WaitFor([] { return g_pool.used() == 0; }),
          "reported and refused transfers return their pool share");
  Require(Clock::now() - lost_started < std::chrono::seconds(10), "reconnect budget is bounded");
  StopArtifactClient();
  Require(g_channel_lost == 1 && Completions().empty(), "loss announced exactly once");
  std::cout << "PASS artifact writer: a vanished receiver reports queued transfers, retries within "
               "a bounded budget, announces the loss once and refuses later transfers\n";
}

// An older receiver acknowledges a rejection before reading the body and
// closes, or closes after any rejection. The writer still reports the real
// status and replaces the connection before the next frame.
void CheckOlderReceiver(const std::string& root) {
  const std::string socket_path = root + "/older.sock";
  const int listener = Listen(socket_path);
  std::atomic<bool> second_closed{false};
  std::thread receiver([&] {
    const int first = AcceptHello(listener);
    const auto early = ReadHeader(first);
    Ack(first, early, NativeArtifactReceiveStatus::kTooLarge);
    close(first);
    const int second = AcceptHello(listener);
    for (const auto status : {NativeArtifactReceiveStatus::kAccepted,
                              NativeArtifactReceiveStatus::kSensitiveCaptureDisabled}) {
      const auto header = ReadHeader(second);
      DiscardBody(second, header);
      Ack(second, header, status);
    }
    close(second);
    second_closed = true;
    const int third = AcceptHello(listener);
    const auto header = ReadHeader(third);
    DiscardBody(third, header);
    Ack(third, header, NativeArtifactReceiveStatus::kAccepted);
    char byte = 0;
    // Hold the connection until the writer stops, which ends it with EOF.
    Require(read(third, &byte, 1) <= 0, "the writer sends nothing after its last frame");
    close(third);
  });
  ConfigureArtifactSwitches(socket_path, root + "/token");
  auto& client = reb::NativeArtifactSocketClient::Get();
  Require(client.StartFromCommandLine(
              kSessionId, &reb::NativeArtifactCaptureSink::TransferCompleted, &ChannelLost),
          "start against the older receiver");
  Require(Enqueue(MakeTransfer(10, 512 * 1024)), "enqueue early-rejected artifact");
  Require(StatusOf(10) == NativeArtifactReceiveStatus::kTooLarge,
          "an acknowledgment buffered before the close is reported, not an I/O error");
  Require(Enqueue(MakeTransfer(11, 16)), "enqueue after reconnect");
  Require(StatusOf(11) == NativeArtifactReceiveStatus::kAccepted, "reconnected writer delivers");
  Require(Enqueue(MakeTransfer(12, 16)), "enqueue rejected artifact");
  Require(StatusOf(12) == NativeArtifactReceiveStatus::kSensitiveCaptureDisabled,
          "rejection status");
  Require(WaitFor([&] { return second_closed.load(); }), "scripted close");
  Require(Enqueue(MakeTransfer(13, 16)), "enqueue after the receiver closed");
  Require(StatusOf(13) == NativeArtifactReceiveStatus::kAccepted,
          "a closed idle connection is replaced before the next frame is written");
  Require(client.state() == NativeArtifactChannelState::kConnected && g_channel_lost == 1,
          "an older receiver never takes the channel down");
  StopArtifactClient();
  receiver.join();
  close(listener);
  unlink(socket_path.c_str());
  std::cout << "PASS artifact writer: an older receiver's early or closing rejection keeps its "
               "status and the writer reconnects before the next artifact\n";
}

// Stop() interrupts the reconnect wait promptly and reports queued work
// without announcing a loss.
void CheckStopWhileReconnecting(const std::string& root) {
  const std::string socket_path = root + "/vanishing.sock";
  const int listener = Listen(socket_path);
  ConfigureArtifactSwitches(socket_path, root + "/token");
  auto& client = reb::NativeArtifactSocketClient::Get();
  Require(client.StartFromCommandLine(
              kSessionId, &reb::NativeArtifactCaptureSink::TransferCompleted, &ChannelLost),
          "start against the vanishing receiver");
  close(AcceptHello(listener));
  close(listener);
  unlink(socket_path.c_str());
  Require(Enqueue(MakeTransfer(20, 8)), "enqueue to a closed connection");
  Require(WaitFor([&] { return client.state() == NativeArtifactChannelState::kReconnecting; }),
          "writer reconnects");
  Require(Enqueue(MakeTransfer(21, 8)) && client.IsConnected(),
          "a reconnecting channel still admits transfers");
  const auto stop_started = Clock::now();
  StopArtifactClient();
  Require(Clock::now() - stop_started < std::chrono::seconds(1), "stop interrupts the backoff");
  Require(StatusOf(20) == NativeArtifactReceiveStatus::kIoError &&
              StatusOf(21) == NativeArtifactReceiveStatus::kIoError,
          "stop reports in-flight and queued transfers");
  Require(g_channel_lost == 1, "a requested stop is not a lost channel");
  std::cout << "PASS artifact writer: stop during reconnect returns promptly and reports queued "
               "transfers without a loss record\n";
}

class ScriptedBroker {
 public:
  explicit ScriptedBroker(const std::string& path) : path_(path), listener_(Listen(path)) {}
  ~ScriptedBroker() {
    if (reader_.joinable()) {
      reader_.join();
    }
    close(listener_);
    unlink(path_.c_str());
  }
  int Accept() {
    connection_ = AcceptHello(listener_);
    return connection_;
  }
  void StartReading() {
    reader_ = std::thread([this] {
      reb::NativeProbeEvent event;
      while (ReadExact(connection_, &event, sizeof(event))) {
        {
          std::lock_guard lock(mutex_);
          events_.push_back(event);
        }
        while (paused_.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
      }
    });
  }
  // Stops reading after at most one more record, so the writer stalls again.
  void Pause() { paused_.store(true); }
  void Resume() { paused_.store(false); }
  std::vector<reb::NativeProbeEvent> Events(const std::size_t from = 0) {
    std::lock_guard lock(mutex_);
    return {events_.begin() + static_cast<std::ptrdiff_t>(std::min(from, events_.size())),
            events_.end()};
  }
  std::size_t Count() {
    std::lock_guard lock(mutex_);
    return events_.size();
  }
  void Disconnect() { shutdown(connection_, SHUT_RDWR); }
  void CloseAccepted() { close(connection_); }

 private:
  std::string path_;
  int listener_;
  int connection_ = -1;
  std::atomic<bool> paused_{false};
  std::mutex mutex_;
  std::vector<reb::NativeProbeEvent> events_;
  std::thread reader_;
};

void ConfigureBrokerSwitches(const std::string& root,
                             const std::string& broker,
                             const std::uint64_t category_mask) {
  auto& switches = base::CommandLine::ForCurrentProcess()->switches;
  switches["reb-broker-socket"] = broker;
  switches["reb-broker-token-file"] = root + "/token";
  switches["reb-session-id"] = std::to_string(kSessionId);
  switches["reb-category-mask"] = std::to_string(category_mask);
  switches["reb-duration-seconds"] = "3600";
  switches["user-data-dir"] = root;
}

// A refused session leaves no writer thread behind and closes the broker
// connection on the starting sequence.
void CheckRefusedSession(const std::string& root) {
  ScriptedBroker broker(root + "/refused-broker.sock");
  ConfigureBrokerSwitches(root, root + "/refused-broker.sock",
                          reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas));
  auto& session = reb::NativeProbeSession::Get();
  session.start_result = false;
  const int threads_before = base::Thread::started_count.load();
  Require(!reb::NativeProbeSocketClient::Get().StartFromCommandLine(), "refused session start");
  Require(session.start_calls == 1 && base::Thread::started_count.load() == threads_before,
          "the writer starts only after the session does");
  const int connection = broker.Accept();
  char byte = 0;
  Require(read(connection, &byte, 1) == 0, "refused start closes the broker connection");
  broker.CloseAccepted();
  session.start_result = true;
  std::cout << "PASS broker writer: a refused session never starts the writer and closes its "
               "connection\n";
}

// Replaced by rename, as the backend does, so a poll never reads half a file.
void ReplaceFile(const std::string& path, const std::string& text) {
  const std::string temporary = path + ".tmp";
  {
    std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
    file << text;
    Require(static_cast<bool>(file), "write " + temporary);
  }
  Require(std::rename(temporary.c_str(), path.c_str()) == 0, "rename " + path);
}

// The startup site file of a following capture and its generation, before
// the session starts.
void ConfigureLiveInvocationSites(const std::string& root) {
  const std::string sites = root + "/js-invocation-sites.json";
  const std::string generation = root + "/js-invocation-sites-generation";
  ReplaceFile(sites, R"({"sites":[],"version":2})");
  ReplaceFile(generation, "0\n");
  auto& switches = base::CommandLine::ForCurrentProcess()->switches;
  switches["reb-js-invocation-sites"] = sites;
  switches["reb-js-invocation-sites-generation"] = generation;
  reb::NativeProbeSession::Get().site_revisions.clear();
}

// A following capture's writer rereads the site file each time the backend
// advances the generation, never for the startup, an unchanged or an older
// generation, and hands a file it cannot read to the session as an empty
// revision, which the session refuses with its gap.
void CheckLiveInvocationSites(const std::string& root) {
  const std::string sites = root + "/js-invocation-sites.json";
  const std::string generation = root + "/js-invocation-sites-generation";
  auto& session = reb::NativeProbeSession::Get();
  const auto settle = [] {
    base::SequencedTaskRunner::GetCurrentDefault()->RunUntil([] { return false; },
                                                             std::chrono::milliseconds(800));
  };
  settle();
  Require(session.site_revisions.empty(), "the startup generation is not a revision");
  ReplaceFile(sites, "revision one");
  ReplaceFile(generation, "1\n");
  Require(RunBrowserUntil([&] { return session.site_revisions.size() == 1; }),
          "an advanced generation rereads the site file");
  Require(session.site_revisions[0] == "revision one", "the revision is the file as written");
  ReplaceFile(sites, "not applied");
  ReplaceFile(generation, "1\n");
  settle();
  ReplaceFile(generation, "0\n");
  settle();
  Require(session.site_revisions.size() == 1, "an unchanged or older generation rereads nothing");
  ReplaceFile(sites, std::string(reb::kNativeJsInvocationSitesFileLimit + 1, ' '));
  ReplaceFile(generation, "3\n");
  Require(RunBrowserUntil([&] { return session.site_revisions.size() == 2; }),
          "an over-limit site file is still a revision");
  Require(session.site_revisions[1].empty(), "a file the writer cannot read is an empty revision");
  ReplaceFile(sites, "revision four");
  ReplaceFile(generation, "4\n");
  Require(RunBrowserUntil([&] { return session.site_revisions.size() == 3; }) &&
              session.site_revisions[2] == "revision four",
          "the next generation reads again");
  auto& switches = base::CommandLine::ForCurrentProcess()->switches;
  switches.erase("reb-js-invocation-sites");
  switches.erase("reb-js-invocation-sites-generation");
  std::cout << "PASS broker writer: a following capture rereads the site file only for a newer "
               "generation and hands an unreadable one to the session as an empty revision\n";
}

reb::NativeProbeEvent RendererRecord(const std::uint32_t process, const std::uint64_t sequence) {
  reb::NativeProbeEvent event;
  event.header.category = reb::NativeProbeCategory::kCanvas;
  event.header.type = reb::NativeProbeType::kApiCall;
  event.header.session_id = kSessionId;
  event.header.process_id = process;
  event.header.sequence_number = sequence;
  return event;
}

// A burst far past the ring, queued by several threads at once as the
// browser's UI and IO threads do, waits in the spill while the broker reads
// nothing. It reaches the broker whole, each thread's records in the order
// that thread queued them, and the spill is freed once it has been sent.
void CheckSpilledBurst(ScriptedBroker& broker, const reb::NativeProbeEmitter emit) {
  constexpr std::uint32_t kProducers = 4;
  constexpr std::uint32_t kFirstProcess = 80;
  constexpr std::uint64_t kRecords = 25'000;
  std::vector<std::thread> producers;
  for (std::uint32_t producer = 0; producer < kProducers; ++producer) {
    producers.emplace_back([emit, producer] {
      for (std::uint64_t sequence = 1; sequence <= kRecords; ++sequence) {
        emit(RendererRecord(kFirstProcess + producer, sequence));
      }
    });
  }
  for (auto& producer : producers) {
    producer.join();
  }
  auto& client = reb::NativeProbeSocketClient::Get();
  const std::size_t spilled_chunks = client.SpillChunkCountForTesting();
  Require(spilled_chunks > 0, "a burst past the ring spills");
  broker.StartReading();
  Require(WaitFor([&] { return broker.Count() >= kProducers * kRecords; }),
          "every record of the burst reaches the broker");
  std::map<std::uint32_t, std::uint64_t> last;
  for (const auto& event : broker.Events()) {
    Require(event.header.type != reb::NativeProbeType::kGap, "a spilled burst loses nothing");
    std::uint64_t& previous = last[event.header.process_id];
    Require(event.header.sequence_number == previous + 1,
            "each thread's records arrive in the order it queued them");
    previous = event.header.sequence_number;
  }
  Require(last.size() == kProducers, "every thread's records arrive");
  for (const auto& [process, sequence] : last) {
    Require(process >= kFirstProcess && sequence == kRecords, "every thread's records arrive");
  }
  Require(WaitFor([&] { return client.SpillChunkCountForTesting() == 0; }),
          "the writer frees the spill once it is sent");
  std::cout << "PASS broker writer: " << kProducers * kRecords << " records from " << kProducers
            << " threads, " << spilled_chunks
            << " chunks spilled past the ring, reach a stalled broker whole and in each thread's "
               "order, and the spill is freed\n";
}

// Records the spill's bound refuses, and only those, are reported as browser
// records in the mixed stream, and the end of artifact delivery is a named
// gap in the same stream.
void CheckTransportGaps(const std::string& root) {
  const std::string broker_path = root + "/broker.sock";
  ScriptedBroker broker(broker_path);
  const std::string artifact_path = root + "/gap-artifact.sock";
  const int artifact_listener = Listen(artifact_path);
  ConfigureBrokerSwitches(root, broker_path,
                          reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas) |
                              reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kArtifact));
  ConfigureArtifactSwitches(artifact_path, root + "/token");
  ConfigureLiveInvocationSites(root);
  Require(reb::NativeProbeSocketClient::Get().StartFromCommandLine(), "session start");
  const int artifact_connection = AcceptHello(artifact_listener);
  broker.Accept();
  const reb::NativeProbeEmitter emit = reb::NativeProbeSession::Get().downstream();
  Require(emit != nullptr, "session emitter");
  CheckSpilledBurst(broker, emit);

  // With the bound lowered to two chunks and the broker stalled again, the
  // ring and the spill fill and the spill refuses the rest.
  auto& client = reb::NativeProbeSocketClient::Get();
  const std::size_t spill_limit = client.SetSpillChunkLimitForTesting(2);
  broker.Pause();
  const std::size_t first_event = broker.Count();
  constexpr std::uint64_t kRendererEvents = 20'000;
  for (std::uint64_t sequence = 1; sequence <= kRendererEvents; ++sequence) {
    emit(RendererRecord(77, sequence));
  }
  broker.Resume();
  std::uint64_t retained = 0;
  std::uint64_t reported = 0;
  std::vector<reb::NativeProbeEvent> gaps;
  Require(WaitFor([&] {
            retained = reported = 0;
            gaps.clear();
            std::uint64_t previous = 0;
            for (const auto& event : broker.Events(first_event)) {
              if (event.header.type == reb::NativeProbeType::kGap) {
                gaps.push_back(event);
                reported += reb::NativeProbeDropWeight(event);
              } else if (event.header.process_id == 77) {
                Require(event.header.sequence_number > previous,
                        "records kept around a refusal stay in order");
                previous = event.header.sequence_number;
                ++retained;
              }
            }
            return retained + reported == kRendererEvents;
          }),
          "every refused record is counted by a gap");
  Require(!gaps.empty() && reported > 0, "the spill refused past its bound and said so");
  Require(client.SetSpillChunkLimitForTesting(spill_limit) == 2, "the lowered bound was in force");
  for (const auto& gap : gaps) {
    Require(gap.header.process_id == static_cast<std::uint32_t>(base::kTestBrowserProcessId) &&
                gap.header.session_id == kSessionId &&
                gap.header.category == reb::NativeProbeCategory::kCanvas &&
                gap.header.sequence_number >= reb::NativeProbeSession::kFirstBrowserSequence,
            "a transport gap is a browser record with its own browser sequence");
  }
  std::cout << "PASS broker writer: " << reported << " refused past a two-chunk spill of "
            << kRendererEvents << " mixed-queue records reported by browser-sequenced gaps\n";

  close(artifact_connection);
  close(artifact_listener);
  unlink(artifact_path.c_str());
  Require(Enqueue(MakeTransfer(30, 8)), "enqueue after the receiver left");
  Require(StatusOf(30) == NativeArtifactReceiveStatus::kIoError, "lost transfer reported");
  Require(
      RunBrowserUntil([&] {
        for (const auto& event : broker.Events()) {
          const std::string_view payload(reinterpret_cast<const char*>(event.inline_payload.data()),
                                         event.header.payload_size);
          if (event.header.type == reb::NativeProbeType::kGap &&
              payload == "artifact_channel_lost") {
            return event.header.category == reb::NativeProbeCategory::kArtifact &&
                   event.header.process_id ==
                       static_cast<std::uint32_t>(base::kTestBrowserProcessId) &&
                   event.header.sequence_number >= reb::NativeProbeSession::kFirstBrowserSequence;
          }
        }
        return false;
      }),
      "a lost artifact channel is a named gap in the event stream");
  std::cout << "PASS broker writer: a lost artifact channel becomes an artifact_channel_lost gap\n";
  CheckLiveInvocationSites(root);

  broker.Disconnect();
  Require(RunBrowserUntil([] { return reb::NativeProbeSession::Get().stop_calls.load() == 1; }),
          "broker disconnect stops the session");
  Require(RunBrowserUntil([] {
            return reb::NativeArtifactSocketClient::Get().state() ==
                   NativeArtifactChannelState::kIdle;
          }),
          "broker disconnect stops the artifact channel");
}

}  // namespace

int main(const int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " RECEIVER_BINARY EMPTY_DIRECTORY\n";
    return 2;
  }
  signal(SIGPIPE, SIG_IGN);
  const std::string receiver = argv[1];
  const std::string root = argv[2];
  WriteToken(root + "/token");
  CheckProductionReceiver(receiver, root);
  CheckOlderReceiver(root);
  CheckStopWhileReconnecting(root);
  CheckRefusedSession(root);
  CheckTransportGaps(root);
  base::ThreadPool::JoinAllForTesting();
  return 0;
}
