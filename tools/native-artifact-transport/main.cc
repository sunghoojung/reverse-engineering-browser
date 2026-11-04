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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_socket_client.h"
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

std::unique_ptr<reb::NativeArtifactTransfer> MakeTransfer(const std::uint64_t artifact_id,
                                                          const std::size_t size,
                                                          const bool canvas = false) {
  auto transfer = std::make_unique<reb::NativeArtifactTransfer>();
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
  std::cout << "PASS artifact writer: sensitive, oversize and duplicate rejections answered on one "
               "connection with their real status; the next artifact is accepted\n";

  StopReceiver(pid);
  const std::string stats = ReadFile(log_path);
  Require(CountOf(stats, "accepted=2 ") == 1 && CountOf(stats, "too_large=1 ") == 1 &&
              CountOf(stats, "sensitive_rejected=1 ") == 1 && CountOf(stats, "conflicts=1 ") == 1,
          "receiver counted every rejection");
  const auto lost_started = Clock::now();
  Require(Enqueue(MakeTransfer(5, 8)), "enqueue to a vanished receiver");
  Require(Enqueue(MakeTransfer(6, 8)), "enqueue while the writer reconnects");
  Require(StatusOf(5) == NativeArtifactReceiveStatus::kIoError &&
              StatusOf(6) == NativeArtifactReceiveStatus::kIoError,
          "transfers to a vanished receiver are reported");
  Require(RunBrowserUntil([] { return g_channel_lost == 1; }), "channel loss announced");
  Require(client.state() == NativeArtifactChannelState::kLost && !client.IsConnected(),
          "lost channel refuses admission");
  Require(!Enqueue(MakeTransfer(7, 8)), "lost channel refuses transfers");
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
        std::lock_guard lock(mutex_);
        events_.push_back(event);
      }
    });
  }
  std::vector<reb::NativeProbeEvent> Events() {
    std::lock_guard lock(mutex_);
    return events_;
  }
  void Disconnect() { shutdown(connection_, SHUT_RDWR); }
  void CloseAccepted() { close(connection_); }

 private:
  std::string path_;
  int listener_;
  int connection_ = -1;
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

// Drops in the browser's mixed queue are reported as browser records, and the
// end of artifact delivery is a named gap in the same stream.
void CheckTransportGaps(const std::string& root) {
  const std::string broker_path = root + "/broker.sock";
  ScriptedBroker broker(broker_path);
  const std::string artifact_path = root + "/gap-artifact.sock";
  const int artifact_listener = Listen(artifact_path);
  ConfigureBrokerSwitches(root, broker_path,
                          reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kCanvas) |
                              reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kArtifact));
  ConfigureArtifactSwitches(artifact_path, root + "/token");
  Require(reb::NativeProbeSocketClient::Get().StartFromCommandLine(), "session start");
  const int artifact_connection = AcceptHello(artifact_listener);
  broker.Accept();
  const reb::NativeProbeEmitter emit = reb::NativeProbeSession::Get().downstream();
  Require(emit != nullptr, "session emitter");

  // The broker reads nothing yet, so the writer blocks and the queue fills.
  constexpr std::uint64_t kRendererEvents = 20'000;
  for (std::uint64_t sequence = 1; sequence <= kRendererEvents; ++sequence) {
    reb::NativeProbeEvent event;
    event.header.category = reb::NativeProbeCategory::kCanvas;
    event.header.type = reb::NativeProbeType::kApiCall;
    event.header.session_id = kSessionId;
    event.header.process_id = 77;
    event.header.sequence_number = sequence;
    emit(event);
  }
  broker.StartReading();
  std::uint64_t retained = 0;
  std::uint64_t reported = 0;
  std::vector<reb::NativeProbeEvent> gaps;
  Require(WaitFor([&] {
            retained = reported = 0;
            gaps.clear();
            for (const auto& event : broker.Events()) {
              if (event.header.type == reb::NativeProbeType::kGap) {
                gaps.push_back(event);
                reported += reb::NativeProbeDropWeight(event);
              } else if (event.header.process_id == 77) {
                ++retained;
              }
            }
            return retained + reported == kRendererEvents;
          }),
          "every dropped record is counted by a gap");
  Require(!gaps.empty() && reported > 0, "the queue dropped and said so");
  for (const auto& gap : gaps) {
    Require(gap.header.process_id == static_cast<std::uint32_t>(base::kTestBrowserProcessId) &&
                gap.header.session_id == kSessionId &&
                gap.header.category == reb::NativeProbeCategory::kCanvas &&
                gap.header.sequence_number >= reb::NativeProbeSession::kFirstBrowserSequence,
            "a transport gap is a browser record with its own browser sequence");
  }
  std::cout << "PASS broker writer: " << reported << " dropped of " << kRendererEvents
            << " mixed-queue records reported by browser-sequenced gaps\n";

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
