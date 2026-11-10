// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/common/native_artifact_queue_limits.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <limits>
#include <span>
#include <utility>

#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_local_ipc_client.h"

namespace reb {
namespace {

constexpr char kArtifactSocketSwitch[] = "reb-artifact-socket";
constexpr char kBrokerTokenFileSwitch[] = "reb-broker-token-file";
constexpr int kTransferTimeoutSeconds = 30;
// A local receiver that refuses every connection for about three seconds is
// gone for the session; transfers wait in the bounded queue meanwhile.
constexpr std::array<int, 5> kReconnectDelaysMs = {100, 200, 400, 800, 1600};

using State = NativeArtifactChannelState;

bool AcceptsTransfers(const State state) noexcept {
  return state == State::kConnected || state == State::kReconnecting;
}

bool SendAll(const int descriptor, base::span<const std::uint8_t> bytes) {
  while (!bytes.empty()) {
#if defined(MSG_NOSIGNAL)
    const ssize_t count = send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
#else
    const ssize_t count = send(descriptor, bytes.data(), bytes.size(), 0);
#endif
    if (count > 0) {
      bytes = bytes.subspan(static_cast<std::size_t>(count));
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

bool ReadAll(const int descriptor, base::span<std::uint8_t> bytes) {
  while (!bytes.empty()) {
    const ssize_t count = read(descriptor, bytes.data(), bytes.size());
    if (count > 0) {
      bytes = bytes.subspan(static_cast<std::size_t>(count));
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

bool IsStreamFrame(const NativeArtifactTransfer& transfer) noexcept {
  return transfer.op == NativeArtifactTransferOp::kStream;
}

// The ID the receiver's ACK names: a checkpoint's snapshot, else the stream or artifact.
std::uint64_t AckId(const NativeArtifactTransfer& transfer) noexcept {
  if (!IsStreamFrame(transfer)) {
    return transfer.header.artifact_id;
  }
  return transfer.frame.op == NativeArtifactStreamOp::kCheckpoint ? transfer.frame.value
                                                                  : transfer.frame.artifact_id;
}

std::uint16_t AckVersion(const NativeArtifactTransfer& transfer) noexcept {
  return transfer.op == NativeArtifactTransferOp::kWhole ? kNativeArtifactProtocolVersion
                                                         : kNativeArtifactStreamProtocolVersion;
}

bool IsValidAck(const NativeArtifactAck& ack,
                const std::uint64_t artifact_id,
                const std::uint16_t protocol_version) noexcept {
  return ack.magic == kNativeArtifactAckMagic && ack.protocol_version == protocol_version &&
         ack.ack_size == kNativeArtifactAckSize && ack.reserved0 == 0 &&
         ack.artifact_id == artifact_id &&
         std::ranges::all_of(ack.reserved1,
                             [](const std::byte value) { return value == std::byte{0}; }) &&
         ack.status >= NativeArtifactReceiveStatus::kAccepted &&
         ack.status <= NativeArtifactReceiveStatus::kIoError;
}

// The receiver never writes unprompted, so a readable idle connection means it
// closed, as older receivers do after any rejection. Replacing it before the
// next frame keeps that frame from failing on a dead connection.
bool PeerClosed(const int descriptor) noexcept {
  pollfd connection{descriptor, static_cast<short>(POLLIN), 0};
  return poll(&connection, 1, 0) > 0 &&
         (connection.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0;
}

// A receiver that rejects a frame before its body arrives may acknowledge and
// close while the body is still being written. That acknowledgment is then
// already buffered here and carries the real status.
void ReadBufferedAck(const int descriptor,
                     const NativeArtifactTransfer& transfer,
                     NativeArtifactReceiveStatus& status) {
  pollfd connection{descriptor, static_cast<short>(POLLIN), 0};
  NativeArtifactAck ack;
  if (poll(&connection, 1, 0) > 0 && (connection.revents & POLLIN) != 0 &&
      ReadAll(descriptor, base::byte_span_from_ref(ack)) &&
      IsValidAck(ack, AckId(transfer), AckVersion(transfer))) {
    status = ack.status;
  }
}

enum class TransferOutcome {
  // The receiver acknowledged this frame and the connection carries the next.
  kAcknowledged,
  // The connection cannot carry another frame.
  kConnectionLost,
};

TransferOutcome SendTransfer(const int descriptor,
                             const NativeArtifactTransfer& transfer,
                             NativeArtifactReceiveStatus& status) {
  status = NativeArtifactReceiveStatus::kIoError;
  const bool sent = IsStreamFrame(transfer)
                        ? SendAll(descriptor, base::byte_span_from_ref(transfer.frame)) &&
                              SendAll(descriptor, base::as_byte_span(transfer.content))
                        : SendAll(descriptor, base::byte_span_from_ref(transfer.header)) &&
                              SendAll(descriptor, base::as_byte_span(transfer.url)) &&
                              SendAll(descriptor, base::as_byte_span(transfer.mime_type)) &&
                              SendAll(descriptor, base::as_byte_span(transfer.content));
  if (!sent) {
    ReadBufferedAck(descriptor, transfer, status);
    return TransferOutcome::kConnectionLost;
  }
  NativeArtifactAck ack;
  if (!ReadAll(descriptor, base::byte_span_from_ref(ack)) ||
      !IsValidAck(ack, AckId(transfer), AckVersion(transfer))) {
    return TransferOutcome::kConnectionLost;
  }
  // A rejection is acknowledged after the receiver consumed the whole frame,
  // so it leaves the connection usable.
  status = ack.status;
  return TransferOutcome::kAcknowledged;
}

std::size_t TransferSize(const NativeArtifactTransfer& transfer) noexcept {
  const std::size_t metadata_size = transfer.url.size() + transfer.mime_type.size();
  return metadata_size > std::numeric_limits<std::size_t>::max() - transfer.content.size()
             ? std::numeric_limits<std::size_t>::max()
             : metadata_size + transfer.content.size();
}

}  // namespace

NativeArtifactSocketClient& NativeArtifactSocketClient::Get() {
  static base::NoDestructor<NativeArtifactSocketClient> client;
  return *client;
}

NativeArtifactSocketClient::NativeArtifactSocketClient() = default;

NativeArtifactSocketClient::~NativeArtifactSocketClient() {
  Stop();
}

bool NativeArtifactSocketClient::StartFromCommandLine(
    const std::uint64_t session_id,
    const NativeArtifactCompletion completion,
    const NativeArtifactChannelLost channel_lost) {
  if (state_.load(std::memory_order_acquire) != State::kIdle || !completion || !channel_lost) {
    return false;
  }
  const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  if (!command_line.HasSwitch(kArtifactSocketSwitch)) {
    LOG(ERROR) << "Artifact capture requires --" << kArtifactSocketSwitch;
    return false;
  }
  socket_path_ = command_line.GetSwitchValueASCII(kArtifactSocketSwitch);
  token_path_ = command_line.GetSwitchValuePath(kBrokerTokenFileSwitch);
  session_id_ = session_id;
  const int descriptor = Connect();
  if (descriptor < 0) {
    LOG(ERROR) << "Unable to connect to native artifact receiver";
    return false;
  }
  browser_task_runner_ = base::SequencedTaskRunner::GetCurrentDefault();
  completion_ = completion;
  channel_lost_ = channel_lost;
  {
    base::AutoLock lock(lock_);
    socket_descriptor_ = descriptor;
    state_.store(State::kConnected, std::memory_order_release);
  }
  if (!writer_thread_.Start()) {
    {
      base::AutoLock lock(lock_);
      close(socket_descriptor_);
      socket_descriptor_ = -1;
      state_.store(State::kIdle, std::memory_order_release);
    }
    completion_ = nullptr;
    channel_lost_ = nullptr;
    browser_task_runner_.reset();
    return false;
  }
  writer_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&NativeArtifactSocketClient::Run, base::Unretained(this)));
  return true;
}

bool NativeArtifactSocketClient::Enqueue(
    std::unique_ptr<NativeArtifactTransfer> transfer) noexcept {
  if (!transfer || !AcceptsTransfers(state_.load(std::memory_order_acquire))) {
    return false;
  }
  const std::size_t transfer_size = TransferSize(*transfer);
  const bool stream_frame = IsStreamFrame(*transfer);
  const bool data = stream_frame && transfer->frame.op == NativeArtifactStreamOp::kData;
  base::AutoLock lock(lock_);
  if (!AcceptsTransfers(state_.load(std::memory_order_relaxed))) {
    return false;
  }
  // End, abort and checkpoint frames always fit, so an admitted stream can
  // always be closed.
  if (data ? queued_stream_frames_ >= kNativeArtifactMaxQueuedStreamFrames ||
                 !CanQueueNativeArtifact(0, queued_bytes_, transfer_size)
           : !stream_frame && !CanQueueNativeArtifact(queue_.size() - queued_stream_frames_,
                                                      queued_bytes_, transfer_size)) {
    return false;
  }
  queued_bytes_ += transfer_size;
  queued_stream_frames_ += stream_frame ? 1U : 0U;
  queue_.push_back(std::move(transfer));
  wakeup_.Signal();
  return true;
}

bool NativeArtifactSocketClient::IsConnected() const noexcept {
  return AcceptsTransfers(state_.load(std::memory_order_acquire));
}

NativeArtifactChannelState NativeArtifactSocketClient::state() const noexcept {
  return state_.load(std::memory_order_acquire);
}

bool NativeArtifactSocketClient::Transition(const State from, const State to) noexcept {
  State expected = from;
  return state_.compare_exchange_strong(expected, to, std::memory_order_acq_rel,
                                        std::memory_order_acquire);
}

int NativeArtifactSocketClient::Connect() const {
  const int descriptor = ConnectNativeLocalIpc(socket_path_, token_path_, session_id_, false);
  if (descriptor < 0) {
    return -1;
  }
  const timeval timeout{kTransferTimeoutSeconds, 0};
  if (setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0 ||
      setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
    close(descriptor);
    return -1;
  }
  return descriptor;
}

bool NativeArtifactSocketClient::Reconnect() {
  {
    base::AutoLock lock(lock_);
    if (!Transition(State::kConnected, State::kReconnecting)) {
      return false;
    }
    close(socket_descriptor_);
    socket_descriptor_ = -1;
  }
  LOG(WARNING) << "Native artifact receiver connection lost; reconnecting";
  for (const int delay_ms : kReconnectDelaysMs) {
    {
      base::AutoLock lock(lock_);
      const base::TimeTicks deadline = base::TimeTicks::Now() + base::Milliseconds(delay_ms);
      // Stop() broadcasts to end the wait early; Enqueue() signals spuriously.
      while (state_.load(std::memory_order_relaxed) == State::kReconnecting) {
        const base::TimeDelta remaining = deadline - base::TimeTicks::Now();
        if (!remaining.is_positive()) {
          break;
        }
        wakeup_.TimedWait(remaining);
      }
      if (state_.load(std::memory_order_relaxed) != State::kReconnecting) {
        return false;
      }
    }
    const int descriptor = Connect();
    if (descriptor < 0) {
      continue;
    }
    base::AutoLock lock(lock_);
    if (!Transition(State::kReconnecting, State::kConnected)) {
      close(descriptor);
      return false;
    }
    socket_descriptor_ = descriptor;
    LOG(WARNING) << "Native artifact receiver reconnected";
    return true;
  }
  return false;
}

void NativeArtifactSocketClient::LoseChannel() {
  {
    base::AutoLock lock(lock_);
    // Stop() may have taken over; it then reports the queue itself.
    if (!Transition(State::kReconnecting, State::kLost)) {
      return;
    }
  }
  LOG(ERROR) << "Native artifact receiver unavailable; artifact capture stopped";
  DisconnectPending(NativeArtifactReceiveStatus::kIoError);
  // Posted after every completion, so the loss is recorded after them.
  if (browser_task_runner_ && channel_lost_) {
    browser_task_runner_->PostTask(FROM_HERE, base::BindOnce(channel_lost_));
  }
}

void NativeArtifactSocketClient::Run() {
  for (;;) {
    std::unique_ptr<NativeArtifactTransfer> transfer;
    int descriptor = -1;
    {
      base::AutoLock lock(lock_);
      while (queue_.empty() && state_.load(std::memory_order_relaxed) == State::kConnected) {
        wakeup_.Wait();
      }
      if (state_.load(std::memory_order_relaxed) != State::kConnected) {
        // Stop() reports whatever is still queued.
        return;
      }
      transfer = std::move(queue_.front());
      queue_.pop_front();
      queued_bytes_ -= TransferSize(*transfer);
      queued_stream_frames_ -= IsStreamFrame(*transfer) ? 1U : 0U;
      descriptor = socket_descriptor_;
    }

    if (PeerClosed(descriptor)) {
      LoseOpenStreams(NativeArtifactReceiveStatus::kIoError);
      if (!Reconnect()) {
        ReportUnsent(*transfer, NativeArtifactReceiveStatus::kIoError);
        LoseChannel();
        return;
      }
      base::AutoLock lock(lock_);
      descriptor = socket_descriptor_;
    }
    if (!Send(descriptor, *transfer)) {
      LoseOpenStreams(NativeArtifactReceiveStatus::kIoError);
      if (!Reconnect()) {
        LoseChannel();
        return;
      }
    }
  }
}

bool NativeArtifactSocketClient::Send(const int descriptor,
                                      const NativeArtifactTransfer& transfer) {
  using Op = NativeArtifactStreamOp;
  const bool stream_frame = IsStreamFrame(transfer);
  const std::uint64_t stream_id =
      stream_frame ? transfer.frame.artifact_id : transfer.header.artifact_id;
  if (stream_frame && !open_streams_.contains(stream_id)) {
    // The stream was refused or lost, and reported then.
    ReportUnsent(transfer, NativeArtifactReceiveStatus::kIoError);
    return true;
  }
  NativeArtifactReceiveStatus status = NativeArtifactReceiveStatus::kIoError;
  const bool acknowledged =
      SendTransfer(descriptor, transfer, status) == TransferOutcome::kAcknowledged;
  const bool accepted = acknowledged && status == NativeArtifactReceiveStatus::kAccepted;
  if (!stream_frame) {
    if (transfer.op == NativeArtifactTransferOp::kOpen && accepted) {
      open_streams_.insert(stream_id);
    } else {
      Report(stream_id, status);
    }
    return acknowledged;
  }
  switch (transfer.frame.op) {
    case Op::kCheckpoint:
      Report(transfer.frame.value, status);
      break;
    case Op::kData:
    case Op::kEnd:
      // A lost connection reports its open streams instead.
      if (acknowledged && (!accepted || transfer.frame.op == Op::kEnd)) {
        open_streams_.erase(stream_id);
        Report(stream_id, status);
      }
      break;
    case Op::kAbort:
      open_streams_.erase(stream_id);
      break;
  }
  return acknowledged;
}

void NativeArtifactSocketClient::ReportUnsent(const NativeArtifactTransfer& transfer,
                                              const NativeArtifactReceiveStatus status) {
  if (!IsStreamFrame(transfer)) {
    Report(transfer.header.artifact_id, status);
  } else if (transfer.frame.op == NativeArtifactStreamOp::kCheckpoint) {
    Report(transfer.frame.value, status);
  }
}

void NativeArtifactSocketClient::LoseOpenStreams(const NativeArtifactReceiveStatus status) {
  for (const std::uint64_t stream_id : open_streams_) {
    Report(stream_id, status);
  }
  open_streams_.clear();
}

void NativeArtifactSocketClient::Report(const std::uint64_t artifact_id,
                                        const NativeArtifactReceiveStatus status) {
  if (browser_task_runner_ && completion_) {
    browser_task_runner_->PostTask(FROM_HERE, base::BindOnce(completion_, artifact_id, status));
  }
}

void NativeArtifactSocketClient::DisconnectPending(const NativeArtifactReceiveStatus status) {
  std::deque<std::unique_ptr<NativeArtifactTransfer>> pending;
  {
    base::AutoLock lock(lock_);
    pending.swap(queue_);
    queued_bytes_ = 0;
    queued_stream_frames_ = 0;
  }
  LoseOpenStreams(status);
  for (const auto& transfer : pending) {
    ReportUnsent(*transfer, status);
  }
}

void NativeArtifactSocketClient::Stop() {
  const bool writer_running = writer_thread_.IsRunning();
  {
    base::AutoLock lock(lock_);
    const State state = state_.load(std::memory_order_relaxed);
    if (state == State::kStopping || (state == State::kIdle && !writer_running)) {
      return;
    }
    // The one transition allowed from every state.
    state_.store(State::kStopping, std::memory_order_release);
    if (socket_descriptor_ >= 0) {
      shutdown(socket_descriptor_, SHUT_RDWR);
    }
    wakeup_.Broadcast();
  }
  if (!writer_running) {
    FinishStop();
    return;
  }
  writer_thread_.DetachFromSequence();
  // JoinWriter waits for a base::Thread on this blocking worker, not on the
  // browser sequence. MayBlock alone does not permit base sync primitives.
  base::ThreadPool::PostTaskAndReply(
      FROM_HERE, {base::MayBlock(), base::WithBaseSyncPrimitives()},
      base::BindOnce(&NativeArtifactSocketClient::JoinWriter, base::Unretained(this)),
      base::BindOnce(&NativeArtifactSocketClient::FinishStop, base::Unretained(this)));
}

void NativeArtifactSocketClient::JoinWriter() {
  writer_thread_.Stop();
}

void NativeArtifactSocketClient::FinishStop() {
  {
    base::AutoLock lock(lock_);
    if (socket_descriptor_ >= 0) {
      close(socket_descriptor_);
      socket_descriptor_ = -1;
    }
  }
  DisconnectPending(NativeArtifactReceiveStatus::kIoError);
  completion_ = nullptr;
  channel_lost_ = nullptr;
  browser_task_runner_.reset();
  state_.store(State::kIdle, std::memory_order_release);
}

}  // namespace reb

#else

namespace reb {

NativeArtifactSocketClient& NativeArtifactSocketClient::Get() {
  static base::NoDestructor<NativeArtifactSocketClient> client;
  return *client;
}
NativeArtifactSocketClient::NativeArtifactSocketClient() = default;
NativeArtifactSocketClient::~NativeArtifactSocketClient() = default;
bool NativeArtifactSocketClient::StartFromCommandLine(std::uint64_t,
                                                      NativeArtifactCompletion,
                                                      NativeArtifactChannelLost) {
  return false;
}
bool NativeArtifactSocketClient::Enqueue(std::unique_ptr<NativeArtifactTransfer>) noexcept {
  return false;
}
bool NativeArtifactSocketClient::IsConnected() const noexcept {
  return false;
}
NativeArtifactChannelState NativeArtifactSocketClient::state() const noexcept {
  return NativeArtifactChannelState::kIdle;
}
void NativeArtifactSocketClient::Stop() {}
bool NativeArtifactSocketClient::Transition(NativeArtifactChannelState,
                                            NativeArtifactChannelState) noexcept {
  return false;
}
int NativeArtifactSocketClient::Connect() const {
  return -1;
}
bool NativeArtifactSocketClient::Reconnect() {
  return false;
}
void NativeArtifactSocketClient::LoseChannel() {}
void NativeArtifactSocketClient::Run() {}
void NativeArtifactSocketClient::Report(std::uint64_t, NativeArtifactReceiveStatus) {}
bool NativeArtifactSocketClient::Send(int, const NativeArtifactTransfer&) {
  return false;
}
void NativeArtifactSocketClient::ReportUnsent(const NativeArtifactTransfer&,
                                              NativeArtifactReceiveStatus) {}
void NativeArtifactSocketClient::LoseOpenStreams(NativeArtifactReceiveStatus) {}
void NativeArtifactSocketClient::DisconnectPending(NativeArtifactReceiveStatus) {}
void NativeArtifactSocketClient::JoinWriter() {}
void NativeArtifactSocketClient::FinishStop() {}

}  // namespace reb

#endif
