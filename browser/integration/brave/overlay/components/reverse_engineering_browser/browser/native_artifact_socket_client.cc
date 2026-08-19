// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
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
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_local_ipc_client.h"

namespace reb {
namespace {

constexpr char kArtifactSocketSwitch[] = "reb-artifact-socket";
constexpr char kBrokerTokenFileSwitch[] = "reb-broker-token-file";
constexpr std::size_t kMaxQueuedArtifacts = 16;
constexpr std::size_t kMaxQueuedBytes = 32U * 1024U * 1024U;
constexpr int kTransferTimeoutSeconds = 30;

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

bool IsValidAck(const NativeArtifactAck& ack, const std::uint64_t artifact_id) noexcept {
  return ack.magic == kNativeArtifactAckMagic &&
         ack.protocol_version == kNativeArtifactProtocolVersion &&
         ack.ack_size == kNativeArtifactAckSize && ack.reserved0 == 0 &&
         ack.artifact_id == artifact_id &&
         std::ranges::all_of(ack.reserved1,
                             [](const std::byte value) { return value == std::byte{0}; }) &&
         ack.status >= NativeArtifactReceiveStatus::kAccepted &&
         ack.status <= NativeArtifactReceiveStatus::kIoError;
}

bool SendTransfer(const int descriptor,
                  const NativeArtifactTransfer& transfer,
                  NativeArtifactReceiveStatus& status) {
  if (!SendAll(descriptor, base::byte_span_from_ref(transfer.header)) ||
      !SendAll(descriptor, base::as_byte_span(transfer.url)) ||
      !SendAll(descriptor, base::as_byte_span(transfer.mime_type)) ||
      !SendAll(descriptor, base::as_byte_span(transfer.content))) {
    status = NativeArtifactReceiveStatus::kIoError;
    return false;
  }
  NativeArtifactAck ack;
  if (!ReadAll(descriptor, base::byte_span_from_ref(ack)) ||
      !IsValidAck(ack, transfer.header.artifact_id)) {
    status = NativeArtifactReceiveStatus::kIoError;
    return false;
  }
  status = ack.status;
  return status == NativeArtifactReceiveStatus::kAccepted;
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

bool NativeArtifactSocketClient::StartFromCommandLine(const std::uint64_t session_id,
                                                      const NativeArtifactCompletion completion) {
  if (connected_.load(std::memory_order_acquire) || !completion) {
    return false;
  }
  const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  if (!command_line.HasSwitch(kArtifactSocketSwitch)) {
    LOG(ERROR) << "Artifact capture requires --" << kArtifactSocketSwitch;
    return false;
  }
  socket_descriptor_ = ConnectNativeLocalIpc(
      command_line.GetSwitchValueASCII(kArtifactSocketSwitch),
      command_line.GetSwitchValuePath(kBrokerTokenFileSwitch), session_id, false);
  if (socket_descriptor_ < 0) {
    LOG(ERROR) << "Unable to connect to native artifact receiver";
    return false;
  }
  const timeval timeout{kTransferTimeoutSeconds, 0};
  if (setsockopt(socket_descriptor_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0 ||
      setsockopt(socket_descriptor_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
    close(socket_descriptor_);
    socket_descriptor_ = -1;
    return false;
  }
  browser_task_runner_ = base::SequencedTaskRunner::GetCurrentDefault();
  completion_ = completion;
  connected_.store(true, std::memory_order_release);
  if (!writer_thread_.Start()) {
    connected_.store(false, std::memory_order_release);
    close(socket_descriptor_);
    socket_descriptor_ = -1;
    completion_ = nullptr;
    return false;
  }
  writer_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&NativeArtifactSocketClient::Run, base::Unretained(this)));
  return true;
}

bool NativeArtifactSocketClient::Enqueue(
    std::unique_ptr<NativeArtifactTransfer> transfer) noexcept {
  if (!transfer || !connected_.load(std::memory_order_acquire)) {
    return false;
  }
  const std::size_t transfer_size = TransferSize(*transfer);
  base::AutoLock lock(lock_);
  if (!connected_.load(std::memory_order_relaxed) || queue_.size() >= kMaxQueuedArtifacts ||
      transfer_size > kMaxQueuedBytes - std::min(queued_bytes_, kMaxQueuedBytes)) {
    return false;
  }
  queued_bytes_ += transfer_size;
  queue_.push_back(std::move(transfer));
  wakeup_.Signal();
  return true;
}

bool NativeArtifactSocketClient::IsConnected() const noexcept {
  return connected_.load(std::memory_order_acquire);
}

void NativeArtifactSocketClient::Run() {
  for (;;) {
    std::unique_ptr<NativeArtifactTransfer> transfer;
    {
      base::AutoLock lock(lock_);
      while (queue_.empty() && connected_.load(std::memory_order_relaxed)) {
        wakeup_.Wait();
      }
      if (queue_.empty()) {
        return;
      }
      transfer = std::move(queue_.front());
      queue_.pop_front();
      queued_bytes_ -= TransferSize(*transfer);
    }

    NativeArtifactReceiveStatus status = NativeArtifactReceiveStatus::kIoError;
    const bool accepted = SendTransfer(socket_descriptor_, *transfer, status);
    Report(transfer->header.artifact_id, status);
    if (!accepted) {
      connected_.store(false, std::memory_order_release);
      DisconnectPending(NativeArtifactReceiveStatus::kIoError);
      return;
    }
  }
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
  }
  for (const auto& transfer : pending) {
    Report(transfer->header.artifact_id, status);
  }
}

void NativeArtifactSocketClient::Stop() {
  if (!connected_.exchange(false, std::memory_order_acq_rel) && !writer_thread_.IsRunning()) {
    return;
  }
  if (socket_descriptor_ >= 0) {
    shutdown(socket_descriptor_, SHUT_RDWR);
  }
  {
    base::AutoLock lock(lock_);
    wakeup_.Broadcast();
  }
  writer_thread_.Stop();
  if (socket_descriptor_ >= 0) {
    close(socket_descriptor_);
    socket_descriptor_ = -1;
  }
  DisconnectPending(NativeArtifactReceiveStatus::kIoError);
  completion_ = nullptr;
  browser_task_runner_.reset();
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
bool NativeArtifactSocketClient::StartFromCommandLine(std::uint64_t, NativeArtifactCompletion) {
  return false;
}
bool NativeArtifactSocketClient::Enqueue(std::unique_ptr<NativeArtifactTransfer>) noexcept {
  return false;
}
bool NativeArtifactSocketClient::IsConnected() const noexcept {
  return false;
}
void NativeArtifactSocketClient::Stop() {}
void NativeArtifactSocketClient::Run() {}
void NativeArtifactSocketClient::Report(std::uint64_t, NativeArtifactReceiveStatus) {}
void NativeArtifactSocketClient::DisconnectPending(NativeArtifactReceiveStatus) {}

}  // namespace reb

#endif
