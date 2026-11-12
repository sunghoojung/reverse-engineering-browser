// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_probe_socket_client.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/process/process_handle.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_local_ipc_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
#include "brave/components/reverse_engineering_browser/common/native_wasm_sample_budget.h"

namespace reb {

namespace {

constexpr char kBrokerSocketSwitch[] = "reb-broker-socket";
constexpr char kBrokerTokenFileSwitch[] = "reb-broker-token-file";
constexpr char kSessionIdSwitch[] = "reb-session-id";
constexpr char kCategoryMaskSwitch[] = "reb-category-mask";
constexpr char kDurationSecondsSwitch[] = "reb-duration-seconds";
constexpr char kArtifactSocketSwitch[] = "reb-artifact-socket";
constexpr char kCaptureCanvasImagesSwitch[] = "reb-capture-canvas-images";
constexpr char kCaptureRequestContentSwitch[] = "reb-capture-request-content";
constexpr std::size_t kSocketBatchCapacity = 32;

bool SendAll(const int descriptor, base::span<const std::uint8_t> bytes, const bool non_blocking) {
  while (!bytes.empty()) {
    ssize_t count = -1;
#if defined(MSG_NOSIGNAL)
    count = send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
#else
    count = send(descriptor, bytes.data(), bytes.size(), 0);
#endif
    if (count > 0) {
      bytes = bytes.subspan(static_cast<std::size_t>(count));
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (non_blocking && count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      pollfd writable{descriptor, static_cast<short>(POLLOUT), 0};
      const int poll_result = poll(&writable, 1, 250);
      if (poll_result > 0 && (writable.revents & POLLOUT) != 0) {
        continue;
      }
      if (poll_result < 0 && errno == EINTR) {
        continue;
      }
      if (poll_result == 0) {
        continue;
      }
    }
    return false;
  }
  return true;
}

}  // namespace

NativeProbeSocketClient& NativeProbeSocketClient::Get() {
  static base::NoDestructor<NativeProbeSocketClient> client;
  return *client;
}

NativeProbeSocketClient::NativeProbeSocketClient() = default;

NativeProbeSocketClient::~NativeProbeSocketClient() = default;

bool NativeProbeSocketClient::StartFromCommandLine() {
  if (connected_.load(std::memory_order_acquire)) {
    return true;
  }

  const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  const bool has_socket = command_line.HasSwitch(kBrokerSocketSwitch);
  const bool has_token = command_line.HasSwitch(kBrokerTokenFileSwitch);
  const bool has_session = command_line.HasSwitch(kSessionIdSwitch);
  const bool has_category_mask = command_line.HasSwitch(kCategoryMaskSwitch);
  const bool has_duration = command_line.HasSwitch(kDurationSecondsSwitch);
  if (!has_socket && !has_token && !has_session && !has_category_mask && !has_duration) {
    return false;
  }
  if (!has_socket || !has_token || !has_session || !has_category_mask || !has_duration) {
    LOG(ERROR) << "All native probe session switches are required";
    return false;
  }

  std::uint64_t session_id = 0;
  if (!base::StringToUint64(command_line.GetSwitchValueASCII(kSessionIdSwitch), &session_id) ||
      session_id == 0) {
    LOG(ERROR) << "Invalid native probe session ID";
    return false;
  }

  std::uint64_t category_mask = 0;
  if (!base::StringToUint64(command_line.GetSwitchValueASCII(kCategoryMaskSwitch),
                            &category_mask) ||
      !IsValidNativeProbeCategoryMask(category_mask)) {
    LOG(ERROR) << "Invalid native probe category mask";
    return false;
  }

  std::uint64_t duration_seconds = 0;
  if (!base::StringToUint64(command_line.GetSwitchValueASCII(kDurationSecondsSwitch),
                            &duration_seconds) ||
      duration_seconds == 0 ||
      duration_seconds > std::numeric_limits<std::uint64_t>::max() / 1'000'000'000ULL) {
    LOG(ERROR) << "Invalid native probe session duration";
    return false;
  }
  const std::uint64_t duration_ns = duration_seconds * 1'000'000'000ULL;
  const std::uint64_t now =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  if (duration_ns > std::numeric_limits<std::uint64_t>::max() - now) {
    LOG(ERROR) << "Native probe session duration overflows the monotonic clock";
    return false;
  }
  const std::uint64_t expires_at_monotonic_ns = now + duration_ns;
  const bool capture_canvas_images = command_line.HasSwitch(kCaptureCanvasImagesSwitch);
  const bool capture_request_content = command_line.HasSwitch(kCaptureRequestContentSwitch);

  const base::FilePath user_data_root =
      command_line.HasSwitch("user-data-dir")
          ? base::MakeAbsoluteFilePath(command_line.GetSwitchValuePath("user-data-dir"))
          : base::FilePath();
  if (user_data_root.empty()) {
    LOG(ERROR) << "Native capture requires an explicit existing user-data-dir";
    return false;
  }
  NativeNetworkCaptureSink::Get().SetOwnedProfilePath(user_data_root.AppendASCII("Default"));

  const base::FilePath token_path = command_line.GetSwitchValuePath(kBrokerTokenFileSwitch);
  socket_descriptor_ = ConnectNativeLocalIpc(command_line.GetSwitchValueASCII(kBrokerSocketSwitch),
                                             token_path, session_id, true);
  if (socket_descriptor_ < 0) {
    LOG(ERROR) << "Unable to connect to native probe broker";
    return false;
  }

  const bool artifact_capture_enabled =
      (category_mask & (NativeProbeCategoryMask(NativeProbeCategory::kArtifact) |
                        NativeProbeCategoryMask(NativeProbeCategory::kVm))) != 0;
  const bool has_artifact_socket = command_line.HasSwitch(kArtifactSocketSwitch);
  if (artifact_capture_enabled &&
      (!has_artifact_socket || !NativeArtifactSocketClient::Get().StartFromCommandLine(
                                   session_id, &NativeArtifactCaptureSink::TransferCompleted,
                                   &NativeProbeSocketClient::ArtifactChannelLost))) {
    close(socket_descriptor_);
    socket_descriptor_ = -1;
    return false;
  }

  browser_task_runner_ = base::SequencedTaskRunner::GetCurrentDefault();
  session_id_ = session_id;
  wasm_budget_reset_file_ = command_line.GetSwitchValueASCII("reb-wasm-budget-reset-file");
  applied_wasm_budget_reset_ = 0;
  // Every drop records its category, but a gap can be built before that store
  // is visible; the session's lowest admitted category covers that window.
  last_dropped_category_.store(
      static_cast<NativeProbeCategory>(std::countr_zero(category_mask) + 1),
      std::memory_order_relaxed);
  const auto refuse = [this] {
    connected_.store(false, std::memory_order_release);
    close(socket_descriptor_);
    socket_descriptor_ = -1;
    NativeArtifactSocketClient::Get().Stop();
    return false;
  };
  // Admit records before the session can emit them; they wait in the queue
  // until the writer starts. The writer starts last, so a refused session
  // never leaves a thread polling a descriptor this sequence closes.
  connected_.store(true, std::memory_order_release);
  if (!NativeProbeSession::Get().StartSession(session_id, category_mask, expires_at_monotonic_ns,
                                              capture_canvas_images, &NativeProbeSocketClient::Emit,
                                              capture_request_content)) {
    return refuse();
  }
  if (!writer_thread_.Start()) {
    NativeProbeSession::Get().StopSession();
    return refuse();
  }
  writer_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&NativeProbeSocketClient::Run, base::Unretained(this)));
  // Renderers record what the proxy never sees once they bind; see
  // protocol/native-network-v3.md "Requests answered in the renderer".
  LOG(INFO) << "Native capture armed before profile startup; renderers finish service-worker, "
               "data: and memory-cache answers once they bind; request path and body content "
            << (NativeProbeSession::Get().capture_request_content() ? "enabled" : "disabled");
  return true;
}

void NativeProbeSocketClient::Emit(const NativeProbeEvent& event) noexcept {
  Get().Enqueue(event);
}

void NativeProbeSocketClient::ArtifactChannelLost() noexcept {
  // From here every artifact capture is refused at admission without a
  // per-capture record, so one named gap marks where artifacts stop.
  static constexpr std::string_view kReason = "artifact_channel_lost";
  NativeProbeSession& session = NativeProbeSession::Get();
  NativeProbeEvent gap;
  gap.header.category =
      (session.category_mask() & NativeProbeCategoryMask(NativeProbeCategory::kArtifact)) != 0
          ? NativeProbeCategory::kArtifact
          : NativeProbeCategory::kVm;
  gap.header.type = NativeProbeType::kGap;
  gap.header.session_id = session.session_id();
  gap.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  gap.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  gap.header.sequence_number = session.NextBrowserSequence();
  gap.header.monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  static_assert(kReason.size() <= kNativeProbeInlinePayloadSize);
  std::ranges::transform(kReason, gap.inline_payload.begin(), [](const char value) {
    return static_cast<std::byte>(static_cast<unsigned char>(value));
  });
  gap.header.payload_size = static_cast<std::uint32_t>(kReason.size());
  // Emit applies the session, category and expiry filters.
  session.Emit(gap);
}

void NativeProbeSocketClient::Enqueue(const NativeProbeEvent& event) noexcept {
  if (!connected_.load(std::memory_order_acquire)) {
    return;
  }
  if (!queue_.TryPush(event, NativeProbeDropWeight(event))) {
    last_dropped_category_.store(event.header.category, std::memory_order_relaxed);
    return;
  }
  if (queue_.MarkNotificationPending()) {
    wakeup_.Signal();
  }
}

NativeProbeEvent NativeProbeSocketClient::MakeTransportGap(
    const std::uint64_t dropped) const noexcept {
  // This queue mixes every process's records, so its drops cannot be charged
  // to one renderer stream. The gap is the browser's own record: it takes the
  // next browser sequence instead of repeating another stream's number.
  NativeProbeEvent reference;
  reference.header.category = last_dropped_category_.load(std::memory_order_relaxed);
  reference.header.session_id = session_id_;
  reference.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  reference.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  reference.header.sequence_number = NativeProbeSession::Get().NextBrowserSequence();
  reference.header.monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  return MakeNativeProbeGapEvent(reference, dropped);
}

void NativeProbeSocketClient::Run() {
  std::uint64_t reported_dropped = 0;
  while (connected_.load(std::memory_order_acquire)) {
    wakeup_.TimedWait(base::Milliseconds(250));
    pollfd connection{socket_descriptor_, static_cast<short>(POLLIN), 0};
    const int connection_status = poll(&connection, 1, 0);
    std::uint8_t control_byte = 0;
    const bool peer_closed =
        connection_status > 0 && ((connection.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0 ||
                                  ((connection.revents & POLLIN) != 0 &&
                                   recv(socket_descriptor_, &control_byte, 1, MSG_PEEK) == 0));
    PollWasmBudgetReset();
    if (peer_closed) {
      browser_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&NativeProbeSocketClient::HandleDisconnect, base::Unretained(this)));
      return;
    }
    std::array<NativeProbeEvent, kSocketBatchCapacity> batch;
    for (;;) {
      std::size_t batch_size = 0;
      while (batch_size < batch.size() && queue_.TryPop(batch[batch_size])) {
        ++batch_size;
      }
      if (batch_size == 0) {
        break;
      }
      if (!SendAll(socket_descriptor_, base::as_bytes(base::span(batch).first(batch_size)), true)) {
        browser_task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(&NativeProbeSocketClient::HandleDisconnect, base::Unretained(this)));
        return;
      }
    }

    // Reported on the next wake-up even if nothing else is queued, so drops
    // in a final burst are not held back waiting for a later record.
    const std::uint64_t dropped = queue_.DroppedCount();
    if (dropped > reported_dropped) {
      const NativeProbeEvent gap = MakeTransportGap(dropped - reported_dropped);
      if (!SendAll(socket_descriptor_, base::byte_span_from_ref(gap), true)) {
        browser_task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(&NativeProbeSocketClient::HandleDisconnect, base::Unretained(this)));
        return;
      }
      reported_dropped = dropped;
    }

    queue_.ClearNotificationPending();
    if (!queue_.Empty() && queue_.MarkNotificationPending()) {
      wakeup_.Signal();
    }
  }
}

void NativeProbeSocketClient::PollWasmBudgetReset() {
  if (wasm_budget_reset_file_.empty())
    return;
  const auto generation = ReadNativeWasmBudgetResetGeneration(wasm_budget_reset_file_);
  if (!generation || *generation <= applied_wasm_budget_reset_)
    return;
  applied_wasm_budget_reset_ = *generation;
  // The writer must not touch session hosts. The browser sequence applies a
  // strictly newer generation within this poll, about 250ms after the file
  // changes.
  browser_task_runner_->PostTask(
      FROM_HERE, base::BindOnce([] { NativeProbeSession::Get().ResetWasmSampleBudgets(); }));
}

void NativeProbeSocketClient::HandleDisconnect() {
  if (!connected_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  NativeProbeSession::Get().StopSession();
  NativeArtifactSocketClient::Get().Stop();
  if (socket_descriptor_ >= 0) {
    close(socket_descriptor_);
    socket_descriptor_ = -1;
  }
  LOG(ERROR) << "Native probe broker disconnected; capture disabled";
}

}  // namespace reb

#else

namespace reb {

NativeProbeSocketClient& NativeProbeSocketClient::Get() {
  static base::NoDestructor<NativeProbeSocketClient> client;
  return *client;
}

NativeProbeSocketClient::NativeProbeSocketClient() = default;
NativeProbeSocketClient::~NativeProbeSocketClient() = default;
bool NativeProbeSocketClient::StartFromCommandLine() {
  return false;
}
void NativeProbeSocketClient::Emit(const NativeProbeEvent&) noexcept {}
void NativeProbeSocketClient::ArtifactChannelLost() noexcept {}
void NativeProbeSocketClient::Enqueue(const NativeProbeEvent&) noexcept {}
NativeProbeEvent NativeProbeSocketClient::MakeTransportGap(std::uint64_t) const noexcept {
  return {};
}
void NativeProbeSocketClient::Run() {}
void NativeProbeSocketClient::PollWasmBudgetReset() {}
void NativeProbeSocketClient::HandleDisconnect() {}

}  // namespace reb

#endif
