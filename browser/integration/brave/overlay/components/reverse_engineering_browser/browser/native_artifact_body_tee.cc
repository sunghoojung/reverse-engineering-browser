// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/strings/string_view_util.h"
#include "base/task/sequenced_task_runner.h"
#include "mojo/public/cpp/system/string_data_source.h"

namespace reb {
namespace {

constexpr std::uint32_t kForwardingPipeCapacity = 64U * 1024U;

MojoResult CreateForwardingPipe(mojo::ScopedDataPipeProducerHandle& producer,
                                mojo::ScopedDataPipeConsumerHandle& consumer) {
  MojoCreateDataPipeOptions options;
  options.struct_size = sizeof(options);
  options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
  options.element_num_bytes = 1;
  options.capacity_num_bytes = kForwardingPipeCapacity;
  return mojo::CreateDataPipe(&options, producer, consumer);
}

}  // namespace

mojo::ScopedDataPipeConsumerHandle NativeArtifactBodyTee::Create(
    mojo::ScopedDataPipeConsumerHandle source,
    NativeArtifactCaptureBuffer captured,
    Completion completion,
    bool& started,
    Observer observer) {
  started = false;
  if (!source.is_valid() || captured.status() != NativeArtifactCaptureStatus::kCapturing ||
      !completion) {
    return source;
  }
  mojo::ScopedDataPipeProducerHandle producer;
  mojo::ScopedDataPipeConsumerHandle consumer;
  if (CreateForwardingPipe(producer, consumer) != MOJO_RESULT_OK) {
    return source;
  }
  auto tee = base::WrapRefCounted(
      new NativeArtifactBodyTee(std::move(source), std::move(producer), std::move(captured),
                                std::move(completion), std::move(observer)));
  tee->Start();
  started = true;
  return consumer;
}

NativeArtifactBodyTee::NativeArtifactBodyTee(mojo::ScopedDataPipeConsumerHandle source,
                                             mojo::ScopedDataPipeProducerHandle target,
                                             NativeArtifactCaptureBuffer captured,
                                             Completion completion,
                                             Observer observer)
    : source_(std::move(source)),
      source_watcher_(FROM_HERE,
                      mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                      base::SequencedTaskRunner::GetCurrentDefault()),
      target_(std::make_unique<mojo::DataPipeProducer>(std::move(target))),
      captured_(std::move(captured)),
      completion_(std::move(completion)),
      observer_(std::move(observer)) {}

NativeArtifactBodyTee::~NativeArtifactBodyTee() = default;

void NativeArtifactBodyTee::Start() {
  keep_alive_ = this;
  source_watcher_.Watch(
      source_.get(), MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
      base::BindRepeating(&NativeArtifactBodyTee::OnReadable, weak_factory_.GetWeakPtr()));
  source_watcher_.ArmOrNotify();
}

void NativeArtifactBodyTee::OnReadable(const MojoResult result, const mojo::HandleSignalsState&) {
  if (write_pending_ || !completion_) {
    return;
  }
  if (result != MOJO_RESULT_OK) {
    Finish(NativeArtifactBodyEnd::kSourceFailed);
    return;
  }

  base::span<const std::uint8_t> data;
  const MojoResult read_result = source_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, data);
  if (read_result == MOJO_RESULT_SHOULD_WAIT) {
    source_watcher_.ArmOrNotify();
    return;
  }
  if (read_result == MOJO_RESULT_FAILED_PRECONDITION) {
    Finish(NativeArtifactBodyEnd::kSourceClosed);
    return;
  }
  if (read_result != MOJO_RESULT_OK) {
    Finish(NativeArtifactBodyEnd::kSourceFailed);
    return;
  }

  const std::span<const std::uint8_t> chunk(data.data(), data.size());
  if (observer_) {
    observer_.Run(chunk);
  } else {
    captured_.Append(chunk);
  }
  write_buffer_.assign(base::as_string_view(data));
  source_->EndReadData(data.size());
  write_pending_ = true;
  target_->Write(std::make_unique<mojo::StringDataSource>(
                     write_buffer_,
                     mojo::StringDataSource::AsyncWritingMode::STRING_STAYS_VALID_UNTIL_COMPLETION),
                 base::BindOnce(&NativeArtifactBodyTee::OnDataWritten, weak_factory_.GetWeakPtr()));
}

void NativeArtifactBodyTee::OnDataWritten(const MojoResult result) {
  write_pending_ = false;
  write_buffer_.clear();
  if (result != MOJO_RESULT_OK) {
    Finish(NativeArtifactBodyEnd::kTargetClosed);
    return;
  }
  source_watcher_.ArmOrNotify();
}

void NativeArtifactBodyTee::Finish(const NativeArtifactBodyEnd end) {
  if (!completion_) {
    return;
  }
  scoped_refptr<NativeArtifactBodyTee> keep_alive = std::move(keep_alive_);
  source_watcher_.Cancel();
  source_.reset();
  target_.reset();
  observer_.Reset();
  std::move(completion_).Run(end, std::move(captured_));
}

}  // namespace reb
