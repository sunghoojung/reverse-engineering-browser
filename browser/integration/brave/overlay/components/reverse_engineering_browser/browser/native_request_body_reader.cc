// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_request_body_reader.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h"
#include "content/public/browser/child_process_security_policy.h"
#include "mojo/public/cpp/bindings/callback_helpers.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "net/base/net_errors.h"
#include "services/network/public/cpp/data_element.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/mojom/chunked_data_pipe_getter.mojom.h"
#include "services/network/public/mojom/data_pipe_getter.mojom.h"

namespace reb {
namespace {

constexpr std::size_t kChunk = kNativeArtifactStreamChunkBytes;

using Done = NativeRequestBodyReader::Done;

void Reply(const scoped_refptr<base::SequencedTaskRunner>& reply,
           Done done,
           NativeArtifactStream stream,
           const NativeRequestBodyReadEnd end,
           const std::uint64_t body_length) {
  reply->PostTask(FROM_HERE, base::BindOnce(std::move(done), NativeRequestBodyReadResult{
                                                                 .stream = std::move(stream),
                                                                 .end = end,
                                                                 .body_length = body_length}));
}

struct Part final {
  enum class Kind : std::uint8_t { kBytes, kFile, kDataPipe };
  Kind kind = Kind::kBytes;
  std::size_t element = 0;
  base::FilePath path;
  std::uint64_t offset = 0;
  std::uint64_t length = 0;
  base::Time expected_modification_time;
  mojo::PendingRemote<network::mojom::DataPipeGetter> getter;
};

// Reads in-memory, file and blob parts in order on its own sequence, and
// deletes itself once the result is posted.
class PartsReader final {
 public:
  PartsReader(scoped_refptr<network::ResourceRequestBody> body,
              std::vector<Part> parts,
              NativeArtifactStream stream,
              scoped_refptr<base::SequencedTaskRunner> reply,
              Done done)
      : body_(std::move(body)),
        parts_(std::move(parts)),
        stream_(std::move(stream)),
        reply_(std::move(reply)),
        done_(std::move(done)) {}

  void Next() {
    if (index_ == parts_.size()) {
      Finish(NativeRequestBodyReadEnd::kComplete);
      return;
    }
    position_ = 0;
    counted_ = false;
    switch (parts_[index_].kind) {
      case Part::Kind::kBytes:
        ReadBytes();
        return;
      case Part::Kind::kFile:
        OpenFile();
        return;
      case Part::Kind::kDataPipe:
        OpenPipe();
        return;
    }
  }

 private:
  // Offers bytes. When the pool is full, `step` runs again on this sequence
  // once it has room, and the part's source holds the rest. False when the
  // read ended.
  bool Offer(std::span<const std::uint8_t> data, std::size_t& taken, void (PartsReader::*step)()) {
    taken = stream_.Offer(data);
    if (!stream_.is_open()) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      return false;
    }
    if (taken < data.size()) {
      stream_.WaitForSpace(base::BindOnce(step, weak_factory_.GetWeakPtr()));
    }
    return true;
  }

  void ReadBytes() {
    const auto& data =
        (*body_->elements())[parts_[index_].element].As<network::DataElementBytes>().bytes();
    if (!counted_) {
      body_length_ += data.size();
      counted_ = true;
    }
    while (position_ < data.size()) {
      const auto chunk =
          std::span(data).subspan(position_, std::min(kChunk, data.size() - position_));
      std::size_t taken = 0;
      if (!Offer(chunk, taken, &PartsReader::ReadBytes)) {
        return;
      }
      position_ += taken;
      if (taken < chunk.size()) {
        return;
      }
    }
    ++index_;
    Next();
  }

  void OpenFile() {
    const Part& part = parts_[index_];
    file_ = base::File(part.path, base::File::FLAG_OPEN | base::File::FLAG_READ);
    base::File::Info info;
    // The network service reads the same range and refuses a changed file.
    if (!file_.IsValid() || !file_.GetInfo(&info) || info.size < 0 ||
        (!part.expected_modification_time.is_null() &&
         info.last_modified != part.expected_modification_time) ||
        part.offset > static_cast<std::uint64_t>(info.size)) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      return;
    }
    const std::uint64_t available = static_cast<std::uint64_t>(info.size) - part.offset;
    file_remaining_ =
        part.length == std::numeric_limits<std::uint64_t>::max() ? available : part.length;
    if (file_remaining_ > available) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      return;
    }
    body_length_ += file_remaining_;
    file_offset_ = part.offset;
    buffered_.clear();
    ReadFile();
  }

  void ReadFile() {
    while (!buffered_.empty() || file_remaining_ > 0) {
      if (buffered_.empty()) {
        buffered_.resize(
            static_cast<std::size_t>(std::min<std::uint64_t>(kChunk, file_remaining_)));
        const std::optional<std::size_t> read =
            file_.Read(static_cast<std::int64_t>(file_offset_), buffered_);
        if (!read || *read != buffered_.size()) {
          Finish(NativeRequestBodyReadEnd::kIncomplete);
          return;
        }
        file_offset_ += *read;
        file_remaining_ -= *read;
        position_ = 0;
      }
      const auto chunk = std::span(buffered_).subspan(position_);
      std::size_t taken = 0;
      if (!Offer(chunk, taken, &PartsReader::ReadFile)) {
        return;
      }
      position_ += taken;
      if (taken < chunk.size()) {
        return;
      }
      buffered_.clear();
    }
    file_.Close();
    ++index_;
    Next();
  }

  void OpenPipe() {
    getter_.reset();
    getter_.Bind(std::move(parts_[index_].getter));
    mojo::ScopedDataPipeProducerHandle producer;
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(options);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = static_cast<std::uint32_t>(kChunk);
    if (mojo::CreateDataPipe(&options, producer, pipe_) != MOJO_RESULT_OK) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      return;
    }
    pipe_size_.reset();
    pipe_read_ = 0;
    pipe_done_ = false;
    getter_.set_disconnect_handler(
        base::BindOnce(&PartsReader::OnPipeGone, weak_factory_.GetWeakPtr()));
    getter_->Read(std::move(producer),
                  base::BindOnce(&PartsReader::OnPipeSize, weak_factory_.GetWeakPtr()));
    watcher_.Watch(pipe_.get(), MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
                   MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
                   base::BindRepeating(&PartsReader::OnPipeReadable, weak_factory_.GetWeakPtr()));
    watcher_.ArmOrNotify();
  }

  // The size callback and the pipe travel on different channels, so either
  // may arrive first; the part ends once both say the same thing.
  void OnPipeSize(const network::mojom::DataPipeGetter::ReadResult result) {
    if (!result.has_value()) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      return;
    }
    pipe_size_ = result->InBytes();
    body_length_ += *pipe_size_;
    MaybeEndPipe();
  }

  void OnPipeGone() {
    if (!pipe_size_) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
    }
  }

  void ReadPipe() { watcher_.ArmOrNotify(); }

  void OnPipeReadable(const MojoResult result, const mojo::HandleSignalsState&) {
    if (result != MOJO_RESULT_OK && result != MOJO_RESULT_FAILED_PRECONDITION) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      return;
    }
    base::span<const std::uint8_t> data;
    const MojoResult read = pipe_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, data);
    if (read == MOJO_RESULT_SHOULD_WAIT) {
      watcher_.ArmOrNotify();
      return;
    }
    if (read != MOJO_RESULT_OK) {
      StopPipe();
      return;
    }
    std::size_t taken = 0;
    if (!Offer(std::span(data.data(), data.size()), taken, &PartsReader::ReadPipe)) {
      return;
    }
    pipe_->EndReadData(taken);
    pipe_read_ += taken;
    // A full pool re-arms the watcher from ReadPipe once it has room.
    if (taken == data.size()) {
      watcher_.ArmOrNotify();
    }
  }

  void StopPipe() {
    watcher_.Cancel();
    pipe_.reset();
    pipe_done_ = true;
    MaybeEndPipe();
  }

  void MaybeEndPipe() {
    if (!pipe_done_ || !pipe_size_) {
      return;
    }
    if (pipe_read_ != *pipe_size_) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      return;
    }
    getter_.reset();
    pipe_read_ = 0;
    pipe_done_ = false;
    ++index_;
    Next();
  }

  void Finish(const NativeRequestBodyReadEnd end) {
    if (!done_) {
      return;
    }
    watcher_.Cancel();
    pipe_.reset();
    getter_.reset();
    weak_factory_.InvalidateWeakPtrs();
    Reply(reply_, std::move(done_), std::move(stream_), end, body_length_);
    base::SequencedTaskRunner::GetCurrentDefault()->DeleteSoon(FROM_HERE, this);
  }

  scoped_refptr<network::ResourceRequestBody> body_;
  std::vector<Part> parts_;
  NativeArtifactStream stream_;
  scoped_refptr<base::SequencedTaskRunner> reply_;
  Done done_;
  std::size_t index_ = 0;
  std::size_t position_ = 0;
  bool counted_ = false;
  std::uint64_t body_length_ = 0;
  base::File file_;
  std::uint64_t file_offset_ = 0;
  std::uint64_t file_remaining_ = 0;
  std::vector<std::uint8_t> buffered_;
  mojo::Remote<network::mojom::DataPipeGetter> getter_;
  mojo::ScopedDataPipeConsumerHandle pipe_;
  std::optional<std::uint64_t> pipe_size_;
  std::uint64_t pipe_read_ = 0;
  bool pipe_done_ = false;
  mojo::SimpleWatcher watcher_{FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                               base::SequencedTaskRunner::GetCurrentDefault()};
  base::WeakPtrFactory<PartsReader> weak_factory_{this};
};

// Stands in for a stream body's getter: the network reads the page's stream
// through it byte for byte while a tee keeps the bytes. Owned by its receiver
// on the reader's sequence. The page's size answer is its statement that the
// stream ended, so the read is complete once that answer is OK and the tee saw
// exactly that many bytes. The page's pipe closing and the network dropping
// the getter both follow, in either order: the network drops it as soon as the
// size completes a read that already has every byte
// (ChunkedDataPipeUploadDataStream::OnSizeReceived). Dropped earlier, it ends
// an unfinished read.
class ChunkedTee final : public network::mojom::ChunkedDataPipeGetter {
 public:
  ChunkedTee(mojo::PendingRemote<network::mojom::ChunkedDataPipeGetter> original,
             NativeArtifactStream stream,
             scoped_refptr<base::SequencedTaskRunner> reply,
             Done done)
      : pending_original_(std::move(original)),
        stream_(std::move(stream)),
        reply_(std::move(reply)),
        done_(std::move(done)) {}
  ~ChunkedTee() override {
    Finish(SawDeclaredBody() ? NativeRequestBodyReadEnd::kComplete
                             : NativeRequestBodyReadEnd::kIncomplete);
  }

  void GetSize(GetSizeCallback callback) override {
    // The network still gets an answer if the page's getter goes away.
    Original()->GetSize(mojo::WrapCallbackWithDefaultInvokeIfNotRun(
        base::BindOnce(&ChunkedTee::OnSize, weak_factory_.GetWeakPtr(), std::move(callback)),
        static_cast<std::int32_t>(net::ERR_FAILED), std::uint64_t{0}));
  }

  void StartReading(mojo::ScopedDataPipeProducerHandle pipe) override {
    // A restart replays the stream from its start; its bytes are not kept twice.
    if (started_) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
    }
    started_ = true;
    mojo::ScopedDataPipeProducerHandle producer;
    mojo::ScopedDataPipeConsumerHandle consumer;
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(options);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = static_cast<std::uint32_t>(kChunk);
    if (mojo::CreateDataPipe(&options, producer, consumer) != MOJO_RESULT_OK) {
      // Without a tee the page's pipe goes to the network unobserved.
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      Original()->StartReading(std::move(pipe));
      return;
    }
    Original()->StartReading(std::move(producer));
    static_cast<void>(NativeArtifactBodyTee::Forward(
        std::move(consumer), std::move(pipe),
        base::BindOnce(&ChunkedTee::OnEnd, weak_factory_.GetWeakPtr()),
        base::BindRepeating(&ChunkedTee::ObserveData, weak_factory_.GetWeakPtr())));
  }

 private:
  mojo::Remote<network::mojom::ChunkedDataPipeGetter>& Original() {
    if (!original_.is_bound()) {
      original_.Bind(std::move(pending_original_));
    }
    return original_;
  }

  void OnSize(GetSizeCallback callback, const std::int32_t status, const std::uint64_t size) {
    size_ = size;
    size_status_ = status;
    size_known_ = true;
    std::move(callback).Run(status, size);
    MaybeFinish();
  }

  // A WeakPtr cannot bind a method that returns a value, so the tee's observer
  // checks it here: once the getter is gone, the rest of the upload passes
  // unobserved.
  static std::size_t ObserveData(const base::WeakPtr<ChunkedTee>& tee,
                                 const std::span<const std::uint8_t> chunk,
                                 base::OnceClosure resume) {
    return tee ? tee->OnData(chunk, std::move(resume)) : chunk.size();
  }

  std::size_t OnData(const std::span<const std::uint8_t> chunk, base::OnceClosure resume) {
    if (!done_) {
      return chunk.size();
    }
    // The upload waits for the pool, as a response body does.
    const std::size_t taken = stream_.Offer(chunk);
    if (!stream_.is_open()) {
      Finish(NativeRequestBodyReadEnd::kIncomplete);
      return chunk.size();
    }
    if (taken < chunk.size()) {
      stream_.WaitForSpace(std::move(resume));
    }
    return taken;
  }

  void OnEnd(const NativeArtifactBodyEnd end) {
    tee_end_ = end;
    tee_done_ = true;
    MaybeFinish();
  }

  // A read still open, sized OK by the page, holding exactly that many bytes.
  bool SawDeclaredBody() const {
    return done_ && size_known_ && size_status_ == net::OK && size_ == stream_.observed();
  }

  void MaybeFinish() {
    if (tee_done_ && size_known_) {
      Finish(tee_end_ == NativeArtifactBodyEnd::kSourceClosed && SawDeclaredBody()
                 ? NativeRequestBodyReadEnd::kComplete
                 : NativeRequestBodyReadEnd::kIncomplete);
    }
  }

  void Finish(const NativeRequestBodyReadEnd end) {
    if (!done_) {
      return;
    }
    const std::uint64_t length = std::max(size_, stream_.observed());
    Reply(reply_, std::move(done_), std::move(stream_), end, length);
  }

  mojo::PendingRemote<network::mojom::ChunkedDataPipeGetter> pending_original_;
  mojo::Remote<network::mojom::ChunkedDataPipeGetter> original_;
  NativeArtifactStream stream_;
  scoped_refptr<base::SequencedTaskRunner> reply_;
  Done done_;
  bool started_ = false;
  bool size_known_ = false;
  std::int32_t size_status_ = net::OK;
  std::uint64_t size_ = 0;
  bool tee_done_ = false;
  NativeArtifactBodyEnd tee_end_ = NativeArtifactBodyEnd::kSourceClosed;
  base::WeakPtrFactory<ChunkedTee> weak_factory_{this};
};

}  // namespace

bool NativeRequestBodyReader::CanRead(const network::ResourceRequestBody& body) noexcept {
  for (const network::DataElement& element : *body.elements()) {
    // Start tees only a lone stream; a compromised renderer can send others.
    if (element.TryAs<network::DataElementChunkedDataPipe>() && body.elements()->size() != 1) {
      return false;
    }
    if (!element.TryAs<network::DataElementBytes>() && !element.TryAs<network::DataElementFile>() &&
        !element.TryAs<network::DataElementDataPipe>() &&
        !element.TryAs<network::DataElementChunkedDataPipe>()) {
      return false;
    }
  }
  return !body.elements()->empty();
}

bool NativeRequestBodyReader::MayReadFiles(const network::ResourceRequestBody& body,
                                           const NativeBrowserRequestOwner& owner) noexcept {
  auto* const policy = content::ChildProcessSecurityPolicy::GetInstance();
  for (const network::DataElement& element : *body.elements()) {
    const auto* const file = element.TryAs<network::DataElementFile>();
    if (!file) {
      continue;
    }
    switch (owner.body_files) {
      case NativeBodyFileAccess::kNavigationValidated:
        break;
      case NativeBodyFileAccess::kRendererChecked:
        // The same check the file-upload path makes for this renderer.
        if (policy->CanReadFile(
                content::ChildProcessId::FromUnsafeValue(owner.body_file_process_id),
                file->path())) {
          break;
        }
        return false;
      case NativeBodyFileAccess::kRefused:
        return false;
    }
  }
  return true;
}

bool NativeRequestBodyReader::Start(network::ResourceRequestBody& body,
                                    NativeArtifactStream stream,
                                    Done done) {
  if (!CanRead(body) || !base::SequencedTaskRunner::HasCurrentDefault()) {
    return false;
  }
  const scoped_refptr<base::SequencedTaskRunner> runner =
      base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock(),
                                                   base::TaskPriority::USER_VISIBLE,
                                                   base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN});
  scoped_refptr<base::SequencedTaskRunner> reply = base::SequencedTaskRunner::GetCurrentDefault();
  std::vector<network::DataElement>& elements = *body.elements_mutable();
  if (elements.size() == 1 && elements[0].TryAs<network::DataElementChunkedDataPipe>()) {
    auto& chunked = elements[0].As<network::DataElementChunkedDataPipe>();
    const auto read_only_once = chunked.read_only_once();
    mojo::PendingRemote<network::mojom::ChunkedDataPipeGetter> tee;
    auto receiver = tee.InitWithNewPipeAndPassReceiver();
    // Mojo requires a receiver's first use to be on the sequence that dispatches
    // to it, and setting its disconnect handler is a use, so the tee is bound on
    // the reader's sequence. The network's calls wait in the pipe until then.
    // Only a pool that is shutting down drops the task: the tee then reports the
    // read incomplete as it is destroyed, and the request sees its getter gone.
    static_cast<void>(runner->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](std::unique_ptr<ChunkedTee> impl,
               mojo::PendingReceiver<network::mojom::ChunkedDataPipeGetter> receiver) {
              mojo::MakeSelfOwnedReceiver(std::move(impl), std::move(receiver));
            },
            std::make_unique<ChunkedTee>(chunked.ReleaseChunkedDataPipeGetter(), std::move(stream),
                                         std::move(reply), std::move(done)),
            std::move(receiver))));
    elements[0] =
        network::DataElement(network::DataElementChunkedDataPipe(std::move(tee), read_only_once));
    return true;
  }
  std::vector<Part> parts;
  for (std::size_t index = 0; index < elements.size(); ++index) {
    Part part;
    part.element = index;
    if (const auto* file = elements[index].TryAs<network::DataElementFile>()) {
      part.kind = Part::Kind::kFile;
      part.path = file->path();
      part.offset = file->offset();
      part.length = file->length();
      part.expected_modification_time = file->expected_modification_time();
    } else if (const auto* pipe = elements[index].TryAs<network::DataElementDataPipe>()) {
      part.kind = Part::Kind::kDataPipe;
      // A clone reads the same blob; the request keeps its own getter.
      part.getter = pipe->CloneDataPipeGetter();
    }
    parts.push_back(std::move(part));
  }
  return runner->PostTask(
      FROM_HERE, base::BindOnce(
                     [](scoped_refptr<network::ResourceRequestBody> body, std::vector<Part> parts,
                        NativeArtifactStream stream, scoped_refptr<base::SequencedTaskRunner> reply,
                        Done done) {
                       (new PartsReader(std::move(body), std::move(parts), std::move(stream),
                                        std::move(reply), std::move(done)))
                           ->Next();
                     },
                     base::WrapRefCounted(&body), std::move(parts), std::move(stream),
                     std::move(reply), std::move(done)));
}

}  // namespace reb
