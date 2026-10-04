// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_console_session.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/command_line.h"
#include "base/files/scoped_file.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/no_destructor.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/browser/native_local_ipc_client.h"
#include "brave/components/reverse_engineering_browser/common/native_console.mojom.h"
#include "brave/components/reverse_engineering_browser/common/native_console_io.h"
#include "brave/components/reverse_engineering_browser/common/native_console_protocol.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/weak_document_ptr.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_contents_observer.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "mojo/public/cpp/bindings/callback_helpers.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/mojom/loader/resource_load_info.mojom.h"
#include "url/origin.h"

namespace reb {
namespace {

struct Reply final {
  explicit Reply(std::uint64_t id) { header.request_id = id; }
  NativeConsoleResponse header;
  std::string payload;
  base::WaitableEvent ready{base::WaitableEvent::ResetPolicy::MANUAL,
                            base::WaitableEvent::InitialState::NOT_SIGNALED};
  void Fail(NativeConsoleStatus status, const char* message) {
    header.status = status;
    payload = message;
    header.payload_bytes = static_cast<std::uint32_t>(payload.size());
    ready.Signal();
  }
};

struct Target final {
  std::uint64_t id = 0;
  content::WeakDocumentPtr document;
  base::UnguessableToken renderer_document;
  mojo::AssociatedRemote<mojom::NativeConsoleAgent> agent;
  std::string origin;
  std::string label;
  std::string url;
  bool main_frame = false;
  bool metadata_truncated = false;
  bool complete = false;
};

// One observer per owned WebContents. All collection runs on the UI thread and
// copies metadata only. No response content, headers, cookies, paths or queries.
class ConsoleActivity final : public content::WebContentsObserver {
 public:
  using Capture = base::RepeatingCallback<void(content::RenderFrameHost*,
                                               const blink::mojom::ResourceLoadInfo&)>;
  ConsoleActivity(content::WebContents* contents, Capture capture)
      : content::WebContentsObserver(contents), capture_(std::move(capture)) {}
  void ResourceLoadComplete(content::RenderFrameHost* frame,
                            const content::GlobalRequestID&,
                            const blink::mojom::ResourceLoadInfo& info) override {
    capture_.Run(frame, info);
  }

 private:
  Capture capture_;
};

class Session final {
 public:
  static Session& Get() {
    static base::NoDestructor<Session> session;
    return *session;
  }
  void Start(base::OnceClosure retired) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (started_)
      return;
    started_ = true;
    retired_ = std::move(retired);
    const auto& command = *base::CommandLine::ForCurrentProcess();
    user_data_dir_ = command.GetSwitchValuePath("user-data-dir");
    std::uint64_t id = 0;
    if (!base::StringToUint64(command.GetSwitchValueASCII("reb-native-console-session-id"), &id) ||
        !id)
      return;
    base::ThreadPool::PostTask(
        FROM_HERE,
        {base::MayBlock(), base::WithBaseSyncPrimitives(), base::TaskPriority::USER_VISIBLE,
         base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
        base::BindOnce(&Session::Run, base::Unretained(this),
                       base::SingleThreadTaskRunner::GetCurrentDefault(),
                       command.GetSwitchValueASCII("reb-native-console-socket"),
                       command.GetSwitchValuePath("reb-native-console-token-file"), id));
  }

 private:
  friend class base::NoDestructor<Session>;
  Session() = default;
  void Run(scoped_refptr<base::SingleThreadTaskRunner> ui,
           std::string path,
           base::FilePath token,
           std::uint64_t id) {
    // Socket I/O and token-file access never run on browser UI or renderer
    // threads. One command may be in flight; a timeout retires the session.
    int descriptor = -1;
    for (int attempt = 0; attempt < 40 && descriptor < 0; ++attempt) {
      struct stat parent {
      }, endpoint{};
      const auto directory = base::FilePath(path).DirName();
      if (lstat(directory.value().c_str(), &parent) != 0 || !S_ISDIR(parent.st_mode) ||
          parent.st_uid != geteuid() || (parent.st_mode & 0777) != 0700) {
        ui->PostTask(FROM_HERE, base::BindOnce(&Session::Retire, base::Unretained(this)));
        return;
      }
      if (lstat(path.c_str(), &endpoint) == 0 && S_ISSOCK(endpoint.st_mode) &&
          endpoint.st_uid == geteuid() && (endpoint.st_mode & 0777) == 0600)
        descriptor = ConnectNativeLocalIpc(path, token, id, true);
      if (descriptor < 0)
        base::PlatformThread::Sleep(base::Milliseconds(50));
    }
    base::ScopedFD socket(descriptor);
    if (!socket.is_valid()) {
      ui->PostTask(FROM_HERE, base::BindOnce(&Session::Retire, base::Unretained(this)));
      return;
    }
    active_.store(true, std::memory_order_release);
    const auto expires = std::chrono::steady_clock::now() + std::chrono::hours(1);
    std::uint64_t last_request = 0;
    for (;;) {
      NativeConsoleRequest request;
      if (!NativeConsoleRead(socket.get(), NativeConsoleBytes(request), expires) ||
          !IsNativeConsoleRequest(request) || request.request_id <= last_request)
        break;
      last_request = request.request_id;
      std::string source(request.source_bytes, '\0');
      const auto deadline =
          std::chrono::steady_clock::now() + std::chrono::milliseconds(kNativeConsoleReplyMillis);
      if (!NativeConsoleRead(socket.get(), std::as_writable_bytes(std::span(source)), deadline))
        break;
      auto reply = std::make_shared<Reply>(request.request_id);
      const auto execute_before = base::TimeTicks::Now() + base::Milliseconds(500);
      if (!ui->PostTask(FROM_HERE,
                        base::BindOnce(&Session::Dispatch, base::Unretained(this), request,
                                       std::move(source), execute_before, reply)))
        break;
      if (!reply->ready.TimedWait(base::Milliseconds(kNativeConsoleReplyMillis))) {
        active_.store(false, std::memory_order_release);
        // Do not touch Reply while a late UI callback may still write it.
        NativeConsoleResponse timeout;
        timeout.request_id = request.request_id;
        timeout.status = NativeConsoleStatus::kTimeout;
        static_cast<void>(
            NativeConsoleWrite(socket.get(), NativeConsoleBytes(timeout),
                               std::chrono::steady_clock::now() + std::chrono::milliseconds(100)));
        break;
      }
      if (!NativeConsoleWrite(socket.get(), NativeConsoleBytes(reply->header), deadline) ||
          !NativeConsoleWrite(socket.get(), std::as_bytes(std::span(reply->payload)), deadline))
        break;
    }
    active_.store(false, std::memory_order_release);
    ui->PostTask(FROM_HERE, base::BindOnce(&Session::Retire, base::Unretained(this)));
  }

  void Retire() {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    targets_.clear();
    observers_.clear();
    activity_.clear();
    // The caller owns the disposable browser lifetime. Loss of the control
    // channel must not leave a mutable experiment running without its owner.
    if (retired_)
      std::move(retired_).Run();
  }

  bool Eligible(content::RenderFrameHost* frame) const {
    // BrowserContext paths identify profiles (for example <user-data-dir>/Default),
    // not the user-data root. Only profiles inside the owned disposable root qualify.
    return frame && frame->IsActive() && frame->IsRenderFrameLive() &&
           frame->GetBrowserContext()->GetPath().DirName() == user_data_dir_ &&
           (frame->GetLastCommittedOrigin().scheme() == "http" ||
            frame->GetLastCommittedOrigin().scheme() == "https");
  }

  void Dispatch(NativeConsoleRequest request,
                std::string source,
                base::TimeTicks deadline,
                std::shared_ptr<Reply> reply) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (!active_.load(std::memory_order_acquire) || base::TimeTicks::Now() >= deadline) {
      reply->Fail(NativeConsoleStatus::kTimeout, "Console session expired before dispatch");
      return;
    }
    if (request.operation == NativeConsoleOperation::kTargets) {
      List(std::move(reply));
      return;
    }
    if (!base::IsStringUTF8(source) || source.find('\0') != std::string::npos) {
      reply->Fail(NativeConsoleStatus::kMalformed,
                  "JavaScript must be valid UTF-8 without NUL bytes");
      return;
    }
    Target* selected = nullptr;
    for (auto& target : targets_)
      if (target.id == request.target_id)
        selected = &target;
    if (!selected || selected->renderer_document.is_empty() ||
        !Eligible(selected->document.AsRenderFrameHostIfValid())) {
      reply->Fail(NativeConsoleStatus::kStaleTarget,
                  "Selected document navigated, closed, or is no longer active");
      return;
    }
    const auto command = request.operation == NativeConsoleOperation::kRuntime
                             ? base::JSONReader::ReadDict(source)
                             : std::nullopt;
    const auto* operation = command ? command->FindString("operation") : nullptr;
    if (operation && *operation == "traffic") {
      base::Value::List events;
      for (auto iterator = activity_.begin(); iterator != activity_.end();) {
        if (*iterator->FindString("document_id") == base::NumberToString(request.target_id)) {
          events.Append(std::move(*iterator));
          iterator = activity_.erase(iterator);
        } else
          ++iterator;
      }
      base::Value::Dict value;
      value.Set("status", "ok")
          .Set("events", std::move(events))
          .Set("dropped", static_cast<int>(activity_drops_));
      activity_drops_ = 0;
      if (!base::JSONWriter::Write(value, &reply->payload) ||
          reply->payload.size() > kNativeConsolePayloadLimit) {
        reply->Fail(NativeConsoleStatus::kMalformed, "Activity exceeded bounded transport");
        return;
      }
      reply->header.type = NativeConsoleType::kRuntime;
      reply->header.payload_bytes = static_cast<std::uint32_t>(reply->payload.size());
      reply->ready.Signal();
      return;
    }
    if (request.operation == NativeConsoleOperation::kEvaluate ||
        (operation && *operation == "evaluate"))
      last_evaluation_ = request.request_id;
    const auto weak_document = selected->document;
    auto callback = mojo::WrapCallbackWithDefaultInvokeIfNotRun(
        base::BindOnce(
            [](content::WeakDocumentPtr document, std::shared_ptr<Reply> result,
               std::uint16_t status, std::uint16_t type, const std::string& text, bool truncated) {
              if (!document.AsRenderFrameHostIfValid()) {
                result->Fail(NativeConsoleStatus::kStaleTarget,
                             "Document changed during execution; side effects may have occurred");
                return;
              }
              if (status > static_cast<std::uint16_t>(NativeConsoleStatus::kDisconnected) ||
                  type > static_cast<std::uint16_t>(NativeConsoleType::kRuntime) ||
                  type == static_cast<std::uint16_t>(NativeConsoleType::kTargets) ||
                  text.size() > (type == static_cast<std::uint16_t>(NativeConsoleType::kRuntime)
                                     ? kNativeConsolePayloadLimit
                                     : kNativeConsoleTextLimit) ||
                  !base::IsStringUTF8(text)) {
                result->Fail(NativeConsoleStatus::kMalformed,
                             "Renderer returned an invalid console result");
                return;
              }
              result->header.status = static_cast<NativeConsoleStatus>(status);
              result->header.type = static_cast<NativeConsoleType>(type);
              result->header.flags = truncated ? kNativeConsoleTruncated : 0;
              result->payload = text;
              result->header.payload_bytes = static_cast<std::uint32_t>(text.size());
              result->ready.Signal();
            },
            weak_document, reply),
        static_cast<std::uint16_t>(NativeConsoleStatus::kDisconnected),
        static_cast<std::uint16_t>(NativeConsoleType::kUndefined),
        std::string("Renderer disconnected"), false);
    const auto expires = static_cast<std::uint64_t>(deadline.since_origin().InMicroseconds());
    if (request.operation == NativeConsoleOperation::kRuntime)
      selected->agent->Runtime(selected->renderer_document, expires, source, std::move(callback));
    else
      selected->agent->Evaluate(selected->renderer_document, expires, source, std::move(callback));
  }

  void List(std::shared_ptr<Reply> reply) {
    targets_.clear();
    activity_drops_ =
        std::min(2147483647u, activity_drops_ + static_cast<unsigned>(activity_.size()));
    activity_.clear();
    std::erase_if(observers_,
                  [](const auto& observer) { return observer->web_contents() == nullptr; });
    bool truncated = false;
    std::size_t processes = 0;
    for (auto iterator = content::RenderProcessHost::AllHostsIterator(); !iterator.IsAtEnd();
         iterator.Advance()) {
      if (++processes > kNativeConsoleTargetLimit) {
        truncated = true;
        break;
      }
      iterator.GetCurrentValue()->ForEachRenderFrameHost([&](content::RenderFrameHost* frame) {
        if (!Eligible(frame))
          return;
        if (targets_.size() == kNativeConsoleTargetLimit) {
          truncated = true;
          return;
        }
        Target target;
        target.id = next_target_++;
        target.document = frame->GetWeakDocumentPtr();
        auto* contents = content::WebContents::FromRenderFrameHost(frame);
        if (contents && observers_.size() < kNativeConsoleTargetLimit &&
            std::none_of(observers_.begin(), observers_.end(), [&](const auto& observer) {
              return observer->web_contents() == contents;
            }))
          observers_.push_back(std::make_unique<ConsoleActivity>(
              contents, base::BindRepeating(&Session::CaptureActivity, base::Unretained(this))));
        target.origin = frame->GetLastCommittedOrigin().Serialize();
        target.main_frame = frame->GetParentOrOuterDocument() == nullptr;
        const auto& url = frame->GetLastCommittedURL().spec();
        const auto& frame_name = frame->GetFrameName();
        auto name = frame_name.substr(0, 48);
        while (!name.empty() && !base::IsStringUTF8(name))
          name.pop_back();
        target.url = url.substr(0, 512);
        target.metadata_truncated = url.size() > 512 || name.size() < frame_name.size() ||
                                    (contents && contents->GetTitle().size() > 64);
        target.label =
            (target.main_frame ? "top #" : "frame #") + base::NumberToString(target.id) +
            (target.main_frame || name.empty() ? "" : " " + name) + " · " +
            (contents ? base::UTF16ToUTF8(contents->GetTitle().substr(0, 64)) : std::string());
        frame->GetRemoteAssociatedInterfaces()->GetInterface(&target.agent);
        targets_.push_back(std::move(target));
      });
    }
    reply->header.type = NativeConsoleType::kTargets;
    reply->header.flags = truncated ? kNativeConsoleTruncated : 0;
    pending_ = targets_.size();
    if (!pending_) {
      FinishList(std::move(reply));
      return;
    }
    for (std::size_t index = 0; index < targets_.size(); ++index) {
      targets_[index].agent->Describe(mojo::WrapCallbackWithDefaultInvokeIfNotRun(
          base::BindOnce(&Session::Described, base::Unretained(this), index, reply),
          std::optional<base::UnguessableToken>()));
    }
  }

  void Described(std::size_t index,
                 std::shared_ptr<Reply> reply,
                 const std::optional<base::UnguessableToken>& token) {
    if (!active_.load(std::memory_order_acquire))
      return;
    auto& target = targets_[index];
    target.renderer_document = token.value_or(base::UnguessableToken());
    target.complete = true;
    if (--pending_ == 0)
      FinishList(std::move(reply));
  }

  void FinishList(std::shared_ptr<Reply> reply) {
    for (const auto& target : targets_) {
      if (!target.complete || target.renderer_document.is_empty() ||
          !Eligible(target.document.AsRenderFrameHostIfValid())) {
        reply->header.flags = kNativeConsoleTruncated;
        continue;
      }
      NativeConsoleTarget record;
      record.id = target.id;
      const std::size_t size = std::min(target.origin.size(), record.origin.size());
      record.origin_bytes = static_cast<std::uint16_t>(size);
      record.flags =
          (target.origin.size() > size || target.metadata_truncated ? kNativeConsoleTruncated : 0) |
          (target.main_frame ? 2 : 0);
      std::memcpy(record.origin.data(), target.origin.data(), size);
      auto copy = [&](const std::string& text, auto& buffer, std::uint16_t& bytes) {
        auto bounded = text.substr(0, buffer.size());
        while (!bounded.empty() && !base::IsStringUTF8(bounded))
          bounded.pop_back();
        bytes = static_cast<std::uint16_t>(bounded.size());
        std::memcpy(buffer.data(), bounded.data(), bounded.size());
        if (bounded.size() < text.size())
          record.flags |= kNativeConsoleTruncated;
      };
      copy(target.label, record.label, record.label_bytes);
      copy(target.url, record.url, record.url_bytes);
      reply->payload.append(reinterpret_cast<const char*>(&record), sizeof(record));
      ++reply->header.item_count;
    }
    reply->header.payload_bytes = static_cast<std::uint32_t>(reply->payload.size());
    reply->ready.Signal();
  }

  void CaptureActivity(content::RenderFrameHost* frame,
                       const blink::mojom::ResourceLoadInfo& info) {
    if (!active_.load(std::memory_order_acquire) || !Eligible(frame))
      return;
    for (const auto& target : targets_) {
      if (target.document.AsRenderFrameHostIfValid() != frame)
        continue;
      auto origin = url::Origin::Create(info.final_url).Serialize();
      if (origin.size() > 256 || origin == "null")
        return;
      if (activity_.size() == 64) {
        activity_.pop_front();
        if (activity_drops_ < 2147483647)
          ++activity_drops_;
      }
      activity_.push_back(base::Value::Dict()
                              .Set("event_id", base::NumberToString(next_activity_++))
                              .Set("document_id", base::NumberToString(target.id))
                              .Set("resource_id", base::NumberToString(info.request_id))
                              .Set("after_request_id", base::NumberToString(last_evaluation_))
                              .Set("origin", origin)
                              .Set("method", info.method.substr(0, 16))
                              .Set("status", info.http_status_code)
                              .Set("network_error", info.net_error)
                              .Set("cached", info.was_cached)
                              .Set("time", base::Time::Now().InMillisecondsFSinceUnixEpoch())
                              .Set("operation", "resource_load_complete"));
      break;
    }
  }
  std::vector<std::unique_ptr<ConsoleActivity>> observers_;
  std::deque<base::Value::Dict> activity_;
  std::uint64_t next_activity_ = 1;
  std::uint64_t last_evaluation_ = 0;
  unsigned activity_drops_ = 0;

  // Metadata and weak document references only; no V8 objects are retained.
  base::FilePath user_data_dir_;
  std::vector<Target> targets_;
  std::uint64_t next_target_ = 1;
  std::size_t pending_ = 0;
  bool started_ = false;
  base::OnceClosure retired_;
  std::atomic<bool> active_{false};
};

}  // namespace

bool IsNativeConsoleEnabled() {
  const auto& command = *base::CommandLine::ForCurrentProcess();
  if (!command.HasSwitch(kNativeConsoleSwitch) || command.HasSwitch("remote-debugging-port") ||
      command.HasSwitch("remote-debugging-pipe"))
    return false;
  const auto socket = command.GetSwitchValuePath("reb-native-console-socket");
  return socket.IsAbsolute() &&
         !command.GetSwitchValuePath("reb-native-console-token-file").empty() &&
         command.HasSwitch("reb-native-console-session-id") &&
         command.GetSwitchValuePath("user-data-dir") == socket.DirName().AppendASCII("profile");
}

void StartNativeConsoleSession(base::OnceClosure retired) {
  if (IsNativeConsoleEnabled())
    Session::Get().Start(std::move(retired));
}

}  // namespace reb
