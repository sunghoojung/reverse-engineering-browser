// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_console_session.h"

#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file_util.h"
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
#include "base/unguessable_token.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/browser/native_console_document_start.h"
#include "brave/components/reverse_engineering_browser/browser/native_local_ipc_client.h"
#include "brave/components/reverse_engineering_browser/browser/native_probe_session.h"
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
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/mojom/loader/resource_load_info.mojom.h"
#include "url/gurl.h"
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
  // Reaches the renderer's IO thread, so Stop is heard during a command.
  mojo::Remote<mojom::NativeConsoleControl> control;
  std::string origin;
  std::string label;
  std::string url;
  bool main_frame = false;
  bool metadata_truncated = false;
  bool complete = false;
};

// A Console `watch` on one document: whether to keep its rules, and the exact
// origin and frame kind the browser itself reads from that document, so a
// kept scope never names anything the command supplied.
struct WatchCommand final {
  bool keep = false;
  std::string origin;
  bool top_frame = false;
  base::DictValue rules;
};

// The rules a renderer just accepted, as the scope every renderer rebuilds for
// each later document of this origin and frame kind
// (protocol/native-debugger-observation-v1.md). Null when only DOM rules, which
// name this document's own nodes, or no rule at all would be kept.
mojom::NativeWatchScopePtr KeptWatchScope(const WatchCommand& watch, std::uint64_t serial) {
  auto scope = mojom::NativeWatchScope::New();
  scope->serial = serial;
  scope->origin = watch.origin;
  scope->top_frame = watch.top_frame;
  if (const auto* requests = watch.rules.FindList("requests")) {
    for (const auto& item : *requests) {
      const auto* rule = item.GetIfDict();
      const auto* url = rule ? rule->FindString("url_contains") : nullptr;
      if (!url)
        return nullptr;
      const auto* method = rule->FindString("method");
      scope->requests.push_back(
          mojom::NativeWatchRequestRule::New(*url, method ? *method : std::string()));
    }
  }
  if (const auto* events = watch.rules.FindList("events")) {
    for (const auto& item : *events) {
      if (!item.is_string())
        return nullptr;
      scope->events.push_back(item.GetString());
    }
  }
  scope->timers = watch.rules.FindBool("timers").value_or(false);
  scope->csp = watch.rules.FindBool("csp").value_or(false);
  const auto* exceptions = watch.rules.FindString("exceptions");
  scope->uncaught = exceptions && (*exceptions == "uncaught" || *exceptions == "all");
  scope->caught = exceptions && *exceptions == "all";
  if (scope->requests.empty() && scope->events.empty() && !scope->timers && !scope->csp &&
      !scope->uncaught)
    return nullptr;
  return scope;
}

// One observer per owned WebContents. All collection runs on the UI thread and
// copies metadata only. No response content, headers, cookies, paths or queries.
class ConsoleActivity final : public content::WebContentsObserver {
 public:
  using Capture = base::RepeatingCallback<void(content::RenderFrameHost*,
                                               const blink::mojom::ResourceLoadInfo&)>;
  ConsoleActivity(content::WebContents* contents, Capture capture)
      : content::WebContentsObserver(contents), capture_(std::move(capture)) {}
  // Only info.final_url's origin is kept, so the full original URL that
  // Chromium 157 passes beside the possibly sanitized info is not read.
  void ResourceLoadComplete(content::RenderFrameHost* frame,
                            const content::GlobalRequestID&,
                            const GURL&,
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
    // Chromium canonicalizes the profile root. Resolve the explicitly owned
    // directory once at startup too: /tmp and /var are aliases on macOS.
    user_data_dir_ = base::MakeAbsoluteFilePath(command.GetSwitchValuePath("user-data-dir"));
    if (user_data_dir_.empty())
      return;
    std::uint64_t id = 0;
    if (!base::StringToUint64(command.GetSwitchValueASCII("reb-native-console-session-id"), &id) ||
        !id)
      return;
    // Run waits on the owner's socket for the whole session. Thread pool
    // shutdown joins a running SKIP_ON_SHUTDOWN task, so a connected console
    // would keep the browser alive after Quit or SIGTERM. The never-destroyed
    // Session and failed UI posts make abandoning the worker safe.
    base::ThreadPool::PostTask(
        FROM_HERE,
        {base::MayBlock(), base::WithBaseSyncPrimitives(), base::TaskPriority::USER_VISIBLE,
         base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
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
      struct stat parent = {};
      struct stat endpoint = {};
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
    // A record already being sent must keep moving; however large, it fails
    // only when it stalls this long.
    constexpr std::chrono::milliseconds stall(kNativeConsoleTransferMillis);
    std::uint64_t last_request = 0;
    for (;;) {
      NativeConsoleRequest request;
      if (!NativeConsoleRead(socket.get(), NativeConsoleBytes(request), expires) ||
          !IsNativeConsoleRequest(request))
        break;
      // A Stop that crossed the answer to the request it names is spent.
      if (request.operation == NativeConsoleOperation::kStop) {
        if (request.request_id != last_request)
          break;
        continue;
      }
      if (request.request_id <= last_request)
        break;
      last_request = request.request_id;
      std::string source(request.source_bytes, '\0');
      if (!NativeConsoleRead(socket.get(), std::as_writable_bytes(std::span(source)), stall))
        break;
      auto reply = std::make_shared<Reply>(request.request_id);
      const auto execute_before =
          base::TimeTicks::Now() + base::Milliseconds(kNativeConsoleDispatchMillis);
      if (!ui->PostTask(FROM_HERE,
                        base::BindOnce(&Session::Dispatch, base::Unretained(this), request,
                                       std::move(source), execute_before, reply)))
        break;
      if (!Await(socket.get(), ui, request, *reply, expires)) {
        active_.store(false, std::memory_order_release);
        // Nobody can read a later answer, so the command must not run on.
        ui->PostTask(FROM_HERE, base::BindOnce(&Session::Stop, base::Unretained(this),
                                               request.target_id, request.request_id));
        // Do not touch Reply while a late UI callback may still write it.
        NativeConsoleResponse timeout;
        timeout.request_id = request.request_id;
        timeout.status = NativeConsoleStatus::kTimeout;
        static_cast<void>(
            NativeConsoleWrite(socket.get(), NativeConsoleBytes(timeout),
                               std::chrono::steady_clock::now() + std::chrono::milliseconds(100)));
        break;
      }
      if (!NativeConsoleWrite(socket.get(), NativeConsoleBytes(reply->header), stall) ||
          !NativeConsoleWrite(socket.get(), std::as_bytes(std::span(reply->payload)), stall))
        break;
    }
    active_.store(false, std::memory_order_release);
    ui->PostTask(FROM_HERE, base::BindOnce(&Session::Retire, base::Unretained(this)));
  }

  // Waits for the reply to `request` for as long as the command runs, while
  // listening for the owner's Stop. False when the session hour ends, the
  // owner sends anything but a Stop for this request, or a Stop gets no reply
  // in time: the exchange is then ambiguous and the session retires.
  bool Await(int socket,
             const scoped_refptr<base::SingleThreadTaskRunner>& ui,
             const NativeConsoleRequest& request,
             Reply& reply,
             std::chrono::steady_clock::time_point expires) {
    std::optional<std::chrono::steady_clock::time_point> stopping;
    while (!reply.ready.TimedWait(base::Milliseconds(50))) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= expires || (stopping && now >= *stopping))
        return false;
      pollfd owner{socket, POLLIN, 0};
      const int ready = poll(&owner, 1, 0);
      if (ready < 0 && errno != EINTR)
        return false;
      if (ready <= 0)
        continue;
      if ((owner.revents & POLLIN) == 0)
        return false;
      NativeConsoleRequest stop;
      if (!NativeConsoleRead(socket, NativeConsoleBytes(stop),
                             now + std::chrono::milliseconds(kNativeConsoleTransferMillis)) ||
          !IsNativeConsoleRequest(stop) || stop.operation != NativeConsoleOperation::kStop ||
          stop.request_id != request.request_id)
        return false;
      if (stopping)
        continue;
      stopping = now + std::chrono::milliseconds(kNativeConsoleStopMillis);
      if (!ui->PostTask(FROM_HERE, base::BindOnce(&Session::Stop, base::Unretained(this),
                                                  request.target_id, request.request_id)))
        return false;
    }
    return true;
  }

  void Stop(std::uint64_t target_id, std::uint64_t request_id) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    for (auto& target : targets_)
      if (target.id == target_id && target.control.is_bound())
        target.control->Stop(request_id);
  }

  void Retire() {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    targets_.clear();
    documents_.clear();
    observers_.clear();
    activity_.clear();
    // Losing the owner must not leave armed scripts running in new documents,
    // or kept watch rules arming them.
    NativeConsoleDocumentStartRegistry::Get().Clear();
    NativeProbeSession::Get().SetDebuggerWatchScope(nullptr);
    // The caller owns the disposable browser lifetime. Loss of the control
    // channel must not leave a mutable experiment running without its owner.
    if (retired_)
      std::move(retired_).Run();
  }

 public:
  // Public so the document-start registry applies exactly this admission rule
  // rather than a second copy of it.
  bool Eligible(content::RenderFrameHost* frame) const {
    // BrowserContext paths identify profiles (for example <user-data-dir>/Default),
    // not the user-data root. Only profiles inside the owned disposable root qualify.
    return frame && frame->IsActive() && frame->IsRenderFrameLive() &&
           frame->GetBrowserContext()->GetPath().DirName() == user_data_dir_ &&
           (frame->GetLastCommittedOrigin().scheme() == "http" ||
            frame->GetLastCommittedOrigin().scheme() == "https");
  }

  // One monotonic identity space for Console targets and document-start
  // records. A document that is not a current target still gets a stable
  // nonsecret ID, remembered for the session keyed by its exact generation,
  // so a document that reports again after any number of others keeps it.
  // The lookup half of DocumentId: no assignment.
  std::uint64_t DocumentIdIfAssigned(content::RenderFrameHost* frame) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (!Eligible(frame))
      return 0;
    for (const auto& target : targets_) {
      if (target.document.AsRenderFrameHostIfValid() == frame)
        return target.id;
    }
    const auto found = documents_.find(frame->GetDocumentToken().value());
    return found == documents_.end() ? 0 : found->second;
  }

  std::uint64_t DocumentId(content::RenderFrameHost* frame) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (!Eligible(frame))
      return 0;
    for (const auto& target : targets_) {
      if (target.document.AsRenderFrameHostIfValid() == frame)
        return target.id;
    }
    const auto token = frame->GetDocumentToken().value();
    if (const auto found = documents_.find(token); found != documents_.end())
      return found->second;
    if (!next_target_)
      return 0;
    const auto id = next_target_++;
    documents_.emplace(token, id);
    return id;
  }

 private:
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
    // Session-scoped: the armed set belongs to the console session, never to a
    // selected document, so this path takes no target and never goes stale.
    if (request.operation == NativeConsoleOperation::kDocumentStart) {
      DocumentStart(source, std::move(reply));
      return;
    }
    const auto command = request.operation == NativeConsoleOperation::kRuntime
                             ? base::JSONReader::ReadDict(source, base::JSON_PARSE_RFC)
                             : std::nullopt;
    const auto* operation = command ? command->FindString("operation") : nullptr;
    // Forgets the kept scope even when the document its rules were armed on
    // is gone, so the owner can always clear it.
    if (operation && *operation == "unwatch")
      NativeProbeSession::Get().SetDebuggerWatchScope(nullptr);
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
    if (operation && *operation == "traffic") {
      // Every event waits until the owner reads it. A reply takes the oldest
      // that fit the transport and says whether more remain, so no number of
      // events is refused or lost.
      base::ListValue events;
      bool more = false;
      if (const auto found = activity_.find(request.target_id); found != activity_.end()) {
        // The envelope at its widest: status, dropped and more.
        std::size_t bytes =
            std::string_view(R"({"dropped":2147483647,"events":[],"more":false,"status":"ok"})")
                .size();
        auto& pending = found->second;
        while (!pending.empty()) {
          std::string event;
          if (!base::JSONWriter::Write(pending.front(), &event))
            event.clear();
          const std::size_t needed = event.size() + (events.empty() ? 0 : 1);
          if (bytes + needed > kNativeConsoleReplyLimit) {
            more = true;
            break;
          }
          bytes += needed;
          events.Append(std::move(pending.front()));
          pending.pop_front();
        }
        if (pending.empty())
          activity_.erase(found);
      }
      base::DictValue value;
      value.Set("status", "ok");
      value.Set("events", std::move(events));
      value.Set("more", more);
      value.Set("dropped", static_cast<int>(activity_drops_));
      activity_drops_ = 0;
      if (!base::JSONWriter::Write(value, &reply->payload) ||
          reply->payload.size() > kNativeConsoleReplyLimit) {
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
    std::optional<WatchCommand> watch;
    if (operation && *operation == "watch") {
      auto* const document = selected->document.AsRenderFrameHostIfValid();
      const auto* rules = command->FindDict("rules");
      watch = WatchCommand{command->FindBool("keep").value_or(false),
                           document->GetLastCommittedOrigin().Serialize(),
                           document->GetParentOrOuterDocument() == nullptr,
                           rules ? rules->Clone() : base::DictValue()};
    }
    const auto weak_document = selected->document;
    auto callback = mojo::WrapCallbackWithDefaultInvokeIfNotRun(
        base::BindOnce(
            [](Session* session, std::optional<WatchCommand> watch,
               content::WeakDocumentPtr document, std::shared_ptr<Reply> result,
               std::uint16_t status, std::uint16_t type, const std::string& text, bool truncated) {
              if (!document.AsRenderFrameHostIfValid()) {
                result->Fail(NativeConsoleStatus::kStaleTarget,
                             "Document changed during execution; side effects may have occurred");
                return;
              }
              // Target listings and document-start results are produced by the
              // browser process; a renderer that claims either is malformed.
              if (status > static_cast<std::uint16_t>(NativeConsoleStatus::kStopped) ||
                  type > static_cast<std::uint16_t>(NativeConsoleType::kRuntime) ||
                  type == static_cast<std::uint16_t>(NativeConsoleType::kTargets) ||
                  text.size() > (type == static_cast<std::uint16_t>(NativeConsoleType::kRuntime)
                                     ? kNativeConsoleReplyLimit
                                     : kNativeConsoleTextLimit) ||
                  !base::IsStringUTF8(text)) {
                result->Fail(NativeConsoleStatus::kMalformed,
                             "Renderer returned an invalid console result");
                return;
              }
              result->header.status = static_cast<NativeConsoleStatus>(status);
              result->header.type = static_cast<NativeConsoleType>(type);
              result->header.flags = truncated ? kNativeConsoleTruncated : 0;
              result->payload =
                  watch && status == static_cast<std::uint16_t>(NativeConsoleStatus::kOk) &&
                          type == static_cast<std::uint16_t>(NativeConsoleType::kRuntime)
                      ? session->Watched(*watch, text)
                      : text;
              result->header.payload_bytes = static_cast<std::uint32_t>(result->payload.size());
              result->ready.Signal();
            },
            base::Unretained(this), std::move(watch), weak_document, reply),
        static_cast<std::uint16_t>(NativeConsoleStatus::kDisconnected),
        static_cast<std::uint16_t>(NativeConsoleType::kUndefined),
        std::string("Renderer disconnected"), false);
    const auto expires = static_cast<std::uint64_t>(deadline.since_origin().InMicroseconds());
    if (request.operation == NativeConsoleOperation::kRuntime)
      selected->agent->Runtime(selected->renderer_document, request.request_id, expires, source,
                               std::move(callback));
    else
      selected->agent->Evaluate(selected->renderer_document, request.request_id, expires, source,
                                std::move(callback));
  }

  // A watch the renderer confirmed replaces the kept scope with its rules, or
  // clears it, and its reply then says what is kept. A refused watch changes
  // nothing. After Retire the scope stays clear: nothing outlives its owner.
  std::string Watched(const WatchCommand& watch, const std::string& text) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    auto result = base::JSONReader::ReadDict(text, base::JSON_PARSE_RFC);
    const auto* status = result ? result->FindString("status") : nullptr;
    if (!status || *status != "ok" || !active_.load(std::memory_order_acquire))
      return text;
    auto scope = watch.keep ? KeptWatchScope(watch, next_scope_++) : nullptr;
    std::string reply = text;
    if (watch.keep) {
      const auto* said = result->FindString("text");
      std::string reply_text = said ? *said : std::string();
      if (scope) {
        result->Set("kept", base::DictValue()
                                .Set("origin", watch.origin)
                                .Set("frame", watch.top_frame ? "top" : "child"));
        reply_text += " Kept for every later " + watch.origin +
                      (watch.top_frame ? " top-frame" : " child-frame") +
                      " document, armed before its own scripts run.";
        const auto* dom = watch.rules.FindList("dom");
        if (dom && !dom->empty())
          reply_text += " DOM rules stay with this document.";
      } else {
        result->Set("kept", base::Value());
        reply_text +=
            " Nothing is kept: DOM rules name this document's own nodes, and no other rule is "
            "armed.";
      }
      result->Set("text", reply_text);
      // A reply that cannot say what is kept keeps nothing, so the owner never
      // misses a scope the browser holds.
      if (!base::JSONWriter::Write(*result, &reply) || reply.size() > kNativeConsoleReplyLimit) {
        reply = text;
        scope = nullptr;
      }
    }
    NativeProbeSession::Get().SetDebuggerWatchScope(std::move(scope));
    return reply;
  }

  void List(std::shared_ptr<Reply> reply) {
    const bool live =
        base::CommandLine::ForCurrentProcess()->HasSwitch(kNativeConsoleLiveBindingSwitch);
    auto previous = std::move(targets_);
    targets_.clear();
    // Without the live binding a listing renumbers every target, so no
    // traffic request can name the old IDs again: their events are counted as
    // dropped and freed.
    if (!live) {
      for (const auto& [document, pending] : activity_)
        CountActivityDrops(pending.size());
      activity_.clear();
    }
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
        // Keep an ID only while its exact weak document is still alive. A
        // navigation/reload can reuse the frame host, URL and title, but cannot
        // reuse this document generation. Never join native ownership by URL.
        if (live) {
          const auto same_document =
              std::find_if(previous.begin(), previous.end(), [frame](const Target& old) {
                return old.document.AsRenderFrameHostIfValid() == frame;
              });
          if (same_document != previous.end())
            target.id = same_document->id;
          // A document that reported before it was listed, such as a child
          // frame's document-start record, keeps the ID it reported with.
          else if (const auto reported = documents_.find(frame->GetDocumentToken().value());
                   reported != documents_.end())
            target.id = reported->second;
        }
        if (!target.id) {
          if (!next_target_) {
            truncated = true;
            return;
          }
          target.id = next_target_++;
        }
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
        target.agent->BindControl(target.control.BindNewPipeAndPassReceiver());
        targets_.push_back(std::move(target));
      });
    }
    // A document that is no longer a target cannot be named again either.
    if (live) {
      std::erase_if(activity_, [this](const auto& entry) {
        const bool gone = std::none_of(targets_.begin(), targets_.end(), [&](const Target& target) {
          return target.id == entry.first;
        });
        if (gone)
          CountActivityDrops(entry.second.size());
        return gone;
      });
    }
    reply->header.type = NativeConsoleType::kTargets;
    // The owner learns from the listing whether this browser session permits
    // document-start scripts at all, so it never sends operation 4 to a browser
    // that would reject it and retire a working session.
    reply->header.flags = static_cast<std::uint16_t>(
        (truncated ? kNativeConsoleTruncated : 0) |
        (NativeConsoleDocumentStartRegistry::IsPermitted() ? kNativeConsoleDocumentStartSupported
                                                           : 0));
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
        reply->header.flags |= kNativeConsoleTruncated;
        continue;
      }
      NativeConsoleTarget record;
      record.id = target.id;
      const std::size_t size = std::min(target.origin.size(), record.origin.size());
      record.origin_bytes = static_cast<std::uint16_t>(size);
      record.flags =
          (target.origin.size() > size || target.metadata_truncated ? kNativeConsoleTruncated : 0) |
          (target.main_frame ? 2 : 0);
      base::span(record.origin).first(size).copy_from(base::span(target.origin).first(size));
      auto copy = [&](const std::string& text, auto& buffer, std::uint16_t& bytes) {
        auto bounded = text.substr(0, buffer.size());
        while (!bounded.empty() && !base::IsStringUTF8(bounded))
          bounded.pop_back();
        bytes = static_cast<std::uint16_t>(bounded.size());
        base::span(buffer).first(bounded.size()).copy_from(base::span(bounded));
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

  void DocumentStart(const std::string& source, std::shared_ptr<Reply> reply) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    auto& registry = NativeConsoleDocumentStartRegistry::Get();
    // A refusal reports what is still armed and deliberately omits the output
    // page: it changed neither the set nor its records, so a reader must not be
    // handed records it already has.
    const auto failure = [&registry](const std::string& text) {
      auto result = registry.State(0);
      result.Remove("output");
      result.Set("status", "error");
      result.Set("text", text);
      return result;
    };
    const auto command = base::JSONReader::ReadDict(source, base::JSON_PARSE_RFC);
    const auto* operation = command ? command->FindString("operation") : nullptr;
    base::DictValue result;
    if (!operation) {
      result = failure("Malformed document-start command");
    } else if (*operation == "arm") {
      const auto* scripts = command->FindList("scripts");
      std::string error;
      if (command->size() != 2 || !scripts)
        result = failure("arm takes exactly operation and scripts");
      else if (!registry.Arm(*scripts, error))
        result = failure(error);
      else
        result = registry.State(0);
    } else if (*operation == "clear") {
      if (command->size() != 1) {
        result = failure("clear takes exactly operation");
      } else {
        registry.Clear();
        result = registry.State(0);
      }
    } else if (*operation == "state") {
      const auto* cursor = command->FindString("after");
      std::uint64_t after = 0;
      if (command->size() != 2 || !cursor || !base::StringToUint64(*cursor, &after))
        result = failure("state takes exactly operation and a decimal after cursor");
      else
        result = registry.State(after);
    } else {
      result = failure("Unknown document-start operation");
    }
    if (!base::JSONWriter::Write(result, &reply->payload) ||
        reply->payload.size() > kNativeConsoleDocumentStartReplyLimit) {
      reply->payload.clear();
      reply->Fail(NativeConsoleStatus::kMalformed,
                  "Document-start result exceeded bounded transport");
      return;
    }
    reply->header.type = NativeConsoleType::kDocumentStart;
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
      activity_[target.id].push_back(
          base::DictValue()
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
  void CountActivityDrops(const std::size_t count) {
    activity_drops_ = static_cast<unsigned>(
        std::min<std::size_t>(2147483647u, std::size_t{activity_drops_} + count));
  }
  std::vector<std::unique_ptr<ConsoleActivity>> observers_;
  // Each target's resource completions, oldest first, until the owner reads
  // them; there is no count limit.
  std::map<std::uint64_t, std::deque<base::DictValue>> activity_;
  std::uint64_t next_activity_ = 1;
  std::uint64_t last_evaluation_ = 0;
  unsigned activity_drops_ = 0;

  // Metadata and weak document references only; no V8 objects are retained.
  base::FilePath user_data_dir_;
  std::vector<Target> targets_;
  // Exact document generations only; kept for the session and never
  // published.
  std::map<base::UnguessableToken, std::uint64_t> documents_;
  std::uint64_t next_target_ = 1;
  // Kept watch scope serials; never 0.
  std::uint64_t next_scope_ = 1;
  std::size_t pending_ = 0;
  bool started_ = false;
  base::OnceClosure retired_;
  std::atomic<bool> active_{false};
};

}  // namespace

bool IsNativeConsoleEnabled() {
  const auto& command = *base::CommandLine::ForCurrentProcess();
  if (!command.HasSwitch(kNativeConsoleSwitch))
    return false;
  const auto socket = command.GetSwitchValuePath("reb-native-console-socket");
  const bool credentials = socket.IsAbsolute() &&
                           !command.GetSwitchValuePath("reb-native-console-token-file").empty() &&
                           command.HasSwitch("reb-native-console-session-id");
  if (!credentials)
    return false;
  if (command.HasSwitch(kNativeConsoleLiveBindingSwitch)) {
    // The capture browser already has its profile and may publish a debugger
    // port. Do not require the disposable socket/profile sibling layout.
    return command.GetSwitchValuePath("user-data-dir").IsAbsolute();
  }
  if (command.HasSwitch("remote-debugging-port") || command.HasSwitch("remote-debugging-pipe"))
    return false;
  return command.GetSwitchValuePath("user-data-dir") == socket.DirName().AppendASCII("profile");
}

base::OnceClosure NativeConsoleRetireCallback() {
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(kNativeConsoleLiveBindingSwitch))
    return base::BindOnce([] {});
  // Null tells the Chrome browser client to exit a disposable profile.
  // This component does not depend on chrome/browser.
  return base::OnceClosure();
}

void StartNativeConsoleSession(base::OnceClosure retired) {
  if (IsNativeConsoleEnabled())
    Session::Get().Start(std::move(retired));
}

bool IsNativeConsoleDocument(content::RenderFrameHost* frame) {
  return Session::Get().Eligible(frame);
}

std::uint64_t NativeConsoleDocumentId(content::RenderFrameHost* frame) {
  return Session::Get().DocumentId(frame);
}

std::uint64_t NativeConsoleDocumentIdIfAssigned(content::RenderFrameHost* frame) {
  return Session::Get().DocumentIdIfAssigned(frame);
}

}  // namespace reb
