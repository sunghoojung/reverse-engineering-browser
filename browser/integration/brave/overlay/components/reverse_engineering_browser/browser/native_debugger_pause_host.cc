// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_debugger_pause_host.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/scoped_file.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/no_destructor.h"
#include "base/posix/eintr_wrapper.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/single_thread_task_runner_thread_mode.h"
#include "base/task/thread_pool.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "base/unguessable_token.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/browser/native_console_session.h"
#include "brave/components/reverse_engineering_browser/common/native_console_io.h"
#include "brave/components/reverse_engineering_browser/common/native_debugger_pause.h"
#include "brave/components/reverse_engineering_browser/common/native_debugger_pause.mojom.h"
#include "build/build_config.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"

namespace reb {
namespace {

using Deadline = std::chrono::steady_clock::time_point;

Deadline ReplyDeadline() {
  return std::chrono::steady_clock::now() + std::chrono::milliseconds(kNativeDebuggerPauseReplyMs);
}

std::string SocketPath() {
  return base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(kNativeDebuggerPauseSwitch);
}

bool QuietMode() {
  return base::CommandLine::ForCurrentProcess()
             ->GetSwitchValueASCII("js-flags")
             .find("--reb-ignore-debugger-statements") != std::string::npos;
}

// One contract reply the browser writes itself, so a refusal always says
// which action it refused and the backend never reports an unknown outcome.
// `armed` is what this process knows about the session it refused for: a
// refusal is not a way to learn that nothing is authorized.
std::string Refusal(const NativeDebuggerPauseStatus status,
                    const std::string& action,
                    const bool armed) {
  base::DictValue body;
  body.Set("action", action);
  body.Set("active_indication",
           armed ? base::Value(kNativeDebuggerPauseActiveIndication) : base::Value());
  body.Set("status", NativeDebuggerPauseStatusName(status));
  body.Set("paused", false);
  body.Set("resumed", false);
  for (const char* field : {"lease", "pause", "breakpoint", "value", "properties"}) {
    body.Set(field, base::Value());
  }
  std::string encoded;
  base::JSONWriter::Write(body, &encoded);
  return encoded;
}

// The action a command names, for a refusal the browser writes before any
// renderer sees the body.
std::string ActionOf(const std::string& command) {
  std::optional<base::DictValue> parsed = base::JSONReader::ReadDict(command, base::JSON_PARSE_RFC);
  if (!parsed) {
    return std::string();
  }
  const std::string* action = parsed->FindString("action");
  return action ? *action : std::string();
}

// The state of a browser with nothing authorized, and of one whose
// authorization has ended. The renderer owns every pausing field while a
// document is selected; once it is gone there is no session to ask, and
// inventing one here would be a lie.
std::string IdleState(const std::uint8_t last_clear) {
  base::DictValue state;
  state.Set("action", "state");
  state.Set("status", "ok");
  state.Set("resumed", false);
  state.Set("active_indication", base::Value());
  state.Set("quiet_mode", QuietMode());
  state.Set("document", base::Value());
  state.Set("last_clear", last_clear == kNativeDebuggerPauseClearNone
                              ? base::Value()
                              : base::Value(NativeDebuggerPauseClearName(last_clear)));
  state.Set("exceptions", "none");
  state.Set("breakpoints", base::ListValue());
  state.Set("lease", base::Value());
  state.Set("paused", false);
  state.Set("pause", base::Value());
  std::string encoded;
  base::JSONWriter::Write(state, &encoded);
  return encoded;
}

// One request's reply, filled on the UI thread and read by the socket
// thread. Shared, because the socket thread stops waiting at its deadline
// while a late UI callback may still write this, and `execute_before` keeps
// that callback from running a command nobody is waiting for.
struct Reply {
  NativeDebuggerPauseReply header;
  std::string payload;
  base::WaitableEvent ready{base::WaitableEvent::ResetPolicy::MANUAL,
                            base::WaitableEvent::InitialState::NOT_SIGNALED};

  void Finish(const NativeDebuggerPauseStatus status,
              const bool paused,
              const bool resumed,
              std::string body) {
    header.status = status;
    header.paused = paused ? 1 : 0;
    header.flags = resumed ? kNativeDebuggerPauseResumed : 0;
    payload = std::move(body);
    header.payload_size = static_cast<std::uint32_t>(payload.size());
    ready.Signal();
  }
};

class Host : public mojom::NativeDebuggerPauseObserver {
 public:
  static Host& Get() {
    static base::NoDestructor<Host> host;
    return *host;
  }

  void Serve(const NativeDebuggerPauseRequest& request,
             std::string command,
             base::TimeTicks execute_before,
             std::shared_ptr<Reply> reply) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (base::TimeTicks::Now() > execute_before) {
      // Nobody is waiting for this any more, so it does not run at all: a
      // command whose outcome the backend reported unknown must not take
      // effect afterwards.
      return;
    }
    std::string action = ActionOf(command);
    if (action.empty()) {
      action = NativeDebuggerPauseOperationName(request.operation);
    }
    if (request.operation == NativeDebuggerPauseOperation::kState && request.target_id == 0) {
      if (!attached_) {
        reply->Finish(NativeDebuggerPauseStatus::kOk, false, false, IdleState(last_clear_));
        return;
      }
      Send(NativeDebuggerPauseOperation::kState, 0, std::string(), action, execute_before,
           std::move(reply));
      return;
    }
    // The contract's order: a document that no longer exists is
    // `stale_document` whatever this connection selected. Looking it up
    // attaches nothing, so running this guard first has no side effect.
    content::RenderFrameHost* frame = Resolve(request.target_id);
    if (!frame) {
      reply->Finish(NativeDebuggerPauseStatus::kStaleDocument, false, false,
                    Refusal(NativeDebuggerPauseStatus::kStaleDocument, action, attached_));
      return;
    }
    // Only a selection may change the selection. Any other command naming
    // another document is refused before anything is attached or detached, so
    // a wrong target_id cannot resume and disarm the authorized document.
    if (request.operation != NativeDebuggerPauseOperation::kSelectDocument &&
        (!attached_ || request.target_id != selected_target_)) {
      reply->Finish(NativeDebuggerPauseStatus::kNotAuthorized, false, false,
                    Refusal(NativeDebuggerPauseStatus::kNotAuthorized, action, attached_));
      return;
    }
    if (!Attach(frame, request.target_id)) {
      reply->Finish(NativeDebuggerPauseStatus::kUnsupported, false, false,
                    Refusal(NativeDebuggerPauseStatus::kUnsupported, action, attached_));
      return;
    }
    idle_timer_.Start(FROM_HERE, base::Milliseconds(kNativeDebuggerPauseIdleMs),
                      base::BindOnce(&Host::ReleaseIdle, base::Unretained(this)));
    Send(request.operation, request.lease_id, std::move(command), action, execute_before,
         std::move(reply));
  }

 private:
  friend class base::NoDestructor<Host>;
  Host() = default;
  ~Host() override = default;

  // mojom::NativeDebuggerPauseObserver, on the UI thread.
  void Paused(std::uint64_t lease_id,
              std::uint8_t reason,
              std::uint64_t breakpoint_id,
              std::uint32_t frames_recorded,
              std::uint32_t async_frames,
              bool frames_truncated) override {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    // The deadline starts here, at the pause, with no client involved. When
    // it runs out this process resumes the page whether or not anything is
    // still connected, which is what keeps a page from staying frozen.
    lease_ = lease_id;
    lease_timer_.Start(FROM_HERE, base::Milliseconds(kNativeDebuggerPauseLeaseMs),
                       base::BindOnce(&Host::ExpireLease, base::Unretained(this), lease_id));
  }

  void Resumed(std::uint64_t lease_id, std::uint8_t end, std::uint32_t paused_ms) override {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (lease_id == lease_) {
      lease_timer_.Stop();
      lease_ = 0;
    }
  }

  void Cleared(std::uint8_t reason, std::uint32_t breakpoints_dropped) override {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (reason == kNativeDebuggerPauseClearNone) {
      // The renderer armed a fresh session; nothing has ended.
      last_clear_ = kNativeDebuggerPauseClearNone;
      return;
    }
    last_clear_ = reason;
    // Disarmed, but the pipes stay: the renderer reports a release on the
    // observer before it answers the command that asked for it, and dropping
    // the agent remote here would drop that pending answer and leave the
    // client reporting an outcome it was actually told.
    Disarm();
  }

  content::RenderFrameHost* Resolve(const std::uint64_t target_id) {
    if (target_id == 0) {
      return nullptr;
    }
    content::RenderFrameHost* found = nullptr;
    for (auto iterator = content::RenderProcessHost::AllHostsIterator(); !iterator.IsAtEnd();
         iterator.Advance()) {
      iterator.GetCurrentValue()->ForEachRenderFrameHost([&](content::RenderFrameHost* frame) {
        // The lookup-only form: assigning identities to every document this
        // walk passes would relabel long-idle ones, and a document with no
        // id yet cannot be the one a client named.
        if (!found && NativeConsoleDocumentIdIfAssigned(frame) == target_id) {
          found = frame;
        }
      });
      if (found) {
        break;
      }
    }
    return found;
  }

  bool Attach(content::RenderFrameHost* frame, const std::uint64_t target_id) {
    const base::UnguessableToken token = frame->GetDocumentToken().value();
    if (attached_ && document_ == token && agent_.is_bound()) {
      return true;
    }
    if (attached_) {
      // One document at a time. Dropping the agent pipe is what disarms the
      // one this replaces: the renderer's own disconnect handler resumes a
      // paused page and clears its session, so nothing depends on a message
      // arriving after this remote is gone. A second attach on the same
      // frame is handled in the renderer, which discards before it binds.
      last_clear_ = kNativeDebuggerPauseClearReplaced;
    }
    Detach();
    mojo::AssociatedRemote<mojom::NativeDebuggerPauseBroker> broker;
    frame->GetRemoteAssociatedInterfaces()->GetInterface(&broker);
    if (!broker.is_bound()) {
      return false;
    }
    broker->Attach(agent_.BindNewPipeAndPassReceiver(), observer_.BindNewPipeAndPassRemote(),
                   target_id);
    agent_.set_disconnect_handler(base::BindOnce(&Host::OnAgentLost, base::Unretained(this)));
    broker_ = std::move(broker);
    document_ = token;
    selected_target_ = target_id;
    attached_ = true;
    return true;
  }

  void OnAgentLost() {
    // Only a connection lost while something was still armed is `peer_lost`.
    // A renderer that has already reported why its authorization ended, a
    // navigation for instance, keeps that reason: the document went away, the
    // connection did not break under it.
    if (attached_) {
      last_clear_ = kNativeDebuggerPauseClearPeerLost;
    }
    Detach();
  }

  // Nothing is authorized any more: no deadline, no selection. The Mojo
  // pipes are left alone, so a reply still in flight arrives.
  void Disarm() {
    lease_timer_.Stop();
    idle_timer_.Stop();
    lease_ = 0;
    attached_ = false;
    selected_target_ = 0;
    document_ = base::UnguessableToken::Null();
  }

  // Leaves last_clear_ alone: the state read that follows says why the
  // authorization ended.
  void Detach() {
    Disarm();
    agent_.reset();
    broker_.reset();
    observer_.reset();
  }

  void Send(const NativeDebuggerPauseOperation operation,
            const std::uint64_t lease_id,
            std::string command,
            const std::string& action,
            const base::TimeTicks execute_before,
            std::shared_ptr<Reply> reply) {
    if (!agent_.is_bound()) {
      reply->Finish(NativeDebuggerPauseStatus::kUnsupported, false, false,
                    Refusal(NativeDebuggerPauseStatus::kUnsupported, action, attached_));
      return;
    }
    agent_->Command(document_, static_cast<std::uint16_t>(operation), lease_id,
                    static_cast<std::uint64_t>(execute_before.since_origin().InMicroseconds()),
                    std::move(command),
                    base::BindOnce(&Host::Answered, base::Unretained(this), std::move(reply)));
  }

  void Answered(std::shared_ptr<Reply> reply,
                std::uint16_t status,
                bool paused,
                bool resumed,
                const std::string& body) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (reply) {
      reply->Finish(static_cast<NativeDebuggerPauseStatus>(status), paused, resumed, body);
    }
  }

  // The deadline ran out. The page is resumed whether or not a client is
  // still there, which is what stops an automated client freezing a page.
  void ExpireLease(const std::uint64_t lease) {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (lease != lease_ || !agent_.is_bound()) {
      return;
    }
    lease_ = 0;
    agent_->Command(document_,
                    static_cast<std::uint16_t>(NativeDebuggerPauseOperation::kExpireLease), lease,
                    0, std::string(), base::DoNothing());
  }

  // No command for this long: the client is gone, so the authorization ends
  // rather than leaving breakpoints armed on a page for the whole session.
  void ReleaseIdle() {
    DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
    if (!agent_.is_bound()) {
      return;
    }
    agent_->Command(document_,
                    static_cast<std::uint16_t>(NativeDebuggerPauseOperation::kReleaseIdle), 0, 0,
                    std::string(), base::DoNothing());
  }

  bool attached_ = false;
  // The Console document id the client selected, which only a selection
  // changes.
  std::uint64_t selected_target_ = 0;
  std::uint8_t last_clear_ = kNativeDebuggerPauseClearNone;
  base::UnguessableToken document_ = base::UnguessableToken::Null();
  mojo::AssociatedRemote<mojom::NativeDebuggerPauseBroker> broker_;
  mojo::Remote<mojom::NativeDebuggerPauseAgent> agent_;
  mojo::Receiver<mojom::NativeDebuggerPauseObserver> observer_{this};
  std::uint64_t lease_ = 0;
  base::OneShotTimer lease_timer_;
  base::OneShotTimer idle_timer_;
};

// The same check the backend makes from its side, with the same platform
// split: Linux reads SO_PEERCRED, Apple reads getpeereid, and anything else
// refuses rather than guessing who connected.
bool SameUser(const int socket) {
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
  ucred credentials = {};
  socklen_t length = sizeof(credentials);
  return getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0 &&
         credentials.uid == getuid();
#elif BUILDFLAG(IS_APPLE)
  uid_t uid = 0;
  gid_t gid = 0;
  return getpeereid(socket, &uid, &gid) == 0 && uid == getuid();
#else
  return false;
#endif
}

void ServeConnection(base::ScopedFD connection) {
  // Both deadlines are stamped now, when this connection was accepted. One
  // accept thread serving a queue would otherwise hand a command that waited
  // its turn a full two seconds measured from that turn, while the client
  // gave up long before.
  const Deadline deadline = ReplyDeadline();
  const auto execute_before =
      base::TimeTicks::Now() +
      base::Milliseconds(kNativeDebuggerPauseReplyMs - kNativeDebuggerPauseReplyMarginMs);
  NativeDebuggerPauseRequest request;
  if (!SameUser(connection.get()) ||
      !NativeConsoleRead(connection.get(), NativeConsoleBytes(request), deadline) ||
      !IsValidNativeDebuggerPauseRequest(request)) {
    NativeDebuggerPauseReply refused;
    refused.request_id = request.request_id != 0 ? request.request_id : 1;
    refused.status = NativeDebuggerPauseStatus::kMalformed;
    static_cast<void>(NativeConsoleWrite(connection.get(), NativeConsoleBytes(refused), deadline));
    return;
  }
  std::string command(request.payload_size, '\0');
  if (request.payload_size != 0 &&
      !NativeConsoleRead(connection.get(), std::as_writable_bytes(std::span(command)), deadline)) {
    return;
  }
  auto reply = std::make_shared<Reply>();
  reply->header.request_id = request.request_id;
  if (!content::GetUIThreadTaskRunner({})->PostTask(
          FROM_HERE, base::BindOnce(
                         [](NativeDebuggerPauseRequest served, std::string body,
                            base::TimeTicks deadline_at, std::shared_ptr<Reply> slot) {
                           Host::Get().Serve(served, std::move(body), deadline_at, std::move(slot));
                         },
                         request, std::move(command), execute_before, reply))) {
    return;
  }
  if (!reply->ready.TimedWait(base::Milliseconds(kNativeDebuggerPauseReplyMs))) {
    // The socket closes with no reply, so the backend reports the outcome
    // unknown rather than a status it did not receive. The shared Reply
    // stays alive for the late callback, which execute_before has already
    // told not to run the command.
    return;
  }
  if (reply->payload.size() > kNativeDebuggerPauseReplyLimit) {
    return;
  }
  if (NativeConsoleWrite(connection.get(), NativeConsoleBytes(reply->header), deadline)) {
    static_cast<void>(
        NativeConsoleWrite(connection.get(), std::as_bytes(std::span(reply->payload)), deadline));
  }
}

void Listen(base::ScopedFD listener) {
  base::PlatformThread::SetName("reb-native-debugger");
  while (true) {
    const int connection = HANDLE_EINTR(accept(listener.get(), nullptr, nullptr));
    if (connection < 0) {
      return;
    }
    ServeConnection(base::ScopedFD(connection));
  }
}

}  // namespace

bool IsNativeDebuggerPauseEnabled() {
  const std::string path = SocketPath();
  return !path.empty() && path.size() + 1 < sizeof(sockaddr_un::sun_path);
}

void StartNativeDebuggerPauseHost() {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  static bool started = false;
  if (started || !IsNativeDebuggerPauseEnabled()) {
    return;
  }
  started = true;
  const std::string path = SocketPath();
  // Only a socket this user already owns is replaced. The switch names a
  // path; it does not license deleting whatever is there.
  struct stat existing = {};
  if (lstat(path.c_str(), &existing) == 0) {
    if (!S_ISSOCK(existing.st_mode) || existing.st_uid != geteuid()) {
      return;
    }
    if (unlink(path.c_str()) != 0) {
      return;
    }
  }
  base::ScopedFD listener(socket(AF_UNIX, SOCK_STREAM, 0));
  if (!listener.is_valid()) {
    return;
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path.data(), path.size());
  if (bind(listener.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
      listen(listener.get(), 8) != 0) {
    return;
  }
  // User-only, set on the socket itself rather than by changing this
  // process's umask while its other threads are running. The directory the
  // switch names is the backend's own, created 0700, so no other user can
  // reach the socket in between; the backend then refuses a socket that is
  // not 0600.
  if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
    return;
  }
  // A dedicated thread: this one blocks in accept for the whole session, so
  // it must not be a shared pool thread.
  base::ThreadPool::CreateSingleThreadTaskRunner({base::MayBlock(), base::WithBaseSyncPrimitives(),
                                                  base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
                                                 base::SingleThreadTaskRunnerThreadMode::DEDICATED)
      ->PostTask(FROM_HERE, base::BindOnce(&Listen, std::move(listener)));
}

}  // namespace reb
