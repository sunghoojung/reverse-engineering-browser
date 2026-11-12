// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_debugger_pause_agent.h"

#include <optional>
#include <utility>

#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/bind_post_task.h"
#include "base/task/single_thread_task_runner.h"
#include "brave/components/reverse_engineering_browser/common/native_debugger_pause.h"
#include "content/public/renderer/render_frame.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_registry.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_native_debugger.h"

namespace reb {
namespace {

bool Enabled() {
  return base::CommandLine::ForCurrentProcess()->HasSwitch(kNativeDebuggerPauseSwitch);
}

// The action a command names, so a refusal this agent writes before the
// session sees the body still says which action it refused. The backend
// checks that name against the one it sent, and reports an outcome unknown
// when they disagree, so an unnamed refusal would read as a lost command.
std::string ActionOf(const std::string& command) {
  std::optional<base::DictValue> parsed = base::JSONReader::ReadDict(command, base::JSON_PARSE_RFC);
  if (!parsed) {
    return std::string();
  }
  const std::string* action = parsed->FindString("action");
  return action ? *action : std::string();
}

}  // namespace

// Bound on the renderer IO thread while the page is running, so a command
// never has to be served by a main thread that is already stopped.
// Inside this class the unqualified name `NativeDebuggerPauseAgent` is the
// mojom base class's injected name, so the agent this one serves is written
// out in full.
class NativeDebuggerPauseAgent::IoAgent final : public mojom::NativeDebuggerPauseAgent {
 public:
  IoAgent(scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
          scoped_refptr<blink::WebNativeDebuggerPoster> poster,
          base::WeakPtr<::reb::NativeDebuggerPauseAgent> agent,
          base::OnceClosure lost,
          mojo::PendingReceiver<mojom::NativeDebuggerPauseAgent> receiver)
      : io_task_runner_(std::move(io_task_runner)),
        poster_(std::move(poster)),
        agent_(std::move(agent)),
        lost_(std::move(lost)) {
    io_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&IoAgent::BindInterface, base::Unretained(this), std::move(receiver)));
  }

  IoAgent(const IoAgent&) = delete;
  IoAgent& operator=(const IoAgent&) = delete;
  // Public so the IO thread can delete this through its task runner.
  ~IoAgent() override = default;

  void DeleteSoon() { io_task_runner_->DeleteSoon(FROM_HERE, this); }

 private:
  void BindInterface(mojo::PendingReceiver<mojom::NativeDebuggerPauseAgent> receiver) {
    receiver_.Bind(std::move(receiver), io_task_runner_);
    // Losing the browser side must not leave a page stopped, so the loss is
    // reported to the main thread, which resumes and disarms.
    receiver_.set_disconnect_handler(
        base::BindOnce(&IoAgent::OnDisconnect, base::Unretained(this)));
  }

  void OnDisconnect() {
    if (!lost_) {
      return;
    }
    // Interrupting, because the main thread may be inside the pause this is
    // meant to end.
    static_cast<void>(poster_->Post(true, std::move(lost_)));
  }

  // mojom::NativeDebuggerPauseAgent:
  void Command(const base::UnguessableToken& document,
               std::uint16_t operation,
               std::uint64_t lease_id,
               std::uint64_t expires_at_monotonic_us,
               const std::string& command,
               CommandCallback callback) override {
    // Nothing ran, and nothing is retried.
    const auto refuse = [&callback](const NativeDebuggerPauseStatus status) {
      std::move(callback).Run(static_cast<std::uint16_t>(status), false, false, std::string());
    };
    if (!poster_) {
      refuse(NativeDebuggerPauseStatus::kUnsupported);
      return;
    }
    // The reply has to come back on this sequence, so it is wrapped before
    // it crosses to the main thread. The wrap happens only once the post is
    // certain to be attempted, because a moved-from callback cannot be run.
    CommandCallback reply = base::BindPostTask(io_task_runner_, std::move(callback));
    auto task =
        base::BindOnce(&::reb::NativeDebuggerPauseAgent::RunCommand, agent_, document, operation,
                       lease_id, expires_at_monotonic_us, command, std::move(reply));
    // The weak pointer is created on the main thread and dereferenced there;
    // only the handle travels.
    if (!poster_->Post(
            !NativeDebuggerPauseRunsScript(static_cast<NativeDebuggerPauseOperation>(operation)),
            std::move(task))) {
      // The task runner is disposed: the frame is going away and no reply
      // will ever come from it. The receiver's own disconnect is what the
      // browser sees; this connection answers nothing further.
      return;
    }
  }

  const scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;
  const scoped_refptr<blink::WebNativeDebuggerPoster> poster_;
  const base::WeakPtr<::reb::NativeDebuggerPauseAgent> agent_;
  base::OnceClosure lost_;
  mojo::Receiver<mojom::NativeDebuggerPauseAgent> receiver_{this};
};

// static
void NativeDebuggerPauseAgent::CreateIfEnabled(content::RenderFrame* frame) {
  if (!Enabled() || !frame) {
    return;
  }
  // The observer deletes itself with its frame.
  new NativeDebuggerPauseAgent(frame);
}

NativeDebuggerPauseAgent::NativeDebuggerPauseAgent(content::RenderFrame* frame)
    : content::RenderFrameObserver(frame) {
  frame->GetAssociatedInterfaceRegistry()->AddInterface<mojom::NativeDebuggerPauseBroker>(
      base::BindRepeating(&NativeDebuggerPauseAgent::Bind, base::Unretained(this)));
}

NativeDebuggerPauseAgent::~NativeDebuggerPauseAgent() {
  DiscardSession(kNativeDebuggerPauseClearPeerLost);
}

void NativeDebuggerPauseAgent::OnDestruct() {
  // The frame is being destroyed, which the page can cause from inside the
  // very script this session is evaluating. Nothing more is dispatched: the
  // session is told its frame is gone, and the shared pointer it is held by
  // keeps the object alive until that dispatch has returned.
  if (session_) {
    session_->FrameGone(kNativeDebuggerPauseClearNavigated);
  }
  DiscardSession(kNativeDebuggerPauseClearNavigated);
  delete this;
}

void NativeDebuggerPauseAgent::DidSetPageLifecycleState(const blink::BFCacheStateChange change) {
  if (change != blink::BFCacheStateChange::kStoredToBFCache) {
    return;
  }
  // The document is being kept alive in the back-forward cache instead of
  // being destroyed, so no commit and no detach is coming. Leaving it armed
  // would restore a page with this session's breakpoints on it when the user
  // goes back, under an id the backend still believes it selected.
  DiscardSession(kNativeDebuggerPauseClearNavigated);
}

void NativeDebuggerPauseAgent::DidCommitProvisionalLoad(ui::PageTransition transition) {
  // Navigation ends the authorization in the renderer, not only in the
  // backend: the session goes away with its breakpoints, and a paused page
  // is resumed before it does.
  DiscardSession(kNativeDebuggerPauseClearNavigated);
}

void NativeDebuggerPauseAgent::DiscardSession(const std::uint8_t reason) {
  if (session_) {
    session_->Clear(reason);
    session_.reset();
  }
  if (io_agent_) {
    io_agent_->DeleteSoon();
    io_agent_ = nullptr;
  }
  observer_.reset();
}

void NativeDebuggerPauseAgent::OnIoAgentLost(const std::uint64_t generation) {
  if (generation != generation_) {
    // A replaced IO agent reporting its own disconnect. The attachment that
    // replaced it is the live one and is left alone.
    return;
  }
  DiscardSession(kNativeDebuggerPauseClearPeerLost);
}

void NativeDebuggerPauseAgent::Bind(
    mojo::PendingAssociatedReceiver<mojom::NativeDebuggerPauseBroker> receiver) {
  receiver_.reset();
  receiver_.Bind(std::move(receiver));
}

void NativeDebuggerPauseAgent::Attach(
    mojo::PendingReceiver<mojom::NativeDebuggerPauseAgent> agent,
    mojo::PendingRemote<mojom::NativeDebuggerPauseObserver> observer,
    std::uint64_t target_id) {
  blink::WebLocalFrame* frame = render_frame() ? render_frame()->GetWebFrame() : nullptr;
  scoped_refptr<blink::WebNativeDebuggerPoster> poster =
      frame ? blink::WebNativeDebugger::Poster(frame) : nullptr;
  if (!frame || !poster) {
    return;
  }
  // Attaching again replaces an earlier attachment, which is what lets this
  // frame be selected again after a navigation reused it.
  DiscardSession(kNativeDebuggerPauseClearReplaced);
  observer_.Bind(std::move(observer));
  // Every callback goes through this agent's weak pointer, so one the session
  // runs after this agent is gone, which a dispatch that outlived it can do,
  // does nothing instead of writing to a destroyed remote.
  NativeDebuggerPauseSession::Observer callbacks;
  callbacks.paused =
      base::BindRepeating(&NativeDebuggerPauseAgent::ReportPaused, weak_factory_.GetWeakPtr());
  callbacks.resumed =
      base::BindRepeating(&NativeDebuggerPauseAgent::ReportResumed, weak_factory_.GetWeakPtr());
  callbacks.cleared =
      base::BindRepeating(&NativeDebuggerPauseAgent::ReportCleared, weak_factory_.GetWeakPtr());
  callbacks.post = base::BindRepeating(&NativeDebuggerPauseAgent::PostToPausedThread,
                                       weak_factory_.GetWeakPtr());
  session_ =
      base::MakeRefCounted<NativeDebuggerPauseSession>(frame, target_id, std::move(callbacks));
  ++generation_;
  io_agent_ = new IoAgent(blink::Platform::Current()->GetIOTaskRunner(), std::move(poster),
                          weak_factory_.GetWeakPtr(),
                          base::BindOnce(&NativeDebuggerPauseAgent::OnIoAgentLost,
                                         weak_factory_.GetWeakPtr(), generation_),
                          std::move(agent));
}

void NativeDebuggerPauseAgent::ReportPaused(const std::uint64_t lease,
                                            const std::uint8_t reason,
                                            const std::uint64_t breakpoint,
                                            const std::uint32_t frames,
                                            const std::uint32_t async_frames,
                                            const bool truncated) {
  if (observer_.is_bound()) {
    observer_->Paused(lease, reason, breakpoint, frames, async_frames, truncated);
  }
}

void NativeDebuggerPauseAgent::ReportResumed(const std::uint64_t lease,
                                             const std::uint8_t end,
                                             const std::uint32_t paused_ms) {
  if (observer_.is_bound()) {
    observer_->Resumed(lease, end, paused_ms);
  }
}

void NativeDebuggerPauseAgent::ReportCleared(const std::uint8_t reason,
                                             const std::uint32_t dropped) {
  if (observer_.is_bound()) {
    observer_->Cleared(reason, dropped);
  }
}

void NativeDebuggerPauseAgent::PostToPausedThread(base::OnceClosure task) {
  blink::WebLocalFrame* frame = render_frame() ? render_frame()->GetWebFrame() : nullptr;
  scoped_refptr<blink::WebNativeDebuggerPoster> poster =
      frame ? blink::WebNativeDebugger::Poster(frame) : nullptr;
  if (!poster) {
    return;
  }
  // Not interrupting: this task talks to the inspector, and the queue it goes
  // on is the one that runs while the thread is inside the pause loop.
  static_cast<void>(poster->Post(false, std::move(task)));
}

void NativeDebuggerPauseAgent::RunCommand(
    const base::UnguessableToken& document,
    std::uint16_t operation,
    std::uint64_t lease_id,
    std::uint64_t expires_at_monotonic_us,
    const std::string& command,
    mojom::NativeDebuggerPauseAgent::CommandCallback callback) {
  const std::string action = ActionOf(command);
  const auto refuse = [this, &callback, &action](const NativeDebuggerPauseStatus status) {
    // A refusal carries a body that names its action, so the backend reports
    // the status it was told rather than an outcome it has to guess, and it
    // describes the session it refused rather than reading as a disarmed one.
    const bool armed = session_ && session_->IsAuthorized();
    base::DictValue body;
    body.Set("action", action);
    body.Set("status", NativeDebuggerPauseStatusName(status));
    body.Set("active_indication",
             armed ? base::Value(kNativeDebuggerPauseActiveIndication) : base::Value());
    body.Set("paused", false);
    body.Set("resumed", false);
    for (const char* field : {"lease", "pause", "breakpoint", "value", "properties"}) {
      body.Set(field, base::Value());
    }
    std::string encoded;
    base::JSONWriter::Write(body, &encoded);
    std::move(callback).Run(static_cast<std::uint16_t>(status), false, false, encoded);
  };
  blink::WebLocalFrame* frame = render_frame() ? render_frame()->GetWebFrame() : nullptr;
  if (!session_ || !frame) {
    refuse(NativeDebuggerPauseStatus::kUnsupported);
    return;
  }
  if (operation == 0 ||
      operation > static_cast<std::uint16_t>(NativeDebuggerPauseOperation::kMaximumInternal) ||
      command.size() > kNativeDebuggerPauseRequestLimit) {
    refuse(NativeDebuggerPauseStatus::kMalformed);
    return;
  }
  // The socket thread has already stopped waiting, so this command must not
  // take effect now: the contract says a command whose outcome was reported
  // unknown does not run afterwards. The browser's own deadline operations
  // carry no expiry and are never refused here.
  if (expires_at_monotonic_us != 0 &&
      expires_at_monotonic_us <=
          static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InMicroseconds())) {
    refuse(NativeDebuggerPauseStatus::kExpired);
    return;
  }
  // The exact document the backend selected, checked here rather than in the
  // browser, so a command queued before a commit cannot run in the page that
  // replaced it.
  if (frame->GetDocument().Token().value() != document) {
    refuse(NativeDebuggerPauseStatus::kStaleDocument);
    return;
  }
  const NativeDebuggerPauseSession::Result result =
      session_->Command(static_cast<NativeDebuggerPauseOperation>(operation), lease_id, command);
  std::move(callback).Run(static_cast<std::uint16_t>(result.status), result.paused, result.resumed,
                          result.body);
}

}  // namespace reb
