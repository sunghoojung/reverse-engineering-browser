// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_PAUSE_SESSION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_PAUSE_SESSION_H_

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/time/time.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/common/native_debugger_pause.h"
#include "third_party/blink/public/web/web_native_debugger.h"

namespace blink {
class WebLocalFrame;
}

namespace reb {

// One authorized document's pausing debugger, on the renderer main thread.
// It owns the in-process inspector session and turns this contract's
// commands into inspector protocol messages and its replies back out, so no
// protocol message ever leaves the renderer.
// See protocol/native-debugger-pause-v1.md.
class NativeDebuggerPauseSession final : public blink::WebNativeDebugger::Client,
                                         public base::RefCounted<NativeDebuggerPauseSession> {
 public:
  struct Result {
    NativeDebuggerPauseStatus status = NativeDebuggerPauseStatus::kOk;
    bool paused = false;
    bool resumed = false;
    // This contract's JSON reply body, already bounded. Never empty: a
    // refusal says which action it refused, so the backend never has to
    // report an outcome it was told.
    std::string body;
  };

  // What the browser is told, so its deadline starts at the pause and it can
  // answer a state read after this session is gone. Every callback is bound
  // to the agent's weak pointer, so one that outlives the agent does nothing
  // instead of reaching a destroyed Mojo remote.
  struct Observer {
    base::RepeatingCallback<void(std::uint64_t lease,
                                 std::uint8_t reason,
                                 std::uint64_t breakpoint,
                                 std::uint32_t frames,
                                 std::uint32_t async_frames,
                                 bool truncated)>
        paused;
    base::RepeatingCallback<void(std::uint64_t lease, std::uint8_t end, std::uint32_t paused_ms)>
        resumed;
    base::RepeatingCallback<void(std::uint8_t reason, std::uint32_t dropped)> cleared;
    // Posts a task to this frame's main thread that runs even while it is
    // inside the nested pause loop. Ending a stop from inside the pause
    // notification is not possible: V8 enters that loop afterwards whatever
    // the notification did, and a quit requested before the loop starts is
    // lost.
    base::RepeatingCallback<void(base::OnceClosure)> post;
  };

  // `target_id` is the browser's identity for this document; the renderer
  // only echoes it, so the two sides cannot disagree about which document is
  // authorized.
  NativeDebuggerPauseSession(blink::WebLocalFrame* frame,
                             std::uint64_t target_id,
                             Observer observer);
  NativeDebuggerPauseSession(const NativeDebuggerPauseSession&) = delete;
  NativeDebuggerPauseSession& operator=(const NativeDebuggerPauseSession&) = delete;

  // `command` is the action object the backend validated, or empty for the
  // state read and the browser's own deadline operations.
  [[nodiscard]] Result Command(NativeDebuggerPauseOperation operation,
                               std::uint64_t lease_id,
                               const std::string& command);

  // The authorization ends. Resumes a paused page, drops every breakpoint
  // this session set, disposes the inspector session and tells the browser.
  void Clear(std::uint8_t reason);

  // The frame is being destroyed, possibly from inside script this session
  // is evaluating. Nothing more is dispatched: the inspector session goes
  // away with the frame, so this only drops state and tells the browser. The
  // object itself may outlive the call that destroyed the frame, which is why
  // it is held by shared_ptr.
  void FrameGone(std::uint8_t reason);

  [[nodiscard]] bool IsAuthorized() const { return attached_; }

 private:
  friend class base::RefCounted<NativeDebuggerPauseSession>;
  ~NativeDebuggerPauseSession() override;

  struct Breakpoint {
    std::uint64_t id = 0;
    std::string kind;
    std::string inspector_id;
    std::uint32_t script_id = 0;
    std::uint32_t line = 0;
    std::uint32_t column = 0;
    bool condition_set = false;
    bool logpoint = false;
    std::uint64_t hits = 0;
  };

  // blink::WebNativeDebugger::Client:
  void OnInspectorMessage(std::string_view message) override;

  // Sends one protocol command and returns its result object, or nullopt
  // when the inspector answered with an error or did not answer at all.
  std::optional<base::DictValue> Call(std::string_view method, base::DictValue params);
  bool Attach();
  void OnPaused(const base::DictValue& params);
  // A stop in another document of the same context group: recorded, reported
  // to the browser so its deadline covers it, and ended by a posted task
  // rather than from inside the notification.
  void OnForeignPause(const std::string& reason);
  void EndForeignPause(std::uint64_t lease);
  void OnResumed();
  Result Select();
  Result SetBreakpoint(const base::DictValue& command);
  Result RemoveBreakpoint(const base::DictValue& command);
  Result PauseOnExceptions(const base::DictValue& command);
  Result Step(NativeDebuggerPauseOperation operation, std::uint64_t lease_id);
  // The browser's expire-lease and release-idle operations, which never
  // cross the socket.
  Result RunDeadline(NativeDebuggerPauseOperation operation, std::uint64_t lease_id);
  Result EndLease(std::uint64_t lease_id, bool deadline);
  Result Evaluate(std::uint64_t lease_id, const base::DictValue& command);
  Result Properties(std::uint64_t lease_id, const base::DictValue& command);
  Result Reply(NativeDebuggerPauseStatus status,
               std::string_view action,
               bool resumed,
               base::DictValue extra);
  [[nodiscard]] NativeDebuggerPauseStatus CheckLease(std::uint64_t lease_id) const;
  // Lets the page run and tells the browser the pause is over. The inspector
  // unwinds its nested loop after this command returns, so the reply says
  // the page resumed and carries no new pause.
  void LetPageRun(std::uint8_t end, const char* lease_state);
  base::DictValue BreakpointBody(const Breakpoint& breakpoint) const;
  // Without `include_frames` the pause leaves its call stack out and says
  // so, which is how a 1,024-frame pause stays inside the reply bound.
  base::DictValue StateBody(bool include_frames) const;
  base::DictValue PauseBody(bool include_frames) const;
  base::DictValue LeaseBody() const;
  // Zero when the pause already holds this contract's live-object bound; the
  // caller then leaves the id out rather than naming one it cannot answer.
  std::uint64_t ObjectIdFor(const std::string& inspector_id);
  const std::string* InspectorObject(std::uint64_t id) const;
  void EmitRecord(std::uint8_t record, const std::array<std::uint8_t, 48>& tail) const;

  // Null once the frame has been destroyed under this session.
  base::raw_ptr<blink::WebLocalFrame> frame_;
  // The selected document's own frame, so every record names it even when no
  // V8 context is entered and the broker would otherwise refuse the record.
  const std::uint64_t frame_id_;
  const std::uint64_t target_id_;
  const Observer observer_;
  std::unique_ptr<blink::WebNativeDebugger> debugger_;
  bool attached_ = false;
  // Set by the first Clear. Nothing is reported twice, and a destructor that
  // runs after it reports nothing at all.
  bool cleared_ = false;
  std::uint8_t last_clear_ = kNativeDebuggerPauseClearNone;
  std::string exceptions_ = "none";
  std::vector<Breakpoint> breakpoints_;
  std::uint64_t next_breakpoint_ = 1;

  std::uint64_t lease_ = 0;
  std::uint64_t next_lease_ = 1;
  std::string lease_state_;
  base::TimeTicks lease_started_;

  bool paused_ = false;
  // The frame the current pause stopped in. An inspector session belongs to
  // its local root's context group, so a pause can arrive from another
  // same-process document; such a pause is resumed at once and never read.
  std::uint64_t paused_frame_id_ = 0;
  // A stop in another document of the group, by the lease the browser was
  // told about. Nothing of it is readable: no frames, no values, and the
  // selected document is not paused. It exists so the browser's deadline
  // covers the stop even if the resume this session posts never runs.
  std::uint64_t foreign_lease_ = 0;
  base::TimeTicks foreign_started_;
  std::string pause_reason_;
  std::uint64_t pause_breakpoint_ = 0;
  base::ListValue frames_;
  std::size_t frames_total_ = 0;
  std::size_t async_frames_ = 0;
  // Inspector call frame ids of the current pause, innermost first.
  std::vector<std::string> call_frames_;
  // Our numeric object ids for this pause only; both maps are cleared on
  // resume, which is what makes a stale id an unknown_object.
  std::map<std::uint64_t, std::string> objects_;
  std::map<std::string, std::uint64_t> object_ids_;
  std::uint64_t next_object_ = 1;
  // True while this session asked for `pause`, so V8's reason "other" with
  // no breakpoint can be told from the page's own `debugger;` statement.
  bool pause_requested_ = false;

  int next_call_id_ = 1;
  int awaiting_call_id_ = 0;
  // True while an inspector dispatch is on this stack. The inspector session
  // is never disposed then: V8 may still be inside it.
  bool in_dispatch_ = false;
  // The error text of the last call that failed, so a terminated evaluation
  // is reported as an evaluation error rather than a refused command.
  std::string last_call_error_;
  // A deadline operation that arrived while a dispatch was on the stack. It
  // runs when that dispatch returns rather than being dropped, because
  // dropping it would leave a page paused past its deadline.
  NativeDebuggerPauseOperation pending_deadline_ = NativeDebuggerPauseOperation::kState;
  std::uint64_t pending_deadline_lease_ = 0;
  std::optional<base::DictValue> awaited_response_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_DEBUGGER_PAUSE_SESSION_H_
