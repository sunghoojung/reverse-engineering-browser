// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_debugger_pause_session.h"

#include <algorithm>
#include <array>
#include <utility>

#include "base/command_line.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"
#include "brave/components/reverse_engineering_browser/renderer/native_debugger_observation.h"
#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"
#include "brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h"
#include "third_party/blink/public/web/web_local_frame.h"

namespace reb {
namespace {

// True when this renderer was started with the V8 flag that makes a page's
// own `debugger;` statement a no-op, which the packaged app sets by default.
// Observed rather than assumed, because it changes what can pause.
bool QuietMode() {
  const base::CommandLine* line = base::CommandLine::ForCurrentProcess();
  return line->GetSwitchValueASCII("js-flags").find("--reb-ignore-debugger-statements") !=
         std::string::npos;
}

// The frame identity every renderer record carries, from the public frame
// token, exactly as the probe transport computes it.
std::uint64_t FrameIdOf(const blink::WebLocalFrame* frame) {
  if (!frame) {
    return 0;
  }
  // The token is held by value: binding a reference into the temporary the
  // getter returns would not extend its lifetime past this statement.
  const auto token = frame->GetLocalFrameToken();
  return NativeFrameIdOf(token.value().GetHighForSerialization(),
                         token.value().GetLowForSerialization());
}

std::string Bounded(std::string text, const std::size_t limit) {
  if (text.size() > limit) {
    text.resize(limit);
    while (!text.empty() && !base::IsStringUTF8(text)) {
      text.pop_back();
    }
  }
  return text;
}

std::string Decimal(const std::uint64_t value) {
  return base::NumberToString(value);
}

std::uint64_t ParseDecimal(const std::string* text) {
  std::uint64_t value = 0;
  return text && base::StringToUint64(*text, &value) ? value : 0;
}

std::uint32_t Number32(const base::DictValue& dict, std::string_view key) {
  const std::optional<int> value = dict.FindInt(key);
  return value && *value >= 0 ? static_cast<std::uint32_t>(*value) : 0;
}

std::string Text(const base::DictValue& dict, std::string_view key) {
  const std::string* value = dict.FindString(key);
  return value ? *value : std::string();
}

void Put16(std::array<std::uint8_t, 48>& tail, const std::size_t at, const std::uint16_t value) {
  tail[at] = static_cast<std::uint8_t>(value);
  tail[at + 1] = static_cast<std::uint8_t>(value >> 8U);
}

void Put32(std::array<std::uint8_t, 48>& tail, const std::size_t at, const std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    tail[at + index] = static_cast<std::uint8_t>(value >> (8U * index));
  }
}

void Put64(std::array<std::uint8_t, 48>& tail, const std::size_t at, const std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    tail[at + index] = static_cast<std::uint8_t>(value >> (8U * index));
  }
}

// This contract's words for V8's scope types. An unnamed one is "other"
// rather than a word the schema does not know.
std::string ScopeType(const std::string& type) {
  static constexpr std::string_view kKnown[] = {"global", "local",  "with", "closure", "catch",
                                                "block",  "script", "eval", "module"};
  for (const std::string_view known : kKnown) {
    if (type == known) {
      return std::string(known);
    }
  }
  // V8 spells this one with dashes; every other word matches already.
  return type == "wasm-expression-stack" ? "wasm_expression_stack" : "other";
}

// A remote object as this contract's bounded value. Nothing here is retained
// anywhere, and the object group it belongs to is released on resume.
base::DictValue ValueOf(const base::DictValue& remote, const std::string& object_id) {
  std::string text;
  std::string kind = Text(remote, "type");
  if (const std::string* description = remote.FindString("description")) {
    text = *description;
  } else if (const std::string* unserializable = remote.FindString("unserializableValue")) {
    text = *unserializable;
  } else if (const base::Value* value = remote.Find("value")) {
    base::JSONWriter::Write(*value, &text);
  } else {
    text = kind;
  }
  const std::size_t full = text.size();
  base::DictValue out;
  out.Set("kind", kind);
  out.Set("text", Bounded(std::move(text), kNativeDebuggerPauseValueBytes));
  out.Set("truncated", full > kNativeDebuggerPauseValueBytes);
  out.Set("object_id", object_id.empty() ? base::Value() : base::Value(object_id));
  out.Set("threw", false);
  return out;
}

}  // namespace

NativeDebuggerPauseSession::NativeDebuggerPauseSession(blink::WebLocalFrame* frame,
                                                       std::uint64_t target_id,
                                                       Observer observer)
    : frame_(frame),
      frame_id_(FrameIdOf(frame)),
      target_id_(target_id),
      observer_(std::move(observer)) {}

NativeDebuggerPauseSession::~NativeDebuggerPauseSession() {
  Clear(kNativeDebuggerPauseClearReleased);
}

void NativeDebuggerPauseSession::FrameGone(const std::uint8_t reason) {
  // No inspector call can be made now, and the inspector session must not be
  // disposed from here: V8 may be inside the very dispatch that destroyed the
  // frame. `debugger_` goes when this object does, which the shared_ptr the
  // agent holds defers until no dispatch is on the stack.
  frame_ = nullptr;
  Clear(reason);
}

bool NativeDebuggerPauseSession::Attach() {
  if (debugger_) {
    return true;
  }
  debugger_ = blink::WebNativeDebugger::Attach(frame_, this);
  if (!debugger_) {
    return false;
  }
  // Nothing is armed by enabling: breakpoints are only the ones asked for,
  // and a page's own debugger statements stay subject to quiet mode. The
  // Runtime domain is not enabled: its methods answer without it, and
  // enabling it would deliver every console message of the context group
  // through this channel.
  Call("Debugger.enable", base::DictValue());
  return true;
}

void NativeDebuggerPauseSession::Clear(const std::uint8_t reason) {
  if (cleared_) {
    // One authorization ends once. A destructor running after the agent has
    // already cleared this session reports nothing.
    attached_ = false;
    return;
  }
  if (!debugger_) {
    attached_ = false;
    return;
  }
  cleared_ = true;
  const auto dropped = static_cast<std::uint32_t>(breakpoints_.size());
  if (frame_) {
    if (paused_) {
      LetPageRun(kNativeDebuggerPauseEndCleared, "released");
    }
    Call("Debugger.disable", base::DictValue());
  }
  // Disposing the inspector session while V8 is inside a dispatch would free
  // it under its own stack, so that waits for this object's destructor.
  if (!in_dispatch_) {
    debugger_.reset();
  }
  attached_ = false;
  breakpoints_.clear();
  exceptions_ = "none";
  paused_ = false;
  pause_reason_.clear();
  pause_breakpoint_ = 0;
  pause_requested_ = false;
  frames_ = base::ListValue();
  call_frames_.clear();
  objects_.clear();
  object_ids_.clear();
  last_clear_ = reason;
  std::array<std::uint8_t, 48> tail{};
  tail[0] = 2;
  tail[1] = reason;
  Put32(tail, 4, dropped);
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerAttached), tail);
  if (observer_.cleared) {
    observer_.cleared.Run(reason, dropped);
  }
}

void NativeDebuggerPauseSession::EmitRecord(const std::uint8_t record,
                                            const std::array<std::uint8_t, 48>& tail) const {
  // The same walk the phase 1 observations use, so a pause record names the
  // same scripts a request stack would and shares their 128-byte layout. The
  // frame is this session's own document rather than whatever context happens
  // to be entered: attach, clear and breakpoint records are written with no
  // script running, and the broker refuses a record without a frame.
  NativeRequestStackWalk::RecordObservation(static_cast<NativeProbeType>(record), 0, 0, frame_id_,
                                            tail);
}

// ---------------------------------------------------------------------------
// Inspector messages
// ---------------------------------------------------------------------------

std::optional<base::DictValue> NativeDebuggerPauseSession::Call(std::string_view method,
                                                                base::DictValue params) {
  if (!debugger_ || awaiting_call_id_ != 0) {
    // A V8 interrupt can land a command in the middle of an evaluation. The
    // caller refuses it rather than overwriting the call it is waiting for.
    return std::nullopt;
  }
  const int id = next_call_id_++;
  base::DictValue message;
  message.Set("id", id);
  message.Set("method", std::string(method));
  message.Set("params", std::move(params));
  std::string encoded;
  if (!base::JSONWriter::Write(message, &encoded)) {
    return std::nullopt;
  }
  awaiting_call_id_ = id;
  awaited_response_.reset();
  last_call_error_.clear();
  in_dispatch_ = true;
  // Synchronous for every command this contract sends: none of them awaits a
  // promise, so the channel has already answered when Dispatch returns. A
  // reply that did not arrive by then leaves the response empty and the
  // caller refuses the command rather than reporting a result it never saw.
  debugger_->Dispatch(encoded);
  in_dispatch_ = false;
  awaiting_call_id_ = 0;
  if (pending_deadline_ != NativeDebuggerPauseOperation::kState) {
    const NativeDebuggerPauseOperation deadline = pending_deadline_;
    const std::uint64_t deadline_lease = pending_deadline_lease_;
    pending_deadline_ = NativeDebuggerPauseOperation::kState;
    pending_deadline_lease_ = 0;
    static_cast<void>(RunDeadline(deadline, deadline_lease));
  }
  std::optional<base::DictValue> response = std::move(awaited_response_);
  awaited_response_.reset();
  if (!response) {
    return std::nullopt;
  }
  if (const base::DictValue* error = response->FindDict("error")) {
    if (const std::string* text = error->FindString("message")) {
      last_call_error_ = *text;
    }
    return std::nullopt;
  }
  if (response->Find("error")) {
    return std::nullopt;
  }
  base::DictValue* result = response->FindDict("result");
  return result ? std::optional<base::DictValue>(std::move(*result)) : std::nullopt;
}

void NativeDebuggerPauseSession::OnInspectorMessage(std::string_view message) {
  std::optional<base::DictValue> parsed = base::JSONReader::ReadDict(message, base::JSON_PARSE_RFC);
  if (!parsed) {
    return;
  }
  if (const std::optional<int> id = parsed->FindInt("id")) {
    if (*id == awaiting_call_id_) {
      awaited_response_ = std::move(parsed);
    }
    return;
  }
  const std::string method = Text(*parsed, "method");
  if (method == "Debugger.paused") {
    if (const base::DictValue* params = parsed->FindDict("params")) {
      OnPaused(*params);
    }
  } else if (method == "Debugger.resumed") {
    OnResumed();
  }
}

void NativeDebuggerPauseSession::OnPaused(const base::DictValue& params) {
  // An inspector session belongs to its local root's context group, so a
  // breakpoint, an exception or a page's own `debugger;` in another
  // same-process document of that group stops here too. Only the selected
  // document is authorized, so such a stop is handed to OnForeignPause and
  // nothing about it is read. V8 delivers this notification with the paused
  // script's context entered, which is the same identity every renderer
  // record uses.
  const std::uint64_t pausing_frame = FrameIdOf(blink::WebLocalFrame::FrameForCurrentContext());
  if (frame_id_ != 0 && pausing_frame != 0 && pausing_frame != frame_id_) {
    OnForeignPause(Text(params, "reason"));
    return;
  }
  paused_frame_id_ = pausing_frame;
  objects_.clear();
  object_ids_.clear();
  next_object_ = 1;
  call_frames_.clear();
  frames_ = base::ListValue();
  frames_total_ = 0;
  async_frames_ = 0;

  const std::string reason = Text(params, "reason");
  pause_breakpoint_ = 0;
  if (const base::ListValue* hits = params.FindList("hitBreakpoints"); hits && !hits->empty()) {
    const std::string* first = (*hits)[0].GetIfString();
    for (Breakpoint& breakpoint : breakpoints_) {
      if (first && breakpoint.inspector_id == *first) {
        pause_breakpoint_ = breakpoint.id;
        ++breakpoint.hits;
      }
    }
  }
  std::uint8_t record_reason = kNativeDebuggerPauseReasonBreakpoint;
  if (pause_breakpoint_ != 0) {
    pause_reason_ = "breakpoint";
  } else if (reason == "exception" || reason == "promiseRejection") {
    pause_reason_ = "exception";
    record_reason = kNativeDebuggerPauseReasonException;
  } else if (reason == "step") {
    pause_reason_ = "step";
    record_reason = kNativeDebuggerPauseReasonStep;
  } else if (pause_requested_) {
    // This session asked for it with Debugger.pause.
    pause_reason_ = "pause";
    record_reason = kNativeDebuggerPauseReasonPause;
  } else {
    // V8 reports a page's own `debugger;` statement as "other" with no
    // breakpoint. Quiet mode makes that unreachable, which is why the state
    // says which mode is in force.
    pause_reason_ = "debugger_statement";
    record_reason = kNativeDebuggerPauseReasonDebuggerStatement;
  }
  pause_requested_ = false;

  if (const base::ListValue* call_frames = params.FindList("callFrames")) {
    frames_total_ = call_frames->size();
    for (const base::Value& entry : *call_frames) {
      if (frames_.size() >= kNativeDebuggerPauseFrameLimit) {
        break;
      }
      const base::DictValue* call_frame = entry.GetIfDict();
      if (!call_frame) {
        continue;
      }
      call_frames_.push_back(Text(*call_frame, "callFrameId"));
      const base::DictValue* location = call_frame->FindDict("location");
      std::uint32_t script = 0;
      if (location) {
        base::StringToUint(Text(*location, "scriptId"), &script);
      }
      base::ListValue scopes;
      if (const base::ListValue* chain = call_frame->FindList("scopeChain")) {
        for (const base::Value& scope_entry : *chain) {
          const base::DictValue* scope = scope_entry.GetIfDict();
          if (!scope || scopes.size() >= kNativeDebuggerPauseScopeLimit) {
            continue;
          }
          const base::DictValue* object = scope->FindDict("object");
          const std::string inspector_id = object ? Text(*object, "objectId") : std::string();
          const std::uint64_t id = inspector_id.empty() ? 0 : ObjectIdFor(inspector_id);
          if (id == 0) {
            // Past the live-object bound this scope is left out rather than
            // given an id nothing could read.
            continue;
          }
          base::DictValue row;
          row.Set("type", ScopeType(Text(*scope, "type")));
          const std::string name = Text(*scope, "name");
          if (!name.empty()) {
            row.Set("name", Bounded(name, kNativeDebuggerPauseNameBytes));
          }
          row.Set("object_id", Decimal(id));
          scopes.Append(std::move(row));
        }
      }
      std::string self;
      if (const base::DictValue* receiver = call_frame->FindDict("this")) {
        const std::string inspector_id = Text(*receiver, "objectId");
        const std::uint64_t id = inspector_id.empty() ? 0 : ObjectIdFor(inspector_id);
        if (id != 0) {
          self = Decimal(id);
        }
      }
      base::DictValue frame;
      frame.Set("index", static_cast<int>(frames_.size()));
      frame.Set("function_name",
                Bounded(Text(*call_frame, "functionName"), kNativeDebuggerPauseNameBytes));
      frame.Set("script_id", static_cast<int>(script));
      frame.Set("line", static_cast<int>(location ? Number32(*location, "lineNumber") + 1 : 0));
      frame.Set("column", static_cast<int>(location ? Number32(*location, "columnNumber") : 0));
      frame.Set("this_object_id", self.empty() ? base::Value() : base::Value(self));
      frame.Set("scopes", std::move(scopes));
      frames_.Append(std::move(frame));
    }
  }
  if (const base::DictValue* async = params.FindDict("asyncStackTrace")) {
    if (const base::ListValue* async_frames = async->FindList("callFrames")) {
      async_frames_ =
          std::min<std::size_t>(async_frames->size(), kNativeDebuggerPauseAsyncFrameLimit);
    }
  }
  paused_ = true;
  lease_ = next_lease_++;
  lease_state_ = "active";
  lease_started_ = base::TimeTicks::Now();

  const bool truncated = frames_total_ > frames_.size();
  std::array<std::uint8_t, 48> tail{};
  tail[0] = record_reason;
  tail[1] = truncated ? kNativeDebuggerPauseFramesTruncated : 0;
  Put16(tail, 2, static_cast<std::uint16_t>(frames_.size()));
  Put16(tail, 4, static_cast<std::uint16_t>(async_frames_));
  Put64(tail, 8, lease_);
  Put32(tail, 16, static_cast<std::uint32_t>(pause_breakpoint_));
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerPaused), tail);

  // Before the main thread enters the nested loop: the browser's deadline
  // starts at the pause, not when a client first asks about it.
  if (observer_.paused) {
    observer_.paused.Run(lease_, record_reason, pause_breakpoint_,
                         static_cast<std::uint32_t>(frames_.size()),
                         static_cast<std::uint32_t>(async_frames_), truncated);
  }
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::RunDeadline(
    const NativeDebuggerPauseOperation operation,
    const std::uint64_t lease_id) {
  if (operation == NativeDebuggerPauseOperation::kExpireLease) {
    // A stop in another document of the group is the browser's to end too:
    // its lease is the only deadline covering that stop.
    if (foreign_lease_ != 0 && foreign_lease_ == lease_id) {
      EndForeignPause(lease_id);
      return Reply(NativeDebuggerPauseStatus::kOk, "expire_lease", true, base::DictValue());
    }
    return EndLease(lease_id, true);
  }
  const bool was_paused = paused_;
  Clear(kNativeDebuggerPauseClearIdle);
  return Reply(NativeDebuggerPauseStatus::kOk, "release_idle", was_paused, base::DictValue());
}

void NativeDebuggerPauseSession::OnForeignPause(const std::string& reason) {
  // This stop belongs to another document of the context group. Nothing of it
  // is read: no frames, no values, and the selected document is not paused,
  // so no client command can name it. The browser is told, because its
  // deadline is the only thing that ends this stop if the resume below never
  // runs; the lease it starts is one no client can use.
  if (foreign_lease_ != 0) {
    return;
  }
  foreign_lease_ = next_lease_++;
  foreign_started_ = base::TimeTicks::Now();
  pause_requested_ = false;
  const std::uint8_t record_reason =
      (reason == "exception" || reason == "promiseRejection") ? kNativeDebuggerPauseReasonException
      : reason == "step"                                      ? kNativeDebuggerPauseReasonStep
                         : kNativeDebuggerPauseReasonDebuggerStatement;
  std::array<std::uint8_t, 48> stopped{};
  stopped[0] = record_reason;
  Put64(stopped, 8, foreign_lease_);
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerPaused), stopped);
  if (observer_.paused) {
    observer_.paused.Run(foreign_lease_, record_reason, 0, 0, 0, false);
  }
  // Resuming from inside this notification would be lost: V8 enters
  // `runMessageLoopOnPause` after it returns whatever happened here, and a
  // quit asked for before that loop starts does nothing. The resume is posted
  // instead, on the task queue that runs while the thread is stopped.
  if (observer_.post) {
    observer_.post.Run(base::BindOnce(&NativeDebuggerPauseSession::EndForeignPause,
                                      base::RetainedRef(this), foreign_lease_));
  }
}

void NativeDebuggerPauseSession::EndForeignPause(const std::uint64_t lease) {
  if (foreign_lease_ != lease || !debugger_) {
    return;
  }
  const auto paused_ms = static_cast<std::uint32_t>(
      std::clamp<std::int64_t>((base::TimeTicks::Now() - foreign_started_).InMilliseconds(), 0,
                               kNativeDebuggerPauseLeaseMs));
  base::DictValue release;
  release.Set("objectGroup", std::string(kNativeDebuggerPauseObjectGroup));
  Call("Runtime.releaseObjectGroup", std::move(release));
  Call("Debugger.resume", base::DictValue());
  foreign_lease_ = 0;
  std::array<std::uint8_t, 48> ended{};
  ended[0] = kNativeDebuggerPauseEndForeign;
  Put32(ended, 4, paused_ms);
  Put64(ended, 8, lease);
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerResumed), ended);
  if (observer_.resumed) {
    observer_.resumed.Run(lease, kNativeDebuggerPauseEndForeign, paused_ms);
  }
}

void NativeDebuggerPauseSession::OnResumed() {
  // Every resume this session asked for already reported itself and left
  // `paused_` false. Still being paused here means something else continued
  // the page, a DevTools window on the same isolate for instance, so the
  // browser is told now: otherwise its deadline would keep running against a
  // page that is no longer stopped, and this pause's values would stay held.
  const bool unreported = paused_;
  const std::uint64_t lease = lease_;
  const auto paused_ms = static_cast<std::uint32_t>(std::clamp<std::int64_t>(
      (base::TimeTicks::Now() - lease_started_).InMilliseconds(), 0, kNativeDebuggerPauseLeaseMs));
  paused_ = false;
  paused_frame_id_ = 0;
  pause_reason_.clear();
  pause_breakpoint_ = 0;
  frames_ = base::ListValue();
  call_frames_.clear();
  objects_.clear();
  object_ids_.clear();
  if (lease_state_ == "active") {
    lease_state_ = "released";
  }
  if (!unreported) {
    return;
  }
  if (frame_) {
    base::DictValue release;
    release.Set("objectGroup", std::string(kNativeDebuggerPauseObjectGroup));
    Call("Runtime.releaseObjectGroup", std::move(release));
  }
  std::array<std::uint8_t, 48> tail{};
  tail[0] = kNativeDebuggerPauseEndElsewhere;
  Put32(tail, 4, paused_ms);
  Put64(tail, 8, lease);
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerResumed), tail);
  if (observer_.resumed) {
    observer_.resumed.Run(lease, kNativeDebuggerPauseEndElsewhere, paused_ms);
  }
}

void NativeDebuggerPauseSession::LetPageRun(const std::uint8_t end, const char* lease_state) {
  const std::uint64_t lease = lease_;
  const auto paused_ms = static_cast<std::uint32_t>(std::clamp<std::int64_t>(
      (base::TimeTicks::Now() - lease_started_).InMilliseconds(), 0, kNativeDebuggerPauseLeaseMs));
  // Values live only while the pause does, so the whole group goes now.
  base::DictValue release;
  release.Set("objectGroup", std::string(kNativeDebuggerPauseObjectGroup));
  Call("Runtime.releaseObjectGroup", std::move(release));
  Call("Debugger.resume", base::DictValue());
  paused_ = false;
  pause_reason_.clear();
  pause_breakpoint_ = 0;
  frames_ = base::ListValue();
  call_frames_.clear();
  objects_.clear();
  object_ids_.clear();
  lease_state_ = lease_state;

  std::array<std::uint8_t, 48> tail{};
  tail[0] = end;
  Put32(tail, 4, paused_ms);
  Put64(tail, 8, lease);
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerResumed), tail);
  if (observer_.resumed) {
    observer_.resumed.Run(lease, end, paused_ms);
  }
}

std::uint64_t NativeDebuggerPauseSession::ObjectIdFor(const std::string& inspector_id) {
  const auto known = object_ids_.find(inspector_id);
  if (known != object_ids_.end()) {
    return known->second;
  }
  if (objects_.size() >= kNativeDebuggerPauseObjectLimit) {
    return 0;
  }
  const std::uint64_t id = next_object_++;
  objects_.emplace(id, inspector_id);
  object_ids_.emplace(inspector_id, id);
  return id;
}

const std::string* NativeDebuggerPauseSession::InspectorObject(const std::uint64_t id) const {
  const auto known = objects_.find(id);
  return known == objects_.end() ? nullptr : &known->second;
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

base::DictValue NativeDebuggerPauseSession::LeaseBody() const {
  base::DictValue lease;
  lease.Set("lease_id", Decimal(lease_));
  lease.Set("state", lease_state_);
  std::uint64_t remaining = 0;
  if (lease_state_ == "active") {
    const std::int64_t elapsed = (base::TimeTicks::Now() - lease_started_).InMilliseconds();
    remaining = elapsed >= kNativeDebuggerPauseLeaseMs
                    ? 0
                    : kNativeDebuggerPauseLeaseMs -
                          static_cast<std::uint64_t>(std::max<std::int64_t>(elapsed, 0));
  }
  lease.Set("expires_in_ms", static_cast<int>(remaining));
  return lease;
}

base::DictValue NativeDebuggerPauseSession::PauseBody(const bool include_frames) const {
  base::DictValue pause;
  pause.Set("reason", pause_reason_);
  pause.Set("breakpoint_id",
            pause_breakpoint_ == 0 ? base::Value() : base::Value(Decimal(pause_breakpoint_)));
  pause.Set("lease_id", Decimal(lease_));
  pause.Set("frames_recorded", static_cast<int>(frames_.size()));
  pause.Set("async_frames", static_cast<int>(async_frames_));
  pause.Set("frames_truncated", frames_total_ > frames_.size());
  pause.Set("frames_omitted", !include_frames);
  pause.Set("frames", include_frames ? frames_.Clone() : base::ListValue());
  return pause;
}

base::DictValue NativeDebuggerPauseSession::BreakpointBody(const Breakpoint& breakpoint) const {
  base::DictValue row;
  row.Set("breakpoint_id", Decimal(breakpoint.id));
  row.Set("kind", breakpoint.kind);
  row.Set("resolved", !breakpoint.inspector_id.empty());
  row.Set("hits", static_cast<int>(breakpoint.hits));
  row.Set("script_id", static_cast<int>(breakpoint.script_id));
  row.Set("line", static_cast<int>(breakpoint.line));
  row.Set("column", static_cast<int>(breakpoint.column));
  row.Set("condition_set", breakpoint.condition_set);
  row.Set("logpoint", breakpoint.logpoint);
  return row;
}

base::DictValue NativeDebuggerPauseSession::StateBody(const bool include_frames) const {
  base::DictValue state;
  state.Set("active_indication",
            attached_ ? base::Value(kNativeDebuggerPauseActiveIndication) : base::Value());
  // The page can always tell, so this says which mode is in force rather
  // than claiming the debugger only stops where it was asked to.
  state.Set("quiet_mode", QuietMode());
  if (attached_) {
    base::DictValue document;
    document.Set("target_id", Decimal(target_id_));
    document.Set("frame", frame_ && frame_->Parent() ? "child" : "top");
    state.Set("document", std::move(document));
  } else {
    state.Set("document", base::Value());
  }
  state.Set("last_clear", last_clear_ == kNativeDebuggerPauseClearNone
                              ? base::Value()
                              : base::Value(NativeDebuggerPauseClearName(last_clear_)));
  state.Set("exceptions", exceptions_);
  base::ListValue rows;
  for (const Breakpoint& breakpoint : breakpoints_) {
    rows.Append(BreakpointBody(breakpoint));
  }
  state.Set("breakpoints", std::move(rows));
  state.Set("lease", lease_ == 0 ? base::Value() : base::Value(LeaseBody()));
  state.Set("paused", paused_);
  state.Set("pause", paused_ ? base::Value(PauseBody(include_frames)) : base::Value());
  return state;
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::Reply(
    const NativeDebuggerPauseStatus status,
    std::string_view action,
    const bool resumed,
    base::DictValue extra) {
  base::DictValue body = std::move(extra);
  body.Set("action", std::string(action));
  body.Set("status", NativeDebuggerPauseStatusName(status));
  // Every result says whether the debugger is on this document, so a client
  // that only ever sends commands still carries the notice.
  body.Set("active_indication",
           attached_ ? base::Value(kNativeDebuggerPauseActiveIndication) : base::Value());
  body.Set("paused", paused_);
  body.Set("resumed", resumed);
  body.Set("lease", lease_ == 0 ? base::Value() : base::Value(LeaseBody()));
  for (const char* field : {"pause", "breakpoint", "value", "properties"}) {
    if (!body.contains(field)) {
      body.Set(field, base::Value());
    }
  }
  Result result;
  result.status = status;
  result.paused = paused_;
  result.resumed = resumed;
  base::JSONWriter::Write(body, &result.body);
  if (result.body.size() > kNativeDebuggerPauseReplyLimit) {
    // A view this large is a bug in these bounds, not something to truncate
    // into a reply a reader would believe.
    result.status = NativeDebuggerPauseStatus::kLimit;
    result.body = std::string("{\"action\":\"") + std::string(action) +
                  "\",\"status\":\"limit\",\"active_indication\":" +
                  (attached_ ? std::string("\"") + kNativeDebuggerPauseActiveIndication + "\""
                             : std::string("null")) +
                  ",\"paused\":" + (paused_ ? "true" : "false") +
                  ",\"resumed\":" + (resumed ? "true" : "false") +
                  ",\"lease\":null,\"pause\":null,\"breakpoint\":null,\"value\":null,"
                  "\"properties\":null}";
  }
  return result;
}

NativeDebuggerPauseStatus NativeDebuggerPauseSession::CheckLease(
    const std::uint64_t lease_id) const {
  if (!paused_) {
    return NativeDebuggerPauseStatus::kNotPaused;
  }
  return lease_id == lease_ ? NativeDebuggerPauseStatus::kOk
                            : NativeDebuggerPauseStatus::kStaleLease;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::Command(
    const NativeDebuggerPauseOperation operation,
    const std::uint64_t lease_id,
    const std::string& command) {
  // Page script can destroy this frame from inside an evaluation, which
  // deletes the agent and drops its reference to this session. One reference
  // held here keeps the object, its inspector session and its channel alive
  // until this command has finished with them.
  const scoped_refptr<NativeDebuggerPauseSession> alive(this);
  if (operation == NativeDebuggerPauseOperation::kState) {
    Result result;
    result.paused = paused_;
    base::DictValue body = StateBody(true);
    body.Set("action", "state");
    body.Set("status", "ok");
    body.Set("resumed", false);
    base::JSONWriter::Write(body, &result.body);
    if (result.body.size() > kNativeDebuggerPauseReplyLimit) {
      // A deep pause with long names can outgrow the reply bound. The state
      // is still answered, without the call stack and saying so, rather than
      // dropped for being too large.
      base::DictValue bounded = StateBody(false);
      bounded.Set("action", "state");
      bounded.Set("status", "ok");
      bounded.Set("resumed", false);
      result.body.clear();
      base::JSONWriter::Write(bounded, &result.body);
    }
    return result;
  }
  // The browser's own deadline operations. They cannot run inside another
  // dispatch, so one that arrives then is remembered and run when that
  // dispatch returns: dropping it would leave a page paused past its
  // deadline, which is the one thing the deadline exists to prevent.
  if (operation == NativeDebuggerPauseOperation::kExpireLease ||
      operation == NativeDebuggerPauseOperation::kReleaseIdle) {
    if (awaiting_call_id_ != 0) {
      pending_deadline_ = operation;
      pending_deadline_lease_ = lease_id;
      return Reply(NativeDebuggerPauseStatus::kBusy, NativeDebuggerPauseOperationName(operation),
                   false, base::DictValue());
    }
    return RunDeadline(operation, lease_id);
  }
  // The action this operation names, so a refusal taken before the body is
  // read still says which action it refused.
  const char* const named = NativeDebuggerPauseOperationName(operation);
  // A command that arrived while this session is dispatching another ran
  // nothing. The pinned V8 postpones interrupts inside a DebugScope, so this
  // cannot happen during a paused evaluation; it stays as a guard that fails
  // closed rather than overwriting the call being waited for.
  if (awaiting_call_id_ != 0) {
    return Reply(NativeDebuggerPauseStatus::kBusy, named, false, base::DictValue());
  }
  std::optional<base::DictValue> parsed = base::JSONReader::ReadDict(command, base::JSON_PARSE_RFC);
  if (!parsed) {
    return Reply(NativeDebuggerPauseStatus::kMalformed, named, false, base::DictValue());
  }
  std::string action = Text(*parsed, "action");
  if (action.empty()) {
    action = named;
  }
  if (operation != NativeDebuggerPauseOperation::kSelectDocument && !attached_) {
    return Reply(NativeDebuggerPauseStatus::kNotAuthorized, action, false, base::DictValue());
  }
  // Every command that can make the page stop carries the same confirmation,
  // and the renderer fails closed on it as well as the backend.
  if (NativeDebuggerPauseNeedsConfirmation(operation) &&
      parsed->FindBool("confirm_pause") != true) {
    return Reply(NativeDebuggerPauseStatus::kInvalidInput, action, false, base::DictValue());
  }

  switch (operation) {
    case NativeDebuggerPauseOperation::kSelectDocument:
      return Select();
    case NativeDebuggerPauseOperation::kReleaseDocument: {
      const bool was_paused = paused_;
      Clear(kNativeDebuggerPauseClearReleased);
      return Reply(NativeDebuggerPauseStatus::kOk, action, was_paused, base::DictValue());
    }
    case NativeDebuggerPauseOperation::kSetBreakpoint:
      return SetBreakpoint(*parsed);
    case NativeDebuggerPauseOperation::kRemoveBreakpoint:
      return RemoveBreakpoint(*parsed);
    case NativeDebuggerPauseOperation::kPauseOnExceptions:
      return PauseOnExceptions(*parsed);
    case NativeDebuggerPauseOperation::kPause:
      pause_requested_ = !paused_;
      Call("Debugger.pause", base::DictValue());
      return Reply(NativeDebuggerPauseStatus::kOk, action, false, base::DictValue());
    case NativeDebuggerPauseOperation::kResume:
    case NativeDebuggerPauseOperation::kStepOver:
    case NativeDebuggerPauseOperation::kStepInto:
    case NativeDebuggerPauseOperation::kStepOut:
      return Step(operation, lease_id);
    case NativeDebuggerPauseOperation::kReleaseLease:
      return EndLease(lease_id, false);
    case NativeDebuggerPauseOperation::kEvaluateOnFrame:
      return Evaluate(lease_id, *parsed);
    case NativeDebuggerPauseOperation::kGetProperties:
      return Properties(lease_id, *parsed);
    default:
      return Reply(NativeDebuggerPauseStatus::kMalformed, action, false, base::DictValue());
  }
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::Select() {
  if (!Attach()) {
    return Reply(NativeDebuggerPauseStatus::kStaleDocument, "select_document", false,
                 base::DictValue());
  }
  attached_ = true;
  last_clear_ = kNativeDebuggerPauseClearNone;
  std::array<std::uint8_t, 48> tail{};
  tail[0] = 1;
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerAttached), tail);
  // The browser answers a later state read from what it was told, so it is
  // told that this document is armed and nothing has ended.
  if (observer_.cleared) {
    observer_.cleared.Run(kNativeDebuggerPauseClearNone, 0);
  }
  return Reply(NativeDebuggerPauseStatus::kOk, "select_document", false, base::DictValue());
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::SetBreakpoint(
    const base::DictValue& command) {
  const std::string action = Text(command, "action");
  if (breakpoints_.size() >= kNativeDebuggerPauseBreakpointLimit) {
    return Reply(NativeDebuggerPauseStatus::kLimit, action, false, base::DictValue());
  }
  const std::string condition = Text(command, "condition");
  const std::string log_message = Text(command, "log_message");
  if (!condition.empty() && !log_message.empty()) {
    return Reply(NativeDebuggerPauseStatus::kInvalidInput, action, false, base::DictValue());
  }
  Breakpoint breakpoint;
  breakpoint.id = next_breakpoint_++;
  breakpoint.script_id = Number32(command, "script_id");
  breakpoint.line = Number32(command, "line");
  breakpoint.column = Number32(command, "column");
  breakpoint.condition_set = !condition.empty();
  breakpoint.logpoint = !log_message.empty();
  breakpoint.kind = breakpoint.logpoint        ? "logpoint"
                    : breakpoint.condition_set ? "conditional"
                                               : "line";
  base::DictValue location;
  location.Set("scriptId", Decimal(breakpoint.script_id));
  location.Set("lineNumber", static_cast<int>(breakpoint.line == 0 ? 0 : breakpoint.line - 1));
  location.Set("columnNumber", static_cast<int>(breakpoint.column));
  base::DictValue params;
  params.Set("location", std::move(location));
  if (breakpoint.logpoint) {
    // A logpoint is a condition that logs and evaluates to false, which is
    // how DevTools keeps it from stopping the page. The message is one
    // literal argument: nothing in it is interpolated.
    std::string escaped;
    base::JSONWriter::Write(base::Value(log_message), &escaped);
    params.Set("condition", "console.log(" + escaped + "), false");
  } else if (breakpoint.condition_set) {
    params.Set("condition", condition);
  }
  std::optional<base::DictValue> result = Call("Debugger.setBreakpoint", std::move(params));
  std::array<std::uint8_t, 48> tail{};
  tail[1] = breakpoint.logpoint ? 3 : breakpoint.condition_set ? 2 : 1;
  Put32(tail, 4, breakpoint.script_id);
  Put32(tail, 8, breakpoint.line);
  if (!result) {
    tail[0] = 3;
    EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerBreakpoint), tail);
    return Reply(NativeDebuggerPauseStatus::kInvalidInput, action, false, base::DictValue());
  }
  breakpoint.inspector_id = Text(*result, "breakpointId");
  if (const base::DictValue* location_out = result->FindDict("actualLocation")) {
    breakpoint.line = Number32(*location_out, "lineNumber") + 1;
    breakpoint.column = Number32(*location_out, "columnNumber");
  }
  tail[0] = 1;
  Put32(tail, 8, breakpoint.line);
  Put32(tail, 12, static_cast<std::uint32_t>(breakpoint.id));
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerBreakpoint), tail);
  base::DictValue extra;
  extra.Set("breakpoint", BreakpointBody(breakpoint));
  breakpoints_.push_back(std::move(breakpoint));
  return Reply(NativeDebuggerPauseStatus::kOk, action, false, std::move(extra));
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::RemoveBreakpoint(
    const base::DictValue& command) {
  const std::string action = Text(command, "action");
  const std::uint64_t id = ParseDecimal(command.FindString("breakpoint_id"));
  const auto found =
      std::find_if(breakpoints_.begin(), breakpoints_.end(),
                   [id](const Breakpoint& breakpoint) { return breakpoint.id == id; });
  if (found == breakpoints_.end()) {
    return Reply(NativeDebuggerPauseStatus::kUnknownBreakpoint, action, false, base::DictValue());
  }
  base::DictValue params;
  params.Set("breakpointId", found->inspector_id);
  Call("Debugger.removeBreakpoint", std::move(params));
  std::array<std::uint8_t, 48> tail{};
  tail[0] = 2;
  tail[1] = found->logpoint ? 3 : found->condition_set ? 2 : 1;
  Put32(tail, 4, found->script_id);
  Put32(tail, 8, found->line);
  Put32(tail, 12, static_cast<std::uint32_t>(found->id));
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerBreakpoint), tail);
  breakpoints_.erase(found);
  return Reply(NativeDebuggerPauseStatus::kOk, action, false, base::DictValue());
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::PauseOnExceptions(
    const base::DictValue& command) {
  const std::string action = Text(command, "action");
  const std::string mode = Text(command, "mode");
  if (mode != "none" && mode != "uncaught" && mode != "all") {
    return Reply(NativeDebuggerPauseStatus::kInvalidInput, action, false, base::DictValue());
  }
  base::DictValue params;
  params.Set("state", mode);
  if (!Call("Debugger.setPauseOnExceptions", std::move(params))) {
    return Reply(NativeDebuggerPauseStatus::kInvalidInput, action, false, base::DictValue());
  }
  exceptions_ = mode;
  return Reply(NativeDebuggerPauseStatus::kOk, action, false, base::DictValue());
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::Step(
    const NativeDebuggerPauseOperation operation,
    const std::uint64_t lease_id) {
  const char* action = operation == NativeDebuggerPauseOperation::kResume     ? "resume"
                       : operation == NativeDebuggerPauseOperation::kStepOver ? "step_over"
                       : operation == NativeDebuggerPauseOperation::kStepInto ? "step_into"
                                                                              : "step_out";
  if (const NativeDebuggerPauseStatus status = CheckLease(lease_id);
      status != NativeDebuggerPauseStatus::kOk) {
    return Reply(status, action, false, base::DictValue());
  }
  const char* method = operation == NativeDebuggerPauseOperation::kResume     ? "Debugger.resume"
                       : operation == NativeDebuggerPauseOperation::kStepOver ? "Debugger.stepOver"
                       : operation == NativeDebuggerPauseOperation::kStepInto ? "Debugger.stepInto"
                                                                              : "Debugger.stepOut";
  const std::uint64_t lease = lease_;
  const auto paused_ms = static_cast<std::uint32_t>(std::clamp<std::int64_t>(
      (base::TimeTicks::Now() - lease_started_).InMilliseconds(), 0, kNativeDebuggerPauseLeaseMs));
  base::DictValue release;
  release.Set("objectGroup", std::string(kNativeDebuggerPauseObjectGroup));
  Call("Runtime.releaseObjectGroup", std::move(release));
  Call(method, base::DictValue());
  // The inspector quits the nested loop from inside that call and sends
  // Debugger.resumed only after it unwinds, which is after this reply. The
  // page is running as far as this command is concerned, and the pause it
  // lands on is read from the state.
  paused_ = false;
  pause_reason_.clear();
  pause_breakpoint_ = 0;
  frames_ = base::ListValue();
  call_frames_.clear();
  objects_.clear();
  object_ids_.clear();
  lease_state_ = "released";
  const std::uint8_t end = operation == NativeDebuggerPauseOperation::kResume
                               ? kNativeDebuggerPauseEndResume
                               : kNativeDebuggerPauseEndStep;
  std::array<std::uint8_t, 48> tail{};
  tail[0] = end;
  Put32(tail, 4, paused_ms);
  Put64(tail, 8, lease);
  EmitRecord(static_cast<std::uint8_t>(NativeProbeType::kDebuggerResumed), tail);
  if (observer_.resumed) {
    observer_.resumed.Run(lease, end, paused_ms);
  }
  return Reply(NativeDebuggerPauseStatus::kOk, action, true, base::DictValue());
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::EndLease(
    const std::uint64_t lease_id,
    const bool deadline) {
  const char* action = deadline ? "expire_lease" : "release_lease";
  if (const NativeDebuggerPauseStatus status = CheckLease(lease_id);
      status != NativeDebuggerPauseStatus::kOk) {
    return Reply(status, action, false, base::DictValue());
  }
  LetPageRun(deadline ? kNativeDebuggerPauseEndExpired : kNativeDebuggerPauseEndRelease,
             deadline ? "expired" : "released");
  return Reply(NativeDebuggerPauseStatus::kOk, action, true, base::DictValue());
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::Evaluate(
    const std::uint64_t lease_id,
    const base::DictValue& command) {
  const std::string action = Text(command, "action");
  if (const NativeDebuggerPauseStatus status = CheckLease(lease_id);
      status != NativeDebuggerPauseStatus::kOk) {
    return Reply(status, action, false, base::DictValue());
  }
  const std::optional<int> index = command.FindInt("call_frame_index");
  if (!index || *index < 0 || static_cast<std::size_t>(*index) >= call_frames_.size()) {
    return Reply(NativeDebuggerPauseStatus::kLimit, action, false, base::DictValue());
  }
  const std::string expression = Text(command, "expression");
  if (expression.empty() || expression.size() > kNativeDebuggerPauseExpressionBytes) {
    return Reply(NativeDebuggerPauseStatus::kInvalidInput, action, false, base::DictValue());
  }
  base::DictValue params;
  params.Set("callFrameId", call_frames_[static_cast<std::size_t>(*index)]);
  params.Set("expression", expression);
  params.Set("objectGroup", std::string(kNativeDebuggerPauseObjectGroup));
  params.Set("silent", true);
  params.Set("returnByValue", false);
  params.Set("timeout", kNativeDebuggerPauseEvaluationMs);
  std::optional<base::DictValue> result = Call("Debugger.evaluateOnCallFrame", std::move(params));
  if (!result) {
    if (last_call_error_.empty()) {
      // The inspector refused the call itself; nothing was evaluated.
      return Reply(NativeDebuggerPauseStatus::kInvalidInput, action, false, base::DictValue());
    }
    // V8 answers a terminated evaluation with a server error carrying its own
    // text ("Execution was terminated" when the deadline stopped it), so this
    // is an evaluation that ran and failed, not a command that was refused.
    base::DictValue value;
    value.Set("kind", "string");
    value.Set("text", Bounded(last_call_error_, kNativeDebuggerPauseValueBytes));
    value.Set("truncated", false);
    value.Set("object_id", base::Value());
    value.Set("threw", true);
    base::DictValue extra;
    extra.Set("value", std::move(value));
    return Reply(NativeDebuggerPauseStatus::kEvaluationError, action, false, std::move(extra));
  }
  const bool threw = result->FindDict("exceptionDetails") != nullptr;
  base::DictValue extra;
  if (const base::DictValue* remote = result->FindDict("result")) {
    const std::string inspector_id = Text(*remote, "objectId");
    const std::uint64_t id = inspector_id.empty() ? 0 : ObjectIdFor(inspector_id);
    base::DictValue value = ValueOf(*remote, id == 0 ? std::string() : Decimal(id));
    value.Set("threw", threw);
    extra.Set("value", std::move(value));
  }
  // A timeout is an exception V8 raises inside the evaluation, so it is an
  // evaluation error with its text, not a refused command.
  return Reply(threw ? NativeDebuggerPauseStatus::kEvaluationError : NativeDebuggerPauseStatus::kOk,
               action, false, std::move(extra));
}

NativeDebuggerPauseSession::Result NativeDebuggerPauseSession::Properties(
    const std::uint64_t lease_id,
    const base::DictValue& command) {
  const std::string action = Text(command, "action");
  if (const NativeDebuggerPauseStatus status = CheckLease(lease_id);
      status != NativeDebuggerPauseStatus::kOk) {
    return Reply(status, action, false, base::DictValue());
  }
  const std::uint64_t id = ParseDecimal(command.FindString("object_id"));
  const std::string* inspector_id = InspectorObject(id);
  if (!inspector_id) {
    return Reply(NativeDebuggerPauseStatus::kUnknownObject, action, false, base::DictValue());
  }
  const std::optional<int> offset = command.FindInt("offset");
  const std::size_t start = offset && *offset > 0 ? static_cast<std::size_t>(*offset) : 0;
  base::DictValue params;
  params.Set("objectId", *inspector_id);
  params.Set("ownProperties", true);
  params.Set("generatePreview", false);
  std::optional<base::DictValue> result = Call("Runtime.getProperties", std::move(params));
  if (!result) {
    return Reply(NativeDebuggerPauseStatus::kUnknownObject, action, false, base::DictValue());
  }
  const base::ListValue* all = result->FindList("result");
  const std::size_t total =
      std::min<std::size_t>(all ? all->size() : 0, kNativeDebuggerPausePropertyLimit);
  base::ListValue items;
  for (std::size_t at = start; at < total && items.size() < kNativeDebuggerPausePropertyPage;
       ++at) {
    const base::DictValue* property = (*all)[at].GetIfDict();
    if (!property) {
      continue;
    }
    // An accessor has no value until it is called, which this contract never
    // does: it is reported as an accessor rather than as undefined.
    const base::DictValue* remote = property->FindDict("value");
    const bool accessor = !remote && (property->FindDict("get") || property->FindDict("set"));
    std::string object_id;
    if (remote) {
      const std::string inspector = Text(*remote, "objectId");
      const std::uint64_t child = inspector.empty() ? 0 : ObjectIdFor(inspector);
      if (child != 0) {
        object_id = Decimal(child);
      }
    }
    base::DictValue row = remote ? ValueOf(*remote, object_id) : base::DictValue();
    row.Remove("threw");
    if (!remote) {
      row.Set("kind", accessor ? "accessor" : "undefined");
      row.Set("text", accessor ? "(getter)" : "undefined");
      row.Set("truncated", false);
      row.Set("object_id", base::Value());
    }
    row.Set("name", Bounded(Text(*property, "name"), kNativeDebuggerPauseNameBytes));
    items.Append(std::move(row));
  }
  const std::size_t next = start + items.size();
  base::DictValue properties;
  properties.Set("object_id", Decimal(id));
  properties.Set("offset", static_cast<int>(std::min(start, total)));
  properties.Set("next_offset", next < total ? base::Value(Decimal(next)) : base::Value());
  properties.Set("total", static_cast<int>(total));
  properties.Set("items", std::move(items));
  base::DictValue extra;
  extra.Set("properties", std::move(properties));
  return Reply(NativeDebuggerPauseStatus::kOk, action, false, std::move(extra));
}

}  // namespace reb
