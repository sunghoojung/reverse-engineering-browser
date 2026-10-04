// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_console_agent.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <optional>
#include <string>

#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "base/strings/string_util.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/common/native_console_protocol.h"
#include "content/public/renderer/render_frame.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_registry.h"
#include "third_party/blink/public/platform/scheduler/web_agent_group_scheduler.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "v8/include/v8.h"

namespace reb {
namespace {

// Only the watchdog and the renderer execution thread share this state. The
// lock ensures a late watchdog can never terminate a subsequent page task or
// access an isolate after this evaluation has released it. No V8 handles cross
// threads. TerminateExecution is explicitly safe to call from another thread.
class ExecutionDeadline final {
 public:
  static ExecutionDeadline& Get() {
    static base::NoDestructor<ExecutionDeadline> deadline;
    return *deadline;
  }
  bool Begin(v8::Isolate* isolate) {
    base::AutoLock lock(lock_);
    if (isolate_)
      return false;
    isolate_ = isolate;
    expires_ = base::TimeTicks::Now() + base::Milliseconds(kNativeConsoleExecutionMillis);
    expired_ = false;
    if (!worker_running_) {
      worker_running_ = base::ThreadPool::PostTask(
          FROM_HERE, {base::WithBaseSyncPrimitives(), base::TaskPriority::USER_BLOCKING},
          base::BindOnce(&ExecutionDeadline::Watch, base::Unretained(this)));
      if (!worker_running_) {
        isolate_ = nullptr;
        return false;
      }
    }
    changed_.Signal();
    return true;
  }
  bool Finish() {
    base::AutoLock lock(lock_);
    if (expired_)
      isolate_->CancelTerminateExecution();
    isolate_ = nullptr;
    changed_.Signal();
    return expired_;
  }

 private:
  friend class base::NoDestructor<ExecutionDeadline>;
  ExecutionDeadline() = default;
  void Watch() {
    base::AutoLock lock(lock_);
    for (;;) {
      if (!isolate_) {
        const auto idle_until = base::TimeTicks::Now() + base::Milliseconds(500);
        while (!isolate_ && base::TimeTicks::Now() < idle_until)
          changed_.TimedWait(std::max(base::TimeDelta(), idle_until - base::TimeTicks::Now()));
        if (!isolate_) {
          worker_running_ = false;
          return;
        }
      }
      if (!expired_ && base::TimeTicks::Now() >= expires_) {
        expired_ = true;
        isolate_->TerminateExecution();
      }
      if (expired_)
        changed_.Wait();
      else
        changed_.TimedWait(std::max(base::TimeDelta(), expires_ - base::TimeTicks::Now()));
    }
  }
  base::Lock lock_;
  base::ConditionVariable changed_{&lock_};
  v8::Isolate* isolate_ = nullptr;
  base::TimeTicks expires_;
  bool expired_ = false;
  bool worker_running_ = false;
};

std::string CopyString(v8::Isolate* isolate, v8::Local<v8::String> string, bool& truncated) {
  std::array<char, kNativeConsoleTextLimit> buffer{};
  std::size_t characters = 0;
  const auto bytes = string->WriteUtf8(isolate, buffer.data(), buffer.size(),
                                       v8::String::WriteFlags::kReplaceInvalidUtf8, &characters);
  truncated = characters < static_cast<std::size_t>(string->Length());
  return std::string(buffer.data(), bytes);
}

NativeConsoleType Preview(v8::Isolate* isolate,
                          v8::Local<v8::Context> context,
                          v8::Local<v8::Value> value,
                          std::string& text,
                          bool& truncated) {
  if (value->IsUndefined()) {
    text = "undefined";
    return NativeConsoleType::kUndefined;
  }
  if (value->IsNull()) {
    text = "null";
    return NativeConsoleType::kNull;
  }
  if (value->IsBoolean()) {
    text = value.As<v8::Boolean>()->Value() ? "true" : "false";
    return NativeConsoleType::kBoolean;
  }
  if (value->IsString()) {
    text = CopyString(isolate, value.As<v8::String>(), truncated);
    return NativeConsoleType::kString;
  }
  if (value->IsNumber()) {
    const double number = value.As<v8::Number>()->Value();
    if (std::isnan(number))
      text = "NaN";
    else if (std::isinf(number))
      text = number < 0 ? "-Infinity" : "Infinity";
    else {
      std::array<char, 128> buffer{};
      const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), number);
      if (result.ec == std::errc{})
        text.assign(buffer.data(), result.ptr);
    }
    return NativeConsoleType::kNumber;
  }
  if (value->IsBigInt()) {
    // Conversion is bounded before requesting decimal formatting.
    if (value.As<v8::BigInt>()->WordCount() > 16) {
      text = "[BigInt larger than 1024 bits]";
      truncated = true;
    } else {
      v8::Local<v8::String> formatted;
      if (value->ToString(context).ToLocal(&formatted))
        text = CopyString(isolate, formatted, truncated);
    }
    return NativeConsoleType::kBigInt;
  }
  // Never enumerate objects or coerce them to strings: proxies, accessors,
  // custom formatters, toJSON, and toString can run page code. Keeping no object
  // handles also avoids retaining page heaps across evaluations or navigation.
  if (value->IsSymbol()) {
    text = "[Symbol]";
    return NativeConsoleType::kSymbol;
  }
  if (value->IsFunction()) {
    text = "[Function]";
    return NativeConsoleType::kFunction;
  }
  if (value->IsPromise()) {
    text = "[Promise; asynchronous results are not awaited]";
    return NativeConsoleType::kPromise;
  }
  text = "[Object; evaluate an explicit property to inspect it]";
  return NativeConsoleType::kObject;
}

}  // namespace

void NativeConsoleAgent::CreateIfEnabled(content::RenderFrame* frame) {
  static const bool enabled =
      base::CommandLine::ForCurrentProcess()->HasSwitch(kNativeConsoleSwitch);
  if (enabled)
    new NativeConsoleAgent(frame);
}

NativeConsoleAgent::NativeConsoleAgent(content::RenderFrame* frame)
    : content::RenderFrameObserver(frame) {
  frame->GetAssociatedInterfaceRegistry()->AddInterface<mojom::NativeConsoleAgent>(
      base::BindRepeating(&NativeConsoleAgent::Bind, base::Unretained(this)));
}
NativeConsoleAgent::~NativeConsoleAgent() = default;
void NativeConsoleAgent::OnDestruct() {
  delete this;
}
void NativeConsoleAgent::Bind(mojo::PendingAssociatedReceiver<mojom::NativeConsoleAgent> receiver) {
  receiver_.reset();
  receiver_.Bind(std::move(receiver));
}
void NativeConsoleAgent::Describe(DescribeCallback callback) {
  const auto* frame = render_frame() ? render_frame()->GetWebFrame() : nullptr;
  std::move(callback).Run(frame && !frame->IsProvisional()
                              ? std::optional(frame->GetDocument().Token().value())
                              : std::nullopt);
}

void NativeConsoleAgent::Evaluate(const base::UnguessableToken& document,
                                  std::uint64_t expires_at_monotonic_us,
                                  const std::string& source,
                                  EvaluateCallback callback) {
  auto reply = [&callback](NativeConsoleStatus status, const char* text) {
    std::move(callback).Run(static_cast<std::uint16_t>(status),
                            static_cast<std::uint16_t>(NativeConsoleType::kUndefined), text, false);
  };
  auto* frame = render_frame() ? render_frame()->GetWebFrame() : nullptr;
  if (!frame || frame->IsProvisional() || document.is_empty() ||
      frame->GetDocument().Token().value() != document) {
    reply(NativeConsoleStatus::kStaleTarget, "Selected document changed before execution");
    return;
  }
  if (expires_at_monotonic_us <=
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InMicroseconds())) {
    reply(NativeConsoleStatus::kTimeout, "Command expired while waiting for the renderer");
    return;
  }
  if (source.empty() || source.size() > kNativeConsoleSourceLimit || !base::IsStringUTF8(source) ||
      source.find('\0') != std::string::npos) {
    reply(NativeConsoleStatus::kMalformed, "JavaScript must be 1 to 8192 bytes of valid UTF-8");
    return;
  }
  v8::Isolate* isolate = frame->GetAgentGroupScheduler()->Isolate();
  v8::HandleScope handles(isolate);
  const auto context = frame->MainWorldScriptContext();
  if (context.IsEmpty() || isolate->IsExecutionTerminating()) {
    reply(NativeConsoleStatus::kForbidden, "Page context is not available for execution");
    return;
  }
  v8::Context::Scope entered(context);
  v8::MicrotasksScope microtasks(isolate, context->GetMicrotaskQueue(),
                                 v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::TryCatch exception(isolate);
  auto& deadline = ExecutionDeadline::Get();
  if (!deadline.Begin(isolate)) {
    reply(NativeConsoleStatus::kForbidden, "Execution watchdog is unavailable");
    return;
  }
  v8::Local<v8::String> code;
  v8::Local<v8::Script> script;
  v8::Local<v8::Value> value;
  const bool success = v8::String::NewFromUtf8(isolate, source.data(), v8::NewStringType::kNormal,
                                               static_cast<int>(source.size()))
                           .ToLocal(&code) &&
                       v8::Script::Compile(context, code).ToLocal(&script) &&
                       script->Run(context).ToLocal(&value);
  std::string text;
  bool truncated = false;
  NativeConsoleType type = NativeConsoleType::kUndefined;
  if (success)
    type = Preview(isolate, context, value, text, truncated);
  const bool timed_out = deadline.Finish();
  if (timed_out) {
    exception.Reset();
    reply(NativeConsoleStatus::kTimeout,
          "Synchronous execution exceeded its 200 ms budget; changes are not rolled back");
    return;
  }
  if (!success) {
    // A primitive thrown string is safe to copy. Never format an Error object
    // through page-controlled Error.prepareStackTrace or property accessors.
    if (!exception.Exception().IsEmpty() && exception.Exception()->IsString()) {
      text = CopyString(isolate, exception.Exception().As<v8::String>(), truncated);
    } else
      text = "JavaScript failed to compile or threw an exception";
    std::move(callback).Run(static_cast<std::uint16_t>(NativeConsoleStatus::kException),
                            static_cast<std::uint16_t>(NativeConsoleType::kUndefined), text,
                            truncated);
    return;
  }
  std::move(callback).Run(static_cast<std::uint16_t>(NativeConsoleStatus::kOk),
                          static_cast<std::uint16_t>(type), text, truncated);
}

}  // namespace reb
