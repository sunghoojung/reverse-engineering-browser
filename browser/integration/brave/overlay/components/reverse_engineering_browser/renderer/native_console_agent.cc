// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_console_agent.h"

#include <array>
#include <charconv>
#include <cmath>
#include <memory>
#include <optional>
#include <string>

#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/common/native_console_protocol.h"
#include "brave/components/reverse_engineering_browser/renderer/native_console_deadline.h"
#include "brave/components/reverse_engineering_browser/renderer/native_console_document_start.h"
#include "content/public/renderer/render_frame.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_registry.h"
#include "third_party/blink/public/platform/scheduler/web_agent_group_scheduler.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "v8/include/v8.h"

namespace reb {
namespace {

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
      const auto result = std::to_chars(buffer.data(), std::to_address(buffer.end()), number);
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

// Blink creates the main-world context before any script can run in it, so a
// matching snippet observes this document before its own scripts. Nothing runs
// here unless the separate document-start experiment is armed.
void NativeConsoleAgent::DidCreateScriptContext(v8::Local<v8::Context> context, int world_id) {
  if (world_id == 0)
    InjectNativeConsoleDocumentStart(render_frame(), context);
}

void NativeConsoleAgent::WillReleaseScriptContext(v8::Local<v8::Context> context, int world_id) {
  if (world_id == 0)
    runtime_.Reset();
}
void NativeConsoleAgent::DetailedConsoleMessageAdded(const std::u16string& message,
                                                     const std::u16string& source,
                                                     const std::u16string& stack,
                                                     uint32_t line,
                                                     blink::mojom::ConsoleMessageLevel level) {
  runtime_.Message(base::UTF16ToUTF8(message.substr(0, 2048)),
                   base::UTF16ToUTF8(source.substr(0, 512)),
                   base::UTF16ToUTF8(stack.substr(0, 2048)), line, static_cast<int>(level),
                   message.size() > 2048 || source.size() > 512 || stack.size() > 2048);
}
void NativeConsoleAgent::Runtime(const base::UnguessableToken& document,
                                 std::uint64_t expires_at_monotonic_us,
                                 const std::string& command,
                                 RuntimeCallback callback) {
  auto reply = [&callback](NativeConsoleStatus status, const char* text) {
    std::move(callback).Run(static_cast<uint16_t>(status),
                            static_cast<uint16_t>(NativeConsoleType::kUndefined), text, false);
  };
  auto* frame = render_frame() ? render_frame()->GetWebFrame() : nullptr;
  if (!frame || frame->IsProvisional() || document.is_empty() ||
      frame->GetDocument().Token().value() != document) {
    reply(NativeConsoleStatus::kStaleTarget, "Selected document changed");
    return;
  }
  if (expires_at_monotonic_us <=
      static_cast<uint64_t>(base::TimeTicks::Now().since_origin().InMicroseconds())) {
    reply(NativeConsoleStatus::kTimeout, "Request expired before dispatch");
    return;
  }
  auto* isolate = frame->GetAgentGroupScheduler()->Isolate();
  v8::HandleScope handles(isolate);
  auto context = frame->MainWorldScriptContext();
  if (context.IsEmpty() || isolate->IsExecutionTerminating()) {
    reply(NativeConsoleStatus::kForbidden, "Page context unavailable");
    return;
  }
  v8::Context::Scope entered(context);
  auto& deadline = NativeConsoleDeadline::Get();
  if (!deadline.Begin(isolate, kNativeConsoleExecutionMillis)) {
    reply(NativeConsoleStatus::kForbidden, "Watchdog unavailable");
    return;
  }
  v8::TryCatch terminated(isolate);
  std::string result;
  {
    // Explicit commands can schedule promise continuations. Run their checkpoint
    // inside the synchronous watchdog, rather than outside its 200 ms budget.
    v8::MicrotasksScope microtasks(isolate, context->GetMicrotaskQueue(),
                                   v8::MicrotasksScope::kRunMicrotasks);
    result = runtime_.Run(isolate, context, frame, command);
  }
  if (deadline.Finish()) {
    terminated.Reset();
    reply(NativeConsoleStatus::kTimeout,
          "Synchronous execution exceeded 200 ms; changes are not rolled back");
    return;
  }
  std::move(callback).Run(static_cast<uint16_t>(NativeConsoleStatus::kOk),
                          static_cast<uint16_t>(NativeConsoleType::kRuntime), result, false);
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
  auto& deadline = NativeConsoleDeadline::Get();
  if (!deadline.Begin(isolate, kNativeConsoleExecutionMillis)) {
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
