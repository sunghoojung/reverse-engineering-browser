// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_console_document_start.h"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/memory/read_only_shared_memory_region.h"
#include "base/no_destructor.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "brave/components/reverse_engineering_browser/common/native_console_document_start.h"
#include "brave/components/reverse_engineering_browser/renderer/native_console_execution.h"
#include "content/public/renderer/render_frame.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/platform/scheduler/web_agent_group_scheduler.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "v8/include/v8.h"

namespace reb {
namespace {

// Renderer main thread only, and false until the browser arms a decoded set.
// Document creation is on the critical path of every navigation, so the
// disarmed path must not reach the singleton, V8, or any matching work.
bool g_armed = false;

std::uint64_t FrameIdentity(const blink::WebLocalFrame* frame) noexcept {
  // Same derived identity the capture path already publishes for a frame, so a
  // document-start record and a captured event name the same frame alike.
  // GetLocalFrameToken() returns by value; a reference into it would dangle.
  const base::UnguessableToken token = frame->GetLocalFrameToken().value();
  return std::rotl(token.GetHighForSerialization(), 17) ^ token.GetLowForSerialization();
}

// Never formats an object, invokes an accessor, or calls a page-replaceable
// conversion: only primitives reach this function.
std::string PrimitiveText(v8::Isolate* isolate,
                          v8::Local<v8::Context> context,
                          v8::Local<v8::Value> value,
                          bool& truncated) {
  if (value->IsString() || value->IsBigInt()) {
    v8::Local<v8::String> text;
    if (value->IsBigInt()) {
      if (value.As<v8::BigInt>()->WordCount() > 16) {
        truncated = true;
        return "[BigInt larger than 1024 bits]";
      }
      if (!value->ToString(context).ToLocal(&text))
        return std::string();
    } else {
      text = value.As<v8::String>();
    }
    std::array<char, kNativeConsoleDocumentStartReportLimit> buffer{};
    std::size_t characters = 0;
    const auto bytes = text->WriteUtf8(isolate, buffer.data(), buffer.size(),
                                       v8::String::WriteFlags::kReplaceInvalidUtf8, &characters);
    truncated = truncated || characters < static_cast<std::size_t>(text->Length());
    return std::string(buffer.data(), bytes);
  }
  if (value->IsBoolean())
    return value.As<v8::Boolean>()->Value() ? "true" : "false";
  const double number = value.As<v8::Number>()->Value();
  if (std::isnan(number))
    return "NaN";
  if (std::isinf(number))
    return number < 0 ? "-Infinity" : "Infinity";
  std::array<char, 128> buffer{};
  const auto result = std::to_chars(buffer.data(), std::to_address(buffer.end()), number);
  return result.ec == std::errc{} ? std::string(buffer.data(), result.ptr) : std::string();
}

const char* ValueKind(v8::Local<v8::Value> value) noexcept {
  if (value->IsUndefined())
    return "undefined";
  if (value->IsNull())
    return "null";
  if (value->IsSymbol())
    return "a symbol";
  if (value->IsFunction())
    return "a function";
  return "an object";
}

class DocumentStart final : public mojom::NativeConsoleScriptClient {
 public:
  static DocumentStart& Get() {
    static base::NoDestructor<DocumentStart> injector;
    return *injector;
  }

  DocumentStart(const DocumentStart&) = delete;
  DocumentStart& operator=(const DocumentStart&) = delete;

  void Connect(mojo::PendingRemote<mojom::NativeConsoleScriptHost> pending) {
    if (host_.is_bound() || !pending.is_valid())
      return;
    host_.Bind(std::move(pending), base::SequencedTaskRunner::GetCurrentDefault());
    host_.set_disconnect_handler(base::BindOnce(&DocumentStart::Disarm, base::Unretained(this)));
    mojo::PendingRemote<mojom::NativeConsoleControl> control;
    BindNativeConsoleControl(control.InitWithNewPipeAndPassReceiver());
    host_->BindClient(receiver_.BindNewPipeAndPassRemote(), std::move(control));
  }

  void Inject(content::RenderFrame* render_frame,
              v8::Local<v8::Context> context,
              NativeConsoleDocumentStartFrame& state) {
    auto* frame = render_frame ? render_frame->GetWebFrame() : nullptr;
    if (!frame || frame->IsProvisional() || context.IsEmpty())
      return;
    // Decided for this document whether or not a rule matches, so the window
    // clear that follows in the same commit never injects it a second time.
    state.document = frame->GetDocument().Token().value();
    // The browser serializes the rule's origin with url::Origin, so compare the
    // document's own url::Origin serialization: an opaque origin becomes "null"
    // and can never equal a valid rule.
    const url::Origin origin = frame->GetSecurityOrigin();
    const GURL url = frame->GetDocument().Url();
    if (!url.SchemeIsHTTPOrHTTPS())
      return;
    const std::string serialized = origin.Serialize();
    const std::string_view path = url.path();
    const bool top = frame->IsOutermostMainFrame();
    // Only scripts for this exact origin can match, so the work per document
    // grows with that origin's scripts, not with the whole set. The index is
    // stably sorted, so they still run in the order they were armed.
    const std::string_view key(serialized);
    const auto first = std::lower_bound(by_origin_.begin(), by_origin_.end(), key,
                                        [this](std::uint32_t index, std::string_view origin) {
                                          return scripts_[index].rule.origin < origin;
                                        });
    const auto last = std::upper_bound(first, by_origin_.end(), key,
                                       [this](std::string_view origin, std::uint32_t index) {
                                         return origin < scripts_[index].rule.origin;
                                       });
    // Positions, not iterators, and the epoch is rechecked before each run:
    // the set can only change between tasks, but a stale position must never
    // be read if it ever did.
    const auto epoch = epoch_;
    const auto end = static_cast<std::size_t>(last - by_origin_.begin());
    for (auto position = static_cast<std::size_t>(first - by_origin_.begin());
         position < end && epoch == epoch_; ++position) {
      const auto index = by_origin_[position];
      if (NativeConsoleDocumentStartMatches(scripts_[index].rule, serialized, path, top))
        Run(frame, context, index);
    }
  }

  void InjectReused(content::RenderFrame* render_frame, NativeConsoleDocumentStartFrame& state) {
    auto* frame = render_frame ? render_frame->GetWebFrame() : nullptr;
    if (!frame || frame->IsProvisional() || frame->GetDocument().Token().value() == state.document)
      return;
    v8::HandleScope handles(frame->GetAgentGroupScheduler()->Isolate());
    // The context already exists, so this reads it and never creates one.
    Inject(render_frame, frame->MainWorldScriptContext(), state);
  }

  // Called from the `report` function the injected snippet received. A function
  // the page retained past a re-arm or clear resolves to no script and becomes
  // an inert no-op, so clearing the experiment stops all output.
  void Report(const v8::FunctionCallbackInfo<v8::Value>& info) {
    auto* frame = blink::WebLocalFrame::FrameForCurrentContext();
    // V8 15.7 deprecates Data() in favor of DataV2(), which returns v8::Data.
    const v8::Local<v8::Data> bound = info.DataV2();
    if (!frame || bound.IsEmpty() || !bound->IsValue() || !bound.As<v8::Value>()->IsBigInt())
      return;
    bool lossless = false;
    const auto data = bound.As<v8::BigInt>()->Uint64Value(&lossless);
    const auto epoch = static_cast<std::uint32_t>(data >> 32);
    const std::size_t index = static_cast<std::uint32_t>(data);
    if (!lossless || epoch != epoch_ || index >= scripts_.size())
      return;
    if (info.Length() != 1) {
      Emit(frame, index, NativeConsoleDocumentStartRecord::kRefused, false,
           "report(value) takes exactly one argument");
      return;
    }
    const auto value = info[0];
    if (!value->IsString() && !value->IsNumber() && !value->IsBoolean() && !value->IsBigInt()) {
      Emit(frame, index, NativeConsoleDocumentStartRecord::kRefused, false,
           std::string("report(value) refused ") + ValueKind(value) +
               "; pass a string, number, boolean or bigint");
      return;
    }
    bool truncated = false;
    auto* const isolate = info.GetIsolate();
    const auto text = PrimitiveText(isolate, isolate->GetCurrentContext(), value, truncated);
    Emit(frame, index, NativeConsoleDocumentStartRecord::kReport, truncated, text);
  }

 private:
  friend class base::NoDestructor<DocumentStart>;
  DocumentStart() = default;
  ~DocumentStart() override = default;

  void Arm(std::uint64_t generation,
           base::ReadOnlySharedMemoryRegion scripts,
           ArmCallback callback) override {
    Disarm();
    // The decoded scripts are views into this read-only mapping, which every
    // renderer shares, so arming copies no source.
    if (generation && scripts.IsValid())
      mapping_ = scripts.Map();
    if (mapping_.IsValid() && DecodeNativeConsoleDocumentStartScripts(
                                  mapping_.GetMemoryAsSpan<std::uint8_t>(), scripts_)) {
      generation_ = generation;
      by_origin_.resize(scripts_.size());
      for (std::uint32_t index = 0; index < by_origin_.size(); ++index)
        by_origin_[index] = index;
      // Script indices by their rule's origin, for the per-document lookup.
      std::stable_sort(by_origin_.begin(), by_origin_.end(),
                       [this](std::uint32_t left, std::uint32_t right) {
                         return scripts_[left].rule.origin < scripts_[right].rule.origin;
                       });
      g_armed = true;
    } else {
      mapping_ = base::ReadOnlySharedMemoryMapping();
    }
    // Acknowledge the count this renderer can actually run. The owner marks the
    // generation delivered only on an exact match, so a refused or partially
    // decoded set never looks armed.
    std::move(callback).Run(static_cast<std::uint32_t>(scripts_.size()));
  }

  void Disarm() {
    // Every retained `report` function becomes inert, and the mapping and the
    // views into it are released rather than retained at their peak size.
    ++epoch_;
    generation_ = 0;
    std::vector<NativeConsoleDocumentStartScript>().swap(scripts_);
    std::vector<std::uint32_t>().swap(by_origin_);
    mapping_ = base::ReadOnlySharedMemoryMapping();
    g_armed = false;
  }

  void Run(blink::WebLocalFrame* frame, v8::Local<v8::Context> context, std::size_t index) {
    auto* const isolate = frame->GetAgentGroupScheduler()->Isolate();
    // Release this injection's temporaries instead of leaving them in Blink's
    // enclosing scope for the rest of document creation.
    v8::HandleScope handles(isolate);
    v8::Context::Scope entered(context);
    if (isolate->IsExecutionTerminating())
      return;
    // Runs until it returns. A Clear, a new arm or the end of the session
    // stops it from the IO thread. A snippet that synchronously creates a
    // matching frame nests here, and stopping the outer execution ends both.
    auto& execution = NativeConsoleExecution::Get();
    execution.Begin(isolate, kNativeConsoleDocumentStartStopBit | generation_);
    v8::TryCatch failure(isolate);
    bool ran = false;
    {
      // Document creation must not run page promise continuations, so this
      // injection never performs a microtask checkpoint.
      v8::MicrotasksScope microtasks(isolate, context->GetMicrotaskQueue(),
                                     v8::MicrotasksScope::kDoNotRunMicrotasks);
      // The wrapper only supplies `report`. It is not a sandbox: a snippet runs
      // with the page's full main-world authority, exactly like an explicit
      // console command would. The wrapper is joined as V8 cons strings, so
      // the snippet is copied once, into V8, however large it is.
      const auto snippet = scripts_[index].source;
      const std::string name =
          "reb-console-document-start://" + base::NumberToString(scripts_[index].script_id);
      v8::Local<v8::String> body;
      v8::Local<v8::String> resource;
      v8::Local<v8::Script> script;
      v8::Local<v8::Value> wrapper;
      v8::Local<v8::Function> report;
      v8::Local<v8::Value> ignored;
      const auto data = (std::uint64_t{epoch_} << 32) | static_cast<std::uint32_t>(index);
      if (v8::String::NewFromUtf8(isolate, snippet.data(), v8::NewStringType::kNormal,
                                  static_cast<int>(snippet.size()))
              .ToLocal(&body) &&
          v8::String::NewFromUtf8(isolate, name.data(), v8::NewStringType::kNormal,
                                  static_cast<int>(name.size()))
              .ToLocal(&resource)) {
        const auto source = v8::String::Concat(
            isolate,
            v8::String::Concat(
                isolate,
                v8::String::NewFromUtf8Literal(isolate, "(function(report){\"use strict\";\n"),
                body),
            v8::String::NewFromUtf8Literal(isolate, "\n})"));
        v8::ScriptOrigin script_origin(resource);
        const bool compiled =
            v8::Script::Compile(context, source, &script_origin).ToLocal(&script) &&
            script->Run(context).ToLocal(&wrapper) && wrapper->IsFunction() &&
            v8::Function::New(context, &DocumentStart::Dispatch,
                              v8::BigInt::NewFromUnsigned(isolate, data))
                .ToLocal(&report);
        if (compiled) {
          // Announce before calling, so this document's own records follow the
          // marker that says a snippet reached it.
          Announce(frame, index);
          v8::Local<v8::Value> argv[] = {report};
          ran = wrapper.As<v8::Function>()
                    ->Call(context, v8::Undefined(isolate), 1, argv)
                    .ToLocal(&ignored);
        }
      }
    }
    if (execution.Finish() != NativeConsoleExecution::End::kReturned) {
      failure.Reset();
      Emit(frame, index, NativeConsoleDocumentStartRecord::kScriptError, false,
           "Snippet stopped by a Clear, a new arm or the end of the session; changes are not "
           "rolled back");
      return;
    }
    if (!ran) {
      std::string text = "Snippet failed to compile or threw";
      bool truncated = false;
      const auto message = failure.Message();
      if (!message.IsEmpty()) {
        text = PrimitiveText(isolate, context, message->Get(), truncated);
      }
      Emit(frame, index, NativeConsoleDocumentStartRecord::kScriptError, truncated, text);
    }
  }

  // The in-browser indicator. Blink's console sink is not the page's `console`
  // object, so a page cannot read or suppress this, and it reaches a researcher
  // who opens devtools in the browser the experiment is running in.
  void Announce(blink::WebLocalFrame* frame, std::size_t index) {
    frame->AddMessageToConsole(blink::WebConsoleMessage(
        blink::mojom::ConsoleMessageLevel::kWarning,
        blink::WebString::FromUtf8("Reverse Engineering Browser: document-start Console script " +
                                   base::NumberToString(scripts_[index].script_id) +
                                   " runs in this document's main world before its own scripts")));
    Emit(frame, index, NativeConsoleDocumentStartRecord::kInjected, false,
         "Snippet injected before this document's own scripts");
  }

  static void Dispatch(const v8::FunctionCallbackInfo<v8::Value>& info) { Get().Report(info); }

  void Emit(blink::WebLocalFrame* frame,
            std::size_t index,
            NativeConsoleDocumentStartRecord record,
            bool truncated,
            const std::string& text) {
    if (!host_.is_bound() || index >= scripts_.size())
      return;
    const base::UnguessableToken document = frame->GetDocument().Token().value();
    if (document.is_empty())
      return;
    // Every record is sent: a document has no record budget. The browser
    // keeps a bounded output and counts what it evicts.
    host_->Observed(generation_, scripts_[index].script_id, FrameIdentity(frame), document,
                    static_cast<std::uint32_t>(record), truncated, text);
  }

  std::uint64_t generation_ = 0;
  std::uint32_t epoch_ = 1;
  base::ReadOnlySharedMemoryMapping mapping_;
  // Views into `mapping_`, in arming order.
  std::vector<NativeConsoleDocumentStartScript> scripts_;
  std::vector<std::uint32_t> by_origin_;
  mojo::Remote<mojom::NativeConsoleScriptHost> host_;
  mojo::Receiver<mojom::NativeConsoleScriptClient> receiver_{this};
};

}  // namespace

bool IsNativeConsoleDocumentStartPermitted() {
  static const bool permitted =
      base::CommandLine::ForCurrentProcess()->HasSwitch(kNativeConsoleSwitch) &&
      base::CommandLine::ForCurrentProcess()->HasSwitch(kNativeConsoleDocumentStartSwitch);
  return permitted;
}

void ConnectNativeConsoleDocumentStart(mojo::PendingRemote<mojom::NativeConsoleScriptHost> host) {
  if (!IsNativeConsoleDocumentStartPermitted())
    return;
  DocumentStart::Get().Connect(std::move(host));
}

void InjectNativeConsoleDocumentStart(content::RenderFrame* frame,
                                      v8::Local<v8::Context> context,
                                      NativeConsoleDocumentStartFrame& state) {
  state.context = true;
  if (!g_armed) {
    // Nothing was decided for this document, so a later commit that keeps
    // this context is matched as the new document it is.
    state.document = base::UnguessableToken();
    return;
  }
  DocumentStart::Get().Inject(frame, context, state);
}

void InjectNativeConsoleDocumentStartIntoReusedWindow(content::RenderFrame* frame,
                                                      NativeConsoleDocumentStartFrame& state) {
  if (!g_armed || !state.context)
    return;
  DocumentStart::Get().InjectReused(frame, state);
}

}  // namespace reb
