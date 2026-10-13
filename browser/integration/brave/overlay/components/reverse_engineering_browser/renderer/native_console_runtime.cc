// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_console_runtime.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <memory>
#include <set>
#include <string_view>

#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "v8/include/v8-debug.h"
#include "v8/include/v8-native-console.h"

namespace reb {
namespace {
std::int64_t Now() {
  return base::TimeTicks::Now().since_origin().InMicroseconds();
}
std::string Bounded(std::string text, std::size_t limit = 2048) {
  if (text.size() > limit) {
    text.resize(limit);
    while (!text.empty() && !base::IsStringUTF8(text))
      text.pop_back();
  }
  return text;
}
v8::Local<v8::String> Key(v8::Isolate* isolate, const char* text) {
  return v8::String::NewFromUtf8(isolate, text).ToLocalChecked();
}
std::string WebText(const blink::WebString& value, std::size_t limit = 2048) {
  return Bounded(value.Substring(0, limit).Utf8(), limit);
}
std::string Text(v8::Isolate* isolate, v8::Local<v8::String> value, bool* truncated = nullptr) {
  if (value.IsEmpty())
    return "";
  std::array<char, 2048> buffer{};
  std::size_t characters = 0;
  const auto bytes = value->WriteUtf8(isolate, buffer.data(), buffer.size(),
                                      v8::String::WriteFlags::kReplaceInvalidUtf8, &characters);
  if (truncated)
    *truncated = characters < static_cast<std::size_t>(value->Length());
  return std::string(buffer.data(), bytes);
}
bool Inspectable(v8::Local<v8::Value> value) {
  if (!value->IsObject() || value->IsProxy())
    return false;
  const auto object = value.As<v8::Object>();
  // V8 marks typed-array instance types as capable of embedder slots. That
  // classification is not a host callback: native indexed descriptors remain
  // safe. Actual interceptors and proxies stay excluded.
  return !object->HasNamedLookupInterceptor() && !object->HasIndexedLookupInterceptor() &&
         (!object->IsApiWrapper() || value->IsTypedArray());
}
// Descriptors are read only on ordinary objects. The descriptor itself is an
// engine-created plain object, so reading its data fields cannot call a getter.
v8::Local<v8::Value> Data(v8::Isolate* isolate,
                          v8::Local<v8::Context> context,
                          v8::Local<v8::Object> object,
                          v8::Local<v8::Name> key) {
  if (!Inspectable(object) && !object->StrictEquals(context->Global()->GetPrototype()))
    return {};
  v8::Local<v8::Value> descriptor;
  if (!object->GetOwnPropertyDescriptor(context, key).ToLocal(&descriptor) ||
      !descriptor->IsObject())
    return {};
  auto record = descriptor.As<v8::Object>();
  if (!record->HasOwnProperty(context, Key(isolate, "value")).FromMaybe(false))
    return {};
  v8::Local<v8::Value> result;
  if (!record->Get(context, Key(isolate, "value")).ToLocal(&result))
    return {};
  return result;
}
// V8 REPL evaluation returns an engine-owned promise whose fulfilled result
// is a null-prototype record. Unwrap that record only for handles created by
// REPL evaluation, never for a promise supplied by the page.
v8::Local<v8::Value> ReplResult(v8::Isolate* isolate,
                                v8::Local<v8::Context> context,
                                v8::Local<v8::Value> value) {
  if (!Inspectable(value) || !value.As<v8::Object>()->GetPrototype()->IsNull())
    return {};
  return Data(isolate, context, value.As<v8::Object>(), Key(isolate, ".repl_result"));
}
base::DictValue Failure(const char* text) {
  return base::DictValue().Set("status", "error").Set("text", text);
}
bool Identifier(std::string_view name) {
  if (name.empty() || name.size() > 128)
    return false;
  auto first = [](char c) { return base::IsAsciiAlpha(c) || c == '_' || c == '$'; };
  if (!first(name.front()))
    return false;
  return std::all_of(name.begin(), name.end(),
                     [&](char c) { return first(c) || base::IsAsciiDigit(c); });
}
base::DictValue Location(v8::Isolate* isolate,
                         v8::Local<v8::Value> resource,
                         int line,
                         int column) {
  return base::DictValue()
      .Set("url", !resource.IsEmpty() && resource->IsString()
                      ? Text(isolate, resource.As<v8::String>())
                      : "")
      .Set("line", std::max(1, line))
      .Set("column", std::max(1, column));
}
}  // namespace

NativeConsoleRuntime::NativeConsoleRuntime() = default;

NativeConsoleRuntime::~NativeConsoleRuntime() = default;

void NativeConsoleRuntime::Reset() {
  for (auto& slot : slots_) {
    slot.value.Reset();
    slot.id = 0;
  }
  expiration_.Stop();
  monitors_.clear();
  last_ = 0;
  messages_.Reset();
}
void NativeConsoleRuntime::Message(const std::string& text,
                                   const std::string& source,
                                   const std::string& stack,
                                   unsigned line,
                                   int level,
                                   bool truncated) {
  auto message = Bounded(text);
  auto url = Bounded(source, 512);
  auto trace = Bounded(stack);
  const bool clipped = truncated || text.size() > message.size() || source.size() > url.size() ||
                       stack.size() > trace.size();
  static constexpr std::array levels{"debug", "info", "warning", "error"};
  const auto record = base::DictValue()
                          .Set("text", std::move(message))
                          .Set("url", std::move(url))
                          .Set("stack", std::move(trace))
                          .Set("line", static_cast<int>(std::min(line, 2147483647u)))
                          .Set("level", levels[std::clamp(level, 0, 3)])
                          .Set("time", base::Time::Now().InMillisecondsFSinceUnixEpoch())
                          .Set("truncated", clipped);
  std::string encoded;
  if (base::JSONWriter::Write(record, &encoded))
    messages_.Push(std::move(encoded));
  else
    messages_.Drop();
}
void NativeConsoleRuntime::Expire() {
  bool retained = false;
  for (auto& slot : slots_) {
    if (slot.id && slot.expires_us <= Now()) {
      slot.value.Reset();
      slot.id = 0;
    }
    retained |= slot.id != 0;
  }
  std::erase_if(monitors_, [](const Monitor& monitor) { return monitor.expires_us <= Now(); });
  if (!retained && monitors_.empty())
    expiration_.Stop();
}
std::uint64_t NativeConsoleRuntime::Retain(v8::Isolate* isolate,
                                           v8::Local<v8::Value> value,
                                           bool repl) {
  if (next_handle_ == UINT64_MAX)
    return 0;
  if (!expiration_.IsRunning())
    expiration_.Start(FROM_HERE, base::Seconds(1),
                      base::BindRepeating(&NativeConsoleRuntime::Expire, base::Unretained(this)));
  // Reusing a slot does not reuse its identity. The UI sees an expired-handle
  // error instead of accidentally inspecting a more recent command's value.
  auto& slot = slots_[next_slot_++ % slots_.size()];
  slot.value.Reset(isolate, value);
  slot.id = next_handle_++;
  slot.expires_us = Now() + 60000000;
  slot.repl = repl;
  return slot.id;
}
v8::Local<v8::Value> NativeConsoleRuntime::Lookup(v8::Isolate* isolate,
                                                  const std::string& handle,
                                                  bool* repl) {
  std::uint64_t id = 0;
  if (!base::StringToUint64(handle, &id) || !id || base::NumberToString(id) != handle)
    return {};
  for (auto& slot : slots_)
    if (slot.id == id && slot.expires_us > Now()) {
      if (repl)
        *repl = slot.repl;
      return slot.value.Get(isolate);
    }
  return {};
}
base::DictValue NativeConsoleRuntime::Value(v8::Isolate* isolate,
                                            v8::Local<v8::Context> context,
                                            v8::Local<v8::Value> value,
                                            bool repl) {
  base::DictValue result;
  std::string type = "object", text = "Object";
  bool truncated = false;
  if (value->IsUndefined()) {
    type = text = "undefined";
  } else if (value->IsNull()) {
    type = text = "null";
  } else if (value->IsBoolean()) {
    type = "boolean";
    text = value.As<v8::Boolean>()->Value() ? "true" : "false";
  } else if (value->IsString()) {
    type = "string";
    text = Text(isolate, value.As<v8::String>(), &truncated);
  } else if (value->IsNumber()) {
    type = "number";
    const auto number = value.As<v8::Number>()->Value();
    if (std::isnan(number))
      text = "NaN";
    else if (std::isinf(number))
      text = number < 0 ? "-Infinity" : "Infinity";
    else if (number == 0 && std::signbit(number))
      text = "-0";
    else {
      std::array<char, 128> buffer{};
      auto converted = std::to_chars(buffer.data(), std::to_address(buffer.end()), number);
      text.assign(buffer.data(), converted.ptr);
    }
  } else if (value->IsBigInt()) {
    type = "bigint";
    if (value.As<v8::BigInt>()->WordCount() > 16) {
      text = "BigInt > 1024 bits";
      truncated = true;
    } else {
      v8::Local<v8::String> number;
      if (value->ToString(context).ToLocal(&number))
        text = Text(isolate, number) + "n";
    }
  } else if (value->IsSymbol()) {
    type = "symbol";
    const auto description = value.As<v8::Symbol>()->Description(isolate);
    text = "Symbol(" +
           (!description.IsEmpty() && description->IsString()
                ? Text(isolate, description.As<v8::String>())
                : "") +
           ")";
  } else if (value->IsProxy())
    text = "Proxy (inspection blocked)";
  else if (value->IsFunction()) {
    type = "function";
    const auto function = value.As<v8::Function>();
    const auto name = function->GetName();
    text = "ƒ " + (name->IsString() ? Text(isolate, name.As<v8::String>()) : "") + "(…)";
    result.Set("location", Location(isolate, function->GetScriptOrigin().ResourceName(),
                                    function->GetScriptLineNumber() + 1,
                                    function->GetScriptColumnNumber() + 1));
  } else if (value->IsPromise()) {
    type = "promise";
    switch (value.As<v8::Promise>()->State()) {
      case v8::Promise::kPending:
        text = "Promise {<pending>}";
        break;
      case v8::Promise::kFulfilled:
        text = "Promise {<fulfilled>}";
        break;
      case v8::Promise::kRejected:
        text = "Promise {<rejected>}";
        break;
    }
  } else if (value->IsNativeError() && Inspectable(value)) {
    const auto message = Data(isolate, context, value.As<v8::Object>(), Key(isolate, "message"));
    text = "Error" + (!message.IsEmpty() && message->IsString()
                          ? ": " + Text(isolate, message.As<v8::String>())
                          : "");
  } else if (value->IsArray())
    text = "Array(" + base::NumberToString(value.As<v8::Array>()->Length()) + ")";
  else if (value->IsTypedArray())
    text = "TypedArray(" + base::NumberToString(value.As<v8::TypedArray>()->Length()) + ")";
  else if (value->IsArrayBuffer())
    text = "ArrayBuffer(" + base::NumberToString(value.As<v8::ArrayBuffer>()->ByteLength()) +
           " bytes)";
  else {
    const auto element = blink::WebElement::FromV8Value(isolate, value);
    if (!element.IsNull())
      text =
          "<" + WebText(element.TagName(), 128) +
          (element.GetIdAttribute().IsEmpty() ? "" : "#" + WebText(element.GetIdAttribute(), 128)) +
          ">";
  }
  if (value->IsObject() || value->IsSymbol()) {
    const auto handle = Retain(isolate, value, repl);
    if (handle)
      result.Set("handle", base::NumberToString(handle));
  }
  truncated |= text.size() > 2048;
  result.Set("type", type);
  result.Set("text", Bounded(std::move(text)));
  result.Set("truncated", truncated);
  return result;
}
base::DictValue NativeConsoleRuntime::Properties(v8::Isolate* isolate,
                                                 v8::Local<v8::Context> context,
                                                 v8::Local<v8::Value> value,
                                                 int offset) {
  const auto element = blink::WebElement::FromV8Value(isolate, value);
  if (!element.IsNull()) {
    base::ListValue properties;
    auto property = [&](const char* name, const blink::WebString& value) {
      const auto text = value.Substring(0, 2048).Utf8();
      properties.Append(
          base::DictValue()
              .Set("name", name)
              .Set("value", base::DictValue()
                                .Set("type", "string")
                                .Set("text", Bounded(text))
                                .Set("truncated", value.length() > 2048 || text.size() > 2048)));
    };
    property("tagName", element.TagName());
    property("id", element.GetIdAttribute());
    property("class", element.GetAttribute(blink::WebString::FromUtf8("class")));
    property("textContent", element.TextContentAbridged(512));
    auto child = element.FirstChild();
    if (!child.IsNull())
      properties.Append(base::DictValue()
                            .Set("name", "firstChild")
                            .Set("value", Value(isolate, context, child.ToV8Value(isolate))));
    return base::DictValue()
        .Set("status", "ok")
        .Set("properties", std::move(properties))
        .Set("more", false)
        .Set("offset", 0);
  }
  if (!Inspectable(value))
    return Failure("Proxy, host interceptor or non-object: automatic property access is blocked");
  const auto object = value.As<v8::Object>();
  if (value->IsArray() || value->IsTypedArray()) {
    const auto length =
        value->IsArray() ? value.As<v8::Array>()->Length() : value.As<v8::TypedArray>()->Length();
    const auto limit = std::min(length, static_cast<std::size_t>(65536));
    const auto end = std::min(limit, static_cast<std::size_t>(offset + 16));
    base::ListValue properties;
    for (std::size_t index = static_cast<std::size_t>(offset); index < end; ++index) {
      auto member =
          Data(isolate, context, object, Key(isolate, base::NumberToString(index).c_str()));
      properties.Append(base::DictValue()
                            .Set("name", base::NumberToString(index))
                            .Set("value", member.IsEmpty() ? base::DictValue()
                                                                 .Set("type", "accessor")
                                                                 .Set("text", "[Empty / Accessor]")
                                                                 .Set("truncated", false)
                                                           : Value(isolate, context, member)));
    }
    return base::DictValue()
        .Set("status", "ok")
        .Set("properties", std::move(properties))
        .Set("more", end < limit)
        .Set("truncated", length > limit)
        .Set("offset", static_cast<int>(end));
  }
  v8::Local<v8::Array> names;
  if (!object
           ->GetOwnPropertyNames(context, v8::ALL_PROPERTIES,
                                 v8::KeyConversionMode::kConvertToString)
           .ToLocal(&names))
    return Failure("Property enumeration failed");
  base::ListValue properties;
  const auto limit = std::min(names->Length(), 65536u);
  const auto end = std::min(limit, static_cast<unsigned>(offset + 16));
  for (unsigned i = offset; i < end; ++i) {
    v8::Local<v8::Value> name;
    if (!names->Get(context, i).ToLocal(&name) || !name->IsName())
      continue;
    v8::Local<v8::Value> descriptor;
    if (!object->GetOwnPropertyDescriptor(context, name.As<v8::Name>()).ToLocal(&descriptor) ||
        !descriptor->IsObject())
      continue;
    base::DictValue property;
    property.Set("name", name->IsString() ? Text(isolate, name.As<v8::String>()) : "[Symbol]");
    auto data = Data(isolate, context, object, name.As<v8::Name>());
    if (data.IsEmpty()) {
      property.Set("accessor", true);
      property.Set("value", base::DictValue()
                                .Set("type", "accessor")
                                .Set("text", "[Getter / Setter]")
                                .Set("truncated", false));
    } else {
      property.Set("accessor", false);
      property.Set("value", Value(isolate, context, data));
    }
    properties.Append(std::move(property));
  }
  if (offset == 0) {
    const auto prototype = object->GetPrototype();
    if (!prototype.IsEmpty() && !prototype->IsNull())
      properties.Append(base::DictValue()
                            .Set("name", "[[Prototype]]")
                            .Set("value", Value(isolate, context, prototype)));
  }
  return base::DictValue()
      .Set("status", "ok")
      .Set("properties", std::move(properties))
      .Set("more", end < limit)
      .Set("truncated", names->Length() > limit)
      .Set("offset", static_cast<int>(end));
}
base::DictValue NativeConsoleRuntime::Complete(v8::Isolate* isolate,
                                               v8::Local<v8::Context> context,
                                               const base::DictValue& command) {
  const auto* path = command.FindList("path");
  const auto* prefix = command.FindString("prefix");
  if (!path || path->size() > 8 || !prefix || prefix->size() > 128)
    return Failure("Invalid completion path");
  std::vector<v8::Global<v8::String>> lexicals;
  v8::debug::GetNativeConsoleLexicalNames(context, &lexicals, 1024);
  v8::Local<v8::Value> owner = context->Global()->GetPrototype();
  for (const auto& component : *path) {
    if (owner.IsEmpty())
      return Failure("Completion owner is unavailable");
    if (!component.is_string() || !Identifier(component.GetString()))
      return Failure("Completion accepts identifier chains only");
    if (owner->StrictEquals(context->Global()->GetPrototype()) &&
        (component.GetString() == "window" || component.GetString() == "globalThis" ||
         component.GetString() == "self")) {
      owner = context->Global()->GetPrototype();
      continue;
    }
    if (component.GetString() == "$_") {
      owner = Lookup(isolate, base::NumberToString(last_));
      continue;
    }
    if (owner.IsEmpty() || !owner->IsObject())
      return Failure("Completion owner is unavailable");
    auto object = owner.As<v8::Object>();
    v8::Local<v8::Value> member;
    if (owner->StrictEquals(context->Global()->GetPrototype())) {
      for (const auto& lexical : lexicals)
        if (Text(isolate, lexical.Get(isolate)) == component.GetString()) {
          // The name is verified as a lexical binding, so this identifier lookup
          // cannot fall through to a page-global accessor. Side effects are denied.
          if (!v8::debug::EvaluateNativeConsole(isolate, lexical.Get(isolate),
                                                v8::debug::NativeConsoleEvaluationMode::kReadOnly)
                   .ToLocal(&member)) {
            return Failure("Completion lexical binding is unavailable");
          }
          break;
        }
    }
    for (int depth = 0;
         member.IsEmpty() && depth < 8 &&
         (Inspectable(object) || object->StrictEquals(context->Global()->GetPrototype()));
         ++depth) {
      member = Data(isolate, context, object, Key(isolate, component.GetString().c_str()));
      if (!member.IsEmpty())
        break;
      const auto prototype = object->GetPrototype();
      if (prototype.IsEmpty() || !prototype->IsObject())
        break;
      object = prototype.As<v8::Object>();
    }
    if (member.IsEmpty())
      return Failure("Completion stopped at an accessor or unavailable property");
    owner = member;
  }
  base::ListValue items;
  std::set<std::string> seen;
  if (path->empty())
    for (const auto& lexical : lexicals) {
      const auto name = Text(isolate, lexical.Get(isolate));
      if (items.size() < 24 && Identifier(name) && name.starts_with(*prefix) &&
          seen.insert(name).second)
        items.Append(base::DictValue()
                         .Set("name", name)
                         .Set("kind", "property")
                         .Set("signature", "lexical binding"));
    }
  for (int depth = 0;
       depth < 8 && !owner.IsEmpty() &&
       (Inspectable(owner) || owner->StrictEquals(context->Global()->GetPrototype()));
       ++depth) {
    auto object = owner.As<v8::Object>();
    v8::Local<v8::Array> names;
    if (!object
             ->GetOwnPropertyNames(context, static_cast<v8::PropertyFilter>(v8::SKIP_SYMBOLS),
                                   v8::KeyConversionMode::kConvertToString)
             .ToLocal(&names))
      break;
    for (unsigned i = 0; i < std::min(names->Length(), 4096u) && items.size() < 24; ++i) {
      v8::Local<v8::Value> name;
      if (!names->Get(context, i).ToLocal(&name) || !name->IsString())
        continue;
      auto label = Text(isolate, name.As<v8::String>());
      if (!Identifier(label) || !label.starts_with(*prefix) || !seen.insert(label).second)
        continue;
      const auto data = Data(isolate, context, object, name.As<v8::Name>());
      base::DictValue item;
      item.Set("name", label);
      item.Set("kind", !data.IsEmpty() && data->IsFunction() ? "function" : "property");
      if (!data.IsEmpty() && data->IsFunction()) {
        const auto length = Data(isolate, context, data.As<v8::Object>(), Key(isolate, "length"));
        if (!length.IsEmpty() && length->IsNumber())
          item.Set("signature",
                   "(" + base::NumberToString(length.As<v8::Number>()->Value()) + " arguments)");
      }
      items.Append(std::move(item));
    }
    if (items.size() == 24)
      break;
    owner = object->GetPrototype();
  }
  return base::DictValue().Set("status", "ok").Set("items", std::move(items));
}
std::string NativeConsoleRuntime::Run(v8::Isolate* isolate,
                                      v8::Local<v8::Context> context,
                                      blink::WebLocalFrame* frame,
                                      const std::string& command) {
  for (auto& slot : slots_)
    if (slot.id && slot.expires_us <= Now()) {
      slot.value.Reset();
      slot.id = 0;
    }
  static_cast<void>(frame);
  const auto parsed = base::JSONReader::ReadDict(command, base::JSON_PARSE_RFC);
  base::DictValue result;
  const auto* operation = parsed ? parsed->FindString("operation") : nullptr;
  v8::TryCatch exception(isolate);
  if (!operation)
    result = Failure("Malformed runtime command");
  else if (*operation == "poll") {
    return messages_.Poll();
  } else if (*operation == "clear") {
    Reset();
    result.Set("status", "ok");
  } else if (*operation == "complete")
    result = Complete(isolate, context, *parsed);
  else if (*operation == "evaluate") {
    const auto* source = parsed->FindString("source");
    if (!source || source->empty() || source->size() > 8192 ||
        source->find('\0') != std::string::npos)
      result = Failure("JavaScript must be 1 to 8192 bytes without NUL");
    else {
      auto text = v8::String::NewFromUtf8(isolate, source->data(), v8::NewStringType::kNormal,
                                          static_cast<int>(source->size()))
                      .ToLocalChecked();
      v8::Local<v8::Value> value;
      bool success = false;
      bool repl = false;
      if (base::TrimWhitespaceASCII(*source, base::TRIM_ALL) == "$_" ||
          base::TrimWhitespaceASCII(*source, base::TRIM_ALL) == "$_;") {
        value = Lookup(isolate, base::NumberToString(last_), &repl);
        success = !value.IsEmpty();
      } else {
        success = v8::debug::EvaluateNativeConsole(isolate, text,
                                                   v8::debug::NativeConsoleEvaluationMode::kRepl)
                      .ToLocal(&value);
        repl = success && value->IsPromise();
      }
      if (success && repl) {
        const auto promise = value.As<v8::Promise>();
        promise->MarkAsHandled();
        if (promise->State() == v8::Promise::kRejected) {
          isolate->ThrowException(promise->Result());
          success = false;
        } else if (promise->State() == v8::Promise::kFulfilled) {
          value = ReplResult(isolate, context, promise->Result());
          success = !value.IsEmpty();
          repl = false;
        }
      }
      if (success) {
        last_ = Retain(isolate, value, repl);
        result.Set("status", "ok");
        result.Set("value", Value(isolate, context, value, repl));
      } else
        result = Failure("JavaScript failed");
    }
  } else if (*operation == "last") {
    bool repl = false;
    auto value = Lookup(isolate, base::NumberToString(last_), &repl);
    result = value.IsEmpty() ? Failure("Previous result expired")
                             : base::DictValue()
                                   .Set("status", "ok")
                                   .Set("value", Value(isolate, context, value, repl));
  } else {
    const auto* handle = parsed->FindString("handle");
    bool repl = false;
    auto value = handle ? Lookup(isolate, *handle, &repl) : v8::Local<v8::Value>();
    if (value.IsEmpty())
      result = Failure("Value expired, was released, or belongs to another document");
    else if (*operation == "release" || *operation == "cancel") {
      for (auto& slot : slots_)
        if (base::NumberToString(slot.id) == *handle) {
          slot.value.Reset();
          slot.id = 0;
        }
      result.Set("status", "ok");
      result.Set("text", *operation == "cancel" ? "Stopped waiting; page work is not rolled back"
                                                : "Value released");
    } else if (*operation == "source") {
      if (!value->IsFunction() || value->IsProxy())
        result = Failure("Value is not an inspectable function");
      else {
        v8::Local<v8::String> source;
        if (value.As<v8::Function>()->FunctionProtoToString(context).ToLocal(&source)) {
          bool truncated = false;
          result.Set("status", "ok");
          result.Set("text", Text(isolate, source, &truncated));
          result.Set("truncated", truncated);
        } else
          result = Failure("Function source unavailable");
      }
    } else if (*operation == "listeners" || *operation == "monitor" || *operation == "unmonitor") {
      auto node = blink::WebElement::FromV8Value(isolate, value);
      if (node.IsNull())
        result = Failure("Select an Element to inspect or monitor its events");
      else if (*operation == "listeners") {
        base::ListValue properties;
        auto listeners = node.ConsoleEventListeners(isolate, 32);
        for (const auto& listener : listeners) {
          const auto label = WebText(listener.type, 128) + (listener.capture ? " capture" : "") +
                             (listener.passive ? " passive" : "") + (listener.once ? " once" : "");
          properties.Append(
              base::DictValue()
                  .Set("name", label)
                  .Set("value", listener.callback->IsUndefined()
                                    ? base::DictValue()
                                          .Set("type", "accessor")
                                          .Set("text", "[Inline / Native callback: not inspected]")
                                          .Set("truncated", false)
                                    : Value(isolate, context, listener.callback)));
        }
        result.Set("status", "ok");
        result.Set("properties", std::move(properties));
        result.Set("more", false);
        result.Set("offset", 0);
        result.Set("truncated", listeners.size() == 32);
      } else if (*operation == "unmonitor") {
        std::erase_if(monitors_,
                      [&](const Monitor& monitor) { return monitor.element.Equals(node); });
        result.Set("status", "ok");
        result.Set("text", "Event monitoring stopped");
      } else {
        std::erase_if(monitors_,
                      [&](const Monitor& monitor) { return monitor.element.Equals(node); });
        if (monitors_.size() >= 8)
          result = Failure("At most 8 event monitors; stop a monitor first");
        else {
          Monitor monitor{node, Now() + 60000000, {}};
          for (const char* type : {"click", "input", "keydown", "submit"}) {
            monitor.removals.push_back(node.AddConsoleEventListener(
                blink::WebString::FromUtf8(type),
                base::BindRepeating(
                    [](NativeConsoleRuntime* runtime, std::string type, blink::WebDOMEvent) {
                      runtime->Message("event: " + type, "", "", 0, 1);
                    },
                    base::Unretained(this), std::string(type))));
          }
          monitors_.push_back(std::move(monitor));
          result.Set("status", "ok");
          result.Set("text", "Monitoring click, input, keydown and submit for 60 seconds");
        }
      }
    } else if (*operation == "inspect") {
      const int offset = parsed->FindInt("offset").value_or(-1);
      result = offset < 0 || offset > 65536 ? Failure("Invalid property offset")
                                            : Properties(isolate, context, value, offset);
    } else if (*operation == "await") {
      if (!value->IsPromise())
        result = Failure("Value is not a promise");
      else {
        const auto promise = value.As<v8::Promise>();
        if (promise->State() == v8::Promise::kPending)
          result.Set("status", "pending");
        else {
          const bool rejected = promise->State() == v8::Promise::kRejected;
          auto settled = promise->Result();
          if (repl && !rejected)
            settled = ReplResult(isolate, context, settled);
          if (settled.IsEmpty())
            result = Failure("Malformed engine REPL result");
          else {
            last_ = Retain(isolate, settled);
            result.Set("status", rejected ? "rejected" : "ok");
            result.Set("value", Value(isolate, context, settled));
          }
        }
      }
    } else if (*operation == "store" && repl) {
      result = Failure("Await this REPL evaluation before storing its result");
    } else if (*operation == "store") {
      std::string name;
      for (int attempt = 0; attempt < 128; ++attempt) {
        name = "temp" + base::NumberToString(next_temp_++);
        if (!context->Global()->HasOwnProperty(context, Key(isolate, name.c_str())).FromMaybe(true))
          break;
        name.clear();
      }
      // CreateDataProperty defines an own data property without invoking a
      // setter. Storing is an explicit, visible mutation in the experiment.
      if (!name.empty() && context->Global()
                               ->CreateDataProperty(context, Key(isolate, name.c_str()), value)
                               .FromMaybe(false)) {
        result.Set("status", "ok");
        result.Set("text", "window." + name);
      } else
        result = Failure("Could not store temporary value");
    } else
      result = Failure("Unknown runtime operation");
  }
  if (exception.HasCaught() && !exception.HasTerminated()) {
    const auto message = exception.Message();
    result.Set("status", "exception");
    if (!message.IsEmpty()) {
      result.Set("text", Text(isolate, message->Get()));
      result.Set("location", Location(isolate, message->GetScriptResourceName(),
                                      message->GetLineNumber(context).FromMaybe(1),
                                      message->GetStartColumn(context).FromMaybe(0) + 1));
      base::ListValue stack;
      auto trace = message->GetStackTrace();
      if (trace.IsEmpty() && !exception.Exception().IsEmpty())
        trace = v8::Exception::GetStackTrace(exception.Exception());
      if (!trace.IsEmpty())
        for (int i = 0; i < std::min(16, trace->GetFrameCount()); ++i) {
          auto entry = trace->GetFrame(isolate, i);
          stack.Append(Location(isolate, entry->GetScriptNameOrSourceURL(), entry->GetLineNumber(),
                                entry->GetColumn())
                           .Set("function", Text(isolate, entry->GetFunctionName())));
        }
      result.Set("stack", std::move(stack));
    }
  }
  std::string encoded;
  if (!base::JSONWriter::Write(result, &encoded) || encoded.size() > 65536)
    return "{\"status\":\"error\",\"text\":\"Result exceeded bounded transport\"}";
  return encoded;
}
}  // namespace reb
