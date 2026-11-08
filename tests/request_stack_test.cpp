#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <unistd.h>

#include "components/reverse_engineering_browser/common/native_artifact_header.h"
#include "components/reverse_engineering_browser/common/native_probe_event.h"
#include "components/reverse_engineering_browser/common/native_request_stack.h"
#include "reb/artifact.hpp"
#include "reb/event.hpp"
#include "reb/request_stack.hpp"

namespace {

int failures = 0;
// Every record checked here, for the cross-language golden (--golden).
std::vector<std::pair<std::string, reb::EventRecord>> golden;

void Check(const bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL " << message << '\n';
    ++failures;
  }
}

static_assert(static_cast<std::uint16_t>(reb::EventType::kRequestInitiatorStack) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kRequestInitiatorStack));
static_assert(static_cast<std::uint16_t>(reb::EventType::kScriptIdentity) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kScriptIdentity));
static_assert(static_cast<std::uint16_t>(reb::ArtifactKind::kStack) ==
              static_cast<std::uint16_t>(reb::NativeArtifactKind::kStack));
static_assert(static_cast<std::uint16_t>(reb::ArtifactCaptureOrigin::kRequestStack) ==
              static_cast<std::uint16_t>(reb::NativeArtifactCaptureOrigin::kRequestStack));
static_assert(static_cast<std::uint16_t>(reb::ArtifactCaptureOrigin::kStackScript) ==
              static_cast<std::uint16_t>(reb::NativeArtifactCaptureOrigin::kStackScript));
static_assert(sizeof(reb::NativeStackFrame) == sizeof(reb::StackFrame));
static_assert(sizeof(reb::NativeRequestStackPayload) == sizeof(reb::RequestStackPayload));
static_assert(sizeof(reb::NativeScriptIdentityPayload) == sizeof(reb::ScriptIdentityPayload));
static_assert(sizeof(reb::NativeStackArtifactHeader) == sizeof(reb::StackArtifactHeader));
static_assert(offsetof(reb::NativeRequestStackPayload, innermost) ==
              offsetof(reb::RequestStackPayload, innermost));
static_assert(offsetof(reb::NativeScriptIdentityPayload, sha256) ==
              offsetof(reb::ScriptIdentityPayload, sha256));
static_assert(reb::kNativeStackArtifactMaxBytes == reb::kStackArtifactMaxBytes);

reb::NativeStackFrame JsFrame(const std::uint32_t script, const std::uint32_t position) {
  reb::NativeStackFrame frame;
  frame.kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kJavaScript);
  frame.script_id = script;
  frame.position = position;
  frame.detail = position > 4 ? position - 4 : 0;
  return frame;
}

reb::NativeRequestStackPayload Captured(const std::uint32_t total, const std::uint16_t async) {
  reb::NativeRequestStackPayload value;
  value.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kCaptured);
  value.flags = reb::kNativeRequestStackTaskCallersNotCaptured;
  value.total_depth = total;
  value.recorded =
      total > reb::kNativeRequestStackSyncLimit ? reb::kNativeRequestStackSyncLimit : total;
  value.omitted = total - value.recorded;
  if (value.omitted != 0) {
    value.flags |= reb::kNativeRequestStackFramesOmitted;
  }
  value.async_frames = async;
  value.async_segments = async;
  value.scripts = 1;
  value.digest.fill(0x5a);
  value.innermost = JsFrame(7, 120);
  return value;
}

reb::EventRecord Event(const reb::EventType type,
                       const reb::EventCategory category,
                       const std::array<std::byte, 128>& payload) {
  auto event = reb::MakeEvent(category, type, 12, 100, 42);
  event.header.process_id = 9;
  event.header.thread_id = 9;
  event.header.parent_event_id = 11;
  event.header.request_id = type == reb::EventType::kRequestInitiatorStack ? 3 : 0;
  event.header.frame_id = 5;
  event.inline_payload = payload;
  event.header.payload_size = 128;
  return event;
}

void CheckStackRecords() {
  int index = 0;
  const auto valid = [&index](const reb::NativeRequestStackPayload& value) {
    const bool produced = reb::IsValidNativeRequestStackPayload(value);
    reb::RequestStackPayload decoded;
    const auto bytes = reb::EncodeNativeRequestStackRecord(value);
    golden.emplace_back(
        "stack payload " + std::to_string(index++),
        Event(reb::EventType::kRequestInitiatorStack, reb::EventCategory::kNetwork, bytes));
    const bool consumed =
        reb::DecodeRequestStackPayload(bytes, decoded) && reb::IsValidRequestStackPayload(decoded);
    Check(produced == consumed, "overlay and core agree on a stack payload");
    return consumed;
  };
  Check(valid(Captured(150, 0)), "150 synchronous frames are one valid record");
  Check(valid(Captured(5000, 3)), "a 5,000-deep stack keeps 1,024 frames and the omitted count");
  auto value = Captured(150, 0);
  value.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kNoScript);
  Check(!valid(value), "no_script carries no frames");
  value = {};
  value.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kNoScript);
  value.flags = reb::kNativeRequestStackTaskCallersNotCaptured;
  Check(valid(value), "parser-started request is an empty no_script record");
  value.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kUnsupportedThread);
  Check(valid(value), "worker request is an empty unsupported_thread record");
  value.state = 9;
  Check(!valid(value), "unknown state");

  const auto invalid = [&](const char* name,
                           const std::function<void(reb::NativeRequestStackPayload&)>& change) {
    auto copy = Captured(150, 2);
    change(copy);
    Check(!valid(copy), std::string("stack payload rejected: ") + name);
  };
  invalid("depth mismatch", [](auto& v) { v.total_depth = 151; });
  invalid("omitted without flag", [](auto& v) {
    v.total_depth = 2000;
    v.recorded = 1024;
    v.omitted = 976;
  });
  invalid("omitted below the bound", [](auto& v) {
    v.total_depth = 160;
    v.omitted = 10;
    v.flags |= reb::kNativeRequestStackFramesOmitted;
  });
  invalid("too many async frames", [](auto& v) {
    v.async_frames = 33;
    v.async_segments = 33;
  });
  invalid("segments above frames", [](auto& v) { v.async_segments = 3; });
  invalid("truncated below the bound",
          [](auto& v) { v.flags |= reb::kNativeRequestStackAsyncTruncated; });
  invalid("zero digest", [](auto& v) { v.digest.fill(0); });
  invalid("queued while unavailable", [](auto& v) {
    v.state =
        static_cast<std::uint8_t>(reb::NativeRequestStackState::kNotRetainedArtifactUnavailable);
    v.flags |= reb::kNativeRequestStackArtifactQueued;
  });
  invalid("async innermost", [](auto& v) {
    v.innermost.kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kAwait);
  });
  invalid("unknown flag", [](auto& v) { v.flags |= 0x10; });
  invalid("dirty reserved", [](auto& v) { v.reserved1[3] = 1; });
  invalid("version", [](auto& v) { v.protocol_version = 2; });

  auto event = Event(reb::EventType::kRequestInitiatorStack, reb::EventCategory::kNetwork,
                     reb::EncodeNativeRequestStackRecord(Captured(40, 1)));
  Check(reb::IsValidEvent(event), "stack record envelope is valid");
  golden.emplace_back("stack record", event);
  const auto envelope = [&](const char* name, const std::function<void(reb::EventRecord&)>& f) {
    auto copy = event;
    f(copy);
    golden.emplace_back(std::string("stack envelope ") + name, copy);
    Check(!reb::IsValidEvent(copy), std::string("stack envelope rejected: ") + name);
  };
  envelope("no request", [](auto& e) { e.header.request_id = 0; });
  envelope("parent after", [](auto& e) { e.header.parent_event_id = 12; });
  envelope("artifact id", [](auto& e) { e.header.artifact_id = 4; });
  envelope("runtime category", [](auto& e) { e.header.category = reb::EventCategory::kRuntime; });
  envelope("short payload", [](auto& e) { e.header.payload_size = 64; });
  Check(reb::EventTypeName(reb::EventType::kRequestInitiatorStack) == "request_initiator_stack",
        "stack record name");
}

void CheckScriptIdentities() {
  reb::NativeScriptIdentityPayload base;
  base.kind = static_cast<std::uint8_t>(reb::NativeScriptIdentityKind::kJavaScript);
  base.flags = reb::kNativeScriptIdentitySourceQueued;
  base.script_id = 7;
  base.start_line = 12;
  base.start_column = 8;
  base.execution_context_id = 99;
  base.source_length = 400;
  base.sha256.fill(0x11);
  int index = 0;
  const auto valid = [&index](const reb::NativeScriptIdentityPayload& value) {
    reb::ScriptIdentityPayload decoded;
    const auto bytes = reb::EncodeNativeRequestStackRecord(value);
    golden.emplace_back(
        "identity payload " + std::to_string(index++),
        Event(reb::EventType::kScriptIdentity, reb::EventCategory::kNetwork, bytes));
    const bool consumed = reb::DecodeScriptIdentityPayload(bytes, decoded) &&
                          reb::IsValidScriptIdentityPayload(decoded);
    Check(reb::IsValidNativeScriptIdentityPayload(value) == consumed,
          "overlay and core agree on a script identity");
    return consumed;
  };
  Check(valid(base), "retained inline script identity");
  auto eval = base;
  eval.flags = reb::kNativeScriptIdentityEval | reb::kNativeScriptIdentityNotRetained;
  Check(valid(eval), "eval script without retention");
  auto wasm = base;
  wasm.kind = static_cast<std::uint8_t>(reb::NativeScriptIdentityKind::kWasm);
  wasm.flags = 0;
  Check(valid(wasm), "Wasm module joins by digest");
  const auto invalid = [&](const char* name,
                           const std::function<void(reb::NativeScriptIdentityPayload&)>& change) {
    auto copy = base;
    change(copy);
    Check(!valid(copy), std::string("script identity rejected: ") + name);
  };
  invalid("no retention bit", [](auto& v) { v.flags = 0; });
  invalid("two retention bits", [](auto& v) { v.flags |= reb::kNativeScriptIdentityNotRetained; });
  invalid("too large but short", [](auto& v) {
    v.flags = reb::kNativeScriptIdentitySourceTooLarge;
    v.sha256.fill(0);
  });
  invalid("unavailable with digest",
          [](auto& v) { v.flags = reb::kNativeScriptIdentitySourceUnavailable; });
  invalid("Wasm queued", [](auto& v) {
    v.kind = static_cast<std::uint8_t>(reb::NativeScriptIdentityKind::kWasm);
  });
  invalid("no context", [](auto& v) { v.execution_context_id = 0; });
  invalid("no script", [](auto& v) { v.script_id = 0; });
  invalid("zero digest", [](auto& v) { v.sha256.fill(0); });

  auto event = Event(reb::EventType::kScriptIdentity, reb::EventCategory::kNetwork,
                     reb::EncodeNativeRequestStackRecord(base));
  Check(reb::IsValidEvent(event), "script identity envelope is valid");
  event.header.request_id = 3;
  golden.emplace_back("identity with request", event);
  Check(!reb::IsValidEvent(event), "a script identity names no request");
}

std::vector<std::byte> StackArtifact(const std::uint32_t total, const std::uint16_t async) {
  reb::NativeStackArtifactHeader header;
  header.total_depth = total;
  header.recorded = total > 1024 ? 1024 : total;
  header.omitted = total - header.recorded;
  header.flags = header.omitted ? reb::kNativeRequestStackFramesOmitted : 0;
  header.async_frames = async;
  header.async_segments = async;
  std::vector<std::byte> bytes(sizeof(header));
  std::memcpy(bytes.data(), &header, sizeof(header));
  const auto append = [&](const reb::NativeStackFrame& frame) {
    const auto* raw = reinterpret_cast<const std::byte*>(&frame);
    bytes.insert(bytes.end(), raw, raw + sizeof(frame));
  };
  for (std::uint32_t i = 0; i < header.recorded; ++i) {
    append(JsFrame(7 + (i % 3), 100 + i));
  }
  for (std::uint16_t i = 0; i < async; ++i) {
    auto frame = JsFrame(8, 40 + i);
    frame.kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kAwait);
    append(frame);
  }
  return bytes;
}

void CheckStackArtifacts() {
  std::array<reb::StackFrame, reb::kRequestStackSyncLimit + reb::kRequestStackAsyncLimit> frames{};
  reb::StackArtifactHeader header;
  std::size_t count = 0;
  auto deep = StackArtifact(5000, 0);
  Check(reb::DecodeStackArtifact(deep, header, frames, count) && count == 1024 &&
            header.omitted == 3976 && header.total_depth == 5000,
        "5,000-deep artifact decodes 1,024 frames and the omitted count");
  auto mixed = StackArtifact(150, 2);
  Check(reb::DecodeStackArtifact(mixed, header, frames, count) && count == 152 &&
            frames[150].kind == static_cast<std::uint8_t>(reb::StackFrameKind::kAwait),
        "async frames follow the synchronous ones");
  auto wasm = StackArtifact(3, 0);
  reb::NativeStackFrame wasm_frame;
  wasm_frame.kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kWasm);
  wasm_frame.script_id = 30;
  wasm_frame.position = 0x2a1;
  wasm_frame.detail = 12;
  std::memcpy(wasm.data() + 32 + 16, &wasm_frame, sizeof(wasm_frame));
  Check(reb::DecodeStackArtifact(wasm, header, frames, count) && frames[1].detail == 12,
        "a Wasm frame keeps its function index and module offset");
  auto truncated = mixed;
  truncated.pop_back();
  Check(!reb::DecodeStackArtifact(truncated, header, frames, count), "size mismatch rejected");
  auto sync_await = StackArtifact(2, 0);
  sync_await[32] = std::byte{3};
  Check(!reb::DecodeStackArtifact(sync_await, header, frames, count),
        "an await frame among synchronous frames is rejected");
  auto magic = StackArtifact(2, 0);
  magic[0] = std::byte{0};
  Check(!reb::DecodeStackArtifact(magic, header, frames, count), "magic rejected");

  reb::ArtifactHeader artifact;
  artifact.kind = reb::ArtifactKind::kStack;
  artifact.capture_origin = reb::ArtifactCaptureOrigin::kRequestStack;
  artifact.session_id = 7;
  artifact.artifact_id = 5;
  artifact.creator_event_id = 12;
  artifact.execution_context_id = 99;
  const std::string url = "reb-stack:sha256-00";
  const std::string mime = "application/x-reb-stack";
  const std::string content(reinterpret_cast<const char*>(mixed.data()), mixed.size());
  artifact.url_size = static_cast<std::uint32_t>(url.size());
  artifact.mime_type_size = static_cast<std::uint32_t>(mime.size());
  artifact.content_size = content.size();
  Check(reb::IsValidArtifactHeader(artifact), "stack artifact header is valid");
  const auto invalid = [&](const char* name, const std::function<void(reb::ArtifactHeader&)>& f) {
    auto copy = artifact;
    f(copy);
    Check(!reb::IsValidArtifactHeader(copy), std::string("stack artifact rejected: ") + name);
  };
  invalid("sensitive", [](auto& h) { h.flags = reb::kArtifactFlagSensitive; });
  invalid("dynamic origin",
          [](auto& h) { h.capture_origin = reb::ArtifactCaptureOrigin::kDynamicJavaScript; });
  invalid("no creator", [](auto& h) { h.creator_event_id = 0; });
  invalid("no context", [](auto& h) { h.execution_context_id = 0; });
  invalid("JavaScript with stack origin", [](auto& h) { h.kind = reb::ArtifactKind::kJavaScript; });
  auto script = artifact;
  script.kind = reb::ArtifactKind::kJavaScript;
  script.capture_origin = reb::ArtifactCaptureOrigin::kStackScript;
  Check(reb::IsValidArtifactHeader(script), "stack script source header is valid");
  script.creator_event_id = 0;
  Check(!reb::IsValidArtifactHeader(script), "stack script source needs its identity record");

  const auto root = std::filesystem::temp_directory_path() /
                    ("reb-request-stack-test-" + std::to_string(::getpid()));
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  {
    reb::ArtifactReceiver receiver(root,
                                   {.max_artifact_bytes = 1U << 20, .max_store_bytes = 1U << 22});
    std::string frame(reinterpret_cast<const char*>(&artifact), sizeof(artifact));
    std::istringstream stream(frame + url + mime + content);
    Check(receiver.ReceiveOne(stream) == reb::ArtifactReceiveStatus::kAccepted,
          "default receiver keeps a stack artifact: " + receiver.LastError());
  }
  {
    // Reopening validates the stack manifest line again.
    reb::ArtifactReceiver reopened(root,
                                   {.max_artifact_bytes = 1U << 20, .max_store_bytes = 1U << 22});
    std::ifstream manifest(root / "manifest.jsonl");
    const std::string line{std::istreambuf_iterator<char>(manifest), {}};
    Check(
        line.find("\"capture_origin\":\"request_stack\",\"kind\":\"stack\"") != std::string::npos &&
            line.find("\"sensitive\":false") != std::string::npos,
        "manifest records the stack kind and origin");
  }
  std::filesystem::remove_all(root, ignored);
}

}  // namespace

int main(int argc, char** argv) {
  CheckStackRecords();
  CheckScriptIdentities();
  CheckStackArtifacts();
  if (argc == 2 && std::string_view(argv[1]) == "--golden") {
    std::string json;
    std::cout << '[';
    for (std::size_t index = 0; index < golden.size(); ++index) {
      reb::WriteEventJson(golden[index].second, json);
      std::cout << (index ? ",\n" : "\n") << "{\"name\":\"" << golden[index].first
                << "\",\"valid\":" << (reb::IsValidEvent(golden[index].second) ? "true" : "false")
                << ",\"event\":" << json << '}';
    }
    std::cout << "\n]\n";
    return failures == 0 ? 0 : 1;
  }
  if (failures != 0) {
    std::cerr << failures << " request stack checks failed\n";
    return 1;
  }
  std::cout << "Request stack checks passed\n";
  return 0;
}
