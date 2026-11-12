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
#include "request_child_check.hpp"

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
static_assert(static_cast<std::uint16_t>(reb::EventType::kNavigationInitiatorStack) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kNavigationInitiatorStack));
static_assert(static_cast<std::uint16_t>(reb::EventType::kNavigationInitiatorLink) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kNavigationInitiatorLink));
static_assert(static_cast<std::uint16_t>(reb::EventType::kAsyncTaskStack) ==
              static_cast<std::uint16_t>(reb::NativeProbeType::kAsyncTaskStack));
static_assert(sizeof(reb::NativeTaskSegment) == sizeof(reb::TaskSegment));
static_assert(sizeof(reb::NativeAsyncTaskStackPayload) == sizeof(reb::AsyncTaskStackPayload));
static_assert(sizeof(reb::NativeNavigationLinkPayload) == sizeof(reb::NavigationLinkPayload));
static_assert(offsetof(reb::NativeAsyncTaskStackPayload, innermost) ==
              offsetof(reb::AsyncTaskStackPayload, innermost));
static_assert(offsetof(reb::NativeNavigationStackTail, target_frame_id) ==
              offsetof(reb::NavigationStackTail, target_frame_id));
static_assert(reb::kNativeTaskSegmentLimit == reb::kTaskSegmentLimit &&
              reb::kNativeAsyncTaskFrameLimit == reb::kAsyncTaskFrameLimit &&
              reb::kNativePromiseRegistrationFrameLimit == reb::kPromiseRegistrationFrameLimit);
static_assert(sizeof(reb::NativeStackScope) == sizeof(reb::StackScope) &&
              offsetof(reb::NativeStackScope, isolate_key) ==
                  offsetof(reb::StackScope, isolate_key));
static_assert(sizeof(reb::NativeStackArtifactScope) == sizeof(reb::StackArtifactScope) &&
              offsetof(reb::NativeStackArtifactScope, isolate_key) ==
                  offsetof(reb::StackArtifactScope, isolate_key));
static_assert(reb::kNativeStackArtifactScopeHeaderSize == reb::kStackArtifactScopeHeaderSize &&
              reb::kNativeAsyncTaskKindLimit == reb::kTaskKindLimit);
static_assert(offsetof(reb::NativeTaskSegment, registration) ==
                  offsetof(reb::TaskSegment, registration) &&
              offsetof(reb::NativeAsyncTaskStackPayload, registration) ==
                  offsetof(reb::AsyncTaskStackPayload, registration));

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
  invalid("version", [](auto& v) { v.protocol_version = 4; });
  invalid("version 3 without a scope", [](auto& v) {
    v.protocol_version = reb::kNativeRequestStackScopePayloadVersion;
    v.flags = 0;
  });
  invalid("task segments in version 1", [](auto& v) {
    v.task_segments = 1;
    v.async_segments = 3;
  });
  invalid("chain truncated in version 1",
          [](auto& v) { v.flags |= reb::kNativeRequestStackTaskChainTruncated; });

  // Version 2 carries the task chain: async segments count awaits and tasks.
  const auto tasks = [](const std::uint16_t count) {
    auto v = Captured(150, 2);
    v.protocol_version = reb::kNativeRequestStackTaskPayloadVersion;
    v.flags = 0;
    v.task_segments = count;
    v.async_segments = static_cast<std::uint16_t>(2 + count);
    return v;
  };
  Check(valid(tasks(0)), "version 2 without a task chain");
  Check(valid(tasks(3)), "version 2 with three task segments");
  auto chained = tasks(32);
  chained.flags = reb::kNativeRequestStackTaskChainTruncated | reb::kNativeRequestStackTaskChainCut;
  Check(valid(chained), "a 32-segment chain that continues");
  auto v2 = tasks(33);
  v2.async_segments = 35;
  Check(!valid(v2), "33 task segments rejected");
  v2 = tasks(3);
  v2.async_segments = 3;
  Check(!valid(v2), "async segments must add awaits and tasks");
  v2 = tasks(3);
  v2.flags = reb::kNativeRequestStackTaskChainTruncated;
  Check(!valid(v2), "chain truncated below 32 segments rejected");
  v2 = {};
  v2.protocol_version = reb::kNativeRequestStackTaskPayloadVersion;
  v2.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kNoScript);
  Check(valid(v2), "version 2 parser record");
  v2.flags = reb::kNativeRequestStackTaskChainCut;
  Check(!valid(v2), "a version 2 parser record has no chain flags");
  v2.flags = 0;
  v2.task_segments = 1;
  Check(!valid(v2), "a version 2 parser record has no task segments");

  // Version 3 names the isolate its script IDs belong to.
  const auto scoped = [&](const reb::NativeStackThread thread, const std::uint64_t key) {
    auto v = tasks(2);
    v.protocol_version = reb::kNativeRequestStackScopePayloadVersion;
    reb::NativeStackScope scope;
    scope.thread = static_cast<std::uint8_t>(thread);
    scope.isolate_key = key;
    reb::SetNativeStackScope(v.reserved1, scope);
    return v;
  };
  Check(valid(scoped(reb::NativeStackThread::kDocument, 0)), "a document stack, version 3");
  Check(valid(scoped(reb::NativeStackThread::kDedicatedWorker, 0x77)),
        "a dedicated worker stack names its worker");
  Check(valid(scoped(reb::NativeStackThread::kServiceWorker, 0x78)), "a service worker stack");
  Check(!valid(scoped(reb::NativeStackThread::kSharedWorker, 0)), "a worker scope needs its key");
  Check(!valid(scoped(reb::NativeStackThread::kDocument, 9)), "the main thread has no key");
  Check(!valid(scoped(static_cast<reb::NativeStackThread>(5), 9)), "unknown thread kind");
  auto v3 = scoped(reb::NativeStackThread::kDocument, 0);
  v3.reserved1[2] = 1;
  Check(!valid(v3), "dirty scope reserved bytes");
  v3 = scoped(reb::NativeStackThread::kDocument, 0);
  v3.reserved1[16] = 1;
  Check(!valid(v3), "dirty bytes after the scope");
  v3 = {};
  v3.protocol_version = reb::kNativeRequestStackScopePayloadVersion;
  v3.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kUnsupportedThread);
  Check(valid(v3), "a worklet or pool thread has no scope");
  reb::NativeStackScope worker;
  worker.thread = static_cast<std::uint8_t>(reb::NativeStackThread::kDedicatedWorker);
  worker.isolate_key = 0x77;
  reb::SetNativeStackScope(v3.reserved1, worker);
  Check(!valid(v3), "unsupported_thread names no isolate");
  v3.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kNoScript);
  Check(valid(v3), "a worker request with no script on its stack");
  // A worker past the renderer's table limit: no walk, its scope named.
  v3.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kNotWalkedThreadLimit);
  Check(valid(v3), "a worker past the thread limit names its scope");
  {
    auto limited = Event(reb::EventType::kRequestInitiatorStack, reb::EventCategory::kNetwork,
                         reb::EncodeNativeRequestStackRecord(v3));
    golden.emplace_back("stack record thread limit", limited);
    Check(reb::IsValidEvent(limited), "a thread-limit stack record is a valid event");
    auto unscoped = v3;
    unscoped.reserved1 = {};
    Check(!valid(unscoped), "a thread-limit record names its scope");
    auto walked = v3;
    walked.recorded = 1;
    walked.total_depth = 1;
    Check(!valid(walked), "a thread-limit record carries no frames");
    auto v2_limited = v3;
    v2_limited.protocol_version = reb::kNativeRequestStackTaskPayloadVersion;
    v2_limited.reserved1 = {};
    Check(!valid(v2_limited), "only version 3 has the thread limit state");
    auto bad = Event(reb::EventType::kRequestInitiatorStack, reb::EventCategory::kNetwork,
                     reb::EncodeNativeRequestStackRecord(v2_limited));
    golden.emplace_back("stack record version 2 thread limit", bad);
    Check(!reb::IsValidEvent(bad), "a version 2 thread-limit record is not a valid event");
  }
  v3.state = static_cast<std::uint8_t>(reb::NativeRequestStackState::kNoScript);

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

reb::EventRecord RendererRecord(const reb::EventType type,
                                const std::array<std::byte, 128>& payload) {
  auto event = Event(type, reb::EventCategory::kNetwork, payload);
  event.header.parent_event_id = 0;
  event.header.request_id = 0;
  return event;
}

void CheckNavigationAndTaskRecords() {
  const auto check = [](const std::string& name, const reb::EventRecord& event,
                        const bool expected) {
    golden.emplace_back(name, event);
    Check(reb::IsValidEvent(event) == expected, name);
  };
  auto stack = Captured(40, 1);
  stack.protocol_version = reb::kNativeRequestStackTaskPayloadVersion;
  stack.flags = 0;
  stack.task_segments = 2;
  stack.async_segments = 3;
  reb::NativeNavigationStackTail tail;
  tail.kind = static_cast<std::uint8_t>(reb::NativeNavigationKind::kWindowOpen);
  tail.target_frame_id = 0x5151;
  auto navigation = stack;
  navigation.reserved1 = std::bit_cast<std::array<std::uint8_t, 48>>(tail);
  Check(reb::IsValidNativeNavigationStackPayload(navigation), "overlay accepts a navigation stack");
  const auto record = RendererRecord(reb::EventType::kNavigationInitiatorStack,
                                     reb::EncodeNativeRequestStackRecord(navigation));
  check("navigation stack", record, true);
  const auto variant = [&](const std::string& name, const std::function<void(reb::EventRecord&)>& f,
                           const bool expected) {
    auto copy = record;
    f(copy);
    check(name, copy, expected);
  };
  variant("navigation stack with a parent", [](auto& e) { e.header.parent_event_id = 3; }, false);
  variant("navigation stack with a request", [](auto& e) { e.header.request_id = 3; }, false);
  variant("navigation kind 0", [](auto& e) { e.inline_payload[80] = std::byte{0}; }, false);
  variant("navigation kind 5", [](auto& e) { e.inline_payload[80] = std::byte{5}; }, false);
  variant(
      "navigation without a target",
      [](auto& e) { std::fill_n(e.inline_payload.begin() + 88, 8, std::byte{0}); }, false);
  variant("navigation dirty tail", [](auto& e) { e.inline_payload[100] = std::byte{1}; }, false);
  variant("navigation version 1", [](auto& e) { e.inline_payload[0] = std::byte{1}; }, false);
  variant(
      "navigation parser state",
      [](auto& e) {
        std::fill(e.inline_payload.begin() + 4, e.inline_payload.begin() + 80, std::byte{0});
        e.inline_payload[4] = std::byte{2};
      },
      false);
  Check(
      reb::EventTypeName(reb::EventType::kNavigationInitiatorStack) == "navigation_initiator_stack",
      "navigation stack name");

  reb::NativeAsyncTaskStackPayload task;
  task.kind = static_cast<std::uint8_t>(reb::NativeAsyncTaskKind::kSetTimeout);
  task.recorded = 256;
  task.flags = reb::kNativeTaskSegmentBounded;
  task.scripts = 2;
  task.digest.fill(0x33);
  task.innermost = JsFrame(9, 70);
  Check(reb::IsValidNativeAsyncTaskStackPayload(task), "overlay accepts an async task stack");
  const auto scheduled =
      RendererRecord(reb::EventType::kAsyncTaskStack, reb::EncodeNativeRequestStackRecord(task));
  check("async task stack", scheduled, true);
  const auto task_variant = [&](const std::string& name,
                                const std::function<void(reb::NativeAsyncTaskStackPayload&)>& f) {
    auto copy = task;
    f(copy);
    Check(!reb::IsValidNativeAsyncTaskStackPayload(copy), "overlay rejects " + name);
    check(
        name,
        RendererRecord(reb::EventType::kAsyncTaskStack, reb::EncodeNativeRequestStackRecord(copy)),
        false);
  };
  task_variant("async task microtask kind", [](auto& v) { v.kind = 9; });
  task_variant("async task bounded below 256", [](auto& v) { v.recorded = 255; });
  task_variant("async task above 256 frames", [](auto& v) { v.recorded = 257; });
  task_variant("async task no digest", [](auto& v) { v.digest.fill(0); });
  task_variant("async task await innermost", [](auto& v) {
    v.innermost.kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kAwait);
  });
  auto parented = scheduled;
  parented.header.parent_event_id = 4;
  check("async task stack with a parent", parented, false);
  Check(reb::EventTypeName(reb::EventType::kAsyncTaskStack) == "async_task_stack",
        "async task stack name");

  // Version 2: the scope, message kinds and promise registrations.
  reb::NativeStackScope worker;
  worker.thread = static_cast<std::uint8_t>(reb::NativeStackThread::kSharedWorker);
  worker.isolate_key = 0x91;
  auto scoped_task = task;
  scoped_task.protocol_version = reb::kNativeAsyncTaskStackScopeVersion;
  reb::SetNativeStackScope(scoped_task.reserved2, worker);
  const auto scoped_variant = [&](const std::string& name,
                                  const std::function<void(reb::NativeAsyncTaskStackPayload&)>& f,
                                  const bool expected) {
    auto copy = scoped_task;
    f(copy);
    Check(reb::IsValidNativeAsyncTaskStackPayload(copy) == expected, "overlay verdict for " + name);
    check(
        name,
        RendererRecord(reb::EventType::kAsyncTaskStack, reb::EncodeNativeRequestStackRecord(copy)),
        expected);
  };
  scoped_variant("async task stack version 2", [](auto&) {}, true);
  scoped_variant("MessagePort.postMessage stack", [](auto& v) { v.kind = 10; }, true);
  scoped_variant("BroadcastChannel.postMessage stack", [](auto& v) { v.kind = 11; }, true);
  scoped_variant("worker postMessage stack", [](auto& v) { v.kind = 12; }, true);
  scoped_variant("async task kind 13", [](auto& v) { v.kind = 13; }, false);
  const auto then = [](reb::NativeAsyncTaskStackPayload& v) {
    v.kind = 9;
    v.registration = static_cast<std::uint8_t>(reb::NativePromiseRegistration::kThen);
    v.recorded = 32;
  };
  scoped_variant("promise then registration stack", then, true);
  scoped_variant(
      "promise registration without its call",
      [&](auto& v) {
        then(v);
        v.registration = 0;
      },
      false);
  scoped_variant(
      "promise registration kind 5",
      [&](auto& v) {
        then(v);
        v.registration = 5;
      },
      false);
  scoped_variant(
      "promise registration above 32 frames",
      [&](auto& v) {
        then(v);
        v.recorded = 33;
        v.flags = 0;
      },
      false);
  scoped_variant("registration on a timer", [](auto& v) { v.registration = 1; }, false);
  scoped_variant("async task version 2 without a scope", [](auto& v) { v.reserved2 = {}; }, false);
  scoped_variant("async task dirty after the scope", [](auto& v) { v.reserved2[20] = 1; }, false);
  task_variant("version 1 message kind", [](auto& v) { v.kind = 10; });

  reb::NativeNavigationLinkPayload link;
  link.renderer_process_id = 41;
  link.renderer_sequence = 9;
  auto browser = Event(reb::EventType::kNavigationInitiatorLink, reb::EventCategory::kNetwork,
                       std::bit_cast<std::array<std::byte, 128>>(link));
  browser.header.tab_id = 4;
  browser.header.request_id = 300;
  check("navigation link", browser, true);
  Check(reb_test::StaysRequestChild(browser), "navigation link stays a request child");
  const auto link_variant = [&](const std::string& name,
                                const std::function<void(reb::EventRecord&)>& f) {
    auto copy = browser;
    f(copy);
    check(name, copy, false);
  };
  link_variant("navigation link without a parent", [](auto& e) { e.header.parent_event_id = 0; });
  link_variant("navigation link without a request", [](auto& e) { e.header.request_id = 0; });
  link_variant("navigation link without a renderer",
               [](auto& e) { std::fill_n(e.inline_payload.begin() + 4, 4, std::byte{0}); });
  link_variant("navigation link without a sequence",
               [](auto& e) { std::fill_n(e.inline_payload.begin() + 8, 8, std::byte{0}); });
  link_variant("navigation link dirty reserved",
               [](auto& e) { e.inline_payload[64] = std::byte{1}; });
  Check(reb::EventTypeName(reb::EventType::kNavigationInitiatorLink) == "navigation_initiator_link",
        "navigation link name");
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
  invalid("version 2 without a scope",
          [](auto& v) { v.protocol_version = reb::kNativeScriptIdentityScopeVersion; });
  auto worker = base;
  worker.protocol_version = reb::kNativeScriptIdentityScopeVersion;
  reb::NativeStackScope scope;
  scope.thread = static_cast<std::uint8_t>(reb::NativeStackThread::kDedicatedWorker);
  scope.isolate_key = 0x55;
  reb::SetNativeStackScope(worker.reserved2, scope);
  Check(valid(worker), "a worker script identity names its isolate");
  worker.reserved2[30] = 1;
  Check(!valid(worker), "a worker script identity with dirty reserved bytes");

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

// A version 2 artifact: the frames, then one setTimeout and one microtask segment.
std::vector<std::byte> TaskArtifact() {
  auto bytes = StackArtifact(5, 1);
  reb::NativeStackArtifactHeader header;
  std::memcpy(&header, bytes.data(), sizeof(header));
  header.version = reb::kNativeStackArtifactTaskVersion;
  header.task_segments = 2;
  header.async_segments = 3;
  std::memcpy(bytes.data(), &header, sizeof(header));
  reb::NativeTaskSegment timeout;
  timeout.kind = static_cast<std::uint8_t>(reb::NativeAsyncTaskKind::kSetTimeout);
  timeout.state = static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kCaptured);
  timeout.recorded = 3;
  timeout.digest.fill(0x44);
  reb::NativeTaskSegment microtask;
  microtask.kind = static_cast<std::uint8_t>(reb::NativeAsyncTaskKind::kMicrotask);
  microtask.state = static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kNotRecorded);
  for (const auto& segment : {timeout, microtask}) {
    Check(reb::IsValidNativeTaskSegment(segment), "overlay accepts a task segment");
    const auto* raw = reinterpret_cast<const std::byte*>(&segment);
    bytes.insert(bytes.end(), raw, raw + sizeof(segment));
  }
  return bytes;
}

reb::NativeTaskSegment Segment(const reb::NativeAsyncTaskKind kind,
                               const reb::NativeTaskSegmentState state,
                               const std::uint32_t recorded,
                               const std::uint8_t fill) {
  reb::NativeTaskSegment segment;
  segment.kind = static_cast<std::uint8_t>(kind);
  segment.state = static_cast<std::uint8_t>(state);
  segment.recorded = recorded;
  if (recorded != 0) {
    segment.digest.fill(fill);
  }
  return segment;
}

// A version 3 artifact: the scope header, frames, then the given segments.
std::vector<std::byte> ScopedArtifact(
    const std::vector<reb::NativeTaskSegment>& chain,
    const std::uint16_t flags = 0,
    const reb::NativeStackThread thread = reb::NativeStackThread::kDedicatedWorker) {
  const auto v1 = StackArtifact(4, 0);
  reb::NativeStackArtifactHeader header;
  std::memcpy(&header, v1.data(), sizeof(header));
  header.version = reb::kNativeStackArtifactScopeVersion;
  header.header_size = reb::kNativeStackArtifactScopeHeaderSize;
  header.task_segments = static_cast<std::uint16_t>(chain.size());
  header.async_segments = static_cast<std::uint16_t>(chain.size());
  header.flags = flags;
  reb::NativeStackArtifactScope scope;
  scope.process_id = 41;
  scope.thread = static_cast<std::uint8_t>(thread);
  scope.isolate_key = thread == reb::NativeStackThread::kDocument ? 0 : 0x77;
  std::vector<std::byte> bytes(sizeof(header) + sizeof(scope));
  std::memcpy(bytes.data(), &header, sizeof(header));
  std::memcpy(bytes.data() + sizeof(header), &scope, sizeof(scope));
  bytes.insert(bytes.end(), v1.begin() + sizeof(header), v1.end());
  for (const auto& segment : chain) {
    const auto* raw = reinterpret_cast<const std::byte*>(&segment);
    bytes.insert(bytes.end(), raw, raw + sizeof(segment));
  }
  return bytes;
}

void CheckScopedArtifactsAndOrigins() {
  using Kind = reb::NativeAsyncTaskKind;
  using State = reb::NativeTaskSegmentState;
  std::array<reb::StackFrame, reb::kRequestStackSyncLimit + reb::kRequestStackAsyncLimit> frames{};
  reb::StackArtifactHeader header;
  std::size_t count = 0;
  std::array<reb::TaskSegment, reb::kTaskSegmentLimit> chain{};
  std::size_t segments = 0;
  reb::StackArtifactScope scope;
  auto then = Segment(Kind::kMicrotask, State::kCaptured, 5, 0x21);
  then.registration = static_cast<std::uint8_t>(reb::NativePromiseRegistration::kThen);
  const auto port = Segment(Kind::kMessagePort, State::kCaptured, 3, 0x22);
  const auto parser = Segment(Kind::kEvent, State::kNoScript, 0, 0);
  for (const auto& segment : {then, port, parser}) {
    Check(reb::IsValidNativeTaskSegment(segment, reb::kNativeStackArtifactScopeVersion),
          "overlay accepts a version 3 segment");
    Check(!reb::IsValidNativeTaskSegment(segment), "version 2 has no such segment");
  }
  const auto good = ScopedArtifact({then, port, parser});
  Check(reb::DecodeStackArtifact(good, header, frames, count, chain, &segments, &scope) &&
            count == 4 && segments == 3 && scope.process_id == 41 && scope.thread == 2 &&
            scope.isolate_key == 0x77 && chain[0].registration == 1 && chain[1].kind == 10 &&
            chain[2].state == reb::kTaskSegmentNoScript,
        "a version 3 artifact decodes its scope, registration, message and no-script segments");
  Check(!reb::DecodeStackArtifact(ScopedArtifact({parser, port}), header, frames, count, chain,
                                  &segments),
        "a no-script segment ends the chain");
  Check(!reb::DecodeStackArtifact(
            ScopedArtifact({port, parser}, reb::kNativeRequestStackTaskChainCut), header, frames,
            count, chain, &segments),
        "a chain that ends with no script is not cut");
  auto unregistered = then;
  unregistered.registration = 0;
  Check(!reb::DecodeStackArtifact(ScopedArtifact({unregistered}), header, frames, count, chain,
                                  &segments),
        "a recorded microtask names its registration");
  auto long_then = then;
  long_then.recorded = 33;
  Check(!reb::DecodeStackArtifact(ScopedArtifact({long_then}), header, frames, count, chain,
                                  &segments),
        "a registration keeps at most 32 frames");
  auto no_process = good;
  std::fill_n(no_process.begin() + 32, 4, std::byte{0});
  Check(!reb::DecodeStackArtifact(no_process, header, frames, count, chain, &segments),
        "a version 3 artifact names its renderer process");
  auto short_header = good;
  short_header[6] = std::byte{32};
  Check(!reb::DecodeStackArtifact(short_header, header, frames, count, chain, &segments),
        "a version 3 artifact has a 48-byte header");
  Check(reb::DecodeStackArtifact(ScopedArtifact({}, 0, reb::NativeStackThread::kDocument), header,
                                 frames, count, chain, &segments, &scope) &&
            scope.thread == 1 && scope.isolate_key == 0,
        "a document artifact has no isolate key");

  // A received message whose origin was rejected ends the chain at a
  // segment of the receiving kind; kind 9 says when promise stacks were on.
  const auto rejected = Segment(Kind::kBroadcastChannel, State::kOriginRejected, 0, 0);
  Check(reb::IsValidNativeTaskSegment(rejected, reb::kNativeStackArtifactScopeVersion) &&
            !reb::IsValidNativeTaskSegment(rejected) &&
            !reb::IsValidNativeTaskSegment(Segment(Kind::kSetTimeout, State::kOriginRejected, 0, 0),
                                           reb::kNativeStackArtifactScopeVersion),
        "origin_rejected is a version 3 message segment");
  Check(reb::DecodeStackArtifact(ScopedArtifact({port, rejected}), header, frames, count, chain,
                                 &segments) &&
            segments == 2 && chain[1].state == reb::kTaskSegmentOriginRejected,
        "a rejected origin ends a decoded chain");
  Check(!reb::DecodeStackArtifact(ScopedArtifact({rejected, port}), header, frames, count, chain,
                                  &segments),
        "nothing follows a rejected origin");
  Check(!reb::DecodeStackArtifact(ScopedArtifact({rejected}, reb::kNativeRequestStackTaskChainCut),
                                  header, frames, count, chain, &segments),
        "a chain that ends at a rejected origin is not cut");
  auto remembered_none = Segment(Kind::kMicrotask, State::kNotRecorded, 0, 0);
  remembered_none.flags = reb::kNativeTaskSegmentRegistrationsOn;
  Check(reb::IsValidNativeTaskSegment(remembered_none, reb::kNativeStackArtifactScopeVersion) &&
            !reb::IsValidNativeTaskSegment(remembered_none),
        "a version 3 microtask says promise stacks were on");
  Check(reb::DecodeStackArtifact(ScopedArtifact({remembered_none}), header, frames, count, chain,
                                 &segments) &&
            chain[0].flags == reb::kTaskSegmentRegistrationsOn,
        "the core decodes the promise stacks flag");
  auto on_then = then;
  on_then.flags = reb::kNativeTaskSegmentRegistrationsOn;
  auto on_port = port;
  on_port.flags = reb::kNativeTaskSegmentRegistrationsOn;
  for (const auto& segment : {on_then, on_port}) {
    Check(!reb::IsValidNativeTaskSegment(segment, reb::kNativeStackArtifactScopeVersion) &&
              !reb::DecodeStackArtifact(ScopedArtifact({segment}), header, frames, count, chain,
                                        &segments),
          "only a not_recorded microtask carries the promise stacks flag");
  }

  // Message origins: an 8-byte header, then the posting segment first, at
  // most 32, validated whole. Nothing names a process, thread or table.
  const auto origin = [](const std::vector<reb::NativeTaskSegment>& carried,
                         const std::uint8_t flags = 0) {
    reb::NativeTaskOriginHeader head;
    head.count = static_cast<std::uint8_t>(carried.size());
    head.flags = flags;
    std::vector<std::uint8_t> bytes(sizeof(head));
    std::memcpy(bytes.data(), &head, sizeof(head));
    for (const auto& segment : carried) {
      const auto* raw = reinterpret_cast<const std::uint8_t*>(&segment);
      bytes.insert(bytes.end(), raw, raw + sizeof(segment));
    }
    return bytes;
  };
  static_assert(sizeof(reb::NativeTaskOriginHeader) == 8);
  reb::NativeTaskOriginHeader head;
  std::array<reb::NativeTaskSegment, reb::kNativeTaskSegmentLimit> carried{};
  const auto timeout = Segment(Kind::kSetTimeout, State::kCaptured, 4, 0x23);
  Check(reb::DecodeNativeTaskOrigin(origin({port, then, timeout}), head, carried) &&
            head.version == 2 && head.count == 3 && carried[2].kind == 1,
        "a message origin carries the posting segment and the sender's chain");
  Check(reb::DecodeNativeTaskOrigin(origin({Segment(Kind::kWorkerMessage, State::kNoScript, 0, 0)}),
                                    head, carried),
        "a message posted with no script running");
  Check(reb::DecodeNativeTaskOrigin(origin({port, timeout}, reb::kNativeTaskOriginCut), head,
                                    carried),
        "a sender's chain cut after its carried segments");
  std::vector<reb::NativeTaskSegment> full(32, timeout);
  full[0] = port;
  Check(reb::DecodeNativeTaskOrigin(origin(full, reb::kNativeTaskOriginTruncated), head, carried),
        "a sender's chain that went on past 32 segments");
  Check(!reb::DecodeNativeTaskOrigin(origin({port, timeout}, reb::kNativeTaskOriginTruncated), head,
                                     carried),
        "only 32 carried segments can be truncated");
  Check(
      !reb::DecodeNativeTaskOrigin(
          origin(full, reb::kNativeTaskOriginCut | reb::kNativeTaskOriginTruncated), head, carried),
      "a chain is cut or truncated, not both");
  Check(!reb::DecodeNativeTaskOrigin(origin({timeout}), head, carried),
        "the first carried segment is a message kind");
  Check(!reb::DecodeNativeTaskOrigin(origin({}), head, carried), "an empty origin");
  Check(!reb::DecodeNativeTaskOrigin(origin({port}, 4), head, carried), "unknown origin flag");
  Check(!reb::DecodeNativeTaskOrigin(origin({port, rejected}), head, carried),
        "a sender never carries a rejected origin");
  Check(!reb::DecodeNativeTaskOrigin(origin({Segment(Kind::kWorkerMessage, State::kNoScript, 0, 0)},
                                            reb::kNativeTaskOriginCut),
                                     head, carried),
        "a no-script end is neither cut nor truncated");
  std::vector<reb::NativeTaskSegment> many(33, port);
  Check(!reb::DecodeNativeTaskOrigin(origin(many), head, carried), "33 carried segments");
  auto truncated = origin({port, timeout});
  truncated.pop_back();
  Check(!reb::DecodeNativeTaskOrigin(truncated, head, carried), "a short origin");
  for (std::size_t at = 4; at < 8; ++at) {
    auto named = origin({port});
    named[at] = 1;
    Check(!reb::DecodeNativeTaskOrigin(named, head, carried),
          "an origin's reserved header bytes are zero");
  }
  auto version_one = origin({port});
  version_one[0] = 1;
  Check(!reb::DecodeNativeTaskOrigin(version_one, head, carried),
        "the version 1 origin that named a process and table is refused");
  const std::vector<std::uint8_t> oversize{reb::kNativeTaskOriginOversize};
  Check(!reb::DecodeNativeTaskOrigin(oversize, head, carried),
        "the marker the Mojo traits leave for an oversize origin never validates");
  std::vector<std::uint8_t> too_long(reb::kNativeTaskOriginMaxBytes + 1, 0);
  Check(!reb::DecodeNativeTaskOrigin(too_long, head, carried), "an origin above 1,544 bytes");
}

void CheckStackArtifacts() {
  std::array<reb::StackFrame, reb::kRequestStackSyncLimit + reb::kRequestStackAsyncLimit> frames{};
  reb::StackArtifactHeader header;
  std::size_t count = 0;
  std::array<reb::TaskSegment, reb::kTaskSegmentLimit> chain{};
  std::size_t segments = 0;
  const auto task_artifact = TaskArtifact();
  Check(reb::DecodeStackArtifact(task_artifact, header, frames, count, chain, &segments) &&
            count == 6 && segments == 2 && chain[0].kind == 1 && chain[0].recorded == 3 &&
            chain[1].kind == reb::kTaskKindMicrotask,
        "a version 2 artifact decodes its task chain");
  Check(!reb::DecodeStackArtifact(task_artifact, header, frames, count),
        "a task chain needs room for its segments");
  auto bad_segment = task_artifact;
  bad_segment[bad_segment.size() - 48] = std::byte{10};
  Check(!reb::DecodeStackArtifact(bad_segment, header, frames, count, chain, &segments),
        "an unknown task kind is rejected");
  auto short_chain = task_artifact;
  short_chain.resize(short_chain.size() - 48);
  Check(!reb::DecodeStackArtifact(short_chain, header, frames, count, chain, &segments),
        "a missing task segment is rejected");
  auto v1_chain = task_artifact;
  v1_chain[4] = std::byte{1};
  Check(!reb::DecodeStackArtifact(v1_chain, header, frames, count, chain, &segments),
        "version 1 carries no task chain");
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
  CheckNavigationAndTaskRecords();
  CheckScriptIdentities();
  CheckStackArtifacts();
  CheckScopedArtifactsAndOrigins();
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
