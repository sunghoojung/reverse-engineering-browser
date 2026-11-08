// Request initiator stacks: the real sink, transport and ring with a fixture
// provider in place of Blink and V8. The provider is process-global, so the
// disabled case runs before it is installed.
#pragma once

#include <string>

#include "brave/components/reverse_engineering_browser/common/native_request_stack.h"
#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"

namespace {
using reb::NativeRequestStackPayload;
using reb::NativeRequestStackWalk;
using reb::NativeScriptIdentityPayload;
using reb::NativeStackFrame;

struct StackScenario {
  reb::NativeRequestStackWalkResult result = reb::NativeRequestStackWalkResult::kWalked;
  std::uint32_t depth = 0;
  std::uint32_t scripts = 3;
  std::uint32_t seed = 0;
  std::uint32_t wasm = 0;
  std::uint32_t async = 0;
  std::uint64_t context = 77;
  unsigned walks = 0;
};
StackScenario scenario;
const std::string kStackSource = "function wrapper(){ return fetch('/x'); }";

NativeStackFrame ScenarioFrame(const std::uint32_t index) {
  NativeStackFrame frame;
  if (index < scenario.wasm) {
    frame.kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kWasm);
    frame.script_id = 900;
    frame.position = 0x100 + index;
    frame.detail = index;
    return frame;
  }
  frame.kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kJavaScript);
  frame.script_id = 10 + index % scenario.scripts;
  frame.position = scenario.seed + index;
  frame.detail = scenario.seed;
  return frame;
}

// Writes what V8's NativeStackBuilder writes: the innermost and outermost
// halves of a deep stack, then the await chain at the async offset.
reb::NativeRequestStackWalkResult FixtureWalk(NativeRequestStackWalk& walk) {
  ++scenario.walks;
  if (scenario.result != reb::NativeRequestStackWalkResult::kWalked) {
    return scenario.result;
  }
  walk.SetExecutionContext(scenario.context);
  const auto frames = walk.frames();
  assert(frames.size() == reb::kNativeRequestStackFrameCapacity);
  const std::uint32_t limit = reb::kNativeRequestStackSyncLimit;
  const std::uint32_t recorded = std::min(scenario.depth, limit);
  for (std::uint32_t i = 0; i < recorded; ++i) {
    const std::uint32_t index = i < limit / 2 ? i : scenario.depth - (recorded - i);
    frames[i] = ScenarioFrame(index);
  }
  for (std::uint32_t i = 0; i < scenario.async; ++i) {
    NativeStackFrame frame;
    frame.kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kAwait);
    frame.script_id = 10;
    frame.position = 500 + i;
    frame.detail = 480;
    frames[limit + i] = frame;
  }
  std::vector<std::uint32_t> needed;
  for (std::uint32_t i = 0; i < recorded; ++i) {
    const auto id = frames[i].script_id;
    if (std::find(needed.begin(), needed.end(), id) == needed.end() && walk.ScriptNeeded(id))
      needed.push_back(id);
  }
  walk.FramesReady(scenario.depth, recorded, scenario.depth - recorded,
                   std::min(scenario.async, reb::kNativeRequestStackAsyncLimit),
                   scenario.async >= reb::kNativeRequestStackAsyncLimit);
  for (const auto id : needed) {
    reb::NativeStackScriptSource source;
    source.script_id = id;
    source.kind = id == 900 ? reb::NativeScriptIdentityKind::kWasm
                            : reb::NativeScriptIdentityKind::kJavaScript;
    source.is_eval = id == 11;
    source.start_line = id == 10 ? 41 : 0;
    source.start_column = id == 10 ? 12 : 0;
    source.execution_context_id = scenario.context;
    source.bytes =
        std::span(reinterpret_cast<const std::uint8_t*>(kStackSource.data()), kStackSource.size());
    source.url = "https://app.example.test/page";
    walk.DescribeScript(source);
  }
  return reb::NativeRequestStackWalkResult::kWalked;
}

NativeRequestStackPayload StackPayload(const NativeProbeEvent& event) {
  assert(event.header.type == reb::NativeProbeType::kRequestInitiatorStack &&
         event.header.category == reb::NativeProbeCategory::kNetwork);
  auto value = std::bit_cast<NativeRequestStackPayload>(event.inline_payload);
  assert(reb::IsValidNativeRequestStackPayload(value));
  return value;
}

NativeScriptIdentityPayload IdentityPayload(const NativeProbeEvent& event) {
  assert(event.header.type == reb::NativeProbeType::kScriptIdentity &&
         event.header.request_id == 0);
  auto value = std::bit_cast<NativeScriptIdentityPayload>(event.inline_payload);
  assert(reb::IsValidNativeScriptIdentityPayload(value));
  return value;
}

// One request start: the request_initiated record, then its stack child.
std::pair<NativeProbeEvent, NativeProbeEvent> Start(NativeProbeQueue& queue,
                                                    const std::int32_t request) {
  const auto initiated = sink.RecordRequestInitiated(request, "POST", "api.example.test");
  assert(initiated != 0);
  NativeRequestStackWalk::Record(request, initiated);
  const auto parent = Pop(queue);
  assert(parent.header.type == reb::NativeProbeType::kRequestInitiated &&
         parent.header.sequence_number == initiated);
  const auto stack = Pop(queue);
  assert(stack.header.parent_event_id == initiated &&
         stack.header.request_id == static_cast<std::uint64_t>(request) &&
         stack.header.process_id == parent.header.process_id);
  return {parent, stack};
}

[[gnu::noinline]] void NativeRequestStacks() {
  NativeProbeQueue queue;
  Configure(queue);
  // Flag off: no provider, so a request start walks nothing and allocates
  // nothing beyond its request_initiated record.
  {
    const auto before = allocations.load();
    const auto initiated = sink.RecordRequestInitiated(1, "GET", "a.example.test");
    NativeRequestStackWalk::Record(1, initiated);
    NativeRequestStackWalk::Record(1, 0);
    assert(allocations.load() == before && scenario.walks == 0 && Drain(queue) == 1);
  }
  NativeRequestStackWalk::SetProvider(&FixtureWalk);
  transport.Disable();
  {
    // Inactive session: RecordRequestInitiated admits nothing, so no walk.
    const auto before = allocations.load();
    NativeRequestStackWalk::Record(2, sink.RecordRequestInitiated(2, "GET", "a.example.test"));
    assert(allocations.load() == before && scenario.walks == 0 && Drain(queue) == 0);
  }

  Configure(queue);
  const auto artifacts = reb::mojom::NativeProbeHost::artifacts.load();
  // 150 frames through three scripts: the whole stack, its artifact once,
  // and one identity per script with its retained source.
  scenario.depth = 150;
  auto [parent, stack] = Start(queue, 3);
  auto payload = StackPayload(stack);
  assert(payload.state == 1 && payload.recorded == 150 && payload.total_depth == 150 &&
         payload.omitted == 0 && payload.scripts == 3 &&
         (payload.flags & reb::kNativeRequestStackArtifactQueued) != 0 &&
         (payload.flags & reb::kNativeRequestStackTaskCallersNotCaptured) != 0 &&
         payload.innermost.script_id == 10 && payload.innermost.position == 0);
  for (std::uint32_t id = 10; id < 13; ++id) {
    const auto identity_event = Pop(queue);
    assert(identity_event.header.parent_event_id == stack.header.sequence_number);
    const auto identity = IdentityPayload(identity_event);
    assert(identity.script_id == id && identity.execution_context_id == 77 &&
           identity.source_length == kStackSource.size() &&
           identity.sha256 == crypto::hash::Sha256(kStackSource) &&
           (identity.flags & reb::kNativeScriptIdentitySourceQueued) != 0 &&
           ((identity.flags & reb::kNativeScriptIdentityEval) != 0) == (id == 11) &&
           identity.start_line == (id == 10 ? 41U : 0U));
  }
  assert(Drain(queue) == 0 && reb::mojom::NativeProbeHost::artifacts == artifacts + 4);

  // The same call site again: the record names the digest, nothing is re-sent.
  const auto digest = payload.digest;
  auto repeat = StackPayload(Start(queue, 4).second);
  assert(repeat.digest == digest && repeat.state == 1 &&
         (repeat.flags & reb::kNativeRequestStackArtifactQueued) == 0);
  assert(Drain(queue) == 0 && reb::mojom::NativeProbeHost::artifacts == artifacts + 4);

  // Runaway recursion keeps the innermost and outermost 512 frames.
  scenario.depth = 5000;
  scenario.scripts = 1;
  payload = StackPayload(Start(queue, 5).second);
  assert(payload.total_depth == 5000 && payload.recorded == 1024 && payload.omitted == 3976 &&
         (payload.flags & reb::kNativeRequestStackFramesOmitted) != 0);
  assert(Drain(queue) == 0);

  // Wasm frames from an import and an await chain, with the Wasm module's
  // identity joined by digest and never re-sent.
  scenario.depth = 6;
  scenario.scripts = 2;
  scenario.wasm = 2;
  scenario.async = 2;
  payload = StackPayload(Start(queue, 6).second);
  assert(payload.wasm_frames == 2 && payload.async_frames == 2 && payload.async_segments == 2 &&
         payload.innermost.kind == static_cast<std::uint8_t>(reb::NativeStackFrameKind::kWasm));
  const auto wasm_identity = IdentityPayload(Pop(queue));
  assert(wasm_identity.kind == static_cast<std::uint8_t>(reb::NativeScriptIdentityKind::kWasm) &&
         wasm_identity.flags == 0);
  assert(Drain(queue) == 0);
  scenario.wasm = 0;
  scenario.async = 40;
  payload = StackPayload(Start(queue, 7).second);
  assert(payload.async_frames == 32 && (payload.flags & reb::kNativeRequestStackAsyncTruncated));
  scenario.async = 0;
  assert(Drain(queue) == 0);

  // No script on the stack, and a worker loader thread.
  scenario.result = reb::NativeRequestStackWalkResult::kNoScript;
  assert(StackPayload(Start(queue, 8).second).state == 2);
  scenario.result = reb::NativeRequestStackWalkResult::kUnsupportedThread;
  assert(StackPayload(Start(queue, 9).second).state == 3);
  scenario.result = reb::NativeRequestStackWalkResult::kWalked;

  // 256 remembered digests: an evicted stack is sent again, never dropped.
  scenario.depth = 3;
  scenario.scripts = 1;
  const auto before_eviction = reb::mojom::NativeProbeHost::artifacts.load();
  for (std::uint32_t seed = 1; seed <= 300; ++seed) {
    scenario.seed = seed * 7;
    StackPayload(Start(queue, static_cast<std::int32_t>(100 + seed)).second);
    Drain(queue);
  }
  // At most 256 of those 300 are still remembered, so replaying them re-sends
  // at least 44, each as one more artifact.
  std::uint32_t resent = 0;
  for (std::uint32_t seed = 1; seed <= 300; ++seed) {
    scenario.seed = seed * 7;
    const auto value = StackPayload(Start(queue, static_cast<std::int32_t>(1000 + seed)).second);
    resent += (value.flags & reb::kNativeRequestStackArtifactQueued) != 0;
    Drain(queue);
  }
  assert(resent >= 300 - reb::kNativeRequestStackDigestTable &&
         reb::mojom::NativeProbeHost::artifacts == before_eviction + 300 + resent);

  // 1,024 stack artifacts per configuration, then frames stay unretained.
  for (std::uint32_t seed = 301; seed <= 1100; ++seed) {
    scenario.seed = seed * 7;
    const auto value = StackPayload(Start(queue, static_cast<std::int32_t>(2000 + seed)).second);
    Drain(queue);
    if (seed == 1100) {
      assert(value.state == 5 && (value.flags & reb::kNativeRequestStackArtifactQueued) == 0);
    }
  }

  // A new configuration forgets digests, scripts and budgets.
  Configure(queue, 43);
  scenario.seed = 7;
  const auto fresh = StackPayload(Start(queue, 4000).second);
  assert(fresh.state == 1 && (fresh.flags & reb::kNativeRequestStackArtifactQueued) != 0);
  assert(IdentityPayload(Pop(queue)).script_id == 10);
  Drain(queue);

  // Without the Artifact category frames are walked but not retained.
  Configure(queue, 44, kForever, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork));
  const auto no_artifacts = reb::mojom::NativeProbeHost::artifacts.load();
  const auto unretained = StackPayload(Start(queue, 4001).second);
  assert(unretained.state == 4);
  const auto identity = IdentityPayload(Pop(queue));
  assert((identity.flags & reb::kNativeScriptIdentityNotRetained) != 0);
  assert(Drain(queue) == 0 && reb::mojom::NativeProbeHost::artifacts == no_artifacts);
  transport.Disable();
  std::cout << "PASS request stacks: disabled, depth bounds, Wasm, await, dedupe, "
               "eviction, budgets and script identity\n";
}
}  // namespace
