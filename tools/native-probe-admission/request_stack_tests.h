// Request initiator stacks: the real sink, transport and ring with a fixture
// provider in place of Blink and V8. The provider is process-global, so the
// disabled case runs before it is installed.
#pragma once

#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "brave/components/reverse_engineering_browser/common/native_request_stack.h"
#include "brave/components/reverse_engineering_browser/renderer/native_fetch_owner.h"
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
  bool microtask = false;
  std::uint32_t attribution = 0;
  // A scheduling-time walk's depth; 0 means no script was running.
  std::uint32_t task_depth = 3;
  std::uint32_t task_seed = 0;
  unsigned walks = 0;
  unsigned described = 0;
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
void DescribeFixtureScripts(NativeRequestStackWalk& walk, const std::vector<std::uint32_t>& ids) {
  // Mirrors the check patch 0029 adds to Blink's NativeStackScriptDescribed. It
  // tests has_admitted_record(), which the overlay owns; the patch line itself
  // needs a Chromium build, so removing it does not fail this fixture.
  if (!walk.has_admitted_record()) {
    return;
  }
  for (const auto id : ids) {
    ++scenario.described;
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
}

// What Blink's walker does at an async task's scheduling: at most 256
// innermost frames, then the scripts they name.
reb::NativeRequestStackWalkResult FixtureTaskWalk(NativeRequestStackWalk& walk) {
  if (scenario.task_depth == 0) {
    return reb::NativeRequestStackWalkResult::kNoScript;
  }
  const auto frames = walk.frames();
  const std::uint32_t limit = walk.task_frame_limit();
  const std::uint32_t recorded = std::min(scenario.task_depth, limit);
  std::vector<std::uint32_t> needed;
  for (std::uint32_t i = 0; i < recorded; ++i) {
    frames[i] = NativeStackFrame{};
    frames[i].kind = static_cast<std::uint8_t>(reb::NativeStackFrameKind::kJavaScript);
    frames[i].script_id = 20 + i % 2;
    frames[i].position = scenario.task_seed + i;
    frames[i].detail = scenario.task_seed;
    const auto id = frames[i].script_id;
    if (std::find(needed.begin(), needed.end(), id) == needed.end() && walk.ScriptNeeded(id))
      needed.push_back(id);
  }
  walk.FramesReady(recorded, recorded, 0, 0, false, scenario.task_depth > limit);
  DescribeFixtureScripts(walk, needed);
  return reb::NativeRequestStackWalkResult::kWalked;
}

reb::NativeRequestStackWalkResult FixtureWalk(NativeRequestStackWalk& walk) {
  ++scenario.walks;
  // Blink walks only on a thread whose tables and frame buffer exist.
  if (walk.scope().thread == 0 || !walk.embedder_frames()) {
    return reb::NativeRequestStackWalkResult::kUnsupportedThread;
  }
  if (scenario.result != reb::NativeRequestStackWalkResult::kWalked) {
    return scenario.result;
  }
  walk.SetExecutionContext(scenario.context);
  walk.SetAsyncContext(scenario.microtask, scenario.attribution);
  if (walk.async_task_walk()) {
    return FixtureTaskWalk(walk);
  }
  const auto frames = walk.frames();
  assert(frames.size() == reb::kNativeRequestStackFrameCapacity);
  const std::uint32_t limit = reb::kNativeRequestStackSyncLimit;
  const std::uint32_t recorded = std::min(scenario.depth, limit);
  for (std::uint32_t i = 0; i < recorded; ++i) {
    const std::uint32_t index = i < limit / 2 ? i : scenario.depth - (recorded - i);
    frames[i] = ScenarioFrame(index);
  }
  for (std::uint32_t i = 0; i < std::min(scenario.async, reb::kNativeRequestStackAsyncLimit); ++i) {
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
  DescribeFixtureScripts(walk, needed);
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

// Stands in for Blink's V8 frame buffer: counted and static, so the
// allocation checks see only the sink's own.
std::atomic<int> fixture_frames_made{0};
std::atomic<int> fixture_frames_freed{0};
int fixture_frames = 0;
void* AllocateFixtureFrames() {
  ++fixture_frames_made;
  return &fixture_frames;
}
void ReleaseFixtureFrames(void* frames) {
  assert(frames == &fixture_frames);
  ++fixture_frames_freed;
}

std::string GapReason(const NativeProbeEvent& event) {
  assert(event.header.type == reb::NativeProbeType::kGap);
  return {reinterpret_cast<const char*>(event.inline_payload.data()), event.header.payload_size};
}

// One request start: the request_initiated record, then its stack child.
std::pair<NativeProbeEvent, NativeProbeEvent> Start(NativeProbeQueue& queue,
                                                    const std::int32_t request) {
  const auto initiated =
      sink.RecordRequestInitiated(request, "POST", "https", "api.example.test").initiated_sequence;
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
  // nothing beyond its request_initiated record. Async task and navigation
  // hooks are one atomic load each.
  {
    const auto before = allocations.load();
    const auto initiated =
        sink.RecordRequestInitiated(1, "GET", "https", "a.example.test").initiated_sequence;
    NativeRequestStackWalk::Record(1, initiated);
    NativeRequestStackWalk::Record(1, 0);
    assert(!NativeRequestStackWalk::Enabled() &&
           NativeRequestStackWalk::RecordAsyncTask(reb::NativeAsyncTaskKind::kSetTimeout) == 0 &&
           NativeRequestStackWalk::EnterAsyncTask(5) == 0 &&
           NativeRequestStackWalk::CurrentAsyncTask() == 0 &&
           NativeRequestStackWalk::RecordNavigation(reb::NativeNavigationKind::kLocation, 9) == 0);
    NativeRequestStackWalk::ExitAsyncTask(0);
    NativeRequestStackWalk::AttributeAsyncTask(3, 5);
    NativeRequestStackWalk::ScheduleFormNavigation(9);
    assert(NativeRequestStackWalk::TakeFormNavigation(9) == 0);
    assert(allocations.load() == before && scenario.walks == 0 && Drain(queue) == 1);
  }
  // Blink names the main thread's isolate, then installs the provider with
  // its frame buffer allocator. Neither allocates: the tables and buffer
  // wait for the first walk while capture is active.
  reb::NativeStackScope document;
  document.thread = static_cast<std::uint8_t>(reb::NativeStackThread::kDocument);
  {
    const auto before = allocations.load();
    NativeRequestStackWalk::AttachThread(document);
    NativeRequestStackWalk::SetProvider(&FixtureWalk, &AllocateFixtureFrames,
                                        &ReleaseFixtureFrames);
    assert(allocations.load() == before && fixture_frames_made == 0 &&
           NativeRequestStackWalk::CurrentScope() == document);
  }
  transport.Disable();
  {
    // Inactive session: RecordRequestInitiated admits nothing, so no walk.
    const auto before = allocations.load();
    NativeRequestStackWalk::Record(
        2, sink.RecordRequestInitiated(2, "GET", "https", "a.example.test").initiated_sequence);
    assert(allocations.load() == before && scenario.walks == 0 && Drain(queue) == 0 &&
           fixture_frames_made == 0);
  }

  Configure(queue);
  const auto artifacts = reb::mojom::NativeProbeHost::artifacts.load();
  // 150 frames through three scripts: the whole stack, its artifact once,
  // and one identity per script with its retained source.
  scenario.depth = 150;
  auto [parent, stack] = Start(queue, 3);
  // The first active walk made the main thread's tables and Blink's buffer.
  assert(fixture_frames_made == 1);
  auto payload = StackPayload(stack);
  assert(payload.protocol_version == reb::kNativeRequestStackScopePayloadVersion &&
         reb::NativeStackScopeOf(payload.reserved1).thread == 1 && payload.state == 1 &&
         payload.recorded == 150 && payload.total_depth == 150 && payload.omitted == 0 &&
         payload.scripts == 3 && payload.task_segments == 0 &&
         (payload.flags & reb::kNativeRequestStackArtifactQueued) != 0 &&
         (payload.flags & reb::kNativeRequestStackTaskChainCut) == 0 &&
         payload.innermost.script_id == 10 && payload.innermost.position == 0);
  for (std::uint32_t id = 10; id < 13; ++id) {
    const auto identity_event = Pop(queue);
    assert(identity_event.header.parent_event_id == stack.header.sequence_number);
    const auto identity = IdentityPayload(identity_event);
    assert(identity.protocol_version == reb::kNativeScriptIdentityScopeVersion &&
           reb::NativeStackScopeOf(identity.reserved2).thread == 1 && identity.script_id == id &&
           identity.execution_context_id == 77 && identity.source_length == kStackSource.size() &&
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

  // A refused stack artifact is forgotten, so its repeat is sent again rather
  // than claiming the artifact was captured.
  scenario.seed = 8101;
  const auto [refused_parent, refused_event] = Start(queue, 4100);
  static_cast<void>(refused_parent);
  const auto refused_first = StackPayload(refused_event);
  assert((refused_first.flags & reb::kNativeRequestStackArtifactQueued) != 0);
  Drain(queue);
  transport.NativeStackArtifactRefused(refused_event.header.sequence_number);
  const auto resent_payload = StackPayload(Start(queue, 4101).second);
  assert(resent_payload.state == 1 &&
         (resent_payload.flags & reb::kNativeRequestStackArtifactQueued) != 0 &&
         resent_payload.digest == refused_first.digest);
  Drain(queue);
  const auto repeated = StackPayload(Start(queue, 4102).second);
  assert((repeated.flags & reb::kNativeRequestStackArtifactQueued) == 0);
  Drain(queue);

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

  // A metadata session keeps frames, positions and digests, never script source.
  Configure(queue, 46, kForever, reb::kAllNativeProbeCategoryMask, false);
  scenario.seed = 7;
  const auto metadata_before = reb::mojom::NativeProbeHost::artifacts.load();
  const auto metadata = StackPayload(Start(queue, 4003).second);
  assert(metadata.state == 1 && (metadata.flags & reb::kNativeRequestStackArtifactQueued) != 0);
  const auto metadata_identity = IdentityPayload(Pop(queue));
  assert((metadata_identity.flags & reb::kNativeScriptIdentityNotRetained) != 0 &&
         (metadata_identity.flags & reb::kNativeScriptIdentitySourceQueued) == 0);
  assert(Drain(queue) == 0 && reb::mojom::NativeProbeHost::artifacts == metadata_before + 1);

  // Every frame from its own script: counting distinct scripts always ends.
  Configure(queue, 45);
  scenario.depth = reb::kNativeRequestStackSyncLimit;
  scenario.scripts = reb::kNativeRequestStackSyncLimit;
  const auto before_sources = reb::mojom::NativeProbeHost::artifacts.load();
  assert(StackPayload(Start(queue, 4002).second).scripts == reb::kNativeRequestStackSyncLimit);
  Drain(queue);
  // Sources are bounded by bytes, not by a small count: every script is sent.
  assert(reb::mojom::NativeProbeHost::artifacts - before_sources > 513);
  scenario.scripts = 3;
  transport.Disable();
  std::cout << "PASS request stacks: disabled, depth bounds, Wasm, await, dedupe, "
               "eviction, budgets and script identity\n";
}

reb::NativeAsyncTaskStackPayload TaskPayload(const NativeProbeEvent& event) {
  assert(event.header.type == reb::NativeProbeType::kAsyncTaskStack &&
         event.header.request_id == 0 && event.header.parent_event_id == 0);
  auto value = std::bit_cast<reb::NativeAsyncTaskStackPayload>(event.inline_payload);
  assert(reb::IsValidNativeAsyncTaskStackPayload(value));
  return value;
}

// The scope of the newest generated stack artifact, a version 3 one.
reb::NativeStackArtifactScope GeneratedScope() {
  const auto& bytes = reb::mojom::NativeProbeHost::generated;
  reb::NativeStackArtifactHeader header;
  reb::NativeStackArtifactScope scope;
  assert(bytes.size() >= reb::kNativeStackArtifactScopeHeaderSize);
  std::memcpy(&header, bytes.data(), sizeof(header));
  assert(header.version == reb::kNativeStackArtifactScopeVersion &&
         header.header_size == reb::kNativeStackArtifactScopeHeaderSize);
  std::memcpy(&scope, bytes.data() + sizeof(header), sizeof(scope));
  assert(scope.process_id != 0);
  return scope;
}

// The task chain of the newest generated stack artifact, a version 3 one.
std::vector<reb::NativeTaskSegment> GeneratedChain() {
  const auto& bytes = reb::mojom::NativeProbeHost::generated;
  static_cast<void>(GeneratedScope());
  reb::NativeStackArtifactHeader header;
  std::memcpy(&header, bytes.data(), sizeof(header));
  const std::size_t at =
      reb::kNativeStackArtifactScopeHeaderSize +
      reb::kNativeStackFrameSize * (std::size_t{header.recorded} + header.async_frames);
  assert(bytes.size() == at + reb::kNativeTaskSegmentSize * header.task_segments);
  std::vector<reb::NativeTaskSegment> chain(header.task_segments);
  std::memcpy(chain.data(), bytes.data() + at, bytes.size() - at);
  for (const auto& segment : chain) {
    assert(reb::IsValidNativeTaskSegment(segment, reb::kNativeStackArtifactScopeVersion));
  }
  return chain;
}

std::uint8_t Kind(const reb::NativeAsyncTaskKind kind) {
  return static_cast<std::uint8_t>(kind);
}

// A queue that refused the async record means no artifact left this renderer
// either, so a later chain must not call that segment captured.
[[gnu::noinline]] void NativeAsyncSegmentNotAdmitted() {
  using reb::NativeAsyncTaskKind;
  NativeProbeQueue queue;
  Configure(queue, 66);
  scenario = {};
  scenario.depth = 4;
  scenario.scripts = 1;
  scenario.seed = 300;
  scenario.task_seed = 9000;
  for (std::size_t index = 0; index < 2 * reb::kNativeProbeQueueCapacity; ++index) {
    static_cast<void>(sink.RecordRequestInitiated(1, "GET", "https", "fill.example.test"));
  }
  const auto artifacts_before = reb::mojom::NativeProbeHost::artifacts.load();
  scenario.described = 0;
  const auto dropped = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
  assert(dropped != 0 && reb::mojom::NativeProbeHost::artifacts == artifacts_before &&
         scenario.described == 0);
  Drain(queue);
  const auto inside = NativeRequestStackWalk::EnterAsyncTask(dropped);
  StackPayload(Start(queue, 6000).second);
  const auto chain = GeneratedChain();
  assert(chain[0].kind == Kind(NativeAsyncTaskKind::kSetTimeout) &&
         chain[0].state == static_cast<std::uint8_t>(
                               reb::NativeTaskSegmentState::kNotRetainedArtifactUnavailable));
  Drain(queue);
  NativeRequestStackWalk::ExitAsyncTask(inside);
  scenario = {};
  transport.Disable();
  std::cout << "PASS an async segment whose record was refused is not called captured\n";
}

// A browser refusal arrives after the segment was stored, so it has to reach the
// ring: the segment that queued the artifact and one that found its digest known.
[[gnu::noinline]] void NativeAsyncSegmentArtifactRefused() {
  using reb::NativeAsyncTaskKind;
  NativeProbeQueue queue;
  Configure(queue, 67);
  scenario = {};
  scenario.depth = 4;
  scenario.scripts = 1;
  scenario.seed = 310;
  scenario.task_seed = 9100;
  const auto segment_state = [&](const std::uint64_t segment) {
    const auto inside = NativeRequestStackWalk::EnterAsyncTask(segment);
    StackPayload(Start(queue, 6010).second);
    const auto chain = GeneratedChain();
    Drain(queue);
    NativeRequestStackWalk::ExitAsyncTask(inside);
    assert(chain.size() == 1 && chain[0].kind == Kind(NativeAsyncTaskKind::kSetTimeout));
    // Each call names a fresh top frame, so its stack artifact is sent again.
    ++scenario.seed;
    return chain[0];
  };
  const auto captured = static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kCaptured);
  const auto refused_state =
      static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kNotRetainedArtifactUnavailable);

  const auto queued = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
  const auto record = Pop(queue);
  const auto digest = TaskPayload(record).digest;
  Drain(queue);
  const auto known = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
  assert(known != 0 && known != queued && Drain(queue) == 0);
  assert(segment_state(queued).state == captured && segment_state(known).state == captured);

  transport.NativeStackArtifactRefused(record.header.sequence_number);
  const auto queued_chain = segment_state(queued);
  const auto known_chain = segment_state(known);
  assert(queued_chain.state == refused_state && queued_chain.digest == digest &&
         known_chain.state == refused_state && known_chain.digest == digest);

  // A segment recorded after the refusal resends the stack and owns that attempt.
  const auto artifacts_before = reb::mojom::NativeProbeHost::artifacts.load();
  const auto resent = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
  assert(TaskPayload(Pop(queue)).digest == digest &&
         reb::mojom::NativeProbeHost::artifacts == artifacts_before + 1);
  Drain(queue);
  assert(segment_state(resent).state == captured && segment_state(queued).state == refused_state);

  // A refusal naming no stack this renderer queued changes nothing.
  transport.NativeStackArtifactRefused(record.header.sequence_number + 100000);
  assert(segment_state(resent).state == captured);
  scenario = {};
  transport.Disable();
  std::cout << "PASS a refused async stack artifact stops every segment on its digest claiming "
               "capture, and a later resend owns its own state\n";
}

// A refused attempt stored nothing, so refused retries cannot spend a budget.
[[gnu::noinline]] void NativeRefusedStackBudgets() {
  using reb::NativeAsyncTaskKind;
  NativeProbeQueue queue;
  Configure(queue, 68);
  scenario = {};
  scenario.depth = 4;
  scenario.scripts = 1;
  scenario.seed = 320;
  scenario.task_seed = 9200;
  const auto attempts = reb::kNativeRequestStackArtifactBudget + 16;
  for (std::uint32_t attempt = 0; attempt < attempts; ++attempt) {
    const auto stack = Start(queue, 7000).second;
    const auto value = StackPayload(stack);
    assert(value.state == 1 && (value.flags & reb::kNativeRequestStackArtifactQueued) != 0);
    Drain(queue);
    transport.NativeStackArtifactRefused(stack.header.sequence_number);
  }
  const auto task_attempts = reb::kNativeAsyncTaskArtifactBudget + 16;
  for (std::uint32_t attempt = 0; attempt < task_attempts; ++attempt) {
    assert(NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout) != 0);
    // A task over its budget would record nothing here.
    const auto record = Pop(queue);
    assert(record.header.type == reb::NativeProbeType::kAsyncTaskStack);
    Drain(queue);
    transport.NativeStackArtifactRefused(record.header.sequence_number);
  }
  scenario = {};
  transport.Disable();
  std::cout << "PASS refused stack and async task artifacts return their budget slots\n";
}

// Scheduling-time segments linked through async task runs and task
// attribution, and script-initiated navigations.
[[gnu::noinline]] void NativeTaskChainsAndNavigations() {
  using reb::NativeAsyncTaskKind;
  NativeProbeQueue queue;
  Configure(queue, 61);
  scenario = {};
  scenario.depth = 4;
  scenario.scripts = 1;
  scenario.seed = 300;

  // A setTimeout scheduled with script on the stack: its stack goes out once
  // as an async_task_stack record and artifact, with its scripts described.
  const auto artifacts = reb::mojom::NativeProbeHost::artifacts.load();
  const auto timeout = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
  assert(timeout != 0);
  const auto scheduled = Pop(queue);
  const auto task = TaskPayload(scheduled);
  assert(task.kind == Kind(NativeAsyncTaskKind::kSetTimeout) && task.recorded == 3 &&
         task.scripts == 2 && task.flags == 0 &&
         reb::mojom::NativeProbeHost::generated_creator == scheduled.header.sequence_number &&
         reb::mojom::NativeProbeHost::generated.size() == 48 + 3 * 16 &&
         task.protocol_version == reb::kNativeAsyncTaskStackScopeVersion &&
         reb::NativeStackScopeOf(task.reserved2).thread == 1);
  assert(IdentityPayload(Pop(queue)).script_id == 20 &&
         IdentityPayload(Pop(queue)).script_id == 21);
  assert(Drain(queue) == 0 && reb::mojom::NativeProbeHost::artifacts == artifacts + 3);
  // The same call site again: a new segment, nothing re-sent.
  const auto again = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
  assert(again != 0 && again != timeout && Drain(queue) == 0);
  // No script running: nothing walked or stored, and a request in that task
  // ends its chain there with the reason instead of silently.
  scenario.task_depth = 0;
  const auto parser = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kEvent);
  assert(parser != 0 && Drain(queue) == 0);
  scenario.task_depth = 3;
  const auto unscripted =
      NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kXmlHttpRequest,
                                              /*script_running=*/false);
  assert(unscripted != 0 && Drain(queue) == 0 && scenario.walks != 0);
  {
    const auto walks_before = scenario.walks;
    static_cast<void>(NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kEvent, false));
    assert(scenario.walks == walks_before);
  }
  auto outside = NativeRequestStackWalk::EnterAsyncTask(parser);
  auto ended = StackPayload(Start(queue, 6000).second);
  auto ended_chain = GeneratedChain();
  assert(ended.task_segments == 1 && (ended.flags & reb::kNativeRequestStackTaskChainCut) == 0 &&
         ended_chain[0].kind == Kind(NativeAsyncTaskKind::kEvent) &&
         ended_chain[0].state == static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kNoScript));
  Drain(queue);
  NativeRequestStackWalk::ExitAsyncTask(outside);

  // A request inside the timer names the timer segment by its digest.
  const auto outer = NativeRequestStackWalk::EnterAsyncTask(timeout);
  assert(outer == 0 && NativeRequestStackWalk::CurrentAsyncTask() == timeout);
  auto stack = StackPayload(Start(queue, 6001).second);
  assert(stack.task_segments == 1 && stack.async_segments == 1 &&
         (stack.flags & reb::kNativeRequestStackTaskChainCut) == 0);
  auto chain = GeneratedChain();
  assert(chain[0].kind == Kind(NativeAsyncTaskKind::kSetTimeout) && chain[0].state == 1 &&
         chain[0].recorded == 3 && chain[0].digest == task.digest);
  Drain(queue);

  // A postMessage scheduled inside the timer: its run reaches back through it.
  scenario.task_seed = 50;
  const auto message = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kPostMessage);
  Drain(queue);
  NativeRequestStackWalk::ExitAsyncTask(outer);
  assert(NativeRequestStackWalk::CurrentAsyncTask() == 0);
  const auto previous = NativeRequestStackWalk::EnterAsyncTask(message);
  StackPayload(Start(queue, 6002).second);
  chain = GeneratedChain();
  assert(chain.size() == 2 && chain[0].kind == Kind(NativeAsyncTaskKind::kPostMessage) &&
         chain[1].kind == Kind(NativeAsyncTaskKind::kSetTimeout));
  Drain(queue);
  // Promise reactions registered while this task ran carry its attribution.
  NativeRequestStackWalk::AttributeAsyncTask(77, message);
  NativeRequestStackWalk::ExitAsyncTask(previous);

  // A microtask names the segment its task attribution was registered under,
  // after a microtask hop whose registering stack is not recorded.
  scenario.microtask = true;
  scenario.attribution = 77;
  stack = StackPayload(Start(queue, 6003).second);
  chain = GeneratedChain();
  assert(stack.task_segments == 3 && chain[0].kind == Kind(NativeAsyncTaskKind::kMicrotask) &&
         chain[0].state == static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kNotRecorded) &&
         chain[1].kind == Kind(NativeAsyncTaskKind::kPostMessage) &&
         (stack.flags & reb::kNativeRequestStackTaskChainCut) == 0);
  Drain(queue);
  // An attribution no segment was registered under cuts the chain visibly.
  scenario.attribution = 78;
  stack = StackPayload(Start(queue, 6004).second);
  assert(stack.task_segments == 1 && (stack.flags & reb::kNativeRequestStackTaskChainCut) != 0);
  Drain(queue);
  // A task scheduled in that microtask keeps the hop and the cut.
  const auto orphan = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetInterval);
  Drain(queue);
  scenario.microtask = false;
  scenario.attribution = 0;
  NativeRequestStackWalk::ExitAsyncTask(NativeRequestStackWalk::EnterAsyncTask(orphan));
  const auto inside_orphan = NativeRequestStackWalk::EnterAsyncTask(orphan);
  stack = StackPayload(Start(queue, 6005).second);
  chain = GeneratedChain();
  assert(chain.size() == 2 && chain[0].kind == Kind(NativeAsyncTaskKind::kSetInterval) &&
         chain[1].kind == Kind(NativeAsyncTaskKind::kMicrotask) &&
         (stack.flags & reb::kNativeRequestStackTaskChainCut) != 0);
  Drain(queue);
  NativeRequestStackWalk::ExitAsyncTask(inside_orphan);

  // 40 nested timers: 32 segments and the truncation flag.
  std::uint64_t nested = 0;
  for (std::uint32_t i = 0; i < 40; ++i) {
    const auto saved = NativeRequestStackWalk::EnterAsyncTask(nested);
    scenario.task_seed = 1000 + i;
    nested = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
    NativeRequestStackWalk::ExitAsyncTask(saved);
    Drain(queue);
  }
  auto saved = NativeRequestStackWalk::EnterAsyncTask(nested);
  stack = StackPayload(Start(queue, 6006).second);
  assert(stack.task_segments == 32 && stack.async_segments == 32 &&
         (stack.flags & reb::kNativeRequestStackTaskChainTruncated) != 0 &&
         GeneratedChain().size() == 32);
  Drain(queue);
  NativeRequestStackWalk::ExitAsyncTask(saved);

  // A deep scheduling stack keeps its innermost 256 frames and says so.
  scenario.task_depth = 500;
  scenario.task_seed = 7000;
  const auto deep = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kEvent);
  const auto bounded = TaskPayload(Pop(queue));
  assert(bounded.recorded == 256 && (bounded.flags & reb::kNativeTaskSegmentBounded) != 0);
  Drain(queue);
  scenario.task_depth = 3;

  // 2,048 later segments overwrite it: its chain is cut, never guessed.
  for (std::uint32_t i = 0; i < reb::kNativeAsyncTaskRing; ++i) {
    scenario.task_seed = 20000 + i % 8;
    static_cast<void>(NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout));
    Drain(queue);
  }
  saved = NativeRequestStackWalk::EnterAsyncTask(deep);
  stack = StackPayload(Start(queue, 6007).second);
  assert(stack.task_segments == 0 && (stack.flags & reb::kNativeRequestStackTaskChainCut) != 0);
  Drain(queue);
  NativeRequestStackWalk::ExitAsyncTask(saved);

  // Without the Artifact category a segment is hashed but not retained.
  Configure(queue, 62, kForever, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kNetwork));
  scenario.task_seed = 9;
  const auto unretained = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kPostTask);
  assert(unretained != 0 && Drain(queue) == 0);
  saved = NativeRequestStackWalk::EnterAsyncTask(unretained);
  stack = StackPayload(Start(queue, 6008).second);
  assert(stack.state == 4 && stack.task_segments == 1);
  Drain(queue);
  NativeRequestStackWalk::ExitAsyncTask(saved);
  // Network off: nothing walks.
  Configure(queue, 63, kForever, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kRuntime));
  const auto walks = scenario.walks;
  assert(NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout) == 0 &&
         NativeRequestStackWalk::RecordNavigation(reb::NativeNavigationKind::kLocation, 9) == 0 &&
         scenario.walks == walks && Drain(queue) == 0);

  // A location assignment from a timer: a navigation_initiator_stack with the
  // navigation kind, the target frame and the task chain.
  Configure(queue, 64);
  scenario.task_seed = 40;
  const auto timer = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
  Drain(queue);
  saved = NativeRequestStackWalk::EnterAsyncTask(timer);
  assert(reb::NativeNavigationKindScope::Current() == reb::NativeNavigationKind::kOtherScript);
  std::uint64_t navigation = 0;
  {
    const reb::NativeNavigationKindScope kind(reb::NativeNavigationKind::kLocation);
    navigation =
        NativeRequestStackWalk::RecordNavigation(reb::NativeNavigationKindScope::Current(), 0x5151);
  }
  assert(reb::NativeNavigationKindScope::Current() == reb::NativeNavigationKind::kOtherScript);
  NativeRequestStackWalk::ExitAsyncTask(saved);
  const auto record = Pop(queue);
  assert(navigation == record.header.sequence_number &&
         record.header.type == reb::NativeProbeType::kNavigationInitiatorStack &&
         record.header.request_id == 0 && record.header.parent_event_id == 0);
  const auto value = std::bit_cast<NativeRequestStackPayload>(record.inline_payload);
  const auto tail = std::bit_cast<reb::NativeNavigationStackTail>(value.reserved1);
  assert(reb::IsValidNativeNavigationStackPayload(value) && value.task_segments == 1 &&
         tail.kind == 1 && tail.target_frame_id == 0x5151 &&
         reb::mojom::NativeProbeHost::generated_creator == navigation &&
         GeneratedChain()[0].kind == Kind(NativeAsyncTaskKind::kSetTimeout));
  Drain(queue);
  // No script on the stack: no navigation record.
  scenario.result = reb::NativeRequestStackWalkResult::kNoScript;
  assert(NativeRequestStackWalk::RecordNavigation(reb::NativeNavigationKind::kOtherScript, 7) ==
             0 &&
         Drain(queue) == 0);
  // form.submit(): recorded when scheduled, taken once by its navigation, and
  // replaced by a later submission even without script.
  scenario.result = reb::NativeRequestStackWalkResult::kWalked;
  NativeRequestStackWalk::ScheduleFormNavigation(0x77);
  const auto form = Pop(queue);
  assert(std::bit_cast<reb::NativeNavigationStackTail>(
             std::bit_cast<NativeRequestStackPayload>(form.inline_payload).reserved1)
             .kind == 2);
  Drain(queue);
  assert(NativeRequestStackWalk::TakeFormNavigation(0x78) == 0 &&
         NativeRequestStackWalk::TakeFormNavigation(0x77) == form.header.sequence_number &&
         NativeRequestStackWalk::TakeFormNavigation(0x77) == 0);
  NativeRequestStackWalk::ScheduleFormNavigation(0x77);
  Drain(queue);
  scenario.result = reb::NativeRequestStackWalkResult::kNoScript;
  NativeRequestStackWalk::ScheduleFormNavigation(0x77);
  assert(NativeRequestStackWalk::TakeFormNavigation(0x77) == 0 && Drain(queue) == 0);
  scenario = {};
  transport.Disable();
  std::cout << "PASS async task chains and navigation stacks: disabled, scheduling-time segments "
               "sent once, nested and microtask links, cut, 32-segment bound, 256-frame bound, "
               "ring eviction, retention, location kind and form submission\n";
}

// One other thread that runs each step to completion before Run returns, so a
// test can interleave a worker's walks with the transport's thread.
class TestThread {
 public:
  TestThread() : thread_([this] { Loop(); }) {}
  ~TestThread() {
    Run(nullptr);
    thread_.join();
  }
  void Run(std::function<void()> step) {
    std::unique_lock lock(mutex_);
    step_ = std::move(step);
    pending_ = true;
    wake_.notify_all();
    wake_.wait(lock, [this] { return !pending_; });
  }

 private:
  void Loop() {
    for (;;) {
      std::unique_lock lock(mutex_);
      wake_.wait(lock, [this] { return pending_; });
      std::function<void()> step = std::move(step_);
      const bool stop = !step;
      if (step) {
        lock.unlock();
        step();
        lock.lock();
      }
      pending_ = false;
      wake_.notify_all();
      if (stop) {
        return;
      }
    }
  }
  std::mutex mutex_;
  std::condition_variable wake_;
  std::function<void()> step_;
  bool pending_ = false;
  std::thread thread_;
};

reb::NativeStackScope WorkerScope(const reb::NativeStackThread thread, const std::uint64_t key) {
  reb::NativeStackScope scope;
  scope.thread = static_cast<std::uint8_t>(thread);
  scope.isolate_key = key;
  return scope;
}

// Dedicated workers: their own tables, made by the first active walk, scope
// and frame IDs; script IDs described again for their isolate; refusals
// routed from the transport's thread; mailbox overflow; detach.
[[gnu::noinline]] void NativeWorkerRequestStacks() {
  using reb::NativeAsyncTaskKind;
  NativeProbeQueue queue;
  Configure(queue, 70);
  scenario = {};
  scenario.depth = 4;
  scenario.scripts = 2;
  scenario.seed = 500;
  const auto worker = WorkerScope(reb::NativeStackThread::kDedicatedWorker, 0x7777);
  // The main thread describes scripts 10 and 11 for its own isolate.
  StackPayload(Start(queue, 7000).second);
  assert(IdentityPayload(Pop(queue)).script_id == 10);
  Drain(queue);
  TestThread thread;
  std::uint64_t worker_stack = 0;
  const int frames_made = fixture_frames_made;
  const int frames_freed = fixture_frames_freed;
  thread.Run([&] {
    // Attaching, under WorkerThread::lock_ in Blink, is two thread-local
    // stores: nothing is allocated, and a second attach keeps the first scope.
    const auto before = allocations.load();
    NativeRequestStackWalk::AttachThread(worker);
    NativeRequestStackWalk::AttachThread(WorkerScope(reb::NativeStackThread::kSharedWorker, 0x1));
    assert(allocations.load() == before && fixture_frames_made == frames_made &&
           NativeRequestStackWalk::CurrentScope() == worker);
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0x7777});
    const auto [parent, stack] = Start(queue, 7001);
    assert(fixture_frames_made == frames_made + 1);
    assert(parent.header.frame_id == 0x7777 && stack.header.frame_id == 0x7777);
    const auto payload = StackPayload(stack);
    assert(payload.state == 1 && reb::NativeStackScopeOf(payload.reserved1) == worker &&
           (payload.flags & reb::kNativeRequestStackArtifactQueued) != 0);
    const auto scope = GeneratedScope();
    assert(scope.thread == 2 && scope.isolate_key == 0x7777);
    // Script IDs are the worker isolate's: described again, with its scope.
    for (std::uint32_t id = 10; id < 12; ++id) {
      const auto identity = IdentityPayload(Pop(queue));
      assert(identity.script_id == id && reb::NativeStackScopeOf(identity.reserved2) == worker);
    }
    assert(Drain(queue) == 0);
    worker_stack = stack.header.sequence_number;
  });
  thread.Run([&] {
    // A task the worker schedules names the worker, with no fetch owner.
    scenario.task_seed = 9300;
    assert(NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout) != 0);
    const auto task = Pop(queue);
    assert(task.header.frame_id == 0x7777 &&
           reb::NativeStackScopeOf(TaskPayload(task).reserved2) == worker);
    Drain(queue);
  });
  // The transport refuses the worker's artifact on this thread; the worker
  // forgets the digest at its next walk and sends the stack again.
  transport.NativeStackArtifactRefused(worker_stack);
  thread.Run([&] {
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0x7777});
    const auto resent = StackPayload(Start(queue, 7002).second);
    assert((resent.flags & reb::kNativeRequestStackArtifactQueued) != 0);
    Drain(queue);
  });
  // The main thread's tables were not touched: its repeat sends nothing.
  assert((StackPayload(Start(queue, 7003).second).flags & reb::kNativeRequestStackArtifactQueued) ==
         0);
  Drain(queue);

  // More than 256 routed refusals before the worker walks again: the mailbox
  // keeps 256 and records the overflow, so the worker forgets every digest,
  // sends again and counts a request_stack_refusals_overflowed gap.
  std::uint64_t kept = 0;
  std::vector<std::uint64_t> refused;
  thread.Run([&] {
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0x7777});
    scenario.seed = 600;
    kept = Start(queue, 7004).second.header.sequence_number;
    Drain(queue);
    for (std::uint32_t i = 0; i < reb::kNativeStackRefusalMailbox + 20; ++i) {
      scenario.seed = 700 + i;
      refused.push_back(Start(queue, 7005).second.header.sequence_number);
      Drain(queue);
    }
  });
  for (const auto sequence : refused) {
    transport.NativeStackArtifactRefused(sequence);
  }
  thread.Run([&] {
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0x7777});
    // Any call that reads the tables drains them first.
    NativeRequestStackWalk::AttributeAsyncTask(1, 1);
    const auto overflow = Pop(queue);
    assert(GapReason(overflow) == "request_stack_refusals_overflowed" &&
           overflow.header.frame_id == 0x7777 && Drain(queue) == 0);
    scenario.seed = 600;
    assert((StackPayload(Start(queue, 7006).second).flags &
            reb::kNativeRequestStackArtifactQueued) != 0);
    Drain(queue);
  });
  static_cast<void>(kept);

  // Detach frees the tables and Blink's buffer; the thread then has no scope.
  thread.Run([&] {
    NativeRequestStackWalk::DetachThread();
    assert(fixture_frames_freed == frames_freed + 1 &&
           NativeRequestStackWalk::CurrentScope() == reb::NativeStackScope{});
    const auto none = StackPayload(Start(queue, 7007).second);
    assert(none.state == 3 && reb::NativeStackScopeOf(none.reserved1) == reb::NativeStackScope{});
    assert(NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout) == 0);
    Drain(queue);
  });
  // A refusal for a detached thread's artifact goes nowhere.
  transport.NativeStackArtifactRefused(worker_stack);
  scenario = {};
  transport.Disable();
  std::cout << "PASS worker request stacks: attach allocates nothing, tables made by the first "
               "active walk, scope, frame IDs, identities, routed refusals, counted mailbox "
               "overflow, unattached and detached threads\n";
}

// Receives `origin` as `kind`, then starts a request inside its handler and
// returns that request's stack record. A rejected origin's gap comes first.
NativeRequestStackPayload HandlerStack(NativeProbeQueue& queue,
                                       const reb::NativeAsyncTaskKind kind,
                                       const std::span<const std::uint8_t> origin,
                                       const std::int32_t request,
                                       const bool rejected = false) {
  const auto handle = NativeRequestStackWalk::ReceiveMessageOrigin(kind, origin);
  if (rejected) {
    assert(GapReason(Pop(queue)) == "message_task_origin_rejected");
  }
  const auto saved = NativeRequestStackWalk::EnterAsyncTask(handle);
  const auto stack = StackPayload(Start(queue, request).second);
  NativeRequestStackWalk::ExitAsyncTask(saved);
  return stack;
}

// MessagePort, BroadcastChannel and worker messages carry the posting stack
// and the sender's chain to the thread that runs the handler, which stores
// copies; the origin names no process, thread or table.
[[gnu::noinline]] void NativeMessageOrigins() {
  using reb::NativeAsyncTaskKind;
  NativeProbeQueue queue;
  Configure(queue, 71);
  scenario = {};
  scenario.depth = 3;
  scenario.scripts = 1;
  scenario.seed = 800;
  std::array<std::uint8_t, reb::kNativeTaskOriginMaxBytes> origin{};
  // A timer posts to a port.
  scenario.task_seed = 9400;
  const auto timer = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
  Drain(queue);
  auto saved = NativeRequestStackWalk::EnterAsyncTask(timer);
  scenario.task_seed = 9410;
  const auto size =
      NativeRequestStackWalk::PostMessageOrigin(NativeAsyncTaskKind::kMessagePort, true, origin);
  NativeRequestStackWalk::ExitAsyncTask(saved);
  assert(size == reb::kNativeTaskOriginHeaderSize + 2 * reb::kNativeTaskSegmentSize);
  const auto posted = TaskPayload(Pop(queue));
  assert(posted.kind == 10 && posted.protocol_version == reb::kNativeAsyncTaskStackScopeVersion);
  Drain(queue);
  const std::vector<std::uint8_t> bytes(origin.begin(), origin.begin() + size);
  reb::NativeTaskOriginHeader header;
  std::array<reb::NativeTaskSegment, reb::kNativeTaskSegmentLimit> carried{};
  assert(reb::DecodeNativeTaskOrigin(bytes, header, carried) && header.count == 2 &&
         carried[0].kind == 10 && carried[1].kind == 1 && header.flags == 0);
  // Exactly what crosses: version, count and flags, then per segment its
  // kind, state, flags, registration, frame count and digest. Every other
  // byte is zero; no process ID, table or serial.
  const auto zero = [](const auto& range) {
    return std::all_of(range.begin(), range.end(), [](const std::uint8_t b) { return b == 0; });
  };
  assert(header.version == 2 && zero(header.reserved) && carried[0].digest == posted.digest &&
         carried[0].recorded == posted.recorded);
  for (std::size_t i = 0; i < header.count; ++i) {
    assert(zero(carried[i].reserved1));
  }

  // Received on the posting thread: copies, so the same chain.
  auto stack = HandlerStack(queue, NativeAsyncTaskKind::kMessagePort, bytes, 7100);
  auto chain = GeneratedChain();
  assert(stack.task_segments == 2 && chain[0] == carried[0] && chain[1] == carried[1]);
  Drain(queue);

  // An origin that does not validate is rejected and counted: the handler's
  // chain ends at an origin_rejected segment of the receiving kind. Forged:
  // the version 1 header that named this process, table and posting serial,
  // which no longer links to anything; a header byte where a table would go;
  // a damaged segment; the oversize marker the Mojo traits leave in place of
  // an origin longer than 1,544 bytes; and anything longer still.
  std::vector<std::uint8_t> same_table(24 + bytes.size() - reb::kNativeTaskOriginHeaderSize, 0);
  same_table[0] = 1;
  same_table[2] = 2;
  const auto pid = static_cast<std::uint32_t>(base::GetCurrentProcId());
  std::memcpy(same_table.data() + 4, &pid, sizeof(pid));
  const std::uint64_t table = 1;
  std::memcpy(same_table.data() + 8, &table, sizeof(table));
  std::memcpy(same_table.data() + 16, &timer, sizeof(timer));
  std::copy(bytes.begin() + reb::kNativeTaskOriginHeaderSize, bytes.end(), same_table.begin() + 24);
  auto named = bytes;
  named[4] = 1;
  auto damaged = bytes;
  damaged[reb::kNativeTaskOriginHeaderSize + 8] = 1;
  std::vector<std::uint8_t> oversize{reb::kNativeTaskOriginOversize};
  std::vector<std::uint8_t> too_long(reb::kNativeTaskOriginMaxBytes + 1, 0);
  std::copy(bytes.begin(), bytes.end(), too_long.begin());
  std::int32_t request = 7110;
  for (const auto* forged : {&same_table, &named, &damaged, &oversize, &too_long}) {
    stack = HandlerStack(queue, NativeAsyncTaskKind::kMessagePort, *forged, request++, true);
    chain = GeneratedChain();
    assert(stack.task_segments == 1 &&
           (stack.flags & (reb::kNativeRequestStackTaskChainCut |
                           reb::kNativeRequestStackTaskChainTruncated)) == 0 &&
           chain[0].kind == 10 &&
           chain[0].state ==
               static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kOriginRejected));
    Drain(queue);
  }
  // A valid origin posted through another kind is rejected the same way.
  stack = HandlerStack(queue, NativeAsyncTaskKind::kBroadcastChannel, bytes, request++, true);
  assert(stack.task_segments == 1 && GeneratedChain()[0].kind == 11 &&
         GeneratedChain()[0].state ==
             static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kOriginRejected));
  Drain(queue);
  // No origin: the sender carried nothing, so the caller is unknown and the
  // chain is cut there, with no gap.
  stack = HandlerStack(queue, NativeAsyncTaskKind::kMessagePort, {}, request++);
  assert(stack.task_segments == 0 && (stack.flags & reb::kNativeRequestStackTaskChainCut) != 0);
  Drain(queue);

  TestThread thread;
  const auto worker = WorkerScope(reb::NativeStackThread::kDedicatedWorker, 0x8888);
  thread.Run([&] {
    NativeRequestStackWalk::AttachThread(worker);
    // Received on a worker: copies of the carried segments, same digests.
    const auto copied = HandlerStack(queue, NativeAsyncTaskKind::kMessagePort, bytes, 7102);
    const auto copy = GeneratedChain();
    assert(copied.task_segments == 2 && copy[0] == carried[0] && copy[1] == carried[1] &&
           GeneratedScope().thread == 2);
    Drain(queue);
  });

  // A worker posts to the page and shuts down before the page dispatches the
  // message: the origin already holds the segments, so the page's handler
  // still shows the worker's posting stack.
  std::vector<std::uint8_t> from_worker;
  reb::NativeAsyncTaskStackPayload worker_post;
  {
    TestThread short_lived;
    short_lived.Run([&] {
      NativeRequestStackWalk::AttachThread(
          WorkerScope(reb::NativeStackThread::kDedicatedWorker, 0x8889));
      scenario.task_seed = 9420;
      std::array<std::uint8_t, reb::kNativeTaskOriginMaxBytes> out{};
      const auto n =
          NativeRequestStackWalk::PostMessageOrigin(NativeAsyncTaskKind::kWorkerMessage, true, out);
      assert(n == reb::kNativeTaskOriginHeaderSize + reb::kNativeTaskSegmentSize);
      worker_post = TaskPayload(Pop(queue));
      assert(worker_post.kind == 12 &&
             reb::NativeStackScopeOf(worker_post.reserved2).isolate_key == 0x8889);
      Drain(queue);
      from_worker.assign(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(n));
      NativeRequestStackWalk::DetachThread();
    });
  }
  stack = HandlerStack(queue, NativeAsyncTaskKind::kWorkerMessage, from_worker, 7103);
  chain = GeneratedChain();
  assert(stack.task_segments == 1 && chain[0].kind == 12 && chain[0].state == 1 &&
         chain[0].digest == worker_post.digest && chain[0].recorded == worker_post.recorded);
  Drain(queue);

  // Posted with no script running: one no_script segment.
  const auto quiet =
      NativeRequestStackWalk::PostMessageOrigin(NativeAsyncTaskKind::kWorkerMessage, false, origin);
  assert(quiet == reb::kNativeTaskOriginHeaderSize + reb::kNativeTaskSegmentSize &&
         Drain(queue) == 0);
  const std::vector<std::uint8_t> quiet_bytes(origin.begin(), origin.begin() + quiet);
  thread.Run([&] {
    const auto ended = HandlerStack(queue, NativeAsyncTaskKind::kWorkerMessage, quiet_bytes, 7104);
    const auto copy = GeneratedChain();
    assert(ended.task_segments == 1 && (ended.flags & reb::kNativeRequestStackTaskChainCut) == 0 &&
           copy[0].kind == 12 &&
           copy[0].state == static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kNoScript));
    Drain(queue);
  });

  // A post inside a handler whose own caller is unknown carries that cut.
  saved = NativeRequestStackWalk::EnterAsyncTask(
      NativeRequestStackWalk::ReceiveMessageOrigin(NativeAsyncTaskKind::kMessagePort, {}));
  scenario.task_seed = 9430;
  const auto cut_size =
      NativeRequestStackWalk::PostMessageOrigin(NativeAsyncTaskKind::kMessagePort, true, origin);
  NativeRequestStackWalk::ExitAsyncTask(saved);
  Drain(queue);
  const std::vector<std::uint8_t> cut_bytes(origin.begin(), origin.begin() + cut_size);
  assert(reb::DecodeNativeTaskOrigin(cut_bytes, header, carried) && header.count == 1 &&
         header.flags == reb::kNativeTaskOriginCut);
  thread.Run([&] {
    const auto received = HandlerStack(queue, NativeAsyncTaskKind::kMessagePort, cut_bytes, 7105);
    assert(received.task_segments == 1 &&
           (received.flags & reb::kNativeRequestStackTaskChainCut) != 0 &&
           (received.flags & reb::kNativeRequestStackTaskChainTruncated) == 0);
    Drain(queue);
  });

  // 40 nested timers, then a post: 32 carried segments, marked truncated
  // rather than cut, and the receiver says the same.
  std::uint64_t nested = 0;
  for (std::uint32_t i = 0; i < 40; ++i) {
    const auto outer = NativeRequestStackWalk::EnterAsyncTask(nested);
    scenario.task_seed = 9500 + i;
    nested = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
    NativeRequestStackWalk::ExitAsyncTask(outer);
    Drain(queue);
  }
  saved = NativeRequestStackWalk::EnterAsyncTask(nested);
  const auto long_size = NativeRequestStackWalk::PostMessageOrigin(
      NativeAsyncTaskKind::kBroadcastChannel, true, origin);
  NativeRequestStackWalk::ExitAsyncTask(saved);
  Drain(queue);
  assert(long_size == reb::kNativeTaskOriginMaxBytes);
  const std::vector<std::uint8_t> long_bytes(origin.begin(), origin.begin() + long_size);
  assert(reb::DecodeNativeTaskOrigin(long_bytes, header, carried) &&
         header.flags == reb::kNativeTaskOriginTruncated);
  thread.Run([&] {
    const auto bounded =
        HandlerStack(queue, NativeAsyncTaskKind::kBroadcastChannel, long_bytes, 7106);
    assert(bounded.task_segments == 32 &&
           (bounded.flags & reb::kNativeRequestStackTaskChainTruncated) != 0 &&
           (bounded.flags & reb::kNativeRequestStackTaskChainCut) == 0 &&
           GeneratedChain()[0].kind == 11);
    Drain(queue);
    NativeRequestStackWalk::DetachThread();
  });

  // Network off: nothing is walked, carried or counted.
  Configure(queue, 72, kForever, reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kRuntime));
  assert(
      NativeRequestStackWalk::PostMessageOrigin(NativeAsyncTaskKind::kMessagePort, true, origin) ==
          0 &&
      NativeRequestStackWalk::ReceiveMessageOrigin(NativeAsyncTaskKind::kMessagePort, bytes) == 0 &&
      NativeRequestStackWalk::ReceiveMessageOrigin(NativeAsyncTaskKind::kMessagePort, damaged) ==
          0 &&
      Drain(queue) == 0);
  scenario = {};
  transport.Disable();
  std::cout << "PASS message origins: nothing beyond the segments crosses, copies on every "
               "thread, forged, damaged, oversize and wrong-kind origins rejected and counted, "
               "missing origin cut, a worker that posts and detaches first, no-script post, cut "
               "and truncated ends carried apart, network off\n";
}

// --reb-promise-stacks: a registration's stack, sent once per digest, names
// the microtask that runs its reaction.
[[gnu::noinline]] void NativePromiseRegistrations() {
  using reb::NativeAsyncTaskKind;
  using reb::NativePromiseRegistration;
  NativeProbeQueue queue;
  Configure(queue, 73);
  scenario = {};
  scenario.depth = 3;
  scenario.scripts = 1;
  scenario.seed = 900;
  // Flag off: nothing walks, nothing is remembered.
  {
    const auto walks = scenario.walks;
    NativeRequestStackWalk::RecordPromiseRegistration(5, NativePromiseRegistration::kThen);
    assert(!NativeRequestStackWalk::PromiseRegistrationActive() && scenario.walks == walks &&
           Drain(queue) == 0);
    // A reaction started with the flag off is not remembered.
    NativeRequestStackWalk::PromiseReactionStarted(5);
    NativeRequestStackWalk::PromiseReactionFinished(5);
  }
  NativeRequestStackWalk::EnablePromiseRegistrations();
  // The main thread's tables were made before the flag: they keep no ring.
  assert(!NativeRequestStackWalk::PromiseRegistrationActive());
  TestThread thread;
  thread.Run([&] {
    NativeRequestStackWalk::AttachThread(
        WorkerScope(reb::NativeStackThread::kServiceWorker, 0x9999));
    assert(NativeRequestStackWalk::PromiseRegistrationActive());
    // A timer whose callback registers a .then.
    scenario.task_seed = 9600;
    const auto timer = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
    Drain(queue);
    NativeRequestStackWalk::AttributeAsyncTask(31, timer);
    scenario.task_seed = 9610;
    NativeRequestStackWalk::RecordPromiseRegistration(41, NativePromiseRegistration::kThen);
    const auto record = TaskPayload(Pop(queue));
    assert(record.kind == 9 && record.registration == 1 && record.recorded == 3 &&
           reb::NativeStackScopeOf(record.reserved2).thread == 4);
    Drain(queue);
    // The reaction runs as a microtask attributed to the timer's task.
    scenario.microtask = true;
    scenario.attribution = 31;
    NativeRequestStackWalk::PromiseReactionStarted(41);
    StackPayload(Start(queue, 7200).second);
    auto chain = GeneratedChain();
    assert(chain.size() == 2 && chain[0].kind == 9 && chain[0].state == 1 &&
           chain[0].registration == 1 && chain[0].recorded == 3 &&
           chain[0].digest == record.digest && chain[1].kind == 1);
    Drain(queue);
    // A timer scheduled inside the reaction keeps the registration hop.
    scenario.task_seed = 9620;
    const auto inner = NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout);
    Drain(queue);
    NativeRequestStackWalk::PromiseReactionFinished(41);
    scenario.microtask = false;
    scenario.attribution = 0;
    const auto outer = NativeRequestStackWalk::EnterAsyncTask(inner);
    StackPayload(Start(queue, 7201).second);
    chain = GeneratedChain();
    assert(chain.size() == 3 && chain[0].kind == 1 && chain[1].kind == 9 &&
           chain[1].registration == 1 && chain[2].kind == 1);
    Drain(queue);
    NativeRequestStackWalk::ExitAsyncTask(outer);
    // The same registration site again: no record, the same digest.
    scenario.task_seed = 9610;
    NativeRequestStackWalk::RecordPromiseRegistration(42, NativePromiseRegistration::kAwait);
    assert(Drain(queue) == 0);
    // A deep registering stack keeps its innermost 32 frames.
    scenario.task_depth = 100;
    scenario.task_seed = 9630;
    NativeRequestStackWalk::RecordPromiseRegistration(43, NativePromiseRegistration::kCatch);
    const auto deep = TaskPayload(Pop(queue));
    assert(deep.recorded == 32 && (deep.flags & reb::kNativeTaskSegmentBounded) != 0);
    Drain(queue);
    scenario.task_depth = 3;
    // A reaction V8 tagged with no remembered registration reads
    // not_recorded, marked as recorded with promise stacks on.
    scenario.microtask = true;
    scenario.attribution = 31;
    NativeRequestStackWalk::PromiseReactionStarted(77);
    StackPayload(Start(queue, 7202).second);
    assert(GeneratedChain()[0].state ==
               static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kNotRecorded) &&
           GeneratedChain()[0].flags == reb::kNativeTaskSegmentRegistrationsOn);
    Drain(queue);
    NativeRequestStackWalk::PromiseReactionFinished(77);
    scenario.microtask = false;
    scenario.attribution = 0;
    // 1,024 registration stacks per configuration, then not retained.
    for (std::uint32_t i = 0; i < reb::kNativePromiseStackArtifactBudget + 4; ++i) {
      scenario.task_seed = 20000 + i;
      NativeRequestStackWalk::RecordPromiseRegistration(1000 + i, NativePromiseRegistration::kThen);
      Drain(queue);
    }
    scenario.microtask = true;
    scenario.attribution = 31;
    NativeRequestStackWalk::PromiseReactionStarted(1000 + reb::kNativePromiseStackArtifactBudget +
                                                   3);
    StackPayload(Start(queue, 7203).second);
    assert(GeneratedChain()[0].state ==
           static_cast<std::uint8_t>(reb::NativeTaskSegmentState::kNotRetainedBudget));
    Drain(queue);
    NativeRequestStackWalk::PromiseReactionFinished(1000 + reb::kNativePromiseStackArtifactBudget +
                                                    3);
    scenario.microtask = false;
    scenario.attribution = 0;
    NativeRequestStackWalk::DetachThread();
  });
  // Capture off: registrations are inactive, and an attached worker that
  // only schedules tasks and registers reactions never makes its tables.
  transport.Disable();
  thread.Run([&] {
    const auto before = allocations.load();
    const int made = fixture_frames_made;
    NativeRequestStackWalk::AttachThread(
        WorkerScope(reb::NativeStackThread::kSharedWorker, 0x9998));
    assert(!NativeRequestStackWalk::PromiseRegistrationActive());
    NativeRequestStackWalk::RecordPromiseRegistration(5, NativePromiseRegistration::kThen);
    assert(NativeRequestStackWalk::RecordAsyncTask(NativeAsyncTaskKind::kSetTimeout) == 0 &&
           allocations.load() == before && fixture_frames_made == made);
    NativeRequestStackWalk::DetachThread();
  });
  scenario = {};
  std::cout << "PASS promise registrations: flag off, per-thread ring, registration stack in the "
               "microtask segment, hop for tasks scheduled in a reaction, dedupe, 32-frame "
               "bound, unknown reaction, budget, capture off\n";
}

// A request start inside a worker: its stack record, with any gaps that came
// first counted in `gaps` by reason.
NativeProbeEvent StartCountingGaps(NativeProbeQueue& queue,
                                   const std::int32_t request,
                                   std::map<std::string, int>& gaps) {
  const auto initiated =
      sink.RecordRequestInitiated(request, "GET", "https", "api.example.test").initiated_sequence;
  assert(initiated != 0);
  NativeRequestStackWalk::Record(request, initiated);
  assert(Pop(queue).header.sequence_number == initiated);
  for (;;) {
    const auto event = Pop(queue);
    if (event.header.type == reb::NativeProbeType::kGap) {
      ++gaps[GapReason(event)];
      continue;
    }
    assert(event.header.parent_event_id == initiated);
    return event;
  }
}

// More workers than kNativeStackThreadLimit: the extra one walks nothing,
// says so on every request and once per configuration as a gap, until a
// worker's tables are freed. The main thread is not counted.
[[gnu::noinline]] void NativeStackThreadLimit() {
  using reb::NativeStackThread;
  NativeProbeQueue queue;
  Configure(queue, 74);
  scenario = {};
  scenario.depth = 2;
  scenario.scripts = 1;
  scenario.seed = 1100;
  std::vector<std::unique_ptr<TestThread>> workers;
  for (std::uint32_t i = 0; i < reb::kNativeStackThreadLimit; ++i) {
    workers.push_back(std::make_unique<TestThread>());
    workers.back()->Run([&, i] {
      NativeRequestStackWalk::AttachThread(
          WorkerScope(NativeStackThread::kDedicatedWorker, 0xA000 + i));
      const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0xA000 + i});
      assert(StackPayload(Start(queue, static_cast<std::int32_t>(7300 + i)).second).state == 1);
      Drain(queue);
    });
  }
  // An attached worker that never walks holds no place.
  TestThread idle;
  idle.Run([&] {
    NativeRequestStackWalk::AttachThread(WorkerScope(NativeStackThread::kSharedWorker, 0xB000));
  });
  const auto extra_scope = WorkerScope(NativeStackThread::kServiceWorker, 0xB001);
  TestThread extra;
  const int made = fixture_frames_made;
  extra.Run([&] {
    NativeRequestStackWalk::AttachThread(extra_scope);
    std::map<std::string, int> gaps;
    const auto limited = StartCountingGaps(queue, 7400, gaps);
    auto payload = StackPayload(limited);
    assert(payload.state ==
               static_cast<std::uint8_t>(reb::NativeRequestStackState::kNotWalkedThreadLimit) &&
           reb::NativeStackScopeOf(payload.reserved1) == extra_scope &&
           limited.header.frame_id == 0xB001 && gaps["request_stack_thread_limit"] == 1 &&
           gaps.size() == 1);
    // Every request says so; the gap counts the thread once per configuration.
    gaps.clear();
    payload = StackPayload(StartCountingGaps(queue, 7401, gaps));
    assert(payload.state == 6 && gaps.empty());
    // Nothing it schedules or receives is walked or remembered.
    assert(NativeRequestStackWalk::RecordAsyncTask(reb::NativeAsyncTaskKind::kSetTimeout) == 0 &&
           NativeRequestStackWalk::ReceiveMessageOrigin(reb::NativeAsyncTaskKind::kMessagePort,
                                                        {}) == 0 &&
           Drain(queue) == 0 && fixture_frames_made == made);
  });
  // A new configuration counts the thread again.
  Configure(queue, 75);
  extra.Run([&] {
    std::map<std::string, int> gaps;
    assert(StackPayload(StartCountingGaps(queue, 7402, gaps)).state == 6 &&
           gaps["request_stack_thread_limit"] == 1);
  });
  // One worker shuts down: its place goes to the next thread that walks.
  workers.back()->Run([] { NativeRequestStackWalk::DetachThread(); });
  extra.Run([&] {
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kServiceWorker, 0xB001});
    assert(StackPayload(Start(queue, 7403).second).state == 1 && fixture_frames_made == made + 1);
    Drain(queue);
    NativeRequestStackWalk::DetachThread();
  });
  for (auto& worker : workers) {
    worker->Run([] { NativeRequestStackWalk::DetachThread(); });
  }
  idle.Run([] { NativeRequestStackWalk::DetachThread(); });
  scenario = {};
  transport.Disable();
  Drain(queue);
  std::cout << "PASS stack thread limit: 32 worker tables per renderer, the next worker reads "
               "not_walked_thread_limit with its scope, one gap per configuration, nothing "
               "scheduled or allocated, its place taken after a worker detaches\n";
}

// A refusal for an artifact whose owner slot 8,192 newer artifacts reused
// still reaches the thread that queued it: it goes to every attached table,
// and only the owner's queued index knows the creator.
[[gnu::noinline]] void NativeRefusalRouting() {
  using reb::NativeStackThread;
  NativeProbeQueue queue;
  Configure(queue, 76);
  scenario = {};
  scenario.depth = 2;
  scenario.scripts = 1;
  constexpr std::uint32_t kThreads = 9;
  static_assert(kThreads * reb::kNativeRequestStackArtifactBudget > reb::kNativeStackOwnerRing);
  std::vector<std::unique_ptr<TestThread>> workers;
  std::uint64_t first = 0;
  for (std::uint32_t t = 0; t < kThreads; ++t) {
    workers.push_back(std::make_unique<TestThread>());
    workers.back()->Run([&, t] {
      const std::uint64_t key = 0xD000 + t;
      NativeRequestStackWalk::AttachThread(WorkerScope(NativeStackThread::kDedicatedWorker, key));
      const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, key});
      for (std::uint32_t i = 0; i < reb::kNativeRequestStackArtifactBudget; ++i) {
        scenario.seed = 30000 + 2000 * t + i;
        const auto stack = Start(queue, static_cast<std::int32_t>(8000 + i)).second;
        assert((StackPayload(stack).flags & reb::kNativeRequestStackArtifactQueued) != 0);
        if (t == 0 && i == 0) {
          first = stack.header.sequence_number;
        }
        Drain(queue);
      }
    });
  }
  // The first artifact's owner slot now names a later one.
  transport.NativeStackArtifactRefused(first);
  workers.front()->Run([&] {
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0xD000});
    scenario.seed = 30000;
    const auto again = StackPayload(Start(queue, 8999).second);
    assert((again.flags & reb::kNativeRequestStackArtifactQueued) != 0);
    Drain(queue);
  });
  // The other tables ignored it: their first stacks are still known.
  workers[1]->Run([&] {
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0xD001});
    scenario.seed = 32000;
    assert((StackPayload(Start(queue, 8998).second).flags &
            reb::kNativeRequestStackArtifactQueued) == 0);
    Drain(queue);
  });
  for (auto& worker : workers) {
    worker->Run([] { NativeRequestStackWalk::DetachThread(); });
  }
  scenario = {};
  transport.Disable();
  Drain(queue);
  std::cout << "PASS refusal routing: a refusal whose owner slot was reused reaches its owner "
               "through every table's queued index; the others ignore it\n";
}

// The transport's thread refuses while the worker walks, with no ordering
// between them: every refused stack is sent again at its next walk, whether
// its refusal was applied alone or covered by an overflow.
[[gnu::noinline]] void NativeRefusalConcurrency() {
  using reb::NativeStackThread;
  NativeProbeQueue queue;
  Configure(queue, 77);
  scenario = {};
  scenario.depth = 2;
  scenario.scripts = 1;
  // Above the mailbox; with the walks below, under the request budget even
  // when an overflow leaves every refusal's budget charged.
  constexpr std::uint32_t kRefused = 300;
  static_assert(kRefused > reb::kNativeStackRefusalMailbox);
  std::vector<std::uint64_t> sequences(kRefused);
  TestThread worker;
  worker.Run([&] {
    NativeRequestStackWalk::AttachThread(WorkerScope(NativeStackThread::kDedicatedWorker, 0xE000));
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0xE000});
    for (std::uint32_t i = 0; i < kRefused; ++i) {
      scenario.seed = 50000 + i;
      sequences[i] =
          Start(queue, static_cast<std::int32_t>(9000 + i)).second.header.sequence_number;
      Drain(queue);
    }
  });
  std::atomic<bool> refused_all{false};
  std::thread transport_thread([&] {
    for (const auto sequence : sequences) {
      transport.NativeStackArtifactRefused(sequence);
    }
    refused_all.store(true, std::memory_order_release);
  });
  std::map<std::string, int> gaps;
  worker.Run([&] {
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0xE000});
    // Other stacks meanwhile, each walk draining what has arrived.
    for (std::uint32_t i = 0; !refused_all.load(std::memory_order_acquire) || i < 4; ++i) {
      scenario.seed = 60000 + i % 64;
      StartCountingGaps(queue, 9700, gaps);
      Drain(queue);
    }
  });
  transport_thread.join();
  worker.Run([&] {
    const reb::NativeFetchOwnerScope owner({reb::NativeLoaderKind::kDedicatedWorker, 0xE000});
    for (std::uint32_t i = 0; i < kRefused; ++i) {
      scenario.seed = 50000 + i;
      const auto again = StackPayload(StartCountingGaps(queue, 9800, gaps));
      assert((again.flags & reb::kNativeRequestStackArtifactQueued) != 0);
      Drain(queue);
    }
    NativeRequestStackWalk::DetachThread();
  });
  // Only these gaps can appear, and an overflow is always counted.
  for (const auto& [reason, count] : gaps) {
    assert(reason == "request_stack_refusals_overflowed" && count >= 1);
  }
  scenario = {};
  transport.Disable();
  Drain(queue);
  std::cout << "PASS refusal concurrency: " << kRefused
            << " refusals raced with walks; each refused stack was sent again, "
            << (gaps.empty() ? 0 : gaps.begin()->second) << " counted overflows\n";
}
}  // namespace
