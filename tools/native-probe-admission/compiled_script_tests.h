// Compiled-script records: the real sink with capturing emitters, read back
// through the core wire validator.
#pragma once

#include "brave/components/reverse_engineering_browser/common/native_compiled_script.h"
#include "reb/compiled_script.hpp"

namespace {
using reb::NativeCompiledScript;
using reb::NativeCompiledScriptKind;
using Retention = reb::CompiledScriptRetention;

struct CapturedScriptSource final {
  reb::NativeArtifactCaptureOrigin origin = reb::NativeArtifactCaptureOrigin::kUnknown;
  std::uint64_t creator_event_id = 0;
  std::uint64_t execution_context_id = 0;
  std::uint64_t frame_id = 0;
  std::string url;
  // Kept only for small sources; large ones are checked by size and credit.
  std::vector<std::uint8_t> bytes;
  std::size_t size = 0;
  std::uint64_t credit = 0;
};

constexpr std::uint64_t kCompiledContext = 77;
constexpr std::uint64_t kSixteenMiB = 16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kCredit = reb::kNativeRendererArtifactCreditBytes;

std::vector<NativeProbeEvent> compiled_events;
std::vector<CapturedScriptSource> compiled_sources;
bool refuse_compiled_events = false;

reb::NativeProbeEmitStatus CaptureCompiledEvent(const NativeProbeEvent& event,
                                                std::uint64_t) noexcept {
  if (refuse_compiled_events)
    return reb::NativeProbeEmitStatus::kRejected;
  compiled_events.push_back(event);
  return reb::NativeProbeEmitStatus::kAdmitted;
}
void CaptureCompiledSource(reb::NativeArtifactKind kind,
                           reb::NativeArtifactCaptureOrigin origin,
                           std::uint64_t creator_event_id,
                           std::uint64_t execution_context_id,
                           std::uint64_t frame_id,
                           std::string_view url,
                           std::span<const std::uint8_t> content,
                           const reb::NativeRuntimeScript&,
                           std::uint64_t credit) noexcept {
  assert(kind == reb::NativeArtifactKind::kJavaScript);
  compiled_sources.push_back(
      {origin, creator_event_id, execution_context_id, frame_id, std::string(url),
       content.size() <= 4096 ? std::vector<std::uint8_t>(content.begin(), content.end())
                              : std::vector<std::uint8_t>(),
       content.size(), credit});
}
// A new configuration alone returns no credit.
void ReconfigureCompiledScripts(bool capture_sources) {
  sink.SetEmitters(&CaptureCompiledEvent, &CaptureCompiledSource, 42,
                   reb::kAllNativeProbeCategoryMask, kForever, false, nullptr,
                   {.capture_request_content = capture_sources,
                    .capture_browser_internal = false,
                    .exclusion_counter = nullptr});
}
void ConfigureCompiledScripts(bool capture_sources) {
  compiled_events.clear();
  compiled_sources.clear();
  refuse_compiled_events = false;
  // The harness plays the browser: everything sent before has been copied out.
  sink.ReleaseArtifactCredit(std::numeric_limits<std::uint64_t>::max());
  ReconfigureCompiledScripts(capture_sources);
}
std::vector<std::uint8_t> ScriptBytes(std::uint8_t seed, std::size_t size = 32) {
  std::vector<std::uint8_t> bytes(size, 'x');
  bytes[0] = seed;
  return bytes;
}
NativeCompiledScript CompiledScript(NativeCompiledScriptKind kind,
                                    std::uint32_t script_id,
                                    std::span<const std::uint8_t> source) {
  NativeCompiledScript script;
  script.kind = kind;
  script.script_id = script_id;
  script.execution_context_id = kCompiledContext;
  script.frame_id = 5;
  script.context_url = "https://owned.test/page";
  script.is_document = true;
  script.source_length = source.size();
  script.source = source;
  return script;
}
reb::CompiledScriptPayload LastCompiledScript() {
  assert(!compiled_events.empty());
  const NativeProbeEvent& event = compiled_events.back();
  assert(event.header.type == reb::NativeProbeType::kScriptCompiled);
  assert(event.header.category == reb::NativeProbeCategory::kArtifact);
  assert(reb::IsValidScriptCompiled(std::bit_cast<reb::EventRecord>(event)));
  reb::CompiledScriptPayload payload;
  assert(reb::DecodeCompiledScriptPayload(event.inline_payload, payload));
  return payload;
}
std::uint8_t RetentionOf(const reb::CompiledScriptPayload& payload) {
  return payload.retention;
}
constexpr std::uint8_t Value(Retention retention) {
  return static_cast<std::uint8_t>(retention);
}
}  // namespace

// An eval carries its creator and its text, and the artifact names its record.
void CompiledScriptEvalIsRetainedWithLineage() {
  ConfigureCompiledScripts(true);
  const auto source = ScriptBytes(1);
  auto script = CompiledScript(NativeCompiledScriptKind::kEval, 9, source);
  script.creator_script_id = 4;
  script.creator_position = 120;
  assert(sink.CompiledScriptNeedsRecord(kCompiledContext, 9));
  sink.RecordCompiledScript(script);
  const auto payload = LastCompiledScript();
  assert(RetentionOf(payload) == Value(Retention::kQueued));
  assert(payload.script_id == 9 && payload.execution_context_id == kCompiledContext);
  assert(payload.creator_script_id == 4 && payload.creator_position == 120);
  assert(compiled_sources.size() == 1);
  const auto& retained = compiled_sources[0];
  assert(retained.origin == reb::NativeArtifactCaptureOrigin::kDynamicJavaScript);
  assert(retained.creator_event_id == compiled_events.back().header.sequence_number);
  assert(retained.url == "https://owned.test/page" && retained.bytes == source);
  assert(retained.credit == source.size());
}

// A cached eval re-reports its script, and only the first report is recorded.
void CompiledScriptRecordsEachScriptOnce() {
  ConfigureCompiledScripts(true);
  const auto source = ScriptBytes(2);
  const auto script = CompiledScript(NativeCompiledScriptKind::kEval, 11, source);
  sink.RecordCompiledScript(script);
  assert(!sink.CompiledScriptNeedsRecord(kCompiledContext, 11));
  sink.RecordCompiledScript(script);
  assert(compiled_events.size() == 1 && compiled_sources.size() == 1);
  // Identity is per realm: the same ID in another context is another script.
  assert(sink.CompiledScriptNeedsRecord(kCompiledContext + 1, 11));
  // A new configuration starts empty.
  ConfigureCompiledScripts(true);
  assert(sink.CompiledScriptNeedsRecord(kCompiledContext, 11));
}

// Identical text from different scripts is recorded twice and stored once.
void CompiledScriptDeduplicatesSource() {
  ConfigureCompiledScripts(true);
  const auto source = ScriptBytes(3);
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 12, source));
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 13, source));
  assert(compiled_events.size() == 2 && compiled_sources.size() == 1);
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kDuplicate));
}

// Only text no response body carries is retained.
void CompiledScriptRetainsOnlyWhatSkippedTheNetwork() {
  ConfigureCompiledScripts(true);
  const auto retained = [&](std::string_view url, bool is_document, std::uint32_t id) {
    const auto source = ScriptBytes(static_cast<std::uint8_t>(id));
    auto script = CompiledScript(NativeCompiledScriptKind::kScript, id, source);
    script.script_url = url;
    script.is_document = is_document;
    sink.RecordCompiledScript(script);
    return RetentionOf(LastCompiledScript()) == Value(Retention::kQueued);
  };
  assert(retained("https://owned.test/page", true, 20));  // Inline.
  assert(compiled_sources.back().origin == reb::NativeArtifactCaptureOrigin::kCompiledScript);
  assert(retained("", true, 21));  // setTimeout(string).
  assert(retained("blob:https://owned.test/id", true, 22));
  assert(retained("data:text/javascript,1", true, 23));
  assert(retained("about:srcdoc", true, 24));
  assert(retained("blob:https://owned.test/worker", false, 25));
  assert(compiled_sources.size() == 6);
  assert(!retained("https://owned.test/app.js", true, 26));
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kNetworkFetched));
  // A worker's entry script carries its context's URL and was still fetched.
  assert(!retained("https://owned.test/page", false, 27));
  assert(compiled_sources.size() == 6);
}

void CompiledScriptNeedsContentCapture() {
  ConfigureCompiledScripts(false);
  const auto source = ScriptBytes(4);
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 30, source));
  const auto payload = LastCompiledScript();
  assert(RetentionOf(payload) == Value(Retention::kNotPermitted));
  assert(payload.source_length == source.size());
  assert(compiled_sources.empty());
}

// Version 2 hashes a source of any length; only text V8 could not provide has
// no digest.
void CompiledScriptReportsMissingSource() {
  ConfigureCompiledScripts(true);
  auto unavailable = CompiledScript(NativeCompiledScriptKind::kEval, 40, {});
  unavailable.source_length = kSixteenMiB + 1;
  sink.RecordCompiledScript(unavailable);
  assert(compiled_events.size() == 1);
  const auto payload = LastCompiledScript();
  assert(RetentionOf(payload) == Value(Retention::kUnavailable));
  assert(payload.source_length == kSixteenMiB + 1 && compiled_sources.empty());

  std::vector<std::uint8_t> large(kSixteenMiB + 4096, 'y');
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 41, large));
  const auto hashed = LastCompiledScript();
  assert(RetentionOf(hashed) == Value(Retention::kQueued));
  assert(hashed.source_length == large.size());
  assert(compiled_sources.size() == 1 && compiled_sources[0].size == large.size());
  assert(compiled_sources[0].credit == large.size());
}

// Sources the browser has not copied out bound what a renderer sends. Past
// the credit each record says so, the configuration gets one named gap, and
// sending resumes as the browser releases.
void CompiledScriptBacklogIsVisible() {
  ConfigureCompiledScripts(true);
  constexpr std::size_t kQuarter = kCredit / 4;
  std::vector<std::uint8_t> source(kQuarter, 'z');
  const auto record = [&](std::uint32_t id) {
    source[0] = static_cast<std::uint8_t>(id);
    sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, id, source));
  };
  for (std::uint32_t i = 0; i < 4; ++i) {
    record(50 + i);
    assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
  }
  record(60);
  assert(compiled_sources.size() == 4);
  assert(PayloadText(compiled_events.back()) == "compiled_script_source_backlog");
  compiled_events.pop_back();
  const auto refused = LastCompiledScript();
  assert(RetentionOf(refused) == Value(Retention::kTransferBacklog));
  assert(refused.source_length == kQuarter);
  const auto events = compiled_events.size();
  record(61);
  assert(compiled_events.size() == events + 1);
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kTransferBacklog));
  // A new configuration keeps the bytes still in flight and names the backlog
  // again.
  ReconfigureCompiledScripts(true);
  record(62);
  assert(PayloadText(compiled_events.back()) == "compiled_script_source_backlog");
  compiled_events.pop_back();
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kTransferBacklog));
  // Released bytes make room again.
  sink.ReleaseArtifactCredit(kQuarter);
  record(63);
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
  assert(compiled_sources.size() == 5 && compiled_sources.back().credit == kQuarter);
}

// One source larger than the whole credit is sent when nothing else waits.
void CompiledScriptLargerThanTheCredit() {
  ConfigureCompiledScripts(true);
  std::vector<std::uint8_t> huge(kCredit + 1, 'h');
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 68, huge));
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
  assert(compiled_sources.size() == 1 && compiled_sources[0].size == huge.size());
  const auto small = ScriptBytes(69);
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 69, small));
  assert(PayloadText(compiled_events.back()) == "compiled_script_source_backlog");
  compiled_events.pop_back();
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kTransferBacklog));
  sink.ReleaseArtifactCredit(huge.size());
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 70, small));
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
}

// A refused record queues no source and returns its credit, so text identical
// to it is still retained when a later script's record is admitted.
void CompiledScriptRefusedRecordKeepsNothing() {
  ConfigureCompiledScripts(true);
  std::vector<std::uint8_t> source(kCredit / 4, 'r');
  refuse_compiled_events = true;
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 71, source));
  assert(compiled_events.empty() && compiled_sources.empty());
  refuse_compiled_events = false;
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 72, source));
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
  assert(compiled_sources.size() == 1);
  for (std::uint32_t i = 0; i < 3; ++i) {
    source[0] = static_cast<std::uint8_t>(80 + i);
    sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 80 + i, source));
    assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
  }
}

void CompiledScriptDisabledRecordsNothing() {
  sink.SetEmitters(nullptr, nullptr, 0, 0, 0);
  compiled_events.clear();
  compiled_sources.clear();
  assert(!sink.IsArtifactCaptureEnabled());
  const auto source = ScriptBytes(6);
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 90, source));
  assert(compiled_events.empty() && compiled_sources.empty());
  // Without the Artifact category nothing is recorded either.
  sink.SetEmitters(&CaptureCompiledEvent, &CaptureCompiledSource, 42,
                   reb::NativeProbeCategoryMask(reb::NativeProbeCategory::kVm), kForever, false,
                   nullptr,
                   {.capture_request_content = true,
                    .capture_browser_internal = false,
                    .exclusion_counter = nullptr});
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 91, source));
  assert(compiled_events.empty() && compiled_sources.empty());
}
