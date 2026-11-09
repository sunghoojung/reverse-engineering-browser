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
  std::vector<std::uint8_t> bytes;
};

constexpr std::uint64_t kCompiledContext = 77;
constexpr std::uint64_t kSixteenMiB = 16ULL * 1024ULL * 1024ULL;

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
                           const reb::NativeRuntimeScript&) noexcept {
  assert(kind == reb::NativeArtifactKind::kJavaScript);
  compiled_sources.push_back({origin, creator_event_id, execution_context_id, frame_id,
                              std::string(url),
                              std::vector<std::uint8_t>(content.begin(), content.end())});
}
void ConfigureCompiledScripts(bool capture_sources) {
  compiled_events.clear();
  compiled_sources.clear();
  refuse_compiled_events = false;
  sink.SetEmitters(&CaptureCompiledEvent, &CaptureCompiledSource, 42,
                   reb::kAllNativeProbeCategoryMask, kForever, false, nullptr, capture_sources);
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

void CompiledScriptReportsMissingSource() {
  ConfigureCompiledScripts(true);
  auto too_large = CompiledScript(NativeCompiledScriptKind::kEval, 40, {});
  too_large.source_length = kSixteenMiB + 1;
  sink.RecordCompiledScript(too_large);
  // One record for the script, then one named gap for the configuration.
  assert(compiled_events.size() == 2);
  assert(compiled_events[1].header.type == reb::NativeProbeType::kArtifactCaptureFailed);
  assert(PayloadText(compiled_events[1]) == "compiled_script_source_too_large");
  compiled_events.pop_back();
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kTooLarge));
  auto larger = CompiledScript(NativeCompiledScriptKind::kEval, 41, {});
  larger.source_length = kSixteenMiB + 2;
  sink.RecordCompiledScript(larger);
  assert(compiled_events.size() == 2);

  auto unavailable = CompiledScript(NativeCompiledScriptKind::kEval, 42, {});
  unavailable.source_length = 64;
  sink.RecordCompiledScript(unavailable);
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kUnavailable));
  assert(compiled_sources.empty());
}

void CompiledScriptBudgetIsVisible() {
  ConfigureCompiledScripts(true);
  for (std::uint32_t i = 0; i < 4; ++i) {
    const auto source = ScriptBytes(static_cast<std::uint8_t>(50 + i), kSixteenMiB);
    sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 50 + i, source));
    assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
  }
  const auto over = ScriptBytes(60);
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 60, over));
  assert(compiled_sources.size() == 4);
  assert(PayloadText(compiled_events.back()) == "compiled_script_source_budget");
  compiled_events.pop_back();
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kBudgetSpent));
  // A reset configuration gets a fresh budget.
  ConfigureCompiledScripts(true);
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 60, over));
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
}

// A refused record queues no source and spends no budget, so text identical
// to it is still retained when a later script's record is admitted.
void CompiledScriptRefusedRecordKeepsNothing() {
  ConfigureCompiledScripts(true);
  const auto source = ScriptBytes(5, kSixteenMiB);
  refuse_compiled_events = true;
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 70, source));
  assert(compiled_events.empty() && compiled_sources.empty());
  refuse_compiled_events = false;
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 71, source));
  assert(RetentionOf(LastCompiledScript()) == Value(Retention::kQueued));
  assert(compiled_sources.size() == 1);
  for (std::uint32_t i = 0; i < 3; ++i) {
    const auto other = ScriptBytes(static_cast<std::uint8_t>(80 + i), kSixteenMiB);
    sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 80 + i, other));
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
                   nullptr, true);
  sink.RecordCompiledScript(CompiledScript(NativeCompiledScriptKind::kEval, 91, source));
  assert(compiled_events.empty() && compiled_sources.empty());
}
