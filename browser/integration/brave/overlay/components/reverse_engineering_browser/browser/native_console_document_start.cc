// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_console_document_start.h"

#include <algorithm>
#include <span>
#include <utility>

#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/browser/native_console_session.h"
#include "brave/components/reverse_engineering_browser/common/native_console_protocol.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/global_routing_id.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"

namespace reb {
namespace {

constexpr std::uint32_t kCounterLimit = 2147483647;
// What State spends on everything but scripts and records, and the most one
// listed script or one record can take as JSON beyond its strings. Strings are
// counted at their worst-case escaping, so a page never outgrows the reply.
constexpr std::size_t kEnvelopeBytes = 64 * 1024;
constexpr std::size_t kListedScriptBytes = 256;
constexpr std::size_t kRecordBytes = 320;

void Saturate(std::uint32_t& counter, std::uint32_t amount = 1) noexcept {
  counter += amount > kCounterLimit - counter ? kCounterLimit - counter : amount;
}

std::string Hex(std::uint64_t value) {
  std::string text(16, '0');
  for (int index = 15; index >= 0; --index) {
    text[static_cast<std::size_t>(index)] = "0123456789abcdef"[value & 15];
    value >>= 4;
  }
  return text;
}

}  // namespace

// One host per renderer process. Metadata only: no V8 handle, page value, or
// document token is retained, and the process never gains console ownership.
class NativeConsoleDocumentStartHost final : public mojom::NativeConsoleScriptHost {
 public:
  NativeConsoleDocumentStartHost(int render_process_id,
                                 mojo::PendingReceiver<mojom::NativeConsoleScriptHost> receiver)
      : render_process_id_(render_process_id), receiver_(this, std::move(receiver)) {
    receiver_.set_disconnect_handler(
        base::BindOnce(&NativeConsoleDocumentStartHost::Disconnected, base::Unretained(this)));
  }
  NativeConsoleDocumentStartHost(const NativeConsoleDocumentStartHost&) = delete;
  NativeConsoleDocumentStartHost& operator=(const NativeConsoleDocumentStartHost&) = delete;
  ~NativeConsoleDocumentStartHost() override = default;

  [[nodiscard]] int render_process_id() const noexcept { return render_process_id_; }
  [[nodiscard]] bool delivered(std::uint64_t generation) const noexcept {
    return delivered_generation_ == generation;
  }

  // Every renderer maps a duplicate of the same read-only region, so the set
  // is never copied per process. An invalid region is the empty set.
  void Arm(std::uint64_t generation,
           const base::ReadOnlySharedMemoryRegion& set,
           std::size_t count) {
    if (!client_.is_bound())
      return;
    delivered_generation_ = 0;
    expected_ = count;
    client_->Arm(generation, set.IsValid() ? set.Duplicate() : base::ReadOnlySharedMemoryRegion(),
                 base::BindOnce(&NativeConsoleDocumentStartHost::Acknowledged,
                                base::Unretained(this), generation));
  }

  // Heard on the renderer's IO thread, so it reaches an injection that holds
  // the main thread. It names only `generation`'s injections.
  void Stop(std::uint64_t generation) {
    if (control_.is_bound())
      control_->Stop(kNativeConsoleDocumentStartStopBit | generation);
  }

 private:
  void BindClient(mojo::PendingRemote<mojom::NativeConsoleScriptClient> client,
                  mojo::PendingRemote<mojom::NativeConsoleControl> control) override {
    client_.reset();
    client_.Bind(std::move(client));
    control_.reset();
    if (control.is_valid())
      control_.Bind(std::move(control));
    NativeConsoleDocumentStartRegistry::Get().BindHostReady(this);
  }

  void Observed(std::uint64_t generation,
                std::uint64_t script_id,
                std::uint64_t frame_id,
                const base::UnguessableToken& document,
                std::uint32_t record,
                bool truncated,
                const std::string& text) override {
    NativeConsoleDocumentStartRegistry::Get().Observe(Resolve(document), generation, script_id,
                                                      frame_id, record, truncated, text);
  }

  // The renderer names a document it hosts. Resolve it only among this
  // process's own eligible frames, so a record can never claim another
  // process's document, and the exact token is never published. A document
  // usually reports many records in a row, so the last resolution is reused
  // after the frame is found again by id and its token rechecked.
  content::RenderFrameHost* Resolve(const base::UnguessableToken& document) {
    const auto owns = [&document](content::RenderFrameHost* frame) {
      return frame && frame->GetDocumentToken().value() == document &&
             IsNativeConsoleDocument(frame);
    };
    if (document == last_document_) {
      auto* frame = content::RenderFrameHost::FromID(last_frame_);
      if (owns(frame) && frame->GetProcess()->GetDeprecatedID() == render_process_id_)
        return frame;
    }
    content::RenderFrameHost* owner = nullptr;
    if (auto* process = content::RenderProcessHost::FromID(render_process_id_)) {
      process->ForEachRenderFrameHost([&](content::RenderFrameHost* frame) {
        if (!owner && owns(frame))
          owner = frame;
      });
    }
    last_document_ = owner ? document : base::UnguessableToken();
    last_frame_ = owner ? owner->GetGlobalId() : content::GlobalRenderFrameHostId();
    return owner;
  }

  // A renderer that refused or only partially decoded the set never counts as
  // delivered, so State keeps reporting it as pending rather than ready.
  void Acknowledged(std::uint64_t generation, std::uint32_t armed) {
    if (armed == expected_)
      delivered_generation_ = generation;
  }

  // Remove this host after the disconnect dispatch unwinds, so its receiver is
  // never destroyed while it is still delivering.
  void Disconnected() {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&NativeConsoleDocumentStartRegistry::RemoveHost,
                       base::Unretained(&NativeConsoleDocumentStartRegistry::Get()), this));
  }

  const int render_process_id_;
  std::uint64_t delivered_generation_ = 0;
  std::size_t expected_ = 0;
  base::UnguessableToken last_document_;
  content::GlobalRenderFrameHostId last_frame_;
  mojo::Receiver<mojom::NativeConsoleScriptHost> receiver_;
  mojo::Remote<mojom::NativeConsoleScriptClient> client_;
  mojo::Remote<mojom::NativeConsoleControl> control_;
};

NativeConsoleDocumentStartRegistry& NativeConsoleDocumentStartRegistry::Get() {
  static base::NoDestructor<NativeConsoleDocumentStartRegistry> registry;
  return *registry;
}

NativeConsoleDocumentStartRegistry::NativeConsoleDocumentStartRegistry() = default;
NativeConsoleDocumentStartRegistry::~NativeConsoleDocumentStartRegistry() = default;

bool NativeConsoleDocumentStartRegistry::IsPermitted() {
  return IsNativeConsoleEnabled() &&
         base::CommandLine::ForCurrentProcess()->HasSwitch(kNativeConsoleDocumentStartSwitch);
}

void NativeConsoleDocumentStartRegistry::BindHost(
    int render_process_id,
    mojo::PendingReceiver<mojom::NativeConsoleScriptHost> receiver) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  if (!IsPermitted())
    return;
  // One host per live renderer process, with no count limit: each holds two
  // pipes and a few fields, and a host is removed when its process goes away.
  // Every renderer therefore receives the set.
  hosts_.push_back(
      std::make_unique<NativeConsoleDocumentStartHost>(render_process_id, std::move(receiver)));
}

void NativeConsoleDocumentStartRegistry::BindHostReady(NativeConsoleDocumentStartHost* host) {
  // A renderer that connects after arming still receives the current set. A
  // cleared set is sent as well, so its acknowledgement marks the renderer
  // ready instead of leaving it pending while nothing is armed.
  if (generation_)
    host->Arm(generation_, set_, scripts_.size());
}

void NativeConsoleDocumentStartRegistry::RemoveHost(NativeConsoleDocumentStartHost* host) {
  std::erase_if(hosts_, [host](const auto& owned) { return owned.get() == host; });
}

void NativeConsoleDocumentStartRegistry::StopRunning() {
  if (scripts_.empty())
    return;
  for (const auto& host : hosts_)
    host->Stop(generation_);
}

void NativeConsoleDocumentStartRegistry::Push() {
  for (const auto& host : hosts_)
    host->Arm(generation_, set_, scripts_.size());
}

bool NativeConsoleDocumentStartRegistry::Arm(const base::ListValue& scripts, std::string& error) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  if (!IsPermitted()) {
    error =
        "Document-start scripts are not permitted in this browser session. Rebuild the pinned "
        "browser and start the session with the document-start experiment enabled.";
    return false;
  }
  if (scripts.empty()) {
    error = "Arm at least one document-start script";
    return false;
  }
  // Build the whole set before replacing anything: a refusal must leave the
  // previous set and its output exactly as they were. The views point into
  // `scripts`, which outlives the encoding below.
  std::vector<Armed> next;
  std::vector<NativeConsoleDocumentStartScript> views;
  next.reserve(scripts.size());
  views.reserve(scripts.size());
  std::size_t listing = 0;
  auto script_id = next_script_id_;
  for (const auto& entry : scripts) {
    const auto* record = entry.GetIfDict();
    const auto* origin = record ? record->FindString("origin") : nullptr;
    const auto* frame = record ? record->FindString("frame") : nullptr;
    const auto* source = record ? record->FindString("source") : nullptr;
    const auto* prefix = record ? record->FindString("path_prefix") : nullptr;
    if (!record || !origin || !frame || !source) {
      error = "Each document-start script needs origin, frame and source";
      return false;
    }
    if (record->size() != (prefix ? 4u : 3u)) {
      error = "A document-start script takes only origin, frame, path_prefix and source";
      return false;
    }
    NativeConsoleDocumentStartScript view;
    view.script_id = script_id;
    if (*frame == "top") {
      view.rule.frame_flags = kNativeConsoleDocumentStartTopFrame;
    } else if (*frame == "child") {
      view.rule.frame_flags = kNativeConsoleDocumentStartChildFrame;
    } else {
      error = "A document-start rule matches frame \"top\" or \"child\"";
      return false;
    }
    view.rule.origin = *origin;
    view.rule.path = prefix ? std::string_view(*prefix) : std::string_view();
    view.source = *source;
    if (!IsValidNativeConsoleDocumentStartScript(view)) {
      error =
          "A document-start rule needs one exact http or https origin of at most 256 bytes, frame "
          "\"top\" or \"child\", an optional literal path prefix of at most 256 bytes, and a "
          "nonempty valid UTF-8 snippet";
      return false;
    }
    // Origins and prefixes are printable ASCII, so JSON at most doubles them.
    listing += kListedScriptBytes + 2 * (view.rule.origin.size() + view.rule.path.size());
    if (listing > kNativeConsoleDocumentStartListingLimit) {
      error = "The armed set could not be listed in one " +
              base::NumberToString(kNativeConsoleDocumentStartReplyLimit / (1024 * 1024)) +
              " MiB reply; arm fewer scripts";
      return false;
    }
    Armed armed;
    armed.script_id = script_id++;
    armed.frame_flags = view.rule.frame_flags;
    armed.origin = std::string(view.rule.origin);
    armed.path = std::string(view.rule.path);
    armed.source_bytes = view.source.size();
    armed.digest = NativeConsoleDocumentStartDigest(view.source);
    next.push_back(std::move(armed));
    views.push_back(view);
  }
  const auto bytes = NativeConsoleDocumentStartEncodedBytes(views);
  auto mapped =
      bytes ? base::ReadOnlySharedMemoryRegion::Create(bytes) : base::MappedReadOnlyRegion();
  if (!mapped.IsValid() || !EncodeNativeConsoleDocumentStartScripts(
                               views, mapped.mapping.GetMemoryAsSpan<std::uint8_t>())) {
    error = "The document-start set could not be placed in shared memory for the renderers";
    return false;
  }
  StopRunning();
  next_script_id_ = script_id;
  scripts_ = std::move(next);
  set_ = std::move(mapped.region);
  listing_bytes_ = listing;
  ++generation_;
  // Replacing the set invalidates the previous generation's output: a record
  // from a script that is no longer armed must not look current.
  output_.clear();
  retained_bytes_ = 0;
  dropped_ = 0;
  unattributed_ = 0;
  stale_ = 0;
  Push();
  return true;
}

void NativeConsoleDocumentStartRegistry::Clear() {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  if (scripts_.empty() && output_.empty() && !generation_)
    return;
  StopRunning();
  scripts_.clear();
  set_ = base::ReadOnlySharedMemoryRegion();
  listing_bytes_ = 0;
  output_.clear();
  retained_bytes_ = 0;
  dropped_ = 0;
  unattributed_ = 0;
  stale_ = 0;
  ++generation_;
  Push();
}

void NativeConsoleDocumentStartRegistry::Observe(content::RenderFrameHost* owner,
                                                 std::uint64_t generation,
                                                 std::uint64_t script_id,
                                                 std::uint64_t frame_id,
                                                 std::uint32_t record,
                                                 bool truncated,
                                                 const std::string& text) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  if (!IsPermitted() || scripts_.empty())
    return;
  if (generation != generation_ || !IsNativeConsoleDocumentStartRecord(record)) {
    Saturate(stale_);
    return;
  }
  // Identities are assigned in increasing order, so the armed set is sorted.
  auto armed =
      std::lower_bound(scripts_.begin(), scripts_.end(), script_id,
                       [](const Armed& entry, std::uint64_t id) { return entry.script_id < id; });
  if (armed == scripts_.end() || armed->script_id != script_id) {
    Saturate(stale_);
    return;
  }
  if (!owner) {
    Saturate(unattributed_);
    return;
  }
  if (!base::IsStringUTF8(text) || text.size() > kNativeConsoleDocumentStartReportLimit) {
    Saturate(stale_);
    return;
  }
  Saturate(armed->records);
  if (record == static_cast<std::uint32_t>(NativeConsoleDocumentStartRecord::kInjected))
    Saturate(armed->injected_documents);
  if (record == static_cast<std::uint32_t>(NativeConsoleDocumentStartRecord::kRefused))
    Saturate(armed->refused);
  // Retention is bounded by bytes, not by a record count, so many small
  // reports are all kept. Past the bound the oldest go, and are counted.
  const auto bytes = sizeof(Output) + text.size();
  while (!output_.empty() && retained_bytes_ + bytes > kNativeConsoleDocumentStartRetainedBytes) {
    retained_bytes_ -= sizeof(Output) + output_.front().text.size();
    output_.pop_front();
    Saturate(dropped_);
  }
  retained_bytes_ += bytes;
  output_.push_back({.sequence = next_sequence_++,
                     .script_id = script_id,
                     .document_id = NativeConsoleDocumentId(owner),
                     .frame_id = frame_id,
                     .time = base::Time::Now().InMillisecondsFSinceUnixEpoch(),
                     .record = record,
                     .top_frame = owner->GetParentOrOuterDocument() == nullptr,
                     .truncated = truncated,
                     .text = text});
}

base::DictValue NativeConsoleDocumentStartRegistry::State(std::uint64_t after) const {
  base::ListValue armed;
  for (const auto& entry : scripts_) {
    base::DictValue rule;
    rule.Set("origin", entry.origin);
    rule.Set("frame", entry.frame_flags == kNativeConsoleDocumentStartTopFrame ? "top" : "child");
    if (!entry.path.empty())
      rule.Set("path_prefix", entry.path);
    armed.Append(base::DictValue()
                     .Set("script_id", base::NumberToString(entry.script_id))
                     .Set("rule", std::move(rule))
                     .Set("source_bytes", static_cast<int>(entry.source_bytes))
                     .Set("digest", Hex(entry.digest))
                     .Set("records", static_cast<int>(entry.records))
                     .Set("injected_documents", static_cast<int>(entry.injected_documents))
                     .Set("refused", static_cast<int>(entry.refused)));
  }
  // Every retained record after the cursor that fits beside the listing.
  // Records are in sequence order, so the first one after `after` is found by
  // search rather than by scanning everything a reader has already seen.
  base::ListValue page;
  const auto budget = kNativeConsoleDocumentStartReplyLimit - kEnvelopeBytes - listing_bytes_;
  std::size_t used = 0;
  for (auto entry = std::upper_bound(
           output_.begin(), output_.end(), after,
           [](std::uint64_t cursor, const Output& output) { return cursor < output.sequence; });
       entry != output_.end(); ++entry) {
    // A control character escapes to six bytes, the most any byte becomes.
    const auto cost = kRecordBytes + 6 * entry->text.size();
    if (used + cost > budget)
      break;
    used += cost;
    page.Append(base::DictValue()
                    .Set("sequence", base::NumberToString(entry->sequence))
                    .Set("record", NativeConsoleDocumentStartRecordName(entry->record))
                    .Set("provenance", "console-document-start-script")
                    .Set("script_id", base::NumberToString(entry->script_id))
                    .Set("document_id", base::NumberToString(entry->document_id))
                    .Set("frame_id", base::NumberToString(entry->frame_id))
                    .Set("top_frame", entry->top_frame)
                    .Set("time", entry->time)
                    .Set("truncated", entry->truncated)
                    .Set("text", entry->text));
  }
  std::size_t pending = 0;
  for (const auto& host : hosts_) {
    if (!host->delivered(generation_))
      ++pending;
  }
  return base::DictValue()
      .Set("status", "ok")
      .Set("contract_version", 3)
      .Set("permitted", IsPermitted())
      .Set("generation", base::NumberToString(generation_))
      .Set("scripts", std::move(armed))
      .Set("renderer_processes", static_cast<int>(hosts_.size()))
      // Zero means every live renderer holds this exact generation, so a
      // document created now runs it. A positive value is a readiness gap, not
      // a record loss: reload the document after it reaches zero.
      .Set("pending_renderer_processes", static_cast<int>(pending))
      .Set("output", base::DictValue()
                         .Set("records", std::move(page))
                         .Set("next_sequence", base::NumberToString(next_sequence_))
                         .Set("oldest_sequence",
                              base::NumberToString(output_.empty() ? 0 : output_.front().sequence))
                         .Set("retained", static_cast<int>(output_.size()))
                         .Set("retained_bytes", static_cast<int>(retained_bytes_))
                         .Set("dropped", static_cast<int>(dropped_))
                         .Set("unattributed", static_cast<int>(unattributed_))
                         .Set("stale", static_cast<int>(stale_)));
}

}  // namespace reb
