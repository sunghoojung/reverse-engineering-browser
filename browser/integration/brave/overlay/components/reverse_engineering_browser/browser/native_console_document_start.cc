// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_console_document_start.h"

#include <algorithm>
#include <array>
#include <cstring>
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
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"

namespace reb {
namespace {

constexpr std::uint32_t kCounterLimit = 2147483647;

void Saturate(std::uint32_t& counter, std::uint32_t amount = 1) noexcept {
  counter += amount > kCounterLimit - counter ? kCounterLimit - counter : amount;
}

bool IsLiveRenderer(int render_process_id) {
  auto* process = content::RenderProcessHost::FromID(render_process_id);
  return process && process->IsInitializedAndNotDead();
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

  void Arm(std::uint64_t generation, std::span<const std::uint8_t> scripts, std::size_t count) {
    if (!client_.is_bound())
      return;
    delivered_generation_ = 0;
    expected_ = count;
    client_->Arm(generation, std::vector<std::uint8_t>(scripts.begin(), scripts.end()),
                 base::BindOnce(&NativeConsoleDocumentStartHost::Acknowledged,
                                base::Unretained(this), generation));
  }

 private:
  void BindClient(mojo::PendingRemote<mojom::NativeConsoleScriptClient> client) override {
    client_.reset();
    client_.Bind(std::move(client));
    NativeConsoleDocumentStartRegistry::Get().BindHostReady(this);
  }

  void Observed(std::uint64_t generation,
                std::uint64_t script_id,
                std::uint64_t frame_id,
                const base::UnguessableToken& document,
                std::uint32_t record,
                bool truncated,
                const std::string& text) override {
    NativeConsoleDocumentStartRegistry::Get().Observe(render_process_id_, generation, script_id,
                                                      frame_id, document, record, truncated, text);
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
  mojo::Receiver<mojom::NativeConsoleScriptHost> receiver_;
  mojo::Remote<mojom::NativeConsoleScriptClient> client_;
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
  // Forget refused processes that have exited, so this list is bounded by the
  // browser's own live renderers rather than growing for the whole session.
  std::erase_if(refused_, [render_process_id](int id) {
    return id == render_process_id || !IsLiveRenderer(id);
  });
  if (hosts_.size() >= kNativeConsoleTargetLimit) {
    // A refused renderer never receives a set, so State must keep counting it
    // instead of reporting that every renderer holds the armed set.
    refused_.push_back(render_process_id);
    return;
  }
  hosts_.push_back(
      std::make_unique<NativeConsoleDocumentStartHost>(render_process_id, std::move(receiver)));
}

void NativeConsoleDocumentStartRegistry::BindHostReady(NativeConsoleDocumentStartHost* host) {
  // A renderer that connects after arming still receives the current set. A
  // cleared set is sent as well, so its acknowledgement marks the renderer
  // ready instead of leaving it pending while nothing is armed.
  if (!generation_)
    return;
  std::array<std::uint8_t, kNativeConsoleDocumentStartSetBytes> encoded{};
  const auto bytes = scripts_.empty() ? std::size_t{0} : Encode(encoded);
  if (bytes || scripts_.empty())
    host->Arm(generation_, std::span(encoded).first(bytes), scripts_.size());
}

void NativeConsoleDocumentStartRegistry::RemoveHost(NativeConsoleDocumentStartHost* host) {
  std::erase_if(hosts_, [host](const auto& owned) { return owned.get() == host; });
}

std::size_t NativeConsoleDocumentStartRegistry::Encode(std::span<std::uint8_t> out) const {
  std::vector<NativeConsoleDocumentStartScript> records;
  records.reserve(scripts_.size());
  for (const auto& armed : scripts_)
    records.push_back(armed.script);
  return EncodeNativeConsoleDocumentStartScripts(records, out);
}

void NativeConsoleDocumentStartRegistry::Push() {
  std::array<std::uint8_t, kNativeConsoleDocumentStartSetBytes> encoded{};
  const auto bytes = scripts_.empty() ? std::size_t{0} : Encode(encoded);
  for (const auto& host : hosts_)
    host->Arm(generation_, std::span(encoded).first(bytes), scripts_.size());
}

bool NativeConsoleDocumentStartRegistry::Arm(const base::ListValue& scripts, std::string& error) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  if (!IsPermitted()) {
    error =
        "Document-start scripts are not permitted in this browser session. Rebuild the pinned "
        "browser and start the session with the document-start experiment enabled.";
    return false;
  }
  if (scripts.empty() || scripts.size() > kNativeConsoleDocumentStartScriptLimit) {
    error = "Arm 1 to " + base::NumberToString(kNativeConsoleDocumentStartScriptLimit) +
            " document-start scripts";
    return false;
  }
  // Build the whole set before replacing anything: a refusal must leave the
  // previous set and its output exactly as they were.
  std::vector<Armed> next;
  std::size_t total = 0;
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
    Armed armed;
    armed.script.script_id = next_script_id_;
    if (*frame == "top") {
      armed.script.rule.frame_flags = kNativeConsoleDocumentStartTopFrame;
    } else if (*frame == "child") {
      armed.script.rule.frame_flags = kNativeConsoleDocumentStartChildFrame;
    } else {
      error = "A document-start rule matches frame \"top\" or \"child\"";
      return false;
    }
    if (origin->size() > armed.script.rule.origin.size() ||
        (prefix && prefix->size() > armed.script.rule.path.size()) ||
        source->size() > armed.script.source.size()) {
      error = "A document-start origin, path prefix or snippet exceeds its limit";
      return false;
    }
    armed.script.rule.origin_bytes = static_cast<std::uint16_t>(origin->size());
    std::memcpy(armed.script.rule.origin.data(), origin->data(), origin->size());
    if (prefix) {
      armed.script.rule.path_bytes = static_cast<std::uint16_t>(prefix->size());
      std::memcpy(armed.script.rule.path.data(), prefix->data(), prefix->size());
    }
    armed.script.source_bytes = static_cast<std::uint32_t>(source->size());
    std::memcpy(armed.script.source.data(), source->data(), source->size());
    if (!IsValidNativeConsoleDocumentStartScript(armed.script)) {
      error =
          "A document-start rule needs one exact http or https origin, frame \"top\" or \"child\", "
          "an optional literal path prefix, and a valid UTF-8 snippet";
      return false;
    }
    total += source->size();
    if (total > kNativeConsoleDocumentStartTotalSourceLimit) {
      error = "Document-start snippets exceed " +
              base::NumberToString(kNativeConsoleDocumentStartTotalSourceLimit) +
              " total source bytes";
      return false;
    }
    ++next_script_id_;
    next.push_back(std::move(armed));
  }
  scripts_ = std::move(next);
  ++generation_;
  // Replacing the set invalidates the previous generation's output: a record
  // from a script that is no longer armed must not look current.
  output_.clear();
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
  scripts_.clear();
  output_.clear();
  dropped_ = 0;
  unattributed_ = 0;
  stale_ = 0;
  ++generation_;
  Push();
}

void NativeConsoleDocumentStartRegistry::Observe(int render_process_id,
                                                 std::uint64_t generation,
                                                 std::uint64_t script_id,
                                                 std::uint64_t frame_id,
                                                 const base::UnguessableToken& document,
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
  auto armed = std::find_if(scripts_.begin(), scripts_.end(), [script_id](const Armed& entry) {
    return entry.script.script_id == script_id;
  });
  if (armed == scripts_.end()) {
    Saturate(stale_);
    return;
  }
  // The renderer names a document it hosts. Resolve it only among that
  // process's own eligible frames, so a record can never claim another
  // process's document, and the exact token is never published.
  content::RenderFrameHost* owner = nullptr;
  if (auto* process = content::RenderProcessHost::FromID(render_process_id)) {
    process->ForEachRenderFrameHost([&](content::RenderFrameHost* frame) {
      if (owner || !IsNativeConsoleDocument(frame))
        return;
      if (frame->GetDocumentToken().value() == document)
        owner = frame;
    });
  }
  if (!owner) {
    Saturate(unattributed_);
    return;
  }
  if (!base::IsStringUTF8(text) || text.size() > kNativeConsoleDocumentStartReportLimit * 4) {
    Saturate(stale_);
    return;
  }
  Saturate(armed->records);
  if (record == static_cast<std::uint32_t>(NativeConsoleDocumentStartRecord::kInjected))
    Saturate(armed->injected_documents);
  if (record == static_cast<std::uint32_t>(NativeConsoleDocumentStartRecord::kRefused))
    Saturate(armed->refused);
  if (output_.size() >= kNativeConsoleDocumentStartOutputCapacity) {
    output_.pop_front();
    Saturate(dropped_);
  }
  output_.push_back(base::DictValue()
                        .Set("sequence", base::NumberToString(next_sequence_++))
                        .Set("record", NativeConsoleDocumentStartRecordName(record))
                        .Set("provenance", "console-document-start-script")
                        .Set("script_id", base::NumberToString(script_id))
                        .Set("document_id", base::NumberToString(NativeConsoleDocumentId(owner)))
                        .Set("frame_id", base::NumberToString(frame_id))
                        .Set("top_frame", owner->GetParentOrOuterDocument() == nullptr)
                        .Set("time", base::Time::Now().InMillisecondsFSinceUnixEpoch())
                        .Set("truncated", truncated)
                        .Set("text", text));
}

base::DictValue NativeConsoleDocumentStartRegistry::State(std::uint64_t after) const {
  base::ListValue armed;
  for (const auto& entry : scripts_) {
    base::DictValue rule;
    rule.Set("origin", std::string(NativeConsoleDocumentStartOrigin(entry.script.rule)));
    rule.Set("frame", entry.script.rule.frame_flags == kNativeConsoleDocumentStartTopFrame
                          ? "top"
                          : "child");
    if (entry.script.rule.path_bytes)
      rule.Set("path_prefix", std::string(NativeConsoleDocumentStartPath(entry.script.rule)));
    armed.Append(base::DictValue()
                     .Set("script_id", base::NumberToString(entry.script.script_id))
                     .Set("rule", std::move(rule))
                     .Set("source_bytes", static_cast<int>(entry.script.source_bytes))
                     .Set("digest", Hex(NativeConsoleDocumentStartDigest(
                                        NativeConsoleDocumentStartSource(entry.script))))
                     .Set("records", static_cast<int>(entry.records))
                     .Set("injected_documents", static_cast<int>(entry.injected_documents))
                     .Set("refused", static_cast<int>(entry.refused)));
  }
  base::ListValue page;
  for (const auto& entry : output_) {
    if (page.size() >= kNativeConsoleDocumentStartOutputPage)
      break;
    std::uint64_t sequence = 0;
    const auto* text = entry.FindString("sequence");
    if (!text || !base::StringToUint64(*text, &sequence) || sequence <= after)
      continue;
    page.Append(entry.Clone());
  }
  std::size_t pending = 0;
  for (const auto& host : hosts_) {
    if (!host->delivered(generation_))
      ++pending;
  }
  // A refused renderer holds no set. That equals an empty set, but it never
  // holds an armed one, so it counts as pending for as long as one is armed.
  const auto refused = static_cast<std::size_t>(
      std::count_if(refused_.begin(), refused_.end(), [](int id) { return IsLiveRenderer(id); }));
  if (!scripts_.empty())
    pending += refused;
  std::uint64_t oldest = 0;
  if (!output_.empty()) {
    const auto* text = output_.front().FindString("sequence");
    if (text)
      static_cast<void>(base::StringToUint64(*text, &oldest));
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
      // a record loss: reload the document after it reaches zero. It includes
      // refused renderers while a set is armed; those never become ready.
      .Set("pending_renderer_processes", static_cast<int>(pending))
      .Set("refused_renderer_processes", static_cast<int>(refused))
      .Set("output", base::DictValue()
                         .Set("records", std::move(page))
                         .Set("next_sequence", base::NumberToString(next_sequence_))
                         .Set("oldest_sequence", base::NumberToString(oldest))
                         .Set("retained", static_cast<int>(output_.size()))
                         .Set("dropped", static_cast<int>(dropped_))
                         .Set("unattributed", static_cast<int>(unattributed_))
                         .Set("stale", static_cast<int>(stale_)));
}

}  // namespace reb
