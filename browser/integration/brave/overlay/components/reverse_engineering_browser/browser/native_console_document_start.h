// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_DOCUMENT_START_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_DOCUMENT_START_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "base/memory/read_only_shared_memory_region.h"
#include "base/no_destructor.h"
#include "base/unguessable_token.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/common/native_console.mojom.h"
#include "brave/components/reverse_engineering_browser/common/native_console_document_start.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"

namespace content {
class RenderFrameHost;
}  // namespace content

namespace reb {

class NativeConsoleDocumentStartHost;

// Browser UI thread only. Owns the armed document-start script set for the
// console session, pushes it to every renderer process, and keeps the output
// of page-JavaScript observations those scripts reported until a reader has
// had it.
//
// The set is session state, not document state: it is never pinned to a
// selected document, and ending the session clears it.
class NativeConsoleDocumentStartRegistry final {
 public:
  static NativeConsoleDocumentStartRegistry& Get();

  NativeConsoleDocumentStartRegistry(const NativeConsoleDocumentStartRegistry&) = delete;
  NativeConsoleDocumentStartRegistry& operator=(const NativeConsoleDocumentStartRegistry&) = delete;

  // True only when this browser session was launched with the experiment
  // switch. The switch alone arms nothing; without it arming fails closed.
  [[nodiscard]] static bool IsPermitted();

  void BindHost(int render_process_id,
                mojo::PendingReceiver<mojom::NativeConsoleScriptHost> receiver);
  // The renderer completed its side of the connection, so a process that
  // launched after arming can receive the current set immediately.
  void BindHostReady(NativeConsoleDocumentStartHost* host);
  void RemoveHost(NativeConsoleDocumentStartHost* host);

  // Each change is atomic: it applies whole, or is refused and leaves the set
  // and its output exactly as they were. `scripts` is the researcher-supplied
  // declaration; every field is revalidated here and script identities are
  // assigned here, in increasing order, and never reused.
  //
  // Replaces the whole set and drops the previous set's output.
  [[nodiscard]] bool Arm(const base::ListValue& scripts, std::string& error);
  // Adds scripts beside the armed ones, which keep running, reporting and
  // their output.
  [[nodiscard]] bool Add(const base::ListValue& scripts, std::string& error);
  // Removes the named armed scripts and stops any of their injections still
  // running. Their records stay in the output, under their ids.
  [[nodiscard]] bool Remove(const base::ListValue& script_ids, std::string& error);
  // Removes every script and its output. Retained `report` functions in a page
  // become inert as soon as each renderer applies the empty set.
  void Clear();

  // Registry, counters and a non-draining output page after `after`: at least
  // one record when any follows the cursor, then whole records up to a page,
  // and whether more follow.
  [[nodiscard]] base::DictValue State(std::uint64_t after) const;

  // `owner` is the eligible document the sending process named, or null when
  // the record did not resolve to one.
  void Observe(content::RenderFrameHost* owner,
               std::uint64_t script_id,
               std::uint64_t frame_id,
               std::uint32_t record,
               const std::string& text);

 private:
  friend class base::NoDestructor<NativeConsoleDocumentStartRegistry>;
  NativeConsoleDocumentStartRegistry();
  ~NativeConsoleDocumentStartRegistry();

  // The source itself lives only in `set_`; the browser keeps what State
  // reports about it.
  struct Armed {
    std::uint64_t script_id = 0;
    std::uint16_t frame_flags = 0;
    std::string origin;
    std::string path;
    std::size_t source_bytes = 0;
    std::uint64_t digest = 0;
    std::uint32_t records = 0;
    std::uint32_t injected_documents = 0;
    std::uint32_t refused = 0;
  };

  // A compact record, so retention is bounded by reported text rather than by
  // the size of a dictionary per record.
  struct Output {
    std::uint64_t sequence = 0;
    std::uint64_t script_id = 0;
    std::uint64_t document_id = 0;
    std::uint64_t frame_id = 0;
    double time = 0;
    std::uint32_t record = 0;
    bool top_frame = false;
    std::string text;
  };

  // Validates `scripts` and assigns them ids from next_script_id_. The views
  // point into `scripts`.
  [[nodiscard]] bool Parse(const base::ListValue& scripts,
                           std::vector<Armed>& armed,
                           std::vector<NativeConsoleDocumentStartScript>& views,
                           std::string& error) const;
  // Views of the armed scripts, sources included, into `mapping`.
  [[nodiscard]] bool Current(base::ReadOnlySharedMemoryMapping& mapping,
                             std::vector<NativeConsoleDocumentStartScript>& views) const;
  // Encodes `views` as the next set and pushes it to every renderer, or
  // changes nothing and returns false.
  [[nodiscard]] bool Install(std::vector<Armed> scripts,
                             std::span<const NativeConsoleDocumentStartScript> views,
                             std::string& error);
  // Stops injections still running anywhere that `stop_id` names
  // (NativeConsoleStopNames).
  void StopRunning(std::uint64_t stop_id);
  void ClearOutput();
  void Push();

  std::vector<std::unique_ptr<NativeConsoleDocumentStartHost>> hosts_;
  std::vector<Armed> scripts_;
  // The encoded set every renderer maps read-only. Invalid while none is armed.
  base::ReadOnlySharedMemoryRegion set_;
  std::deque<Output> output_;
  std::size_t retained_bytes_ = 0;
  std::uint64_t generation_ = 0;
  std::uint64_t next_script_id_ = 1;
  std::uint64_t next_sequence_ = 1;
  std::uint32_t dropped_ = 0;
  std::uint32_t unattributed_ = 0;
  std::uint32_t stale_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_DOCUMENT_START_H_
