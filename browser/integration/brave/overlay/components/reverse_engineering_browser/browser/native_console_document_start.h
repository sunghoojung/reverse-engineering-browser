// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_DOCUMENT_START_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_DOCUMENT_START_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
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
// console session, pushes it to every renderer process, and keeps the
// byte-bounded output of page-JavaScript observations those scripts reported.
//
// The set is session state, not document state: it is never pinned to a
// selected document, and ending or expiring the session clears it.
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

  // Replaces the whole set atomically, or refuses it entirely and leaves the
  // previous set untouched. `scripts` is the researcher-supplied declaration;
  // every field is revalidated here and script identities are assigned here.
  [[nodiscard]] bool Arm(const base::ListValue& scripts, std::string& error);
  // Removes every script and its output. Retained `report` functions in a page
  // become inert as soon as each renderer applies the empty set.
  void Clear();

  // Registry, counters and a non-draining output page after `after`: every
  // retained record that fits one reply.
  [[nodiscard]] base::DictValue State(std::uint64_t after) const;

  // `owner` is the eligible document the sending process named, or null when
  // the record did not resolve to one.
  void Observe(content::RenderFrameHost* owner,
               std::uint64_t generation,
               std::uint64_t script_id,
               std::uint64_t frame_id,
               std::uint32_t record,
               bool truncated,
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
    bool truncated = false;
    std::string text;
  };

  // Stops an injection of the current set that is still running anywhere,
  // before the set is replaced or cleared.
  void StopRunning();
  void Push();

  std::vector<std::unique_ptr<NativeConsoleDocumentStartHost>> hosts_;
  std::vector<Armed> scripts_;
  // The encoded set every renderer maps read-only. Invalid while none is armed.
  base::ReadOnlySharedMemoryRegion set_;
  std::size_t listing_bytes_ = 0;
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
