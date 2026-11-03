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

#include "base/no_destructor.h"
#include "base/unguessable_token.h"
#include "base/values.h"
#include "brave/components/reverse_engineering_browser/common/native_console.mojom.h"
#include "brave/components/reverse_engineering_browser/common/native_console_document_start.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"

namespace reb {

class NativeConsoleDocumentStartHost;

// Browser UI thread only. Owns the armed document-start script set for the
// console session, pushes it to every renderer process, and keeps the bounded
// ring of page-JavaScript observations those scripts reported.
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

  // Registry, counters and a bounded non-draining output page after `after`.
  [[nodiscard]] base::DictValue State(std::uint64_t after) const;

  void Observe(int render_process_id,
               std::uint64_t generation,
               std::uint64_t script_id,
               std::uint64_t frame_id,
               const base::UnguessableToken& document,
               std::uint32_t record,
               bool truncated,
               const std::string& text);

 private:
  friend class base::NoDestructor<NativeConsoleDocumentStartRegistry>;
  NativeConsoleDocumentStartRegistry();
  ~NativeConsoleDocumentStartRegistry();

  struct Armed {
    NativeConsoleDocumentStartScript script;
    std::uint32_t records = 0;
    std::uint32_t injected_documents = 0;
    std::uint32_t refused = 0;
  };

  [[nodiscard]] std::size_t Encode(std::span<std::uint8_t> out) const;
  void Push();

  std::vector<std::unique_ptr<NativeConsoleDocumentStartHost>> hosts_;
  std::vector<Armed> scripts_;
  std::deque<base::DictValue> output_;
  std::uint64_t generation_ = 0;
  std::uint64_t next_script_id_ = 1;
  std::uint64_t next_sequence_ = 1;
  std::uint32_t dropped_ = 0;
  std::uint32_t unattributed_ = 0;
  std::uint32_t stale_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_DOCUMENT_START_H_
