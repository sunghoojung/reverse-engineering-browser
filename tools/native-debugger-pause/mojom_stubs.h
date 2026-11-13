// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// What `native_debugger_pause.mojom` generates, by hand, so the overlay's
// implementations of these interfaces are checked against the declarations
// the generator would produce: one pure virtual per method, a reply callback
// typedef for each method that has one, and the interface name the registry
// keys on. Kept beside the .mojom; a method added there without a line here
// fails to compile in this harness.
#ifndef REB_TOOLS_NATIVE_DEBUGGER_PAUSE_MOJOM_STUBS_H_
#define REB_TOOLS_NATIVE_DEBUGGER_PAUSE_MOJOM_STUBS_H_

#include <cstdint>
#include <string>

#include "chromium_stubs.h"

namespace reb::mojom {

class NativeDebuggerPauseAgent {
 public:
  static const char Name_[];
  using CommandCallback = base::OnceCallback<void(std::uint16_t, bool, bool, const std::string&)>;
  virtual ~NativeDebuggerPauseAgent() = default;
  virtual void Command(const base::UnguessableToken& document,
                       std::uint16_t operation,
                       std::uint64_t lease_id,
                       std::uint64_t expires_at_monotonic_us,
                       const std::string& command,
                       CommandCallback callback) = 0;
};

class NativeDebuggerPauseObserver {
 public:
  static const char Name_[];
  virtual ~NativeDebuggerPauseObserver() = default;
  virtual void Paused(std::uint64_t lease_id,
                      std::uint8_t reason,
                      std::uint64_t breakpoint_id,
                      std::uint32_t frames_recorded,
                      std::uint32_t async_frames,
                      bool frames_truncated) = 0;
  virtual void Resumed(std::uint64_t lease_id, std::uint8_t end, std::uint32_t paused_ms) = 0;
  virtual void Cleared(std::uint8_t reason, std::uint32_t breakpoints_dropped) = 0;
};

class NativeDebuggerPauseBroker {
 public:
  static const char Name_[];
  virtual ~NativeDebuggerPauseBroker() = default;
  virtual void Attach(mojo::PendingReceiver<NativeDebuggerPauseAgent> agent,
                      mojo::PendingRemote<NativeDebuggerPauseObserver> observer,
                      std::uint64_t target_id) = 0;
};

}  // namespace reb::mojom

#endif  // REB_TOOLS_NATIVE_DEBUGGER_PAUSE_MOJOM_STUBS_H_
