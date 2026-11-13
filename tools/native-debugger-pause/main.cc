// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// The pausing debugger overlay compiled on the host against stand-in
// declarations of the pinned types. Compilation is the check: three rounds of
// review each found code here that a compiler would have refused, and no
// machine in this project can build Brave. Nothing runs: the stand-ins
// declare without defining, so this binary only has to link the overlay's
// own symbols and is never executed.
#include <iostream>

#include "brave/components/reverse_engineering_browser/browser/native_debugger_pause_host.h"
#include "brave/components/reverse_engineering_browser/common/native_debugger_pause.h"
#include "brave/components/reverse_engineering_browser/renderer/native_debugger_pause_agent.h"
#include "brave/components/reverse_engineering_browser/renderer/native_debugger_pause_session.h"

namespace {

// The wire header's own rules, which need no stand-in at all.
void CheckWireRules() {
  static_assert(reb::NativeDebuggerPauseOperation::kMaximum ==
                reb::NativeDebuggerPauseOperation::kGetProperties);
  static_assert(!reb::NativeDebuggerPauseRunsScript(reb::NativeDebuggerPauseOperation::kResume));
  static_assert(
      reb::NativeDebuggerPauseRunsScript(reb::NativeDebuggerPauseOperation::kEvaluateOnFrame));
  static_assert(reb::NativeDebuggerPauseNeedsLease(reb::NativeDebuggerPauseOperation::kStepOver));
  static_assert(reb::NativeDebuggerPauseNeedsConfirmation(
      reb::NativeDebuggerPauseOperation::kSelectDocument));
}

}  // namespace

int main() {
  CheckWireRules();
  std::cout << "PASS native debugger pause overlay compiles against the pinned "
               "declarations (compile-only; no Chromium available)\n";
  return 0;
}
