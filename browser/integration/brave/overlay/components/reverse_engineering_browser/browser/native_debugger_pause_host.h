// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_DEBUGGER_PAUSE_HOST_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_DEBUGGER_PAUSE_HOST_H_

namespace reb {

// The pausing debugger's command socket, protocol/native-debugger-pause-v1.md.
// Enabled only by --reb-native-debugger=<socket path>; without it nothing is
// created and nothing listens. Called on the browser UI thread before the
// first renderer launches.
[[nodiscard]] bool IsNativeDebuggerPauseEnabled();
void StartNativeDebuggerPauseHost();

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_DEBUGGER_PAUSE_HOST_H_
