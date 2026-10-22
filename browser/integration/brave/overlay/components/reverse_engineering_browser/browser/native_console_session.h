// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_SESSION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_SESSION_H_

#include "base/functional/callback.h"

namespace reb {

// Disabled unless the launcher provides every required flag. A disposable
// profile still rejects remote debugging. An explicit live-capture binding
// may share the browser the capture is already using.
// Called on the browser UI thread before renderer launch.
[[nodiscard]] bool IsNativeConsoleEnabled();
// A live-capture binding returns a no-op. A disposable session returns a null
// closure so the Chrome browser client can exit that browser.
[[nodiscard]] base::OnceClosure NativeConsoleRetireCallback();
void StartNativeConsoleSession(base::OnceClosure retired);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_SESSION_H_
