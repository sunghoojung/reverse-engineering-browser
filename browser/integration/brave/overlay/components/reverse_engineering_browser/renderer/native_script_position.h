// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SCRIPT_POSITION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SCRIPT_POSITION_H_

#include "brave/components/reverse_engineering_browser/common/native_network_cookies.h"

namespace reb {

// The innermost JavaScript or Wasm frame of the current isolate, from one
// v8::StackTrace frame: script ID and character position. Function start is
// not public V8 API and stays 0. False without an entered context or script.
bool CurrentNativeScriptFrame(NativeScriptFrame& frame) noexcept;

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SCRIPT_POSITION_H_
