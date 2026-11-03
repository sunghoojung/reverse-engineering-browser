// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DOCUMENT_START_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DOCUMENT_START_H_

#include "brave/components/reverse_engineering_browser/common/native_console.mojom.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "v8/include/v8-forward.h"

namespace content {
class RenderFrame;
}

namespace reb {

// True in a renderer process whose browser session permits the experiment. A
// browser that never passes the switch never builds any of this state.
[[nodiscard]] bool IsNativeConsoleDocumentStartPermitted();

// Connects this renderer process to the browser-owned document-start script
// registry. Called once from RenderThreadStarted.
void ConnectNativeConsoleDocumentStart(mojo::PendingRemote<mojom::NativeConsoleScriptHost> host);

// Runs every armed script whose rule matches this document, in the page main
// world, at main-world script-context creation. Blink creates that context
// before any script can run in it, so a snippet observes the document before
// its own scripts, including inline scripts.
//
// Renderer main thread only. While no set is armed this is one bool load and a
// return: it allocates nothing, touches no V8 handle, and does no matching.
void InjectNativeConsoleDocumentStart(content::RenderFrame* frame, v8::Local<v8::Context> context);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DOCUMENT_START_H_
