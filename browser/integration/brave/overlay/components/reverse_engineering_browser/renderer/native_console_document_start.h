// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DOCUMENT_START_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DOCUMENT_START_H_

#include "base/unguessable_token.h"
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

// Per-frame bookkeeping, owned by the frame's console agent. Blink reuses the
// initial empty document's window for a same-origin commit and keeps a
// main-world context that already exists, so context creation alone does not
// see every document.
struct NativeConsoleDocumentStartFrame final {
  // A main-world context exists for the frame's current window.
  bool context = false;
  // The document whose match was decided in that context. Empty when the
  // context was created while nothing was armed.
  base::UnguessableToken document;
};

// Runs every armed script whose rule matches this document, in the page main
// world, at main-world script-context creation. Blink creates that context
// before any script can run in it, so a snippet observes the document before
// its own scripts, including inline scripts.
//
// Renderer main thread only. While no set is armed this is one bool load and
// two plain stores: it allocates nothing, touches no V8 handle, and does no
// matching.
void InjectNativeConsoleDocumentStart(content::RenderFrame* frame,
                                      v8::Local<v8::Context> context,
                                      NativeConsoleDocumentStartFrame& state);

// Blink cleared the window object for a newly committed document, before its
// parser runs any of its scripts. When the commit kept an existing main-world
// context, no context is created for this document, so it is matched and
// injected here instead. A document already decided at context creation is
// never injected twice, and no context is ever created here.
void InjectNativeConsoleDocumentStartIntoReusedWindow(content::RenderFrame* frame,
                                                      NativeConsoleDocumentStartFrame& state);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_CONSOLE_DOCUMENT_START_H_
