// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_SESSION_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_SESSION_H_

#include <cstdint>

#include "base/functional/callback.h"

namespace content {
class RenderFrameHost;
}

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

// True for an active HTTP(S) document in the Console's own bound profile. The
// document-start registry admits an observation only for such a document.
[[nodiscard]] bool IsNativeConsoleDocument(content::RenderFrameHost* frame);
// Monotonic nonsecret document identity shared with the Console target listing,
// so a target and a document-start record name the same document by the same
// ID. The renderer's document token is never published. Bounded; returns 0 when
// the frame is not an eligible Console document.
[[nodiscard]] std::uint64_t NativeConsoleDocumentId(content::RenderFrameHost* frame);
// The same identity, looked up without assigning one: 0 when this document
// has no ID yet. A walk that only wants to find the document behind an ID a
// client already holds uses this, so it does not label every document it
// passes or recycle the oldest entry of the bounded table.
[[nodiscard]] std::uint64_t NativeConsoleDocumentIdIfAssigned(content::RenderFrameHost* frame);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CONSOLE_SESSION_H_
