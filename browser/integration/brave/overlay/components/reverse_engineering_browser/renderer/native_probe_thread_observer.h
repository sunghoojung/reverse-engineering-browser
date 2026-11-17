// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_THREAD_OBSERVER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_THREAD_OBSERVER_H_

namespace content {
class RenderThread;
}  // namespace content

namespace reb {

// Registers the capture client on this renderer's IPC channel. The browser
// requests it when it launches the process and configures capture there, so
// the configuration is dispatched before any navigation commit the browser
// sends later on the same channel. Call once from RenderThreadStarted, before
// the renderer dispatches channel messages.
void RegisterNativeProbeClient(content::RenderThread& thread);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_PROBE_THREAD_OBSERVER_H_
