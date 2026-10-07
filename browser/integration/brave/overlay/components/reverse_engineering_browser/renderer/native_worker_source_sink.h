// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_SOURCE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_SOURCE_SINK_H_

#include "base/component_export.h"
#include "brave/components/reverse_engineering_browser/common/native_worker_source.h"

namespace reb {

// There is intentionally no production Configure caller until browser-owned
// exact-worker authorization, bounded transport, and native parity are proved.
COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK)
bool IsNativeWorkerSourceCaptureEnabled() noexcept;
COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK)
NativeWorkerCaptureStatus BeginNativeWorkerSourceCapture(
    NativeWorkerToken worker,
    std::uint64_t now_ns,
    NativeWorkerCaptureTicket& ticket) noexcept;
COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK)
NativeWorkerCaptureStatus CaptureNativeWorkerSource(const NativeWorkerCaptureTicket& ticket,
                                                    NativeWorkerToken parent_context,
                                                    NativeWorkerSourceKind kind,
                                                    NativeWorkerText source,
                                                    NativeWorkerText url,
                                                    std::uint64_t now_ns) noexcept;
COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK)
void RetireNativeWorkerSource(NativeWorkerToken worker) noexcept;

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_SOURCE_SINK_H_
