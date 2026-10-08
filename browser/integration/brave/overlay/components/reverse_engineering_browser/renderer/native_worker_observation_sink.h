// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_OBSERVATION_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_OBSERVATION_SINK_H_

#include "base/component_export.h"
#include "brave/components/reverse_engineering_browser/common/native_worker_observation.h"

namespace reb {

// Dormant: deliberately no production Configure or drain API until browser
// authorization, bounded acknowledged transport and publication are implemented.
COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK)
bool IsNativeWorkerObservationEnabled() noexcept;
COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK)
NativeWorkerCaptureStatus ObserveNativeWorker(
    NativeWorkerToken worker,
    NativeWorkerToken creator,
    NativeWorkerCreatorKind creator_kind,
    const NativeWorkerObservationInput& input,
    std::uint64_t now_ns,
    NativeWorkerMessageTag* accepted_tag = nullptr) noexcept;

}  // namespace reb
#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_WORKER_OBSERVATION_SINK_H_
