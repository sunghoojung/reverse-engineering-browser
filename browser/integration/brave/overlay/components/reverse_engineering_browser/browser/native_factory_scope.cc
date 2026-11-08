// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/browser/native_factory_scope.h"

#include "base/command_line.h"
#include "brave/components/reverse_engineering_browser/browser/native_capture_scope.h"
#include "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h"
#include "brave/components/reverse_engineering_browser/browser/native_tab_registry.h"
#include "url/origin.h"

namespace reb {

NativeFactoryScope NativeFactoryScopeOf(content::BrowserContext* context,
                                        content::RenderFrameHost* frame,
                                        const int render_process_id,
                                        const int factory_type,
                                        const url::Origin& initiator) {
  if (!NativeNetworkCaptureSink::Get().IsOwnedContext(context)) {
    return {};
  }
  const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  NativeFactoryScope scope = DecideNativeFactoryScope(
      factory_type, initiator.scheme(), initiator.host(),
      IsNativeBrowserInternalProcess(render_process_id),
      {.record_browser_internal = command_line.HasSwitch(kNativeCaptureBrowserInternalSwitch),
       .record_extensions = command_line.HasSwitch(kNativeCaptureExtensionTrafficSwitch)});
  // Observing before a session starts keeps the workers and frames that predate it.
  NativeTabRegistry& registry = NativeTabRegistry::Get();
  registry.ObserveContext(context);
  if (scope.exclusion == 0 && !scope.owner.extension) {
    const NativeFactoryOwnerTab owner = registry.NoteFactory(frame);
    scope.tab_id = owner.tab;
    scope.owner.service_worker_version = owner.service_worker_version;
  }
  return scope;
}

}  // namespace reb
