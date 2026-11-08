// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CAPTURE_SCOPE_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CAPTURE_SCOPE_H_

#include "brave/components/reverse_engineering_browser/common/native_network_scope.h"
#include "content/public/browser/child_process_security_policy.h"

namespace reb {

inline constexpr char kNativeCaptureBrowserInternalSwitch[] = "reb-capture-browser-internal";
inline constexpr char kNativeCaptureExtensionTrafficSwitch[] = "reb-capture-extension-traffic";

// WebUI bindings, or a process lock to a browser-internal scheme (Chromium patch 0035).
[[nodiscard]] inline bool IsNativeBrowserInternalProcess(const int child_id) {
  auto* const policy = content::ChildProcessSecurityPolicy::GetInstance();
  return policy->HasWebUIBindings(child_id) ||
         IsBrowserInternalSchemeClass(ClassifyNativeScheme(policy->GetProcessLockScheme(child_id)));
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_CAPTURE_SCOPE_H_
