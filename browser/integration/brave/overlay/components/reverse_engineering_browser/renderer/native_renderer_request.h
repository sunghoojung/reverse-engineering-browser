// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_RENDERER_REQUEST_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_RENDERER_REQUEST_H_

#include <cstdint>

#include "brave/components/reverse_engineering_browser/common/native_network_scope.h"
#include "brave/components/reverse_engineering_browser/common/native_probe_event.h"

namespace reb {

// Held by the Blink loader for one recorded request_initiated, so a request
// the browser proxy never sees can still finish. A default value means the
// request was not recorded; every method is then a field read.
struct NativeRendererRequest final {
  std::uint64_t generation = 0;
  std::uint64_t session_id = 0;
  std::uint64_t initiated_sequence = 0;
  std::uint64_t initiated_time_ns = 0;
  std::uint64_t frame_id = 0;
  std::uint32_t thread_id = 0;
  std::uint32_t request_id = 0;
  std::int32_t status_code = 0;
  std::uint16_t flags = 0;
  NativeSchemeClass scheme_class = NativeSchemeClass::kNotRecorded;

  [[nodiscard]] constexpr bool recorded() const noexcept { return generation != 0; }

  constexpr void NoteResponse(const int response_status,
                              const bool from_service_worker,
                              const bool from_cache) noexcept {
    if (!recorded())
      return;
    status_code = response_status;
    if (from_service_worker)
      flags |= static_cast<std::uint16_t>(NativeProbeFlag::kFromServiceWorker);
    if (from_cache)
      flags |= static_cast<std::uint16_t>(NativeProbeFlag::kFromCache);
  }

  // data:, blob: and other local schemes, and responses a service worker
  // supplied, never reach the browser proxy that finishes proxied requests.
  [[nodiscard]] constexpr bool AnsweredInRenderer() const noexcept {
    return recorded() &&
           (!IsProxiedSchemeClass(scheme_class) ||
            (flags & static_cast<std::uint16_t>(NativeProbeFlag::kFromServiceWorker)) != 0);
  }
};

// Whether content::ServiceWorkerSubresourceLoader ends a request itself, so the
// renderer finishes it (protocol/native-network-v3.md): it sent no response (a
// sent one carries from_service_worker, and the loader's client finishes that
// row), it has not ended the request already, and no race network request it
// started answered the page (the browser proxy recorded that answer).
[[nodiscard]] constexpr bool NativeServiceWorkerEndsRequest(const bool response_sent,
                                                            const bool completed,
                                                            const bool network_answered) noexcept {
  return !response_sent && !completed && !network_answered;
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_RENDERER_REQUEST_H_
