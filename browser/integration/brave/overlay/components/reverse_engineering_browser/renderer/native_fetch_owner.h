// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_FETCH_OWNER_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_FETCH_OWNER_H_

#include <cstdint>

#include "base/component_export.h"
#include "brave/components/reverse_engineering_browser/common/native_tab_link.h"

namespace reb {

// The document or worker whose FetchContext started a fetch, as opposed to
// the script running when it started (protocol/native-network-v3.md).
struct NativeFetchOwner final {
  NativeLoaderKind kind = NativeLoaderKind::kNotRecorded;
  std::uint64_t context_id = 0;
};

// Names the owner for request_initiated records made on this thread while it
// lives. Blink's loaders set it around ResourceRequestSender::SendAsync. A
// default owner leaves the thread untouched.
class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeFetchOwnerScope final {
 public:
  explicit NativeFetchOwnerScope(const NativeFetchOwner& owner) noexcept;
  NativeFetchOwnerScope(const NativeFetchOwnerScope&) = delete;
  NativeFetchOwnerScope& operator=(const NativeFetchOwnerScope&) = delete;
  ~NativeFetchOwnerScope();

  [[nodiscard]] static NativeFetchOwner Current() noexcept;

 private:
  NativeFetchOwner previous_;
  bool active_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_FETCH_OWNER_H_
