// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-in for the pinned url/url_constants.h limit the network sink
// asserts against. Used only by the overlay harnesses under tools/.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_URL_URL_CONSTANTS_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_URL_URL_CONSTANTS_H_

#include <cstddef>

namespace url {
inline constexpr std::size_t kMaxURLChars = 2 * 1024 * 1024;
}  // namespace url

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_URL_URL_CONSTANTS_H_
