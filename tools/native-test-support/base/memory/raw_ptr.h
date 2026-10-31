// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-in for Chromium's base/memory/raw_ptr.h, used only by the
// native overlay harnesses under tools/. Never part of a browser build.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_PTR_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_PTR_H_

template <class T>
using raw_ptr = T*;

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_PTR_H_
