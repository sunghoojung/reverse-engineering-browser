// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-in for Chromium's base/memory/raw_ptr_exclusion.h, used only
// by the native overlay harnesses under tools/. Never part of a browser build.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_PTR_EXCLUSION_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_PTR_EXCLUSION_H_

// The Chromium macro only annotates fields for its clang plugin.
#define RAW_PTR_EXCLUSION

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_PTR_EXCLUSION_H_
