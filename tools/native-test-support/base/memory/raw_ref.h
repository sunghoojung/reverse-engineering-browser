// Copyright 2026 The Reverse Engineering Browser Authors
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Portable stand-in for Chromium's base/memory/raw_ref.h, used only by the
// native overlay harnesses under tools/. Never part of a browser build.
#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_REF_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_REF_H_

template <class T>
class raw_ref {
 public:
  constexpr explicit raw_ref(T& value) noexcept : pointer_(&value) {}

  constexpr T& operator*() const noexcept { return *pointer_; }
  constexpr T* operator->() const noexcept { return pointer_; }
  constexpr T& get() const noexcept { return *pointer_; }

 private:
  T* pointer_;
};

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_BASE_MEMORY_RAW_REF_H_
