// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef REB_TOOLS_NATIVE_TEST_SUPPORT_ONCE_CALLBACK_STUB_H_
#define REB_TOOLS_NATIVE_TEST_SUPPORT_ONCE_CALLBACK_STUB_H_

#include <memory>
#include <type_traits>
#include <utility>

namespace base {
// Move-only, like the pinned OnceCallback, so bound streams and contexts fit.
template <class Signature>
class OnceCallback;
template <class R, class... Args>
class OnceCallback<R(Args...)> {
 public:
  OnceCallback() = default;
  template <class F,
            class = std::enable_if_t<!std::is_same_v<std::decay_t<F>, OnceCallback> &&
                                     std::is_invocable_r_v<R, F&, Args...>>>
  OnceCallback(F function) : impl_(std::make_unique<Impl<F>>(std::move(function))) {}
  R Run(Args... args) && {
    auto impl = std::move(impl_);
    return impl->Call(std::forward<Args>(args)...);
  }
  explicit operator bool() const { return impl_ != nullptr; }

 private:
  struct Base {
    virtual ~Base() = default;
    virtual R Call(Args... args) = 0;
  };
  template <class F>
  struct Impl final : Base {
    explicit Impl(F value) : function(std::move(value)) {}
    R Call(Args... args) override {
      if constexpr (std::is_void_v<R>) {
        function(std::forward<Args>(args)...);
      } else {
        return function(std::forward<Args>(args)...);
      }
    }
    F function;
  };
  std::unique_ptr<Base> impl_;
};
}  // namespace base

#endif  // REB_TOOLS_NATIVE_TEST_SUPPORT_ONCE_CALLBACK_STUB_H_
