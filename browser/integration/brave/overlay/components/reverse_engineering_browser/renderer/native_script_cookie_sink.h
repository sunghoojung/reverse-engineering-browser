// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SCRIPT_COOKIE_SINK_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SCRIPT_COOKIE_SINK_H_

#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "base/component_export.h"
#include "base/no_destructor.h"
#include "base/synchronization/lock.h"
#include "brave/components/reverse_engineering_browser/common/native_network_cookies.h"

namespace reb {

inline constexpr std::size_t kNativeScriptCookieReadKeys = 256;

// The frame identity every renderer record carries, from a LocalFrameToken.
[[nodiscard]] constexpr std::uint64_t NativeFrameIdOf(const std::uint64_t token_high,
                                                      const std::uint64_t token_low) noexcept {
  return std::rotl(token_high, 17) ^ token_low;
}

// document.cookie and Cookie Store API calls ("Script cookie access" in
// protocol/native-network-v3.md). Enabled only for a content-capture session;
// Blink checks IsEnabled, one atomic load, before converting any string.
class COMPONENT_EXPORT(REB_NATIVE_PROBE_SINK) NativeScriptCookieSink final {
 public:
  // The innermost script frame of the calling thread, or false.
  using FrameProvider = bool (*)(NativeScriptFrame& frame) noexcept;

  static NativeScriptCookieSink& Get();

  NativeScriptCookieSink(const NativeScriptCookieSink&) = delete;
  NativeScriptCookieSink& operator=(const NativeScriptCookieSink&) = delete;

  // Transport sequence, after NativeProbeSink::SetEmitters: binds the content
  // gate to that configuration.
  void Configure(bool capture_content, FrameProvider provider) noexcept;
  // Transport sequence, before the configuration's emitters change: records
  // each read key's remainder into it, then disables.
  void Flush() noexcept;
  [[nodiscard]] bool IsEnabled() const noexcept {
    return generation_.load(std::memory_order_acquire) != 0;
  }

  void RecordDocumentCookieSet(std::string_view cookie_string, std::uint64_t frame_id) noexcept;
  void RecordDocumentCookieGet(std::size_t string_length, std::uint64_t frame_id) noexcept;
  // The calling frame is recorded.
  void RecordCookieStore(NativeScriptCookieApi api,
                         std::string_view name,
                         std::string_view value) noexcept;

 private:
  friend class base::NoDestructor<NativeScriptCookieSink>;
  NativeScriptCookieSink() noexcept;

  struct ReadKey final {
    std::uint64_t frame_id = 0;
    NativeScriptFrame frame;
    std::uint32_t name_length = 0;
    std::array<std::uint8_t, kNativeScriptCookieNamePrefixBytes> name_prefix{};
    NativeScriptCookieApi api = NativeScriptCookieApi::kDocumentCookieGet;
    friend bool operator==(const ReadKey&, const ReadKey&) = default;
  };
  struct ReadEntry final {
    ReadKey key;
    std::uint32_t string_length = 0;
    std::uint32_t reads = 0;
    std::uint32_t unreported = 0;
  };

  [[nodiscard]] NativeScriptCookieSummary Summary(NativeScriptCookieApi api,
                                                  std::string_view name) const noexcept;
  void Record(NativeScriptCookieSummary summary,
              std::uint64_t frame_id,
              std::string_view value) noexcept;
  void RecordRead(NativeScriptCookieSummary summary, std::uint64_t frame_id) noexcept;
  [[nodiscard]] static std::uint64_t CallingFrameId() noexcept;
  bool Emit(const NativeScriptCookieSummary& summary,
            std::uint64_t frame_id,
            std::uint64_t generation,
            std::uint64_t sequence = 0) noexcept;

  // The NativeProbeSink generation the gate belongs to, or 0 when disabled.
  std::atomic<std::uint64_t> generation_{0};
  std::atomic<FrameProvider> provider_{nullptr};
  // Read aggregation of the current configuration. Blink calls arrive from
  // the main thread and service workers.
  base::Lock reads_lock_;
  std::array<ReadEntry, kNativeScriptCookieReadKeys> reads_{};
  std::size_t read_keys_ = 0;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SCRIPT_COOKIE_SINK_H_
