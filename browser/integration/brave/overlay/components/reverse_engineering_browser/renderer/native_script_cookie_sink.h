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
#include <memory>
#include <string_view>

#include "base/component_export.h"
#include "base/no_destructor.h"
#include "base/synchronization/lock.h"
#include "brave/components/reverse_engineering_browser/common/native_network_cookies.h"

namespace reb {

// Read keys per configuration: a key is a frame, thread, API, script position
// and cookie name, so one script reading a jar of 100 cookies uses 101. The
// table is allocated only for a content-capture configuration.
inline constexpr std::size_t kNativeScriptCookieReadKeys = 4096;
// The most cookies one document.cookie read returns at the pinned Chromium:
// 180 per eTLD+1 (CookieMonster::kDomainMaxCookies) and 180 partitioned ones
// (kPerPartitionDomainMaxCookies). Names past it are counted, not recorded.
inline constexpr std::size_t kNativeScriptCookieReadNames = 360;

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
  // gate to that configuration and, when it is on, allocates the read table.
  void Configure(bool capture_content, FrameProvider provider) noexcept;
  // Transport sequence, before the configuration's emitters change: records
  // each read key's remainder into it, then disables and frees the table.
  void Flush() noexcept;
  [[nodiscard]] bool IsEnabled() const noexcept {
    return generation_.load(std::memory_order_acquire) != 0;
  }

  void RecordDocumentCookieSet(std::string_view cookie_string, std::uint64_t frame_id) noexcept;
  // The string document.cookie returned: the read and each cookie name in it.
  void RecordDocumentCookieGet(std::string_view cookie_string, std::uint64_t frame_id) noexcept;
  // The calling frame is recorded.
  void RecordCookieStore(NativeScriptCookieApi api,
                         std::string_view name,
                         std::string_view value) noexcept;

 private:
  friend class base::NoDestructor<NativeScriptCookieSink>;
  NativeScriptCookieSink() noexcept;

  struct ReadKey final {
    std::uint64_t frame_id = 0;
    std::uint8_t thread = 0;
    NativeScriptCookieApi api = NativeScriptCookieApi::kDocumentCookieGet;
    // The document.cookie read itself rather than one cookie name it returned.
    bool read_record = false;
    NativeScriptFrame frame;
    std::uint32_t name_length = 0;
    std::array<std::uint8_t, kNativeScriptCookieNamePrefixBytes> name_prefix{};
    friend bool operator==(const ReadKey&, const ReadKey&) = default;
  };
  struct ReadEntry final {
    ReadKey key;
    std::uint32_t string_length = 0;
    std::uint32_t reads = 0;
    std::uint32_t unreported = 0;
    // A read record's names no name record counted since its last record.
    std::uint32_t unrecorded_names = 0;
    // The document.cookie read that last counted this key, so a name the
    // jar returns twice (other path or domain) counts once per read.
    std::uint64_t last_read = 0;
  };
  // Open addressing at most half full: a lookup is a hash and a few probes.
  static constexpr std::size_t kReadSlots = 2 * kNativeScriptCookieReadKeys;
  struct ReadTable final {
    std::array<ReadEntry, kNativeScriptCookieReadKeys> entries{};
    // Entry index + 1, or 0 for an empty slot.
    std::array<std::uint16_t, kReadSlots> slots{};
    std::size_t used = 0;
    std::uint64_t reads = 0;
  };
  static_assert(kNativeScriptCookieReadKeys <= 0xffffU);

  [[nodiscard]] NativeScriptCookieSummary Summary(NativeScriptCookieApi api,
                                                  std::string_view name) const noexcept;
  void Record(NativeScriptCookieSummary summary,
              std::uint64_t frame_id,
              std::string_view value) noexcept;
  void RecordRead(NativeScriptCookieSummary summary, std::uint64_t frame_id) noexcept;
  // The entry of `key`, inserted when new; null when the table is full.
  // Called with reads_lock_ held.
  [[nodiscard]] ReadEntry* FindOrInsert(const ReadKey& key) noexcept;
  // Counts one read of `entry`; true when its count is due as a record.
  [[nodiscard]] static bool CountRead(ReadEntry& entry, std::uint32_t string_length) noexcept;
  // The frame a record names: a worker's context ID on a worker, else
  // `frame_id` when Blink passed one, else the calling document's.
  [[nodiscard]] static std::uint64_t CallingFrameId(std::uint64_t frame_id) noexcept;
  bool Emit(const NativeScriptCookieSummary& summary,
            std::uint64_t frame_id,
            std::uint64_t generation,
            std::uint64_t sequence = 0) noexcept;

  // The NativeProbeSink generation the gate belongs to, or 0 when disabled.
  std::atomic<std::uint64_t> generation_{0};
  std::atomic<FrameProvider> provider_{nullptr};
  // Read aggregation of the current configuration, null unless content
  // capture configured it. Blink calls arrive from the main thread and
  // service workers.
  base::Lock reads_lock_;
  std::unique_ptr<ReadTable> reads_;
};

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_RENDERER_NATIVE_SCRIPT_COOKIE_SINK_H_
