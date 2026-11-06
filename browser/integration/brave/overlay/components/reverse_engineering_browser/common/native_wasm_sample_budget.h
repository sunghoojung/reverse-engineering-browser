// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_SAMPLE_BUDGET_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_SAMPLE_BUDGET_H_

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

#include "brave/components/reverse_engineering_browser/common/native_wasm_dispatch.h"

namespace reb {

// The configuration still keeps at most 16 records per stream. A larger global
// cap would not help: one hot function would fill it. These controls stop a
// function, call site, or module from spending slots that belong to the rest
// of the configuration. Zero caps and empty lists are the historical behavior.
inline constexpr std::size_t kNativeWasmModuleAllowlistLimit = 8;
inline constexpr std::size_t kNativeWasmFunctionFilterLimit = 32;
inline constexpr std::uint32_t kNativeWasmFunctionIndexLimit = 16U * 1024U * 1024U;
inline constexpr std::size_t kNativeWasmBudgetKeySlots = kNativeWasmDispatchSampleBudget;
static_assert(kNativeWasmDispatchSampleBudget == kNativeWasmIndirectSampleBudget);

struct NativeWasmSampleBudgetPolicy final {
  std::uint32_t samples_per_function = 0;
  std::uint32_t samples_per_indirect_site = 0;
  std::uint8_t module_allow_count = 0;
  std::uint8_t function_allow_count = 0;
  std::uint8_t function_deny_count = 0;
  std::array<std::array<std::uint8_t, 32>, kNativeWasmModuleAllowlistLimit> module_allow{};
  std::array<std::uint32_t, kNativeWasmFunctionFilterLimit> function_allow{};
  std::array<std::uint32_t, kNativeWasmFunctionFilterLimit> function_deny{};
};
static_assert(std::is_trivially_copyable_v<NativeWasmSampleBudgetPolicy>);

inline constexpr std::size_t kNativeWasmSampleBudgetEncodedBytes =
    12 + kNativeWasmModuleAllowlistLimit * 32 + kNativeWasmFunctionFilterLimit * 4 * 2;
static_assert(kNativeWasmSampleBudgetEncodedBytes == 524);

[[nodiscard]] inline bool IsValidNativeWasmSampleBudgetPolicy(
    const NativeWasmSampleBudgetPolicy& policy) noexcept {
  if (policy.samples_per_function > kNativeWasmDispatchSampleBudget ||
      policy.samples_per_indirect_site > kNativeWasmIndirectSampleBudget ||
      policy.module_allow_count > kNativeWasmModuleAllowlistLimit ||
      policy.function_allow_count > kNativeWasmFunctionFilterLimit ||
      policy.function_deny_count > kNativeWasmFunctionFilterLimit)
    return false;
  for (std::uint8_t index = policy.module_allow_count; index < kNativeWasmModuleAllowlistLimit;
       ++index) {
    if (std::any_of(policy.module_allow[index].begin(), policy.module_allow[index].end(),
                    [](std::uint8_t byte) { return byte != 0; }))
      return false;
  }
  for (std::uint8_t index = 0; index < policy.module_allow_count; ++index) {
    for (std::uint8_t earlier = 0; earlier < index; ++earlier) {
      if (policy.module_allow[index] == policy.module_allow[earlier])
        return false;
    }
  }
  const auto functions_valid = [](std::span<const std::uint32_t> values, std::uint8_t count) {
    for (std::uint8_t index = 0; index < kNativeWasmFunctionFilterLimit; ++index) {
      if (index >= count) {
        if (values[index] != 0)
          return false;
        continue;
      }
      if (values[index] >= kNativeWasmFunctionIndexLimit)
        return false;
      for (std::uint8_t earlier = 0; earlier < index; ++earlier) {
        if (values[index] == values[earlier])
          return false;
      }
    }
    return true;
  };
  return functions_valid(policy.function_allow, policy.function_allow_count) &&
         functions_valid(policy.function_deny, policy.function_deny_count);
}

[[nodiscard]] inline std::array<std::uint8_t, kNativeWasmSampleBudgetEncodedBytes>
EncodeNativeWasmSampleBudgetPolicy(const NativeWasmSampleBudgetPolicy& policy) noexcept {
  std::array<std::uint8_t, kNativeWasmSampleBudgetEncodedBytes> out{};
  const auto put32 = [&out](std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index)
      out[offset + index] = static_cast<std::uint8_t>((value >> (8U * index)) & 255U);
  };
  put32(0, policy.samples_per_function);
  put32(4, policy.samples_per_indirect_site);
  out[8] = policy.module_allow_count;
  out[9] = policy.function_allow_count;
  out[10] = policy.function_deny_count;
  std::size_t offset = 12;
  for (const auto& digest : policy.module_allow) {
    std::copy(digest.begin(), digest.end(), out.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += digest.size();
  }
  for (const auto function : policy.function_allow)
    put32(offset, function), offset += 4;
  for (const auto function : policy.function_deny)
    put32(offset, function), offset += 4;
  return out;
}

[[nodiscard]] inline bool DecodeNativeWasmSampleBudgetPolicy(
    std::span<const std::uint8_t> bytes,
    NativeWasmSampleBudgetPolicy& policy) noexcept {
  policy = {};
  if (bytes.empty())
    return true;
  if (bytes.size() != kNativeWasmSampleBudgetEncodedBytes || bytes[11] != 0)
    return false;
  const auto get32 = [&bytes](std::size_t offset) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index)
      value |= static_cast<std::uint32_t>(bytes[offset + index]) << (8U * index);
    return value;
  };
  policy.samples_per_function = get32(0);
  policy.samples_per_indirect_site = get32(4);
  policy.module_allow_count = bytes[8];
  policy.function_allow_count = bytes[9];
  policy.function_deny_count = bytes[10];
  std::size_t offset = 12;
  for (auto& digest : policy.module_allow) {
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), digest.size(), digest.begin());
    offset += digest.size();
  }
  for (auto& function : policy.function_allow)
    function = get32(offset), offset += 4;
  for (auto& function : policy.function_deny)
    function = get32(offset), offset += 4;
  if (!IsValidNativeWasmSampleBudgetPolicy(policy)) {
    policy = {};
    return false;
  }
  return true;
}

// Deny wins. An empty allowlist admits every function that is not denied.
[[nodiscard]] inline bool NativeWasmFunctionAllowed(const NativeWasmSampleBudgetPolicy& policy,
                                                    std::uint32_t function_index) noexcept {
  for (std::uint8_t index = 0; index < policy.function_deny_count; ++index) {
    if (policy.function_deny[index] == function_index)
      return false;
  }
  if (policy.function_allow_count == 0)
    return true;
  for (std::uint8_t index = 0; index < policy.function_allow_count; ++index) {
    if (policy.function_allow[index] == function_index)
      return true;
  }
  return false;
}

// An empty allowlist admits every module. A missing digest cannot satisfy one.
[[nodiscard]] inline bool NativeWasmModuleAllowed(const NativeWasmSampleBudgetPolicy& policy,
                                                  const std::uint8_t* digest) noexcept {
  if (policy.module_allow_count == 0)
    return true;
  if (digest == nullptr)
    return false;
  for (std::uint8_t index = 0; index < policy.module_allow_count; ++index) {
    if (std::equal(policy.module_allow[index].begin(), policy.module_allow[index].end(), digest))
      return true;
  }
  return false;
}

// One atomic word owns the count so a release and a reuse cannot both update it.
// Layout, low to high: 15-bit count, publish bit, 16-bit incarnation, 32-bit
// epoch. A count of zero keeps the key visible so the same function can be
// claimed again. Reuse for a different key advances the incarnation. A release
// decrements only that incarnation, so it cannot land on a key that took the
// slot later. An epoch does not fit in 32 bits only after far more resets than
// a browser process performs; admission then fails closed.
struct NativeWasmBudgetKeySlot final {
  std::atomic<std::uint64_t> stamp{0};
  std::atomic<std::uint32_t> kind{0};
  std::atomic<std::uint32_t> primary{0};
  std::atomic<std::uint32_t> secondary{0};
};

enum class NativeWasmBudgetKeyKind : std::uint32_t { kFunction = 0, kSite = 1 };

inline constexpr std::uint64_t kNativeWasmBudgetPublishBit = 0x8000ULL;
inline constexpr std::uint64_t kNativeWasmBudgetCountMask = 0x7fffULL;
inline constexpr std::uint64_t kNativeWasmBudgetIncarnationShift = 16;
inline constexpr std::uint64_t kNativeWasmBudgetIncarnationMask = 0xffffULL;
inline constexpr std::uint64_t kNativeWasmBudgetEpochShift = 32;

[[nodiscard]] inline std::uint64_t NativeWasmBudgetEpochOf(std::uint64_t stamp) noexcept {
  return stamp >> kNativeWasmBudgetEpochShift;
}

[[nodiscard]] inline std::uint32_t NativeWasmBudgetIncarnationOf(std::uint64_t stamp) noexcept {
  return static_cast<std::uint32_t>((stamp >> kNativeWasmBudgetIncarnationShift) &
                                    kNativeWasmBudgetIncarnationMask);
}

[[nodiscard]] inline std::uint32_t NativeWasmBudgetCountOf(std::uint64_t stamp) noexcept {
  return static_cast<std::uint32_t>(stamp & kNativeWasmBudgetCountMask);
}

[[nodiscard]] inline std::uint64_t NativeWasmBudgetStamp(std::uint64_t epoch,
                                                         std::uint32_t incarnation,
                                                         std::uint32_t count) noexcept {
  return (epoch << kNativeWasmBudgetEpochShift) |
         (static_cast<std::uint64_t>(incarnation) << kNativeWasmBudgetIncarnationShift) | count;
}

enum class NativeWasmBudgetRetain : std::uint8_t { kRetained = 0, kCapped = 1 };

struct NativeWasmBudgetRetainResult final {
  NativeWasmBudgetRetain status = NativeWasmBudgetRetain::kCapped;
  std::size_t slot = 0;
  std::uint32_t incarnation = 0;
};

// Visible includes a zero count. A publish bit hides the key until its fields
// are stored. Callers must not treat a publish bit from any epoch as free.
[[nodiscard]] inline bool NativeWasmBudgetStampVisible(std::uint64_t stamp,
                                                       std::uint64_t epoch) noexcept {
  return NativeWasmBudgetEpochOf(stamp) == epoch && (stamp & kNativeWasmBudgetPublishBit) == 0;
}

[[nodiscard]] inline bool NativeWasmBudgetKeyMatches(const NativeWasmBudgetKeySlot& slot,
                                                     std::uint64_t epoch,
                                                     NativeWasmBudgetKeyKind kind,
                                                     std::uint32_t primary,
                                                     std::uint32_t secondary) noexcept {
  if (!NativeWasmBudgetStampVisible(slot.stamp.load(std::memory_order_acquire), epoch))
    return false;
  if (slot.kind.load(std::memory_order_relaxed) != static_cast<std::uint32_t>(kind) ||
      slot.primary.load(std::memory_order_relaxed) != primary)
    return false;
  return kind == NativeWasmBudgetKeyKind::kFunction ||
         slot.secondary.load(std::memory_order_relaxed) == secondary;
}

inline void ReleaseWasmBudgetKey(NativeWasmBudgetKeySlot& slot,
                                 std::uint64_t epoch,
                                 std::uint32_t incarnation) noexcept {
  auto stamp = slot.stamp.load(std::memory_order_acquire);
  while (NativeWasmBudgetStampVisible(stamp, epoch) &&
         NativeWasmBudgetIncarnationOf(stamp) == incarnation &&
         NativeWasmBudgetCountOf(stamp) != 0) {
    if (slot.stamp.compare_exchange_weak(stamp, stamp - 1, std::memory_order_acq_rel,
                                         std::memory_order_acquire))
      return;
  }
}

// Same-key admissions probe from one slot. Two threads that publish the same
// new key in one instant can each hold a slot until the later publisher sees
// the earlier one; a thread that has already returned is not pulled back.
// The stream's 16-slot global budget still bounds how many records are kept.
// A publish bit from any epoch is busy: a reset must not steal the slot and
// let the older publisher overwrite the new count.
[[nodiscard]] inline NativeWasmBudgetRetainResult RetainWasmBudgetKey(
    std::span<NativeWasmBudgetKeySlot> slots,
    std::uint64_t epoch,
    NativeWasmBudgetKeyKind kind,
    std::uint32_t primary,
    std::uint32_t secondary,
    std::uint32_t limit) noexcept {
  NativeWasmBudgetRetainResult capped;
  if (slots.empty() || limit == 0 || limit > kNativeWasmBudgetCountMask || epoch < 2 ||
      (epoch & 1U) != 0 || epoch >= (std::uint64_t{1} << kNativeWasmBudgetEpochShift))
    return capped;
  const auto kind_bits = static_cast<std::uint32_t>(kind);
  const auto start = static_cast<std::size_t>(
      (static_cast<std::uint64_t>(primary) * 0x9e3779b1ULL + secondary + kind_bits) % slots.size());
  for (int attempt = 0; attempt < 64; ++attempt) {
    bool retry = false;
    for (std::size_t probe = 0; probe < slots.size(); ++probe) {
      const auto index = (start + probe) % slots.size();
      auto& slot = slots[index];
      if (NativeWasmBudgetKeyMatches(slot, epoch, kind, primary, secondary)) {
        auto stamp = slot.stamp.load(std::memory_order_acquire);
        while (NativeWasmBudgetStampVisible(stamp, epoch) &&
               NativeWasmBudgetKeyMatches(slot, epoch, kind, primary, secondary)) {
          const auto count = NativeWasmBudgetCountOf(stamp);
          if (count >= limit)
            return capped;
          if (slot.stamp.compare_exchange_weak(stamp, stamp + 1, std::memory_order_acq_rel,
                                               std::memory_order_acquire))
            return {NativeWasmBudgetRetain::kRetained, index, NativeWasmBudgetIncarnationOf(stamp)};
        }
        retry = true;
        break;
      }
      const auto stamp = slot.stamp.load(std::memory_order_acquire);
      if ((stamp & kNativeWasmBudgetPublishBit) != 0) {
        retry = true;
        break;
      }
      const bool live = NativeWasmBudgetEpochOf(stamp) == epoch &&
                        NativeWasmBudgetCountOf(stamp) != 0 && stamp != 0;
      if (live)
        continue;
      auto incarnation = NativeWasmBudgetEpochOf(stamp) == epoch
                             ? NativeWasmBudgetIncarnationOf(stamp)
                             : std::uint32_t{0};
      if (incarnation == kNativeWasmBudgetIncarnationMask)
        continue;
      ++incarnation;
      const auto publishing =
          NativeWasmBudgetStamp(epoch, incarnation, 0) | kNativeWasmBudgetPublishBit;
      auto observed = stamp;
      if (!slot.stamp.compare_exchange_strong(observed, publishing, std::memory_order_acq_rel,
                                              std::memory_order_acquire)) {
        retry = true;
        break;
      }
      slot.kind.store(kind_bits, std::memory_order_relaxed);
      slot.primary.store(primary, std::memory_order_relaxed);
      slot.secondary.store(secondary, std::memory_order_relaxed);
      auto published = publishing;
      if (!slot.stamp.compare_exchange_strong(
              published, NativeWasmBudgetStamp(epoch, incarnation, 1), std::memory_order_acq_rel,
              std::memory_order_acquire)) {
        retry = true;
        break;
      }
      for (std::size_t earlier = 0; earlier < probe; ++earlier) {
        auto& prior = slots[(start + earlier) % slots.size()];
        const auto prior_stamp = prior.stamp.load(std::memory_order_acquire);
        if ((prior_stamp & kNativeWasmBudgetPublishBit) != 0 &&
            NativeWasmBudgetEpochOf(prior_stamp) == epoch) {
          ReleaseWasmBudgetKey(slot, epoch, incarnation);
          retry = true;
          break;
        }
        if (!NativeWasmBudgetKeyMatches(prior, epoch, kind, primary, secondary))
          continue;
        ReleaseWasmBudgetKey(slot, epoch, incarnation);
        auto prior_seen = prior.stamp.load(std::memory_order_acquire);
        while (NativeWasmBudgetStampVisible(prior_seen, epoch) &&
               NativeWasmBudgetKeyMatches(prior, epoch, kind, primary, secondary)) {
          if (NativeWasmBudgetCountOf(prior_seen) >= limit)
            return capped;
          if (prior.stamp.compare_exchange_weak(
                  prior_seen, prior_seen + 1, std::memory_order_acq_rel, std::memory_order_acquire))
            return {NativeWasmBudgetRetain::kRetained, (start + earlier) % slots.size(),
                    NativeWasmBudgetIncarnationOf(prior_seen)};
        }
        retry = true;
        break;
      }
      if (retry)
        break;
      return {NativeWasmBudgetRetain::kRetained, index, incarnation};
    }
    if (!retry)
      return capped;
  }
  return capped;
}

struct NativeWasmBudgetAdmission final {
  enum class Status : std::uint8_t {
    kAdmit = 0,
    kFiltered = 1,
    kFunctionBudget = 2,
    kSiteBudget = 3
  };
  Status status = Status::kAdmit;
  bool function_claimed = false;
  bool site_claimed = false;
  std::size_t function_slot = 0;
  std::size_t site_slot = 0;
  std::uint32_t function_incarnation = 0;
  std::uint32_t site_incarnation = 0;
};

// module_digest is required only when the allowlist is non-empty. An empty
// site span is the br_table stream: it has no call-site cap.
[[nodiscard]] inline NativeWasmBudgetAdmission AdmitNativeWasmBudgetKeys(
    const NativeWasmSampleBudgetPolicy& policy,
    std::span<NativeWasmBudgetKeySlot> function_slots,
    std::span<NativeWasmBudgetKeySlot> site_slots,
    std::uint64_t epoch,
    std::uint32_t function_index,
    std::uint32_t site_offset,
    const std::uint8_t* module_digest) noexcept {
  NativeWasmBudgetAdmission result;
  if (!NativeWasmFunctionAllowed(policy, function_index) ||
      !NativeWasmModuleAllowed(policy, module_digest)) {
    result.status = NativeWasmBudgetAdmission::Status::kFiltered;
    return result;
  }
  if (policy.samples_per_function != 0) {
    const auto retained =
        RetainWasmBudgetKey(function_slots, epoch, NativeWasmBudgetKeyKind::kFunction,
                            function_index, 0, policy.samples_per_function);
    if (retained.status != NativeWasmBudgetRetain::kRetained) {
      result.status = NativeWasmBudgetAdmission::Status::kFunctionBudget;
      return result;
    }
    result.function_claimed = true;
    result.function_slot = retained.slot;
    result.function_incarnation = retained.incarnation;
  }
  if (!site_slots.empty() && policy.samples_per_indirect_site != 0) {
    const auto retained =
        RetainWasmBudgetKey(site_slots, epoch, NativeWasmBudgetKeyKind::kSite, function_index,
                            site_offset, policy.samples_per_indirect_site);
    if (retained.status != NativeWasmBudgetRetain::kRetained) {
      if (result.function_claimed)
        ReleaseWasmBudgetKey(function_slots[result.function_slot], epoch,
                             result.function_incarnation);
      result.function_claimed = false;
      result.status = NativeWasmBudgetAdmission::Status::kSiteBudget;
      return result;
    }
    result.site_claimed = true;
    result.site_slot = retained.slot;
    result.site_incarnation = retained.incarnation;
  }
  return result;
}

inline void ReleaseNativeWasmBudgetAdmission(const NativeWasmBudgetAdmission& admission,
                                             std::span<NativeWasmBudgetKeySlot> function_slots,
                                             std::span<NativeWasmBudgetKeySlot> site_slots,
                                             std::uint64_t epoch) noexcept {
  if (admission.function_claimed && admission.function_slot < function_slots.size())
    ReleaseWasmBudgetKey(function_slots[admission.function_slot], epoch,
                         admission.function_incarnation);
  if (admission.site_claimed && admission.site_slot < site_slots.size())
    ReleaseWasmBudgetKey(site_slots[admission.site_slot], epoch, admission.site_incarnation);
}

[[nodiscard]] inline int NativeWasmHexValue(char character) noexcept {
  if (character >= '0' && character <= '9')
    return character - '0';
  if (character >= 'a' && character <= 'f')
    return character - 'a' + 10;
  if (character >= 'A' && character <= 'F')
    return character - 'A' + 10;
  return -1;
}

// Comma-separated indexes, at least one, no spaces. Duplicates are rejected.
[[nodiscard]] inline bool ParseNativeWasmFunctionList(std::string_view text,
                                                      std::span<std::uint32_t> out,
                                                      std::uint8_t& count) noexcept {
  count = 0;
  if (text.empty() || out.size() < kNativeWasmFunctionFilterLimit)
    return false;
  std::uint32_t value = 0;
  bool in_number = false;
  const auto push = [&]() {
    if (!in_number || count >= kNativeWasmFunctionFilterLimit ||
        value >= kNativeWasmFunctionIndexLimit)
      return false;
    for (std::uint8_t index = 0; index < count; ++index) {
      if (out[index] == value)
        return false;
    }
    out[count++] = value;
    value = 0;
    in_number = false;
    return true;
  };
  for (const char character : text) {
    if (character == ',') {
      if (!push())
        return false;
      continue;
    }
    if (character < '0' || character > '9')
      return false;
    const auto digit = static_cast<std::uint32_t>(character - '0');
    if (value > (kNativeWasmFunctionIndexLimit - digit) / 10U)
      return false;
    value = value * 10U + digit;
    in_number = true;
  }
  return push() && count != 0;
}

// One SHA-256 per line, 64 hex characters. Blank lines and # comments are ignored.
[[nodiscard]] inline bool ParseNativeWasmModuleAllowlist(
    std::string_view text,
    NativeWasmSampleBudgetPolicy& policy) noexcept {
  policy.module_allow_count = 0;
  for (auto& digest : policy.module_allow)
    digest.fill(0);
  std::size_t line_start = 0;
  const auto consume = [&](std::string_view line) {
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
      line.remove_prefix(1);
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
      line.remove_suffix(1);
    if (line.empty() || line.front() == '#')
      return true;
    if (line.size() != 64 || policy.module_allow_count >= kNativeWasmModuleAllowlistLimit)
      return false;
    auto& digest = policy.module_allow[policy.module_allow_count];
    for (std::size_t index = 0; index < digest.size(); ++index) {
      const int high = NativeWasmHexValue(line[index * 2]);
      const int low = NativeWasmHexValue(line[index * 2 + 1]);
      if (high < 0 || low < 0)
        return false;
      digest[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    for (std::uint8_t index = 0; index < policy.module_allow_count; ++index) {
      if (policy.module_allow[index] == digest)
        return false;
    }
    ++policy.module_allow_count;
    return true;
  };
  while (line_start <= text.size()) {
    const auto end = text.find('\n', line_start);
    const auto line = text.substr(
        line_start, end == std::string_view::npos ? text.size() - line_start : end - line_start);
    if (!consume(line)) {
      policy.module_allow_count = 0;
      return false;
    }
    if (end == std::string_view::npos)
      break;
    line_start = end + 1;
  }
  if (policy.module_allow_count == 0)
    return false;
  return true;
}

// A decimal generation, optionally followed by one newline. The browser applies
// a value only when it is greater than the last one it applied.
[[nodiscard]] inline std::optional<std::uint64_t> ParseNativeWasmBudgetResetGeneration(
    std::string_view text) noexcept {
  if (!text.empty() && text.back() == '\n')
    text.remove_suffix(1);
  if (!text.empty() && text.back() == '\r')
    text.remove_suffix(1);
  if (text.empty() || text.size() > 20)
    return std::nullopt;
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9')
      return std::nullopt;
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
      return std::nullopt;
    value = value * 10U + digit;
  }
  return value;
}

[[nodiscard]] inline const char* NativeWasmBrowserBudgetReason(
    NativeWasmBudgetAdmission::Status status,
    bool indirect) noexcept {
  switch (status) {
    case NativeWasmBudgetAdmission::Status::kAdmit:
      return nullptr;
    case NativeWasmBudgetAdmission::Status::kFiltered:
      return indirect ? "native_wasm_indirect_browser_filtered"
                      : "native_wasm_dispatch_browser_filtered";
    case NativeWasmBudgetAdmission::Status::kFunctionBudget:
      return indirect ? "native_wasm_indirect_browser_function_budget_incomplete"
                      : "native_wasm_dispatch_browser_function_budget_incomplete";
    case NativeWasmBudgetAdmission::Status::kSiteBudget:
      return "native_wasm_indirect_browser_site_budget_incomplete";
  }
  return nullptr;
}

[[nodiscard]] inline std::optional<std::uint64_t> ReadNativeWasmBudgetResetGeneration(
    std::string_view path) noexcept {
  if (path.empty() || path.size() > 4096 || path.find('\0') != std::string_view::npos)
    return std::nullopt;
  const std::string text(path);
  std::FILE* file = std::fopen(text.c_str(), "r");
  if (file == nullptr)
    return std::nullopt;
  char buffer[32] = {};
  const auto read = std::fread(buffer, 1, sizeof(buffer), file);
  std::fclose(file);
  // A full buffer may be truncated. Generations are short decimals.
  if (read == 0 || read >= sizeof(buffer))
    return std::nullopt;
  return ParseNativeWasmBudgetResetGeneration(std::string_view(buffer, read));
}

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_COMMON_NATIVE_WASM_SAMPLE_BUDGET_H_
