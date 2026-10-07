// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "native_worker_source.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <string_view>

namespace reb {
namespace {

void Increment(std::uint64_t& value, const std::uint64_t count = 1) noexcept {
  value += std::min(count, std::numeric_limits<std::uint64_t>::max() - value);
}

NativeWorkerCaptureStatus Encode(const NativeWorkerText text,
                                 const std::span<std::uint8_t> output,
                                 const std::size_t limit,
                                 std::size_t& size) noexcept {
  size = 0;
  if (text.unavailable) {
    return NativeWorkerCaptureStatus::kSourceUnavailable;
  }
  if (!text.latin1.empty() && !text.utf16.empty()) {
    return NativeWorkerCaptureStatus::kInvalid;
  }
  const std::size_t units = text.latin1.size() + text.utf16.size();
  if (units > limit) {
    return NativeWorkerCaptureStatus::kTooLarge;
  }
  for (std::size_t index = 0; index < units; ++index) {
    std::uint32_t point = text.utf16.empty() ? text.latin1[index] : text.utf16[index];
    if (point >= 0xd800 && point <= 0xdbff) {
      if (index + 1 == units || text.utf16[index + 1] < 0xdc00 ||
          text.utf16[index + 1] > 0xdfff) {
        return NativeWorkerCaptureStatus::kInvalid;
      }
      point = 0x10000U + ((point - 0xd800U) << 10U) + (text.utf16[++index] - 0xdc00U);
    } else if (point >= 0xdc00 && point <= 0xdfff) {
      return NativeWorkerCaptureStatus::kInvalid;
    }
    const std::size_t count = point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
    if (count > limit - size) {
      return NativeWorkerCaptureStatus::kTooLarge;
    }
    if (!output.empty()) {
      if (count > output.size() - size) {
        return NativeWorkerCaptureStatus::kOutputTooSmall;
      }
      if (count == 1) {
        output[size] = static_cast<std::uint8_t>(point);
      } else {
        for (std::size_t byte = count - 1; byte != 0; --byte) {
          output[size + byte] = static_cast<std::uint8_t>(0x80U | (point & 0x3fU));
          point >>= 6U;
        }
        const std::uint32_t prefix = count == 2 ? 0xc0U : count == 3 ? 0xe0U : 0xf0U;
        output[size] = static_cast<std::uint8_t>(prefix | point);
      }
    }
    size += count;
  }
  return NativeWorkerCaptureStatus::kAccepted;
}

// This is a conservative metadata-admission grammar, NOT a URL/origin parser.
// Never infer URL validity, target authorization, or DNS resolution from it.
NativeWorkerUrlStatus AdmitAuthority(std::string_view authority) noexcept {
  bool bracketed = false;
  std::string_view host;
  std::string_view suffix;
  if (authority.starts_with('[')) {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos || close == 1 ||
        authority.find('[', 1) != std::string_view::npos ||
        authority.find(']', close + 1) != std::string_view::npos) {
      return NativeWorkerUrlStatus::kInvalidOmitted;
    }
    bracketed = true;
    suffix = authority.substr(close + 1);
  } else {
    if (authority.find_first_of("[]") != std::string_view::npos) {
      return NativeWorkerUrlStatus::kInvalidOmitted;
    }
    const std::size_t colon = authority.find(':');
    host = authority.substr(0, colon);
    suffix = colon == std::string_view::npos ? std::string_view{} : authority.substr(colon);
    if (host.empty()) {
      return NativeWorkerUrlStatus::kInvalidOmitted;
    }
  }
  if (!suffix.empty()) {
    if (!suffix.starts_with(':') || suffix.size() == 1) {
      return NativeWorkerUrlStatus::kInvalidOmitted;
    }
    std::uint32_t port = 0;
    for (const char digit : suffix.substr(1)) {
      if (digit < '0' || digit > '9') {
        return NativeWorkerUrlStatus::kInvalidOmitted;
      }
      port = port * 10U + static_cast<std::uint32_t>(digit - '0');
      if (port > 65535) {
        return NativeWorkerUrlStatus::kInvalidOmitted;
      }
    }
  }
  // Do not implement an IPv6, IDNA, percent-decoded host, or WHATWG parser in
  // this allocation-free queue. Such authorities are explicitly omitted.
  if (bracketed) {
    return NativeWorkerUrlStatus::kUnsupportedAuthorityOmitted;
  }
  if (host.ends_with('.')) {
    host.remove_suffix(1);
  }
  if (host.empty() || host.size() > 253) {
    return NativeWorkerUrlStatus::kUnsupportedAuthorityOmitted;
  }
  while (!host.empty()) {
    const std::size_t dot = host.find('.');
    const std::string_view label = host.substr(0, dot);
    if (label.empty() || label.size() > 63 || label.starts_with('-') || label.ends_with('-') ||
        std::any_of(label.begin(), label.end(), [](const char character) {
          return !((character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '-');
        })) {
      return NativeWorkerUrlStatus::kUnsupportedAuthorityOmitted;
    }
    if (dot == std::string_view::npos) {
      break;
    }
    host.remove_prefix(dot + 1);
    if (host.empty()) {
      return NativeWorkerUrlStatus::kUnsupportedAuthorityOmitted;
    }
  }
  return NativeWorkerUrlStatus::kSanitized;
}

NativeWorkerUrlStatus SanitizeUrl(const NativeWorkerText text,
                                  const std::span<char> output,
                                  std::uint32_t& size) noexcept {
  size = 0;
  std::array<std::uint8_t, kNativeWorkerSourceMaxUrlBytes> encoded{};
  std::size_t encoded_size = 0;
  if (Encode(text, encoded, encoded.size(), encoded_size) !=
      NativeWorkerCaptureStatus::kAccepted) {
    return NativeWorkerUrlStatus::kInvalidOmitted;
  }
  if (encoded_size == 0) {
    return NativeWorkerUrlStatus::kAbsent;
  }
  std::string_view url(reinterpret_cast<const char*>(encoded.data()), encoded_size);
  if (std::any_of(url.begin(), url.end(), [](const unsigned char value) {
        return value <= 0x20 || value == 0x7f || value == '\\';
      })) {
    return NativeWorkerUrlStatus::kInvalidOmitted;
  }
  const std::size_t scheme = url.starts_with("https://") ? 8 : url.starts_with("http://") ? 7 : 0;
  if (scheme == 0) {
    // Never copy data URLs, blob identifiers, extension/file URLs, or custom
    // schemes into metadata. The omission is explicit, never a fabricated URL.
    return NativeWorkerUrlStatus::kOpaqueOmitted;
  }
  url = url.substr(0, url.find_first_of("?#"));
  const std::size_t authority_end = url.find('/', scheme);
  const std::size_t end = authority_end == std::string_view::npos ? url.size() : authority_end;
  const std::string_view authority = url.substr(scheme, end - scheme);
  const std::size_t at = authority.rfind('@');
  const std::size_t host = at == std::string_view::npos ? scheme : scheme + at + 1;
  const auto admission = AdmitAuthority(url.substr(host, end - host));
  if (admission != NativeWorkerUrlStatus::kSanitized) {
    return admission;
  }
  std::copy_n(url.begin(), scheme, output.begin());
  std::copy(url.begin() + static_cast<std::ptrdiff_t>(host), url.end(),
            output.begin() + static_cast<std::ptrdiff_t>(scheme));
  size = static_cast<std::uint32_t>(scheme + url.size() - host);
  return NativeWorkerUrlStatus::kSanitized;
}

}  // namespace

struct NativeWorkerSourceQueue::Slot final {
  NativeWorkerSourceHeader header;
  std::array<std::uint8_t, kNativeWorkerSourceMaxBytes> source{};
  std::array<char, kNativeWorkerSourceMaxUrlBytes> url{};
  void Clear() noexcept {
    std::fill_n(source.begin(), header.source_size, 0);
    std::fill_n(url.begin(), header.url_size, '\0');
    header = NativeWorkerSourceHeader{};
  }
};

NativeWorkerSourceQueue::NativeWorkerSourceQueue() = default;

NativeWorkerSourceQueue::~NativeWorkerSourceQueue() {
  Disable();
}

NativeWorkerCaptureStatus NativeWorkerSourceQueue::Configure(
    const NativeWorkerSourcePolicy& policy, const std::uint64_t now_ns) noexcept {
  active_generation_.store(0, std::memory_order_release);
  const std::lock_guard lock(mutex_);
  ClearLocked();
  if (policy.session_id == 0 || policy.generation == 0 ||
      policy.generation <= greatest_generation_ || policy.expires_at_monotonic_ns <= now_ns ||
      !policy.browser_context.valid() || !policy.renderer_instance.valid() ||
      !policy.worker.valid() || !policy.sensitive_source_approved) {
    return NativeWorkerCaptureStatus::kInvalid;
  }
  if (!slots_) {
    slots_.reset(new (std::nothrow) Slot[kNativeWorkerSourceCapacity]);
    if (!slots_) {
      return NativeWorkerCaptureStatus::kAllocationFailed;
    }
  }
  greatest_generation_ = policy.generation;
  policy_ = policy;
  worker_high_.store(policy.worker.high, std::memory_order_relaxed);
  worker_low_.store(policy.worker.low, std::memory_order_relaxed);
  // This release publishes the policy and token after the queue has been
  // cleared. A retired generation is never reused, even with the same worker.
  active_generation_.store(policy.generation, std::memory_order_release);
  return NativeWorkerCaptureStatus::kAccepted;
}

void NativeWorkerSourceQueue::ClearLocked() noexcept {
  Increment(stats_.retired, stats_.queued);
  while (stats_.queued != 0) {
    slots_[read_].Clear();
    read_ = (read_ + 1) % kNativeWorkerSourceCapacity;
    --stats_.queued;
  }
  read_ = 0;
  write_ = 0;
  stats_.pending_gap = 0;
}

void NativeWorkerSourceQueue::Disable() noexcept {
  active_generation_.store(0, std::memory_order_release);
  const std::lock_guard lock(mutex_);
  active_generation_.store(0, std::memory_order_release);
  ClearLocked();
}

void NativeWorkerSourceQueue::RetireWorker(const NativeWorkerToken worker) noexcept {
  std::uint64_t generation = active_generation_.load(std::memory_order_acquire);
  if (generation == 0 || worker.high != worker_high_.load(std::memory_order_relaxed) ||
      worker.low != worker_low_.load(std::memory_order_relaxed) ||
      !active_generation_.compare_exchange_strong(generation, 0, std::memory_order_acq_rel,
                                                  std::memory_order_acquire)) {
    return;
  }
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (lock.owns_lock() && policy_.generation == generation) {
    ClearLocked();
  }
}

void NativeWorkerSourceQueue::CountContention() noexcept {
  // Exact accounting with no retry loop. Saturation is represented separately
  // so racing increments cannot be silently lost on a failed CAS.
  if (contended_.fetch_add(1, std::memory_order_relaxed) ==
      std::numeric_limits<std::uint64_t>::max()) {
    contention_overflow_.store(true, std::memory_order_release);
  }
}

NativeWorkerCaptureStatus NativeWorkerSourceQueue::Begin(
    const NativeWorkerKind kind, const NativeWorkerToken worker, const std::uint64_t now_ns,
    NativeWorkerCaptureTicket& ticket) noexcept {
  ticket = {};
  if (!IsEnabled()) [[likely]] {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  if (kind != NativeWorkerKind::kDedicated) {
    return NativeWorkerCaptureStatus::kUnsupportedWorker;
  }
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    CountContention();
    return NativeWorkerCaptureStatus::kBusy;
  }
  if (!IsEnabled()) {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  if (now_ns >= policy_.expires_at_monotonic_ns) {
    return NativeWorkerCaptureStatus::kExpired;
  }
  if (worker != policy_.worker) {
    return NativeWorkerCaptureStatus::kWrongWorker;
  }
  ticket = {policy_.session_id, policy_.generation, worker};
  return NativeWorkerCaptureStatus::kAccepted;
}

NativeWorkerCaptureStatus NativeWorkerSourceQueue::DropLocked(
    const NativeWorkerCaptureStatus status) noexcept {
  Increment(stats_.dropped);
  Increment(stats_.pending_gap);
  return status;
}

NativeWorkerCaptureStatus NativeWorkerSourceQueue::Capture(
    const NativeWorkerCaptureTicket& ticket, const NativeWorkerToken parent_context,
    const NativeWorkerSourceKind kind, const NativeWorkerText source, const NativeWorkerText url,
    const std::uint64_t now_ns) noexcept {
  if (!IsEnabled()) [[likely]] {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    CountContention();
    return NativeWorkerCaptureStatus::kBusy;
  }
  if (ticket.generation != policy_.generation || ticket.session_id != policy_.session_id ||
      ticket.worker != policy_.worker ||
      active_generation_.load(std::memory_order_acquire) != ticket.generation) {
    Increment(stats_.stale);
    return NativeWorkerCaptureStatus::kStaleGeneration;
  }
  if (now_ns >= policy_.expires_at_monotonic_ns) {
    return NativeWorkerCaptureStatus::kExpired;
  }
  if (stats_.attempted == std::numeric_limits<std::uint64_t>::max()) {
    active_generation_.store(0, std::memory_order_release);
    return DropLocked(NativeWorkerCaptureStatus::kFull);
  }
  ++stats_.attempted;
  if (kind != NativeWorkerSourceKind::kClassic && kind != NativeWorkerSourceKind::kModule) {
    return DropLocked(NativeWorkerCaptureStatus::kInvalid);
  }
  if (stats_.queued == kNativeWorkerSourceCapacity) {
    return DropLocked(NativeWorkerCaptureStatus::kFull);
  }
  std::size_t source_size = 0;
  const auto status = Encode(source, {}, kNativeWorkerSourceMaxBytes, source_size);
  if (status != NativeWorkerCaptureStatus::kAccepted) {
    return DropLocked(status);
  }
  Slot& slot = slots_[write_];
  slot.header = NativeWorkerSourceHeader{};
  slot.header.session_id = policy_.session_id;
  slot.header.generation = policy_.generation;
  slot.header.browser_context = policy_.browser_context;
  slot.header.renderer_instance = policy_.renderer_instance;
  slot.header.worker = policy_.worker;
  slot.header.parent_context = parent_context;
  slot.header.sequence = stats_.attempted;
  slot.header.monotonic_time_ns = now_ns;
  slot.header.source_kind = kind;
  slot.header.source_code_units = static_cast<std::uint32_t>(source.latin1.size() + source.utf16.size());
  slot.header.url_status = SanitizeUrl(url, slot.url, slot.header.url_size);
  const auto encoded = Encode(source, slot.source, kNativeWorkerSourceMaxBytes, source_size);
  slot.header.source_size = static_cast<std::uint32_t>(source_size);
  if (encoded != NativeWorkerCaptureStatus::kAccepted ||
      active_generation_.load(std::memory_order_acquire) != ticket.generation) {
    slot.Clear();
    Increment(stats_.stale);
    return DropLocked(NativeWorkerCaptureStatus::kStaleGeneration);
  }
  slot.header.dropped_before = stats_.pending_gap;
  stats_.pending_gap = 0;
  write_ = (write_ + 1) % kNativeWorkerSourceCapacity;
  ++stats_.queued;
  return NativeWorkerCaptureStatus::kAccepted;
}

NativeWorkerCaptureStatus NativeWorkerSourceQueue::Take(NativeWorkerSourceHeader& header,
                                                       const std::span<std::uint8_t> source,
                                                       const std::span<char> url,
                                                       const std::uint64_t now_ns) noexcept {
  header = {};
  if (!IsEnabled()) {
    return NativeWorkerCaptureStatus::kDisabled;
  }
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    return NativeWorkerCaptureStatus::kBusy;
  }
  if (!IsEnabled() || now_ns >= policy_.expires_at_monotonic_ns) {
    ClearLocked();
    return NativeWorkerCaptureStatus::kExpired;
  }
  if (stats_.queued == 0) {
    return NativeWorkerCaptureStatus::kEmpty;
  }
  Slot& slot = slots_[read_];
  if (source.size() < slot.header.source_size || url.size() < slot.header.url_size) {
    return NativeWorkerCaptureStatus::kOutputTooSmall;
  }
  std::copy_n(slot.source.begin(), slot.header.source_size, source.begin());
  std::copy_n(slot.url.begin(), slot.header.url_size, url.begin());
  header = slot.header;
  slot.Clear();
  read_ = (read_ + 1) % kNativeWorkerSourceCapacity;
  --stats_.queued;
  if (active_generation_.load(std::memory_order_acquire) != header.generation) {
    std::fill_n(source.begin(), header.source_size, 0);
    std::fill_n(url.begin(), header.url_size, '\0');
    header = {};
    Increment(stats_.retired);
    return NativeWorkerCaptureStatus::kStaleGeneration;
  }
  return NativeWorkerCaptureStatus::kAccepted;
}

NativeWorkerSourceStats NativeWorkerSourceQueue::Stats() noexcept {
  const std::lock_guard lock(mutex_);
  NativeWorkerSourceStats result = stats_;
  result.contended = contended_.load(std::memory_order_relaxed);
  if (contention_overflow_.load(std::memory_order_acquire)) {
    result.contended = std::numeric_limits<std::uint64_t>::max();
  }
  return result;
}

}  // namespace reb
