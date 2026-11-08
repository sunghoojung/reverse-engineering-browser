// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#include "brave/components/reverse_engineering_browser/renderer/native_script_cookie_sink.h"

#include <algorithm>
#include <limits>

#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "brave/components/reverse_engineering_browser/renderer/native_probe_sink.h"
#include "brave/components/reverse_engineering_browser/renderer/native_request_stack.h"
#include "crypto/hash.h"

namespace reb {

namespace {

std::string_view Trim(const std::string_view text) noexcept {
  constexpr std::string_view kWhitespace = " \t";
  const std::size_t first = text.find_first_not_of(kWhitespace);
  if (first == std::string_view::npos) {
    return {};
  }
  return text.substr(first, text.find_last_not_of(kWhitespace) - first + 1);
}

std::uint32_t Clamp32(const std::size_t value) noexcept {
  return static_cast<std::uint32_t>(
      std::min<std::size_t>(value, std::numeric_limits<std::uint32_t>::max()));
}

}  // namespace

NativeScriptCookieSink& NativeScriptCookieSink::Get() {
  static base::NoDestructor<NativeScriptCookieSink> sink;
  return *sink;
}

NativeScriptCookieSink::NativeScriptCookieSink() noexcept = default;

void NativeScriptCookieSink::Configure(const bool capture_content,
                                       const FrameProvider provider) noexcept {
  Flush();
  const NativeProbeSink& sink = NativeProbeSink::Get();
  const std::uint64_t generation = sink.config_generation_.load(std::memory_order_acquire);
  const bool active = capture_content && provider && (generation & 1U) == 0 &&
                      sink.emitter_.load(std::memory_order_acquire);
  provider_.store(active ? provider : nullptr, std::memory_order_relaxed);
  generation_.store(active ? generation : 0, std::memory_order_release);
}

void NativeScriptCookieSink::Flush() noexcept {
  const std::uint64_t generation = generation_.exchange(0, std::memory_order_acq_rel);
  base::AutoLock lock(reads_lock_);
  if (generation != 0) {
    for (std::size_t index = 0; index < read_keys_; ++index) {
      const ReadEntry& entry = reads_[index];
      if (entry.unreported == 0) {
        continue;
      }
      NativeScriptCookieSummary summary;
      summary.api = entry.key.api;
      summary.count = entry.unreported;
      summary.name_length = entry.key.name_length;
      summary.name_prefix = entry.key.name_prefix;
      summary.string_length = entry.string_length;
      summary.frame = entry.key.frame;
      summary.flags = static_cast<std::uint8_t>(
          (entry.key.name_length > kNativeScriptCookieNamePrefixBytes
               ? kNativeScriptCookieNameTruncated
               : 0) |
          (entry.key.frame.kind != 0 ? kNativeScriptCookieFrameRecorded : 0));
      static_cast<void>(Emit(summary, entry.key.frame_id, generation));
    }
  }
  read_keys_ = 0;
}

NativeScriptCookieSummary NativeScriptCookieSink::Summary(
    const NativeScriptCookieApi api,
    const std::string_view name) const noexcept {
  NativeScriptCookieSummary summary;
  summary.api = api;
  summary.name_length = Clamp32(name.size());
  const std::size_t kept = std::min(name.size(), summary.name_prefix.size());
  std::transform(name.begin(), name.begin() + static_cast<std::ptrdiff_t>(kept),
                 summary.name_prefix.begin(),
                 [](const char c) { return static_cast<std::uint8_t>(c); });
  if (name.size() > kept) {
    summary.flags |= kNativeScriptCookieNameTruncated;
  }
  NativeScriptFrame frame;
  if (const FrameProvider provider = provider_.load(std::memory_order_relaxed);
      provider && provider(frame) && (frame.kind == 1 || frame.kind == 2) && frame.script_id != 0) {
    frame.combinator = 0;
    frame.flags &= 0x03U;
    summary.frame = frame;
    summary.flags |= kNativeScriptCookieFrameRecorded;
  }
  return summary;
}

void NativeScriptCookieSink::RecordDocumentCookieSet(const std::string_view cookie_string,
                                                     const std::uint64_t frame_id) noexcept {
  if (!IsEnabled()) [[likely]] {
    return;
  }
  // ParsedCookie's pair: up to the first ';', split at the first '='.
  const std::string_view pair = cookie_string.substr(0, cookie_string.find(';'));
  const std::size_t equals = pair.find('=');
  const std::string_view name =
      equals == std::string_view::npos ? std::string_view() : Trim(pair.substr(0, equals));
  const std::string_view value =
      Trim(equals == std::string_view::npos ? pair : pair.substr(equals + 1));
  NativeScriptCookieSummary summary = Summary(NativeScriptCookieApi::kDocumentCookieSet, name);
  summary.value_length = Clamp32(value.size());
  summary.string_length = Clamp32(cookie_string.size());
  Record(summary, frame_id, value);
}

void NativeScriptCookieSink::RecordDocumentCookieGet(const std::size_t string_length,
                                                     const std::uint64_t frame_id) noexcept {
  if (!IsEnabled()) [[likely]] {
    return;
  }
  NativeScriptCookieSummary summary = Summary(NativeScriptCookieApi::kDocumentCookieGet, {});
  summary.string_length = Clamp32(string_length);
  RecordRead(summary, frame_id);
}

void NativeScriptCookieSink::RecordCookieStore(const NativeScriptCookieApi api,
                                               const std::string_view name,
                                               const std::string_view value) noexcept {
  if (!IsEnabled()) [[likely]] {
    return;
  }
  NativeScriptCookieSummary summary = Summary(api, name);
  if (api == NativeScriptCookieApi::kCookieStoreSet ||
      api == NativeScriptCookieApi::kCookieStoreDelete) {
    summary.value_length = Clamp32(value.size());
    Record(summary, 0, value);
  } else {
    RecordRead(summary, 0);
  }
}

std::uint64_t NativeScriptCookieSink::CallingFrameId() noexcept {
  const NativeProbeFrameIdProvider calling =
      NativeProbeSink::Get().frame_id_provider_.load(std::memory_order_relaxed);
  return calling ? calling() : 0;
}

void NativeScriptCookieSink::Record(NativeScriptCookieSummary summary,
                                    std::uint64_t frame_id,
                                    const std::string_view value) noexcept {
  const std::uint64_t generation = generation_.load(std::memory_order_acquire);
  if (generation == 0) {
    return;
  }
  summary.count = 1;
  summary.value_sha256 = crypto::hash::Sha256(value);
  frame_id = frame_id ? frame_id : CallingFrameId();
  // Reserved first so the walked stack's artifact can name this record.
  const std::uint64_t sequence =
      NativeProbeSink::Get().next_sequence_.fetch_add(1, std::memory_order_relaxed);
  NativeStackFrame innermost;
  if (NativeRequestStackWalk::RecordCookieStack(sequence, frame_id, summary.stack_digest,
                                                innermost) &&
      (innermost.kind == 1 || innermost.kind == 2)) {
    summary.frame = NativeScriptFrame{innermost.kind,
                                      static_cast<std::uint8_t>(innermost.flags & 0x03U),
                                      0,
                                      innermost.script_id,
                                      innermost.position,
                                      innermost.detail};
    summary.flags |= kNativeScriptCookieFrameRecorded | kNativeScriptCookieStackRecorded;
  } else {
    summary.stack_digest = {};
  }
  static_cast<void>(Emit(summary, frame_id, generation, sequence));
}

void NativeScriptCookieSink::RecordRead(NativeScriptCookieSummary summary,
                                        std::uint64_t frame_id) noexcept {
  const std::uint64_t generation = generation_.load(std::memory_order_acquire);
  if (generation == 0) {
    return;
  }
  frame_id = frame_id ? frame_id : CallingFrameId();
  const ReadKey key{frame_id, summary.frame, summary.name_length, summary.name_prefix, summary.api};
  base::AutoLock lock(reads_lock_);
  // A configuration that ended while this call ran no longer owns the table.
  if (generation_.load(std::memory_order_acquire) != generation) {
    return;
  }
  ReadEntry* const begin = reads_.data();
  ReadEntry* const end = begin + read_keys_;
  ReadEntry* const found =
      std::find_if(begin, end, [&key](const ReadEntry& entry) { return entry.key == key; });
  if (found != end) {
    found->string_length = summary.string_length;
    ++found->unreported;
    if (found->reads != std::numeric_limits<std::uint32_t>::max()) {
      ++found->reads;
    }
    // Powers of two bound a hot key to log2(reads) records.
    if (!std::has_single_bit(found->reads) &&
        found->unreported != std::numeric_limits<std::uint32_t>::max()) {
      return;
    }
    summary.count = found->unreported;
    found->unreported = 0;
  } else if (read_keys_ < reads_.size()) {
    reads_[read_keys_++] = ReadEntry{key, summary.string_length, 1, 0};
    summary.count = 1;
  } else {
    summary.flags |= kNativeScriptCookieTableFull;
    summary.count = 1;
  }
  static_cast<void>(Emit(summary, frame_id, generation));
}

bool NativeScriptCookieSink::Emit(const NativeScriptCookieSummary& summary,
                                  const std::uint64_t frame_id,
                                  const std::uint64_t generation,
                                  const std::uint64_t sequence) noexcept {
  NativeProbeSink& sink = NativeProbeSink::Get();
  NativeProbeEvent event;
  event.header.category = NativeProbeCategory::kNetwork;
  event.header.type = NativeProbeType::kScriptCookie;
  event.header.sequence_number =
      sequence ? sequence : sink.next_sequence_.fetch_add(1, std::memory_order_relaxed);
  event.header.session_id = sink.session_id_.load(std::memory_order_relaxed);
  event.header.monotonic_time_ns =
      static_cast<std::uint64_t>(base::TimeTicks::Now().since_origin().InNanoseconds());
  event.header.process_id = static_cast<std::uint32_t>(base::GetCurrentProcId());
  event.header.thread_id = static_cast<std::uint32_t>(base::PlatformThread::CurrentId().raw());
  event.header.frame_id = frame_id;
  event.header.payload_size = kNativeRequestPayloadSize;
  event.inline_payload = EncodeNativeScriptCookiePayload(summary);
  // The sink admits only the unchanged session, category and expiry.
  return sink.EmitStatus(event, generation) == NativeProbeEmitStatus::kAdmitted;
}

}  // namespace reb
